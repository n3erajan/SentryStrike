import asyncio
import json
import logging
import re
import uuid
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qsl, unquote, urlparse, urlunparse

from app.config import get_settings
from app.core.crawler.spa import SpaFallbackDetector
from app.core.crawler.models import ApiEndpoint, ParameterCandidate, ParameterLocation, RequestObservation
from app.core.detectors.attack_surface import AttackSurface, AttackTarget, PreparedAttackRequest
from app.core.detectors.base_detector import BaseDetector, Finding
from app.core.verification.verification_framework import HttpVerifier
from app.models.vulnerability import OwaspCategory, SeverityLevel

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class _AuthMaterial:
    label: str
    cookies: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)

    @property
    def configured(self) -> bool:
        return bool(self.cookies or self.headers)


@dataclass(frozen=True)
class _MatrixTarget:
    request: PreparedAttackRequest
    source: str
    parameter: str | None = None
    parameter_location: str | None = None
    has_object_reference: bool = False
    admin_like: bool = False


@dataclass(frozen=True)
class _ResponseProfile:
    status_code: int
    content_type: str
    success: bool
    is_json: bool
    json_shape: frozenset[str] = field(default_factory=frozenset)
    identifiers: frozenset[str] = field(default_factory=frozenset)
    sensitive_fields: frozenset[str] = field(default_factory=frozenset)
    # Narrow subset of sensitive_fields that carry genuinely secret material
    # (credentials, tokens, keys, crypto seeds). Unlike broad PII field names
    # (email/username/role), a secret field in an anonymous response is an
    # unambiguous leak regardless of whether the endpoint is otherwise public.
    secret_fields: frozenset[str] = field(default_factory=frozenset)
    item_count: int = 0
    body_length: int = 0

# State-changing HTTP methods whose authorization is tested non-destructively
# (synthetic non-existent id + status differential), never via the read-oriented
# IDOR baseline. POST is excluded: it targets a collection (no owner id to
# destroy) and is already exercised by the auth matrix / create paths.
_MUTATING_AUTHZ_METHODS = frozenset({"PUT", "PATCH", "DELETE"})

# ---------------------------------------------------------------------------
# Regex helpers
# ---------------------------------------------------------------------------
_NUMERIC_RE = re.compile(r"^\d+$")
_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE
)
# Long hex identifiers (Mongo ObjectId = 24, SHA-1 = 40, etc.).
_LONG_HEX_RE = re.compile(r"^[0-9a-f]{16,}$", re.IGNORECASE)
# Opaque base64url/token identifiers: long, mixed, and containing a digit so
# ordinary path words ("changelog", "dashboard") are not treated as ids.
_OPAQUE_ID_SEGMENT_RE = re.compile(r"^(?=.*\d)[A-Za-z0-9_\-]{12,}$")


def _looks_like_path_id_segment(segment: str) -> bool:
    """True when a REST path segment looks like an object id.

    Covers pure integers, UUIDs, long hex strings (ObjectId/SHA), and opaque
    base64url-style tokens that mix letters and digits. Purely alphabetic
    segments are never treated as ids so route words are not fuzzed.
    """
    if not segment:
        return False
    if _NUMERIC_RE.match(segment) or _UUID_RE.match(segment):
        return True
    if _LONG_HEX_RE.match(segment):
        return True
    return bool(_OPAQUE_ID_SEGMENT_RE.match(segment))


# ---------------------------------------------------------------------------
# IDOR value classification
#
# A genuine object-reference ID is one of:
#   1. A pure integer  (e.g. 42, 1000)
#   2. A UUID          (e.g. 550e8400-e29b-41d4-a716-446655440000)
#   3. A short opaque token that contains at least one digit AND is not a
#      common English word / semantic slug.  This prevents "changelog",
#      "about", "home", "admin" etc. from being treated as IDs.
#
# The old IDOR_VALUE_PATTERN matched any [a-zA-Z0-9_-]{1,32}, which was far
# too broad and was the primary root cause of semantic-slug false positives.
# ---------------------------------------------------------------------------

# Pattern 3: opaque token — must have digits mixed in (e.g. "abc123", "user_42")
# Pure alpha strings like "changelog" do NOT match.
_OPAQUE_TOKEN_RE = re.compile(r"^(?=.*\d)[a-zA-Z0-9_\-]{2,32}$")

# Well-known semantic slug words that should never be treated as IDs even if
# they happen to pass a regex.  This list is intentionally generic — it covers
# routing / navigation tokens that appear across many frameworks and apps.
_SEMANTIC_SLUGS: frozenset[str] = frozenset({
    # Navigation / document-type words
    "home", "about", "index", "main", "default", "start", "welcome",
    "help", "faq", "docs", "documentation", "manual", "guide", "tutorial",
    "changelog", "changes", "history", "readme", "license", "terms", "privacy",
    "contact", "support", "feedback", "blog", "news", "events", "updates",
    # Status / action words
    "new", "edit", "create", "delete", "update", "view", "show", "list",
    "search", "filter", "sort", "export", "import", "upload", "download",
    "login", "logout", "register", "signup", "signin", "signout", "reset",
    # Common CMS / framework page names
    "page", "post", "article", "category", "tag", "section", "chapter",
    "dashboard", "overview", "summary", "report", "analytics", "stats",
    # Misc tokens that appear as param values in real apps
    "all", "any", "none", "latest", "recent", "popular", "featured",
    "active", "inactive", "enabled", "disabled", "pending", "done", "open",
    "public", "private", "draft", "published", "archived",
})


def _is_valid_id_value(val: str) -> bool:
    """
    Return True only when *val* looks like a genuine object-reference
    identifier — not a semantic slug or human-readable keyword.

    Accepts:
      - Pure integers: "1", "42", "10000"
      - UUIDs: "550e8400-e29b-41d4-a716-446655440000"
      - Opaque tokens that contain at least one digit mixed with letters
        (e.g. "abc123", "user_42", "t9k3m") and are NOT in the semantic
        slug blocklist.

    Rejects:
      - Empty strings
      - Boolean/null literals ("true", "false", "null", …)
      - Pure alphabetic strings of any length ("changelog", "home", …)
      - Values in the semantic slug blocklist
    """
    if not val:
        return False
    lower = val.lower()
    # Hard blocklist first — quick exit
    if lower in _NON_ID_VALUES or lower in _SEMANTIC_SLUGS:
        return False
    # Pure integers are always valid IDs
    if _NUMERIC_RE.match(val):
        return True
    # UUIDs are always valid IDs
    if _UUID_RE.match(val):
        return True
    # Opaque token: must contain at least one digit
    if _OPAQUE_TOKEN_RE.match(val):
        return True
    # Everything else (pure alpha strings, etc.) is rejected
    return False


# Tokens that signal "this looks like a login page body"
_LOGIN_SIGNALS = frozenset(["login", "sign in", "signin"])
_LOGIN_CREDENTIAL_SIGNALS = frozenset(["password", "username", "email"])

# Signals inside a soft-200 body that indicate "resource not found"
_SOFT_NOTFOUND_SIGNALS: tuple[str, ...] = (
    "not found", "no such", "does not exist", "invalid id",
    "no record", "resource not found", "page not found",
    "404", "error", "invalid", "unknown",
)

# Non-ID literal values that should never be treated as object references
_NON_ID_VALUES: frozenset[str] = frozenset({
    "on", "off", "true", "false", "yes", "no", "null", "none", "undefined",
})


def _looks_like_login_page(body: str) -> bool:
    """Return True when the response body appears to be a login/auth wall.

    A login wall is an HTML document. A structured JSON/data payload is an API
    response and is NEVER a login page — even when it contains field names such
    as ``email``, ``username`` or ``lastLoginIp`` (whose substring "login"
    otherwise trips the word heuristic). Guarding on JSON first prevents a data
    collection (e.g. a user listing) from being misread as a login wall, which
    would suppress genuine authorization findings against it.
    """
    stripped = body.lstrip()
    if stripped[:1] in ("{", "["):
        try:
            json.loads(stripped)
            return False
        except ValueError:
            pass
    b = body.lower()
    has_login_word = any(s in b for s in _LOGIN_SIGNALS)
    has_credential_field = any(s in b for s in _LOGIN_CREDENTIAL_SIGNALS)
    return has_login_word and has_credential_field


def _looks_like_error_page(body: str) -> bool:
    """
    Return True when the body looks like a generic error / not-found page
    rather than a real resource.  Used to filter soft-200 responses.
    """
    b = body.lower()
    return any(s in b for s in _SOFT_NOTFOUND_SIGNALS)


def _mutate_id(val: str) -> list[str]:
    """
    Return a list of candidate mutated IDs for the given value.

    Covers numeric, UUID, and opaque/hash-style identifiers so that the
    detector doesn't silently skip non-integer IDs.
    """
    candidates: list[str] = []

    # Numeric: try +1 and -1 (guard against negative IDs)
    if _NUMERIC_RE.match(val):
        n = int(val)
        candidates.append(str(n + 1))
        if n > 1:
            candidates.append(str(n - 1))
        return candidates

    # UUID v4: flip the last hex digit to produce a plausibly different UUID
    if _UUID_RE.match(val):
        parts = val.split("-")
        last = parts[-1]
        flipped = last[:-1] + ("0" if last[-1] != "0" else "1")
        candidates.append("-".join(parts[:-1] + [flipped]))
        return candidates

    # Opaque short token: swap last digit(s) to produce a different-looking ID
    # E.g. "user42" → "user43"; "abc123" → "abc124"
    m = re.search(r"(\d+)$", val)
    if m:
        prefix = val[: m.start()]
        n = int(m.group(1))
        candidates.append(prefix + str(n + 1))
        if n > 1:
            candidates.append(prefix + str(n - 1))
        return candidates

    # Fallback for fully opaque tokens without trailing digits:
    # try appending "1" / "2" to generate distinct candidates
    candidates.append(val + "1")
    candidates.append(val + "2")
    return candidates


def _strip_query(url: str) -> str:
    """Return the URL with the query-string removed."""
    p = urlparse(url)
    return urlunparse((p.scheme, p.netloc, p.path, p.params, "", p.fragment))


# ---------------------------------------------------------------------------
# Burp-Suite-inspired differential analysis helpers
#
# Burp Suite's IDOR detection (Collaborator + active scanning) works by:
#   1. Making a baseline request with the authenticated session.
#   2. Making the same request *without* credentials → if it already returns
#      200, the resource is public and IDOR is not applicable.
#   3. Mutating the ID and requesting with credentials.
#   4. Comparing the mutated response against:
#      a. The unauthenticated mutated response  — if unauth also gets 200,
#         the mutated resource is public, not an access-control bypass.
#      b. The authenticated own-resource response — the content should be
#         *meaningfully different* (a different object was returned) but not
#         so different that it looks like a generic error page.
#   5. Only flagging when the authenticated mutated response is clearly a
#      real resource that differs from the authenticated session's own data.
#
# We implement the same multi-signal differential below.
# ---------------------------------------------------------------------------

def _json_structural_analysis(a: str, b: str) -> tuple[float, float] | None:
    import json
    try:
        ja = json.loads(a)
        jb = json.loads(b)
    except Exception:
        return None
        
    def flatten(obj: object, prefix: str = "") -> dict[str, object]:
        items: dict[str, object] = {}
        if isinstance(obj, dict):
            for k, v in obj.items():
                items.update(flatten(v, f"{prefix}.{k}"))
        elif isinstance(obj, list):
            for i, v in enumerate(obj):
                items.update(flatten(v, f"{prefix}[{i}]"))
        else:
            items[prefix] = obj
        return items
        
    fa = flatten(ja)
    fb = flatten(jb)
    if not fa and not fb:
        return 1.0, 1.0
        
    keys_union = set(fa.keys()) | set(fb.keys())
    if not keys_union:
        return 1.0, 1.0
        
    key_matches = sum(1 for k in keys_union if k in fa and k in fb)
    val_matches = sum(1 for k in keys_union if fa.get(k) == fb.get(k))
    return key_matches / len(keys_union), val_matches / len(keys_union)

def _differential_idor_verdict(
    *,
    own_body: str,
    mutated_authed_body: str,
    mutated_unauthed_body: str | None,
) -> tuple[bool, float, str]:
    """
    Apply Burp-Suite-style differential analysis to decide whether a response
    to a mutated ID represents a genuine IDOR or a false positive.
    """
    if _looks_like_error_page(mutated_authed_body):
        return False, 0.0, "mutated response resembles an error/not-found page"

    # Semantic JSON Differential
    json_sims = _json_structural_analysis(own_body, mutated_authed_body)
    if json_sims is not None:
        key_sim, val_sim = json_sims
        if key_sim < 0.50:
            return False, key_sim, "mutated JSON structure differs too much (likely an error object)"
        if val_sim == 1.0:
            return False, 1.0, "mutated JSON has identical values (generic template or same object)"
            
        if mutated_unauthed_body is not None:
            unauth_json_sims = _json_structural_analysis(mutated_authed_body, mutated_unauthed_body)
            if unauth_json_sims is not None:
                _, unauth_val_sim = unauth_json_sims
                if unauth_val_sim > 0.99:
                    return False, 0.0, "mutated JSON is identical to unauthed JSON (publicly accessible)"
                    
        return True, val_sim, "JSON differential analysis passed"

    # Fallback to Text-Based Differential
    if mutated_unauthed_body is not None:
        unauth_sim = _body_similarity(mutated_authed_body, mutated_unauthed_body)
        if unauth_sim > 0.85:
            return False, 0.0, f"mutated resource is publicly accessible (authed vs unauthed similarity: {unauth_sim:.0%})"

    own_sim = _body_similarity(own_body, mutated_authed_body)
    if own_sim > 0.95:
        return False, own_sim, "mutated response is virtually identical to own resource (generic template)"
    if own_sim < 0.10:
        return False, own_sim, "mutated response is too dissimilar from own resource — likely an error page"

    return True, own_sim, "differential analysis passed"


# ---------------------------------------------------------------------------
# Main detector
# ---------------------------------------------------------------------------

class AccessControlDetector(BaseDetector):
    name = "access_control"

    sensitive_path_tokens: frozenset[str] = frozenset({
        "admin", "manage", "management", "manager",
        "internal", "debug", "private", "config", "configuration", "settings",
        "backup", "console", "panel", "restricted", "staff",
        "db", "database", "phpmyadmin", "adminer",
        "actuator",                          # Spring Boot actuator endpoints
        "api/internal", "api/admin",         # Common API prefixes
        "graphql", "graphiql",               # GraphQL explorers left open
        "swagger", "swagger-ui", "api-docs", # API docs sometimes left public
        ".env", ".git", ".htaccess",         # Accidental file exposure
        "wp-admin", "wp-login",              # WordPress
        "cpanel", "whm",                     # Hosting panels
    })

    idor_param_tokens: frozenset[str] = frozenset({
        "id", "user", "user_id", "userid",
        "account", "account_id", "accountid",
        "order", "order_id", "orderid",
        "record", "record_id", "recordid",
        "profile", "uid", "uuid",
        "customer", "customer_id", "customerid",
        "invoice", "invoice_id", "invoiceid",
        "ticket", "ticket_id", "ticketid",
        "document", "doc", "doc_id", "docid",
        "file", "file_id", "fileid",
        "message", "msg", "msg_id",
        "ref", "reference",
    })

    # Max parallel HTTP requests to avoid hammering the target
    _CONCURRENCY = 5

    # ---------------------------------------------------------------------------
    # Public entry point
    # ---------------------------------------------------------------------------

    async def detect(
        self, urls: list[str], forms: list[object], **kwargs: object
    ) -> list[Finding]:
        findings: list[Finding] = []
        self._scan_config = kwargs.get("scan_config")
        settings = get_settings()
        session_cookies: dict[str, str] = dict(kwargs.get("session_cookies") or {})
        auth_headers: dict[str, str] = dict(kwargs.get("auth_headers") or {})
        low_auth = _AuthMaterial(
            label="low",
            cookies=session_cookies or self._parse_cookie_string(settings.authentication_cookie),
            headers=auth_headers or self._parse_header_string(settings.authentication_header),
        )
        second_auth = self._build_auth_material(
            label="second",
            cookie_value=kwargs.get("second_user_cookies") or settings.authentication_second_cookie,
            header_value=kwargs.get("second_user_headers") or settings.authentication_second_header,
        )
        privileged_auth = self._build_auth_material(
            label="privileged",
            cookie_value=kwargs.get("privileged_cookies") or settings.authentication_privileged_cookie,
            header_value=kwargs.get("privileged_headers") or settings.authentication_privileged_header,
        )
        is_spa = bool(kwargs.get("is_spa", False))
        spa_root_html = str(kwargs.get("spa_root_html") or "")
        root_url = str(kwargs.get("root_url") or "")

        spa_detector: SpaFallbackDetector | None = None
        if is_spa and spa_root_html:
            spa_detector = SpaFallbackDetector()
            spa_detector.configure_root(root_url, spa_root_html)
            if not spa_detector.root_looks_like_spa():
                spa_detector = None

        authed_verifier = HttpVerifier(cookies=low_auth.cookies, headers=low_auth.headers)
        authed_verifier.set_request_context(module="access_control")

        unauthed_verifier = HttpVerifier()
        unauthed_verifier.set_request_context(module="access_control")

        privileged_verifier: HttpVerifier | None = None
        if privileged_auth.configured:
            privileged_verifier = HttpVerifier(cookies=privileged_auth.cookies, headers=privileged_auth.headers)
            privileged_verifier.set_request_context(module="access_control")

        second_verifier: HttpVerifier | None = None
        if second_auth.configured:
            second_verifier = HttpVerifier(cookies=second_auth.cookies, headers=second_auth.headers)
            second_verifier.set_request_context(module="access_control")

        try:
            forced_browsing_task = self._check_forced_browsing(
                urls, unauthed_verifier, authed_verifier, spa_detector=spa_detector
            )
            idor_task = self._check_idor(
                urls,
                forms,
                unauthed_verifier,
                authed_verifier,
                privileged_verifier,
                second_verifier,
                **kwargs,
            )
            matrix_task = self._check_api_authorization_matrix(
                urls,
                forms,
                unauthed_verifier,
                authed_verifier,
                second_verifier,
                privileged_verifier,
                **kwargs,
            )
            mass_assignment_task = self._check_mass_assignment(
                authed_verifier,
                **kwargs,
            )
            mutating_authz_task = self._check_mutating_authorization(
                urls,
                forms,
                unauthed_verifier,
                authed_verifier,
                second_verifier,
                privileged_verifier,
                **kwargs,
            )
            (
                fb_findings,
                idor_findings,
                matrix_findings,
                mass_assignment_findings,
                mutating_authz_findings,
            ) = await asyncio.gather(
                forced_browsing_task,
                idor_task,
                matrix_task,
                mass_assignment_task,
                mutating_authz_task,
            )
            findings.extend(fb_findings)
            findings.extend(idor_findings)
            findings.extend(matrix_findings)
            findings.extend(mass_assignment_findings)
            findings.extend(mutating_authz_findings)
        finally:
            await authed_verifier.close()
            await unauthed_verifier.close()
            if privileged_verifier:
                await privileged_verifier.close()
            if second_verifier:
                await second_verifier.close()

        return findings

    # ---------------------------------------------------------------------------
    # Mass Assignment / Privilege Field Injection
    # ---------------------------------------------------------------------------

    _MASS_ASSIGNMENT_PROBES: tuple[tuple[str, Any], ...] = (
        ("role", "admin"),
        ("roles", ["admin"]),
        ("isAdmin", True),
        ("admin", True),
        ("is_admin", True),
        ("is_staff", True),
        ("permissions", ["admin"]),
    )

    async def _check_mass_assignment(
        self,
        authed_verifier: HttpVerifier,
        **kwargs: object,
    ) -> list[Finding]:
        findings: list[Finding] = []
        requests = kwargs.get("requests") if isinstance(kwargs.get("requests"), list) else []
        candidates = self._build_mass_assignment_requests(requests)
        if not candidates:
            return findings

        semaphore = asyncio.Semaphore(self._CONCURRENCY)

        async def _verify(candidate: PreparedAttackRequest) -> list[Finding]:
            async with semaphore:
                try:
                    return await self._verify_mass_assignment_candidate(authed_verifier, candidate)
                except Exception:
                    logger.exception("mass-assignment check failed for %s", candidate.url)
                    return []

        results = await asyncio.gather(*[_verify(candidate) for candidate in candidates])
        for result in results:
            findings.extend(result)
        return findings

    def _build_mass_assignment_requests(self, requests: list[RequestObservation]) -> list[PreparedAttackRequest]:
        candidates: list[PreparedAttackRequest] = []
        seen: set[tuple[str, str, str]] = set()
        for observation in requests:
            prepared = self._request_from_observation(observation)
            if prepared is None or not self._is_mass_assignment_candidate(prepared):
                continue
            key = (
                prepared.method.upper(),
                self._canonical_request_url(prepared.url),
                self._body_schema_key(prepared.json_body or prepared.data),
            )
            if key in seen:
                continue
            seen.add(key)
            candidates.append(prepared)
        return candidates[:25]

    def _is_mass_assignment_candidate(self, request: PreparedAttackRequest) -> bool:
        if not self._is_replayable_matrix_request(request):
            return False
        method = request.method.upper()
        if method not in {"POST", "PUT", "PATCH"}:
            return False
        body = request.json_body if request.json_body is not None else request.data
        if not isinstance(body, dict) or not body:
            return False
        path = urlparse(request.url).path.lower()
        if any(token in path for token in ("login", "logout", "token", "password", "reset")):
            return False
        return any(token in path for token in ("user", "account", "profile", "register", "signup")) or any(
            token in str(key).lower() for key in body for token in ("email", "user", "account", "profile")
        )

    # Entire-value email match (a bare address, not free text that mentions one).
    _BARE_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
    # Body keys whose values carry a uniqueness constraint on a create.
    _IDENTITY_KEY_TOKENS: tuple[str, ...] = ("email", "username", "user_name", "login")

    @classmethod
    def _freshen_unique_identity_fields(cls, body: dict[str, Any]) -> dict[str, Any]:
        """Return a shallow copy of a create-request body with uniqueness-
        constrained identity fields replaced by fresh unique values.

        Replaying a captured CREATE (e.g. user registration) verbatim collides
        with the record it originally created; the server rejects the duplicate
        identity (``email must be unique``) with a 4xx, which would abort
        replay-based checks before the real probe runs. Giving each replayed
        create a unique identity lets it succeed so the actual probe is
        evaluated. Framework-agnostic: identity fields are matched by common
        key tokens or a bare-email-shaped value, and each replacement keeps the
        observed shape (an email stays an email on its original domain).
        """
        if not isinstance(body, dict):
            return body
        fresh = dict(body)
        unique = uuid.uuid4().hex[:12]
        for key, value in list(fresh.items()):
            if not isinstance(value, str):
                continue
            lowered = str(key).lower()
            key_is_email = "email" in lowered
            value_is_email = bool(cls._BARE_EMAIL_RE.match(value))
            if key_is_email or value_is_email:
                domain = value.split("@", 1)[1] if value_is_email else "sentrystrike.test"
                fresh[key] = f"ss_ma_{unique}@{domain}"
            elif any(token in lowered for token in cls._IDENTITY_KEY_TOKENS):
                fresh[key] = f"ss_ma_{unique}"
        return fresh

    async def _verify_mass_assignment_candidate(
        self,
        verifier: HttpVerifier,
        request: PreparedAttackRequest,
    ) -> list[Finding]:
        body = request.json_body if request.json_body is not None else request.data
        if not isinstance(body, dict):
            return []

        # A replayed CREATE (registration/signup) collides with the record it
        # originally created — the server rejects the duplicate identity (e.g.
        # "email must be unique") with a 4xx. That aborts the check before the
        # privilege-field probe ever runs, producing a false negative. For POST
        # (create) requests, give each replayed body a fresh unique identity so
        # the create succeeds and the probe can be evaluated. UPDATE (PUT/PATCH)
        # replays keep the observed identity (updating a record to its own value
        # never collides).
        is_create = request.method.upper() == "POST"

        def _prepare_body(source: dict[str, Any]) -> dict[str, Any]:
            return self._freshen_unique_identity_fields(source) if is_create else dict(source)

        def _build(new_body: dict[str, Any]) -> PreparedAttackRequest:
            return PreparedAttackRequest(
                url=request.url,
                method=request.method,
                params=request.params,
                data=new_body if request.data is not None and request.json_body is None else None,
                json_body=new_body if request.json_body is not None else None,
                headers=request.headers,
                cookies=request.cookies,
            )

        baseline = await self._send_prepared_request(
            verifier, _build(_prepare_body(body)), test_phase="mass_assignment_baseline"
        )
        baseline_profile = self._response_profile(baseline)
        if not baseline_profile.success or _looks_like_error_page(baseline.body):
            return []

        for field, value in self._MASS_ASSIGNMENT_PROBES:
            if field in body:
                continue
            mutated_body = _prepare_body(body)
            mutated_body[field] = value
            mutated = _build(mutated_body)
            response = await self._send_prepared_request(
                verifier,
                mutated,
                test_phase="mass_assignment_probe",
            )
            if not (200 <= response.status_code < 300) or _looks_like_error_page(response.body):
                continue
            response_json = self._parse_json(response.body)
            confirmed = self._json_contains_assignment(response_json, field, value)
            response_profile = self._response_profile(response)
            shape_changed = bool(response_profile.json_shape - baseline_profile.json_shape)
            if not confirmed and not shape_changed:
                continue
            return [
                Finding(
                    category=OwaspCategory.a01,
                    vuln_type="Mass Assignment / Privilege Field Injection",
                    severity=SeverityLevel.high if confirmed else SeverityLevel.medium,
                    url=request.url,
                    parameter=field,
                    method=request.method,
                    payload=json.dumps({field: value}, separators=(",", ":"), default=str),
                    evidence=(
                        f"Authenticated request accepted an unexpected privilege-control field '{field}'. "
                        f"Baseline HTTP {baseline.status_code}; mutated HTTP {response.status_code}. "
                        f"Field reflected/accepted: {confirmed}."
                    ),
                    confidence_score=90.0 if confirmed else 65.0,
                    detection_method="mass_assignment_privilege_field",
                    detection_evidence={
                        "field": field,
                        "value": value,
                        "field_confirmed_in_response": confirmed,
                        "baseline_shape": sorted(baseline_profile.json_shape)[:20],
                        "mutated_shape": sorted(response_profile.json_shape)[:20],
                    },
                    verified=True,
                    verification_request_snippet=response.request_snippet,
                    verification_response_snippet=response.response_snippet,
                    reproducible=True,
                )
            ]
        return []

    def _json_contains_assignment(self, value: Any, field: str, expected: Any) -> bool:
        expected_norm = self._normalize_assignment_value(expected)
        field_lower = field.lower()

        def walk(child: Any) -> bool:
            if isinstance(child, dict):
                for key, val in child.items():
                    if str(key).lower() == field_lower and self._normalize_assignment_value(val) == expected_norm:
                        return True
                    if walk(val):
                        return True
            elif isinstance(child, list):
                return any(walk(item) for item in child[:10])
            return False

        return walk(value)

    @staticmethod
    def _normalize_assignment_value(value: Any) -> Any:
        if isinstance(value, list):
            return [AccessControlDetector._normalize_assignment_value(item) for item in value]
        if isinstance(value, dict):
            return {str(key).lower(): AccessControlDetector._normalize_assignment_value(val) for key, val in value.items()}
        if isinstance(value, str):
            return value.strip().lower()
        return value

    # ---------------------------------------------------------------------------
    # Forced Browsing
    # ---------------------------------------------------------------------------

    async def _check_forced_browsing(
        self,
        urls: list[str],
        unauthed_verifier: HttpVerifier,
        authed_verifier: HttpVerifier,
        spa_detector: SpaFallbackDetector | None = None,
    ) -> list[Finding]:
        """
        Detect sensitive paths that are accessible without authentication.
        When an SPA detector is provided, responses that match the SPA root
        shell are treated as fallback pages and are not reported.
        """
        findings: list[Finding] = []
        semaphore = asyncio.Semaphore(self._CONCURRENCY)

        paths_to_test: set[str] = set()
        for url in urls:
            parsed = urlparse(url)
            path_lower = parsed.path.lower()
            segments = {seg for seg in path_lower.split("/") if seg}
            assembled = "/".join(s for s in parsed.path.split("/") if s)
            if segments.intersection(self.sensitive_path_tokens) or any(
                tok in assembled.lower() for tok in self.sensitive_path_tokens
            ):
                paths_to_test.add(_strip_query(url))

        async def _test(test_url: str) -> list[Finding]:
            local_findings: list[Finding] = []
            async with semaphore:
                try:
                    resp = await unauthed_verifier.send_request(
                        test_url, "GET", test_phase="forced_browsing"
                    )

                    if not (200 <= resp.status_code < 300):
                        return []

                    if _looks_like_login_page(resp.body):
                        return []

                    if spa_detector is not None:
                        fallback = spa_detector.detect(
                            test_url,
                            resp.status_code,
                            resp.headers.get("content-type", ""),
                            resp.body,
                            allow_file_like_path=True,
                        )
                        if fallback.is_fallback:
                            logger.debug(
                                "ignoring SPA fallback response for forced browsing "
                                "check on %s: %s similarity=%.3f",
                                test_url,
                                fallback.reason,
                                fallback.similarity,
                            )
                            return []

                    authed_resp = await authed_verifier.send_request(
                        test_url, "GET", test_phase="forced_browsing_authed_baseline"
                    )
                    if authed_resp.status_code not in (200, 201, 206):
                        return []

                    if _body_similarity(resp.body, authed_resp.body) > 0.95:
                        severity = SeverityLevel.medium
                    else:
                        severity = SeverityLevel.high

                    local_findings.append(
                        Finding(
                            category=OwaspCategory.a01,
                            vuln_type="Forced Browsing / Sensitive Directory Exposure",
                            severity=severity,
                            url=test_url,
                            evidence=(
                                f"Sensitive path accessible without authentication "
                                f"(HTTP {resp.status_code}). "
                                f"Authenticated baseline: HTTP {authed_resp.status_code}."
                            ),
                            verified=True,
                            verification_request_snippet=resp.request_snippet,
                            verification_response_snippet=resp.response_snippet,
                            reproducible=True,
                        )
                    )
                except Exception:
                    logger.exception("Forced browsing check failed for %s", test_url)
            return local_findings

        results = await asyncio.gather(*[_test(u) for u in paths_to_test])
        for r in results:
            findings.extend(r)
        return findings

    # ---------------------------------------------------------------------------
    # IDOR / Horizontal + Vertical Privilege Escalation
    # ---------------------------------------------------------------------------

    async def _check_idor(
        self,
        urls: list[str],
        forms: list[object],
        unauthed_verifier: HttpVerifier,
        authed_verifier: HttpVerifier,
        privileged_verifier: HttpVerifier | None,
        second_verifier: HttpVerifier | None,
        **kwargs: object,
    ) -> list[Finding]:
        findings: list[Finding] = []
        semaphore = asyncio.Semaphore(self._CONCURRENCY)
        response_ids = self._response_body_ids(kwargs.get("requests") or [])
        idor_targets = self._build_idor_targets(urls, forms, **kwargs)

        if not idor_targets:
            return findings

        async def _verify(target: AttackTarget) -> list[Finding]:
            cand_findings: list[Finding] = []
            baseline_values = self._baseline_values_for_target(target, response_ids)

            async with semaphore:
                for val in baseline_values:
                    try:
                        target_findings = await self._verify_idor_baseline(
                            target,
                            str(val),
                            unauthed_verifier,
                            authed_verifier,
                            privileged_verifier,
                            second_verifier,
                        )
                        cand_findings.extend(target_findings)
                        if target_findings:
                            break
                    except Exception:
                        logger.exception("IDOR verification failed for %s param=%s", target.url, target.parameter)

            return cand_findings

        results = await asyncio.gather(*[_verify(target) for target in idor_targets])
        for r in results:
            findings.extend(r)
        return findings

    # ---------------------------------------------------------------------------
    # Mutating-method authorization (universal, non-destructive)
    #
    # For ANY id-bearing state-changing request (DELETE/PUT/PATCH /x/:id) on any
    # app, verify the authorization boundary by replaying it under each auth
    # context with a SYNTHETIC NON-EXISTENT object id. A protected endpoint
    # returns 401/403 to an unauthenticated principal BEFORE looking the object
    # up; a broken one processes the request (any non-401/403 status). Because the
    # id does not exist, no real record is ever modified — safe against any
    # target. The optional destructive confirmation (opt-in) re-tests a real
    # self-observed id to prove an actual state change.
    # ---------------------------------------------------------------------------

    async def _check_mutating_authorization(
        self,
        urls: list[str],
        forms: list[object],
        unauthed_verifier: HttpVerifier,
        authed_verifier: HttpVerifier,
        second_verifier: HttpVerifier | None,
        privileged_verifier: HttpVerifier | None,
        **kwargs: object,
    ) -> list[Finding]:
        settings = get_settings()
        if not getattr(settings, "access_control_probe_mutating_methods", True):
            return []
        targets = self._build_mutating_authz_targets(**kwargs)
        if not targets:
            return []
        allow_destructive = bool(getattr(settings, "allow_destructive_authz_confirmation", False))
        semaphore = asyncio.Semaphore(self._CONCURRENCY)

        async def _verify(entry: tuple[PreparedAttackRequest, PreparedAttackRequest | None]) -> list[Finding]:
            synth_req, real_req = entry
            async with semaphore:
                try:
                    return await self._verify_mutating_authz(
                        synth_req,
                        real_req if allow_destructive else None,
                        unauthed_verifier,
                        authed_verifier,
                        second_verifier,
                    )
                except Exception:
                    logger.exception("mutating-authz check failed for %s", synth_req.url)
                    return []

        results = await asyncio.gather(*[_verify(entry) for entry in targets])
        findings: list[Finding] = []
        for result in results:
            findings.extend(result)
        return findings

    def _build_mutating_authz_targets(
        self, **kwargs: object
    ) -> list[tuple[PreparedAttackRequest, PreparedAttackRequest | None]]:
        """Build (synthetic-id, real-id) request pairs for id-bearing mutating
        endpoints. ``synthetic`` is always safe to fire (non-existent id); ``real``
        is the original self-observed request (concrete id) used only for opt-in
        destructive confirmation, or ``None`` when the source was a template with
        no observed real id."""
        requests = kwargs.get("requests") if isinstance(kwargs.get("requests"), list) else []
        api_endpoints = kwargs.get("api_endpoints") if isinstance(kwargs.get("api_endpoints"), list) else []
        out: list[tuple[PreparedAttackRequest, PreparedAttackRequest | None]] = []
        seen: set[tuple[str, str]] = set()

        def _add(req: PreparedAttackRequest | None, real: PreparedAttackRequest | None) -> None:
            if req is None or req.method.upper() not in _MUTATING_AUTHZ_METHODS:
                return
            synth = self._request_with_synthetic_id(req)
            if synth is None:
                # No id-bearing path segment: not safe to fire (an id-less
                # destructive action like DELETE /account would hit the real
                # principal). Skipped in safe mode.
                return
            key = (synth.method.upper(), self._canonical_request_url(synth.url))
            if key in seen:
                return
            seen.add(key)
            out.append((synth, real))

        for observation in requests:
            req = self._request_from_observation(observation)
            if req is None or req.method.upper() not in _MUTATING_AUTHZ_METHODS:
                continue
            # The observed request already carries a concrete (self-owned) id, so
            # it doubles as the real-id request for destructive confirmation.
            real = req if self._request_with_synthetic_id(req) is not None else None
            _add(req, real)

        for endpoint in api_endpoints:
            req = self._request_from_endpoint(endpoint)
            _add(req, None)

        return out[:40]

    def _request_with_synthetic_id(self, request: PreparedAttackRequest) -> PreparedAttackRequest | None:
        """Return ``request`` with its last object-id path segment replaced by a
        synthetic value guaranteed not to exist, or ``None`` when the path has no
        id-bearing segment."""
        parsed = urlparse(request.url)
        segments = parsed.path.split("/")
        target_index: int | None = None
        for index in range(len(segments) - 1, -1, -1):
            if segments[index] and _looks_like_path_id_segment(segments[index]):
                target_index = index
                break
        if target_index is None:
            return None
        segments[target_index] = self._synthetic_nonexistent_id(segments[target_index])
        new_url = urlunparse(parsed._replace(path="/".join(segments)))
        return PreparedAttackRequest(
            url=new_url,
            method=request.method.upper(),
            params=request.params,
            data=request.data,
            json_body=request.json_body,
            headers=request.headers,
            cookies=request.cookies,
        )

    @staticmethod
    def _synthetic_nonexistent_id(original: str) -> str:
        """A deterministic, same-shape id that will not resolve to any record."""
        original = str(original)
        if _NUMERIC_RE.match(original):
            return "988000762197"  # far beyond any plausible sequential id
        if _UUID_RE.match(original):
            return "ffffffff-ffff-4fff-8fff-ffffffffffff"  # valid v4 shape, never assigned
        if _LONG_HEX_RE.match(original):
            return "f" * len(original)
        return "sentrystrike-nonexistent-000000"

    async def _verify_mutating_authz(
        self,
        synth_req: PreparedAttackRequest,
        real_req: PreparedAttackRequest | None,
        unauthed_verifier: HttpVerifier,
        authed_verifier: HttpVerifier,
        second_verifier: HttpVerifier | None,
    ) -> list[Finding]:
        _DENY = {401, 403}
        owner = await self._send_prepared_request(
            authed_verifier, synth_req, test_phase="mutating_authz_owner"
        )
        # Skip when even the authenticated owner is denied (creds insufficient for
        # this endpoint) or the method is simply unsupported (405/501) — no
        # reliable signal. A 404 for the OWNER is expected and fine: the object id
        # is synthetic, so the endpoint (which we observed/extracted as live) ran
        # the auth check, passed it, then failed the object lookup. That "auth
        # passed, object not found" 404 is exactly the owner baseline we compare
        # the unauthenticated principal against.
        if owner.status_code in _DENY or owner.status_code in (405, 501):
            return []

        unauth = await self._send_prepared_request(
            unauthed_verifier, synth_req, test_phase="mutating_authz_unauth"
        )
        # Missing authentication: the unauthenticated principal is treated the
        # same as the authenticated owner (both processed past the auth gate). A
        # protected endpoint returns 401/403 to unauth BEFORE object lookup.
        if unauth.status_code in _DENY or _looks_like_login_page(unauth.body):
            return []
        if unauth.status_code != owner.status_code:
            # Different handling for unauth vs owner (e.g. unauth 400 vs owner 204)
            # is ambiguous; require identical treatment for a high-confidence call.
            return []

        confirmed = False
        confirm_note = ""
        if real_req is not None:
            # Opt-in destructive confirmation (caller already gated on the flag):
            # fire the mutating method with a REAL self-observed id under the
            # unauthenticated context. A success proves an actual unauthorised
            # state change, not merely reachable business logic.
            real_unauth = await self._send_prepared_request(
                unauthed_verifier, real_req, test_phase="mutating_authz_confirm_unauth"
            )
            if real_unauth.status_code in (200, 201, 202, 204):
                confirmed = True
                confirm_note = (
                    f" Destructive confirmation: an unauthenticated {real_req.method} on the "
                    f"real object id returned HTTP {real_unauth.status_code} (state change performed)."
                )

        evidence = (
            f"Missing authentication on state-changing endpoint: an unauthenticated "
            f"{synth_req.method} to {synth_req.url} returned HTTP {unauth.status_code}, identical to "
            f"the authenticated owner's HTTP {owner.status_code} — the endpoint does not enforce "
            f"authentication for a mutating operation. Probed with a synthetic non-existent object id, "
            f"so no real record was modified." + confirm_note
        )
        return [
            Finding(
                category=OwaspCategory.a01,
                vuln_type="Missing Authorization on State-Changing Request",
                severity=SeverityLevel.critical if confirmed else SeverityLevel.high,
                url=synth_req.url,
                parameter="",
                method=synth_req.method,
                payload=self._synthetic_nonexistent_id(""),
                evidence=evidence,
                confidence_score=95.0 if confirmed else 80.0,
                detection_method="mutating_authz_differential",
                detection_evidence={
                    "unauth_status": unauth.status_code,
                    "owner_status": owner.status_code,
                    "destructive_confirmed": confirmed,
                },
                verified=True,
                verification_request_snippet=unauth.request_snippet,
                verification_response_snippet=unauth.response_snippet,
                reproducible=True,
            )
        ]

    # ---------------------------------------------------------------------------
    # API Authorization Matrix
    # ---------------------------------------------------------------------------

    async def _check_api_authorization_matrix(
        self,
        urls: list[str],
        forms: list[object],
        unauthed_verifier: HttpVerifier,
        authed_verifier: HttpVerifier,
        second_verifier: HttpVerifier | None,
        privileged_verifier: HttpVerifier | None,
        **kwargs: object,
    ) -> list[Finding]:
        findings: list[Finding] = []
        targets = self._build_matrix_targets(urls, forms, **kwargs)
        if not targets:
            return findings

        semaphore = asyncio.Semaphore(self._CONCURRENCY)

        async def _verify(target: _MatrixTarget) -> list[Finding]:
            async with semaphore:
                try:
                    return await self._verify_matrix_target(
                        target,
                        unauthed_verifier,
                        authed_verifier,
                        second_verifier,
                        privileged_verifier,
                    )
                except Exception:
                    logger.exception("authorization matrix failed for %s", target.request.url)
                    return []

        results = await asyncio.gather(*[_verify(target) for target in targets])
        for result in results:
            findings.extend(result)
        return findings

    async def _verify_matrix_target(
        self,
        target: _MatrixTarget,
        unauthed_verifier: HttpVerifier,
        authed_verifier: HttpVerifier,
        second_verifier: HttpVerifier | None,
        privileged_verifier: HttpVerifier | None,
    ) -> list[Finding]:
        request = target.request
        unauth = await self._send_prepared_request(
            unauthed_verifier, request, test_phase="auth_matrix_unauth"
        )
        low = await self._send_prepared_request(
            authed_verifier, request, test_phase="auth_matrix_low"
        )
        second = (
            await self._send_prepared_request(
                second_verifier, request, test_phase="auth_matrix_second"
            )
            if second_verifier
            else None
        )
        privileged = (
            await self._send_prepared_request(
                privileged_verifier, request, test_phase="auth_matrix_privileged"
            )
            if privileged_verifier
            else None
        )

        unauth_profile = self._response_profile(unauth)
        low_profile = self._response_profile(low)
        second_profile = self._response_profile(second) if second is not None else None
        privileged_profile = self._response_profile(privileged) if privileged is not None else None

        findings: list[Finding] = []
        protected_low = low_profile.success and not _looks_like_login_page(low.body)
        unauth_success = unauth_profile.success and not _looks_like_login_page(unauth.body)
        unauth_sensitive = self._profile_exposes_nonpublic_data(target, unauth_profile)
        # An endpoint that authenticates via credentials carried in the REQUEST
        # body (login / token / authenticate) is doing its designed job when it
        # returns 200 with a session token — stripping ambient session state does
        # not make the call "unauthenticated", because the body itself carries the
        # credential. Framework-agnostic: never treat such a response as an
        # unauthorized data leak.
        is_auth_endpoint = self._request_carries_credentials(request)

        # PUBLIC-ENDPOINT SUPPRESSION (framework-agnostic).
        # An endpoint that returns a response structurally identical to what an
        # authenticated identity receives is *public by design*: identity does
        # not change the result, so there is no authorization boundary being
        # bypassed (product catalogues, language lists, public config, captcha,
        # feedback walls, …). This is the single largest source of noise — a bare
        # 200 JSON collection is not, on its own, a data leak. Only genuine secret
        # material in the anonymous body overrides this, because such values must
        # never be world-readable regardless of the endpoint's intended audience.
        serves_secret = bool(unauth_profile.secret_fields)
        authed_states = [
            (profile, body)
            for profile, body in (
                (low_profile, low.body),
                (second_profile, second.body if second is not None else ""),
                (privileged_profile, privileged.body if privileged is not None else ""),
            )
            if profile is not None and profile.success
        ]
        serves_public_data = not serves_secret and any(
            self._profiles_compatible(unauth_profile, profile, unauth.body, body)
            for profile, body in authed_states
        )

        if (
            unauth_success
            and unauth_sensitive
            and not is_auth_endpoint
            and not serves_public_data
            and not _looks_like_error_page(unauth.body)
        ):
            findings.append(
                Finding(
                    category=OwaspCategory.a01,
                    vuln_type="Unauthenticated API Data Exposure",
                    severity=SeverityLevel.high if unauth_profile.secret_fields else SeverityLevel.medium,
                    url=request.url,
                    parameter=target.parameter,
                    method=request.method,
                    evidence=(
                        f"API authorization matrix: unauthenticated request returned HTTP "
                        f"{unauth.status_code} with sensitive/object data. "
                        f"Low-privilege baseline returned HTTP {low.status_code}. "
                        f"Sensitive fields: {', '.join(sorted(unauth_profile.sensitive_fields)) or 'none'}. "
                        f"Stable identifiers observed: {len(unauth_profile.identifiers)}."
                    ),
                    confidence_score=88.0,
                    detection_method="authorization_matrix",
                    detection_evidence=self._matrix_evidence(
                        unauth_profile, low_profile, second_profile, privileged_profile, target,
                        serves_public_data=serves_public_data,
                    ),
                    verified=True,
                    verification_request_snippet=unauth.request_snippet,
                    verification_response_snippet=unauth.response_snippet,
                    reproducible=True,
                )
            )

        if (
            second is not None
            and second_profile is not None
            and protected_low
            and second_profile.success
            and not unauth_success
            and not target.has_object_reference
            and self._shared_identifiers(low_profile, second_profile)
            and (bool(low_profile.sensitive_fields) or target.admin_like)
        ):
            findings.append(
                Finding(
                    category=OwaspCategory.a01,
                    vuln_type="Horizontal Authorization Bypass",
                    severity=SeverityLevel.high,
                    url=request.url,
                    parameter=target.parameter,
                    method=request.method,
                    evidence=(
                        "API authorization matrix: a second authenticated user received "
                        "the same stable object identifiers as the low-privilege baseline "
                        f"while unauthenticated access was blocked with HTTP {unauth.status_code}."
                    ),
                    confidence_score=90.0,
                    detection_method="authorization_matrix_second_user",
                    detection_evidence=self._matrix_evidence(
                        unauth_profile, low_profile, second_profile, privileged_profile, target
                    ),
                    verified=True,
                    verification_request_snippet=second.request_snippet,
                    verification_response_snippet=second.response_snippet,
                    reproducible=True,
                )
            )

        if (
            privileged is not None
            and privileged_profile is not None
            and protected_low
            and privileged_profile.success
            and target.admin_like
            and self._profiles_compatible(low_profile, privileged_profile, low.body, privileged.body)
        ):
            findings.append(
                Finding(
                    category=OwaspCategory.a01,
                    vuln_type="Vertical Privilege Bypass",
                    severity=SeverityLevel.critical,
                    url=request.url,
                    parameter=target.parameter,
                    method=request.method,
                    evidence=(
                        "API authorization matrix: low-privilege credentials reached an "
                        "admin/privileged API target with a response compatible with the "
                        f"privileged baseline (low HTTP {low.status_code}, privileged HTTP "
                        f"{privileged.status_code})."
                    ),
                    confidence_score=92.0,
                    detection_method="authorization_matrix_privileged_baseline",
                    detection_evidence=self._matrix_evidence(
                        unauth_profile, low_profile, second_profile, privileged_profile, target
                    ),
                    verified=True,
                    verification_request_snippet=low.request_snippet,
                    verification_response_snippet=low.response_snippet,
                    reproducible=True,
                )
            )

        # BROKEN OBJECT-LEVEL AUTHORIZATION (cross-identity, framework-agnostic).
        # An object-scoped request (an id names ONE record) that is denied to
        # anonymous callers (401/403/login/redirect) but returns the SAME record
        # to two DISTINCT authenticated identities is not scoped to its owner:
        # any authenticated user can read another user's object. The id-mutation
        # path deliberately drops this — identical values across identities look
        # like a "generic template" under its val_sim==1.0 short-circuit — so the
        # matrix consumes {unauth, low, second} directly, regardless of val_sim.
        # The "same record to both" signal is value-level (shared stable object
        # identifiers), so genuine per-owner objects (different ids per identity)
        # do not fire. Complements the horizontal check above, which handles the
        # non-object-scoped (list/collection) case.
        unauth_denied = (
            unauth_profile.status_code in (401, 403)
            or 300 <= unauth_profile.status_code < 400
            or _looks_like_login_page(unauth.body)
        )
        if (
            second is not None
            and second_profile is not None
            and second_profile.success
            and protected_low
            and target.has_object_reference
            and unauth_denied
            and not is_auth_endpoint
            and not _looks_like_error_page(low.body)
            and self._profile_has_sensitive_data(low_profile)
            and bool(self._shared_identifiers(low_profile, second_profile))
        ):
            shared = sorted(self._shared_identifiers(low_profile, second_profile))
            findings.append(
                Finding(
                    category=OwaspCategory.a01,
                    vuln_type="Broken Object-Level Authorization",
                    severity=SeverityLevel.high,
                    url=request.url,
                    parameter=target.parameter,
                    method=request.method,
                    evidence=(
                        "API authorization matrix: an object-scoped resource denied to "
                        f"anonymous callers (HTTP {unauth.status_code}) returned the same "
                        "object identifiers to two distinct authenticated identities "
                        f"(low HTTP {low.status_code}, second HTTP {second.status_code}). "
                        f"Shared identifiers: {', '.join(shared) or 'none'}. "
                        f"Sensitive fields: {', '.join(sorted(low_profile.sensitive_fields)) or 'none'}."
                    ),
                    confidence_score=85.0,
                    detection_method="authorization_matrix_cross_identity",
                    detection_evidence=self._matrix_evidence(
                        unauth_profile, low_profile, second_profile, privileged_profile, target
                    ),
                    verified=True,
                    verification_request_snippet=low.request_snippet,
                    verification_response_snippet=low.response_snippet,
                    reproducible=True,
                )
            )

        return findings

    # ---------------------------------------------------------------------------
    # Shared target construction / request helpers
    # ---------------------------------------------------------------------------

    def _build_idor_targets(self, urls: list[str], forms: list[object], **kwargs: object) -> list[AttackTarget]:
        parameters = kwargs.get("parameters")
        api_endpoints = kwargs.get("api_endpoints")
        requests = kwargs.get("requests")
        targets = AttackSurface.build(
            urls,
            forms,
            parameters=parameters if isinstance(parameters, list) else None,
            api_endpoints=api_endpoints if isinstance(api_endpoints, list) else None,
            requests=requests if isinstance(requests, list) else None,
            filter_fn=self._is_idor_param,
        )

        concrete_path_targets = self._concrete_path_idor_targets(urls)
        targets.extend(concrete_path_targets)
        targets.extend(self._api_path_template_idor_targets(api_endpoints if isinstance(api_endpoints, list) else []))

        deduped: list[AttackTarget] = []
        seen: set[tuple[str, str, str, str, str]] = set()
        for target in targets:
            if not self._target_has_access_control_relevance(target):
                continue
            key = (
                target.url,
                target.method.upper(),
                target.parameter,
                target.location.value,
                target.parent_path or "",
            )
            if key in seen:
                continue
            seen.add(key)
            deduped.append(target)
        return deduped[:80]

    def _build_matrix_targets(self, urls: list[str], forms: list[object], **kwargs: object) -> list[_MatrixTarget]:
        targets: list[_MatrixTarget] = []
        api_endpoints = kwargs.get("api_endpoints") if isinstance(kwargs.get("api_endpoints"), list) else []
        requests = kwargs.get("requests") if isinstance(kwargs.get("requests"), list) else []
        parameters = kwargs.get("parameters") if isinstance(kwargs.get("parameters"), list) else None

        for observation in requests:
            request = self._request_from_observation(observation)
            if request is None:
                continue
            targets.append(
                _MatrixTarget(
                    request=request,
                    source="browser_request",
                    has_object_reference=self._request_has_object_reference(request),
                    admin_like=self._is_admin_like_url(request.url),
                )
            )

        for endpoint in api_endpoints:
            request = self._request_from_endpoint(endpoint)
            if request is None:
                continue
            targets.append(
                _MatrixTarget(
                    request=request,
                    source="api_endpoint",
                    has_object_reference=self._request_has_object_reference(request),
                    admin_like=self._is_admin_like_url(request.url),
                )
            )

        for attack_target in AttackSurface.build(
            urls,
            forms,
            parameters=parameters,
            api_endpoints=api_endpoints,
            requests=requests,
            filter_fn=self._is_matrix_relevant_param,
        ):
            request = self._build_request_for_value(attack_target, attack_target.value or "1")
            targets.append(
                _MatrixTarget(
                    request=request,
                    source=attack_target.source,
                    parameter=attack_target.parameter,
                    parameter_location=attack_target.location.value,
                    has_object_reference=self._target_has_access_control_relevance(attack_target),
                    admin_like=self._is_admin_like_url(request.url),
                )
            )

        deduped: list[_MatrixTarget] = []
        seen: set[tuple[str, str, str, str]] = set()
        for target in targets:
            if not self._is_replayable_matrix_request(target.request):
                continue
            # SAFETY: an id-bearing state-changer (DELETE/PUT/PATCH /x/:id) would,
            # in the matrix, fire against the REAL object id under every auth
            # context — destroying/altering a real record. Those are covered
            # non-destructively (synthetic non-existent id) by
            # ``_check_mutating_authorization``, so exclude them here. POST creates
            # (no owner id in the path) stay in the matrix.
            if target.request.method.upper() in _MUTATING_AUTHZ_METHODS and self._request_with_synthetic_id(
                target.request
            ) is not None:
                continue
            key = (
                target.request.method.upper(),
                self._canonical_request_url(target.request.url),
                self._body_schema_key(target.request.json_body or target.request.data),
                target.parameter or "",
            )
            if key in seen:
                continue
            seen.add(key)
            deduped.append(target)
        return deduped[:80]

    async def _verify_idor_baseline(
        self,
        target: AttackTarget,
        val: str,
        unauthed_verifier: HttpVerifier,
        authed_verifier: HttpVerifier,
        privileged_verifier: HttpVerifier | None,
        second_verifier: HttpVerifier | None,
    ) -> list[Finding]:
        cand_findings: list[Finding] = []

        # SAFETY: the read-oriented IDOR baseline fires ``target.method`` on the
        # OWNER's real value first (``idor_authed_own``). For a state-changing
        # method that would mutate/destroy the owner's real resource, and the
        # body-similarity verdict is meaningless on the empty/204 response anyway.
        # Mutating-method authorization is handled non-destructively (synthetic
        # non-existent id + status differential) by ``_check_mutating_authorization``.
        if target.method.upper() in _MUTATING_AUTHZ_METHODS:
            return []

        mutated_vals = _mutate_id(val)

        own_request = self._build_request_for_value(target, val)
        unauth_own_resp = await self._send_prepared_request(
            unauthed_verifier, own_request, test_phase="idor_unauth_own"
        )

        if self._is_public_resource_response(unauth_own_resp):
            logger.debug(
                "IDOR skip: original resource is public at %s param=%s val=%s",
                target.url,
                target.parameter,
                val,
            )
            return []

        auth_own_resp = await self._send_prepared_request(
            authed_verifier, own_request, test_phase="idor_authed_own"
        )

        if auth_own_resp.status_code not in (200, 201):
            logger.debug(
                "IDOR skip: authed session cannot access own resource %s param=%s",
                target.url,
                target.parameter,
            )
            return []

        if _looks_like_error_page(auth_own_resp.body):
            logger.debug(
                "IDOR skip: own resource response looks like an error page %s param=%s",
                target.url,
                target.parameter,
            )
            return []

        if second_verifier is not None:
            second_own_resp = await self._send_prepared_request(
                second_verifier, own_request, test_phase="idor_second_user_own"
            )
            if (
                second_own_resp.status_code in (200, 201)
                and not _looks_like_login_page(second_own_resp.body)
                and not _looks_like_error_page(second_own_resp.body)
            ):
                similarity = _body_similarity(auth_own_resp.body, second_own_resp.body)
                own_profile = self._response_profile(auth_own_resp)
                second_profile = self._response_profile(second_own_resp)
                if similarity > 0.70 and (
                    self._shared_identifiers(own_profile, second_profile)
                    or self._profile_has_sensitive_data(own_profile)
                ):
                    cand_findings.append(
                        Finding(
                            category=OwaspCategory.a01,
                            vuln_type="Insecure Direct Object Reference (IDOR)",
                            severity=SeverityLevel.high,
                            url=target.url,
                            parameter=target.parameter,
                            method=target.method,
                            payload=val,
                            evidence=(
                                "Horizontal IDOR confirmed with second-user credentials: "
                                f"second user accessed low-user object reference '{target.parameter}'={val}. "
                                f"Unauthenticated baseline returned HTTP {unauth_own_resp.status_code}. "
                                f"Body similarity (low vs second user): {similarity:.0%}."
                            ),
                            confidence_score=95.0,
                            detection_method="second_user_idor",
                            detection_evidence={
                                "parameter_location": target.location.value,
                                "source": target.source,
                                "shared_identifiers": sorted(self._shared_identifiers(own_profile, second_profile)),
                            },
                            verified=True,
                            verification_request_snippet=second_own_resp.request_snippet,
                            verification_response_snippet=second_own_resp.response_snippet,
                            reproducible=True,
                        )
                    )
                    return cand_findings

        for mutated_val in mutated_vals:
            mod_request = self._build_request_for_value(target, mutated_val)
            auth_mod_resp = await self._send_prepared_request(
                authed_verifier, mod_request, test_phase="idor_authed_mod"
            )

            if auth_mod_resp.status_code not in (200, 201):
                continue
            if _looks_like_login_page(auth_mod_resp.body):
                continue

            unauth_mod_resp = await self._send_prepared_request(
                unauthed_verifier, mod_request, test_phase="idor_unauth_mod"
            )
            mutated_unauthed_body: str | None = (
                unauth_mod_resp.body
                if self._is_public_resource_response(unauth_mod_resp)
                else None
            )

            is_idor, similarity, reason = _differential_idor_verdict(
                own_body=auth_own_resp.body,
                mutated_authed_body=auth_mod_resp.body,
                mutated_unauthed_body=mutated_unauthed_body,
            )

            if not is_idor:
                logger.debug(
                    "IDOR false-positive suppressed at %s param=%s mutated=%s: %s",
                    target.url,
                    target.parameter,
                    mutated_val,
                    reason,
                )
                continue

            cand_findings.append(
                Finding(
                    category=OwaspCategory.a01,
                    vuln_type="Insecure Direct Object Reference (IDOR)",
                    severity=SeverityLevel.high,
                    url=target.url,
                    parameter=target.parameter,
                    method=target.method,
                    payload=mutated_val,
                    evidence=(
                        f"Horizontal privilege escalation: authenticated session accessed "
                        f"'{target.parameter}'={mutated_val} (modified from owned value '{val}'). "
                        f"Parameter location: {target.location.value}. "
                        f"Unauthenticated baseline for original value returned HTTP "
                        f"{unauth_own_resp.status_code}. "
                        f"Unauthenticated access to mutated value: "
                        f"{'blocked' if mutated_unauthed_body is None else 'public (skipped)'}. "
                        f"Body similarity (own vs mutated): {similarity:.0%}. "
                        f"Differential verdict: {reason}."
                    ),
                    confidence_score=90.0,
                    detection_method="differential_idor",
                    detection_evidence={
                        "parameter_location": target.location.value,
                        "parent_path": target.parent_path,
                        "source": target.source,
                    },
                    verified=True,
                    verification_request_snippet=auth_mod_resp.request_snippet,
                    verification_response_snippet=auth_mod_resp.response_snippet,
                    reproducible=True,
                )
            )
            break

        if privileged_verifier and not cand_findings:
            for mutated_val in mutated_vals:
                mod_request = self._build_request_for_value(target, mutated_val)
                priv_resp = await self._send_prepared_request(
                    privileged_verifier, mod_request, test_phase="vertical_priv_check"
                )
                auth_check_resp = await self._send_prepared_request(
                    authed_verifier, mod_request, test_phase="vertical_authed_check"
                )
                if (
                    priv_resp.status_code in (200, 201)
                    and auth_check_resp.status_code in (200, 201)
                    and not _looks_like_login_page(auth_check_resp.body)
                    and not _looks_like_error_page(auth_check_resp.body)
                ):
                    similarity = _body_similarity(priv_resp.body, auth_check_resp.body)
                    if similarity > 0.7:
                        cand_findings.append(
                            Finding(
                                category=OwaspCategory.a01,
                                vuln_type="Vertical Privilege Escalation (IDOR)",
                                severity=SeverityLevel.critical,
                                url=target.url,
                                parameter=target.parameter,
                                method=target.method,
                                payload=mutated_val,
                                evidence=(
                                    f"Low-privilege session accessed resource "
                                    f"'{target.parameter}'={mutated_val} which is also accessible to a "
                                    f"high-privilege session (body similarity: {similarity:.0%}). "
                                    f"Parameter location: {target.location.value}."
                                ),
                                confidence_score=90.0,
                                detection_method="vertical_idor",
                                detection_evidence={
                                    "parameter_location": target.location.value,
                                    "source": target.source,
                                },
                                verified=True,
                                verification_request_snippet=auth_check_resp.request_snippet,
                                verification_response_snippet=auth_check_resp.response_snippet,
                                reproducible=True,
                            )
                        )
                        break

        return cand_findings

    async def _send_prepared_request(
        self,
        verifier: HttpVerifier | None,
        request: PreparedAttackRequest,
        *,
        test_phase: str,
    ):
        if verifier is None:
            raise ValueError("verifier is required")
        headers = self._sanitize_replay_headers(request.headers or {})
        return await verifier.send_request(
            request.url,
            request.method,
            request.params,
            request.data,
            headers=headers or None,
            cookies=request.cookies or None,
            json_body=request.json_body,
            test_phase=test_phase,
            parameter="",
        )

    def _build_request_for_value(self, target: AttackTarget, value: Any) -> PreparedAttackRequest:
        if target.location == ParameterLocation.path and target.parameter.startswith("__path_seg_"):
            return PreparedAttackRequest(
                url=self._replace_concrete_path_segment(target.url, target.parameter, str(value)),
                method=target.method.upper(),
                headers=target.headers or None,
                cookies=target.cookies or None,
            )
        return target.build_request(value)

    @staticmethod
    def _replace_concrete_path_segment(url: str, parameter: str, value: str) -> str:
        match = re.match(r"__path_seg_(?P<index>\d+)__:(?P<original>.*)", parameter)
        if not match:
            return url
        index = int(match.group("index"))
        original = match.group("original")
        parsed = urlparse(url)
        segments = parsed.path.split("/")
        non_empty_index = -1
        for i, segment in enumerate(segments):
            if not segment:
                continue
            non_empty_index += 1
            if non_empty_index == index and segment == original:
                segments[i] = value
                break
        return urlunparse(parsed._replace(path="/".join(segments)))

    def _request_from_observation(self, observation: RequestObservation) -> PreparedAttackRequest | None:
        method = str(getattr(observation, "method", "GET") or "GET").upper()
        headers = self._sanitize_replay_headers(getattr(observation, "request_headers", {}) or {})
        post_data = getattr(observation, "post_data", None)
        json_body = self._parse_json(post_data)
        data = None
        if json_body is None and isinstance(post_data, str) and post_data.strip():
            data = dict(parse_qsl(post_data, keep_blank_values=True)) or None
        return PreparedAttackRequest(
            url=str(getattr(observation, "url", "") or ""),
            method=method,
            data=data,
            json_body=json_body,
            headers=headers or None,
        )

    def _request_from_endpoint(self, endpoint: ApiEndpoint) -> PreparedAttackRequest | None:
        url = endpoint.url
        if "{" in url or re.search(r"/:[A-Za-z_]", url):
            params = [p for p in self._parameters_from_endpoint(endpoint) if p.location == ParameterLocation.path]
            if not params:
                return None
            target = AttackTarget(
                url=url,
                parameter=params[0].name,
                method=endpoint.method,
                value=params[0].baseline_value,
                location=ParameterLocation.path,
                source="api_path",
            )
            built = self._build_request_for_value(target, params[0].baseline_value or "1")
            if "{" in built.url or re.search(r"/:[A-Za-z_]", built.url):
                return None
            return built

        headers = self._sanitize_replay_headers(endpoint.headers or {})
        body = self._parse_json(endpoint.request_body)
        data = None
        if body is None and isinstance(endpoint.request_body, str):
            data = dict(parse_qsl(endpoint.request_body, keep_blank_values=True)) or None
        return PreparedAttackRequest(
            url=url,
            method=endpoint.method.upper(),
            data=data,
            json_body=body,
            headers=headers or None,
        )

    @staticmethod
    def _parameters_from_endpoint(endpoint: ApiEndpoint) -> list[ParameterCandidate]:
        from app.core.crawler.api_extractor import ApiExtractor

        return ApiExtractor.parameters_from_endpoint(endpoint)

    def _concrete_path_idor_targets(self, urls: list[str]) -> list[AttackTarget]:
        targets: list[AttackTarget] = []
        for url in urls:
            parsed = urlparse(url)
            segments = [s for s in parsed.path.split("/") if s]
            for i, segment in enumerate(segments):
                if _looks_like_path_id_segment(segment):
                    targets.append(
                        AttackTarget(
                            url=url,
                            parameter=f"__path_seg_{i}__:{segment}",
                            method="GET",
                            value=segment,
                            location=ParameterLocation.path,
                            source="path_segment",
                            security_relevance={"access_control"},
                        )
                    )
        return targets

    def _api_path_template_idor_targets(self, endpoints: list[ApiEndpoint]) -> list[AttackTarget]:
        targets: list[AttackTarget] = []
        for endpoint in endpoints:
            for parameter in self._parameters_from_endpoint(endpoint):
                if parameter.location != ParameterLocation.path:
                    continue
                if not self._is_idor_param(parameter.name):
                    continue
                targets.append(
                    AttackTarget(
                        url=endpoint.url,
                        parameter=parameter.name,
                        method=endpoint.method.upper(),
                        value=parameter.baseline_value or "1",
                        location=ParameterLocation.path,
                        source="api_path_template",
                        security_relevance={"access_control"},
                    )
                )
        return targets

    def _baseline_values_for_target(
        self,
        target: AttackTarget,
        response_ids: dict[str, set[str]],
    ) -> list[str]:
        values: list[str] = []
        raw = str(target.value if target.value is not None else "")
        # Concrete path-segment ids are already vetted by
        # ``_looks_like_path_id_segment`` and may exceed the opaque-token length
        # cap (SHA/base64), so trust the discovered value directly.
        if target.source == "path_segment" and raw:
            values.append(raw)
        elif _is_valid_id_value(raw):
            values.append(raw)
        elif raw in {"", "test", "sample.txt"} and self._target_has_access_control_relevance(target):
            values.append("1")

        param_key = self._normalize_param_name(target.parameter)
        for key, ids in response_ids.items():
            if key == param_key or key.endswith(param_key) or param_key.endswith(key):
                for value in ids:
                    if value not in values:
                        values.append(value)
        for value in response_ids.get("*", set()):
            if len(values) >= 3:
                break
            if value not in values:
                values.append(value)
        return values[:3]

    def _response_body_ids(self, requests: list[RequestObservation]) -> dict[str, set[str]]:
        ids: dict[str, set[str]] = {"*": set()}
        for request in requests:
            body = self._parse_json(getattr(request, "response_snippet", None))
            self._collect_json_ids(body, ids)
        return ids

    def _collect_json_ids(self, value: Any, ids: dict[str, set[str]], parent: str = "") -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                path = f"{parent}.{key}" if parent else key
                if isinstance(child, (str, int)):
                    child_value = str(child)
                    if self._is_idor_param(key) and _is_valid_id_value(child_value):
                        normalized = self._normalize_param_name(key)
                        ids.setdefault(normalized, set()).add(child_value)
                        ids["*"].add(child_value)
                self._collect_json_ids(child, ids, path)
        elif isinstance(value, list):
            for child in value[:10]:
                self._collect_json_ids(child, ids, parent)

    @staticmethod
    def _parse_json(value: Any) -> Any:
        if isinstance(value, (dict, list)):
            return value
        if not isinstance(value, str) or not value.strip():
            return None
        try:
            return json.loads(value)
        except Exception:
            return None

    @staticmethod
    def _sanitize_replay_headers(headers: dict[str, str]) -> dict[str, str]:
        stripped = {}
        blocked = {
            "authorization",
            "proxy-authorization",
            "cookie",
            "set-cookie",
            "x-api-key",
            "api-key",
            "host",
            "content-length",
        }
        for key, value in headers.items():
            if key.lower() in blocked:
                continue
            stripped[key] = value
        return stripped

    def _response_profile(self, response) -> _ResponseProfile:
        if response is None:
            return _ResponseProfile(0, "", False, False)
        content_type = str((response.headers or {}).get("content-type", "")).lower()
        parsed = self._parse_json(response.body)
        is_json = isinstance(parsed, (dict, list)) or "json" in content_type
        json_shape: set[str] = set()
        identifiers: set[str] = set()
        sensitive_fields: set[str] = set()
        secret_fields: set[str] = set()
        item_count = 0

        def walk(value: Any, path: str = "") -> None:
            nonlocal item_count
            if isinstance(value, dict):
                for key, child in value.items():
                    child_path = f"{path}.{key}" if path else key
                    json_shape.add(child_path)
                    lowered = key.lower()
                    if self._is_sensitive_field(lowered):
                        sensitive_fields.add(child_path)
                    if self._is_secret_field(lowered):
                        secret_fields.add(child_path)
                    if self._is_idor_param(key) and isinstance(child, (str, int)):
                        child_value = str(child)
                        if _is_valid_id_value(child_value):
                            identifiers.add(f"{self._normalize_param_name(key)}={child_value}")
                    walk(child, child_path)
            elif isinstance(value, list):
                item_count = max(item_count, len(value))
                for child in value[:10]:
                    walk(child, path + "[]")

        if parsed is not None:
            walk(parsed)

        return _ResponseProfile(
            status_code=response.status_code,
            content_type=content_type,
            success=response.status_code in (200, 201, 202, 206),
            is_json=is_json,
            json_shape=frozenset(json_shape),
            identifiers=frozenset(identifiers),
            sensitive_fields=frozenset(sensitive_fields),
            secret_fields=frozenset(secret_fields),
            item_count=item_count,
            body_length=len(response.body or ""),
        )

    def _matrix_evidence(
        self,
        unauth: _ResponseProfile,
        low: _ResponseProfile,
        second: _ResponseProfile | None,
        privileged: _ResponseProfile | None,
        target: _MatrixTarget,
        *,
        serves_public_data: bool | None = None,
    ) -> dict[str, Any]:
        return {
            "source": target.source,
            "parameter_location": target.parameter_location,
            "has_object_reference": target.has_object_reference,
            "admin_like": target.admin_like,
            # The key discriminative signal for the AI: whether anonymous and
            # authenticated responses are identical (public by design). When
            # True, the endpoint has no authorization boundary — the AI should
            # flag it as a false positive.
            "serves_public_data": serves_public_data,
            "states": {
                "unauthenticated": self._profile_summary(unauth),
                "low": self._profile_summary(low),
                "second": self._profile_summary(second) if second else None,
                "privileged": self._profile_summary(privileged) if privileged else None,
            },
        }

    @staticmethod
    def _profile_summary(profile: _ResponseProfile) -> dict[str, Any]:
        return {
            "status_code": profile.status_code,
            "success": profile.success,
            "is_json": profile.is_json,
            "json_shape": sorted(profile.json_shape)[:20],
            "identifiers": sorted(profile.identifiers)[:20],
            "sensitive_fields": sorted(profile.sensitive_fields)[:20],
            "secret_fields": sorted(profile.secret_fields)[:20],
            "item_count": profile.item_count,
        }

    def _profiles_compatible(
        self,
        left: _ResponseProfile,
        right: _ResponseProfile,
        left_body: str,
        right_body: str,
    ) -> bool:
        if not left.success or not right.success:
            return False
        if left.is_json and right.is_json:
            if left.json_shape and right.json_shape:
                overlap = len(left.json_shape & right.json_shape)
                smaller = max(1, min(len(left.json_shape), len(right.json_shape)))
                if overlap / smaller >= 0.70:
                    return True
            if self._shared_identifiers(left, right):
                return True
        return _body_similarity(left_body or "", right_body or "") > 0.85

    @staticmethod
    def _shared_identifiers(left: _ResponseProfile, right: _ResponseProfile) -> set[str]:
        return set(left.identifiers & right.identifiers)

    @staticmethod
    def _profile_has_sensitive_data(profile: _ResponseProfile) -> bool:
        return bool(profile.sensitive_fields or profile.identifiers or profile.item_count > 0)

    @staticmethod
    def _profile_exposes_nonpublic_data(target: _MatrixTarget, profile: _ResponseProfile) -> bool:
        # Non-public exposure must be evidenced by the anonymous response BODY
        # carrying data that is not meant to be world-readable. Two structural,
        # framework-agnostic signals qualify:
        #   1. Secret material — passwords, tokens, API keys, crypto seeds, etc.
        #      A secret in an anonymous response is a leak regardless of design.
        #   2. Object-scoped data — the request targets a specific object (id in
        #      path/query/body) and the response returns that record. Whether it
        #      is truly a leak is then decided by the public-endpoint suppression
        #      in ``_verify_matrix_target`` (a public detail page is identical
        #      across auth states and is dropped there).
        # A bare public collection (a product/feedback/language list with no
        # secret fields and no object scoping) is NOT, on its own, evidence of a
        # leak — such listings are public on the overwhelming majority of sites.
        # An admin-looking URL is likewise not evidence: a public
        # ``{"version": "x.y.z"}`` under ``/admin/*`` is not a data leak.
        if profile.secret_fields:
            return True
        if target.has_object_reference and (profile.identifiers or profile.item_count > 0):
            return True
        return False

    @staticmethod
    def _is_sensitive_field(name: str) -> bool:
        return any(
            token in name
            for token in (
                "email",
                "username",
                "password",
                "passwd",
                "token",
                "secret",
                "role",
                "permission",
                "address",
                "phone",
                "balance",
                "credit",
                "card",
                "ssn",
                "jwt",
                "api_key",
                "apikey",
            )
        )

    # Narrow secret-material tokens. Deliberately excludes broad PII names
    # (email/username/role/address/phone) that legitimately appear in public
    # listings: those are not, by themselves, a secret disclosure. A field whose
    # name carries one of these tokens holds a credential, key, or crypto seed
    # whose presence in an anonymous response is an unambiguous leak.
    _SECRET_FIELD_TOKENS: tuple[str, ...] = (
        "password",
        "passwd",
        "passwrd",
        "pwd",
        "secret",
        "token",
        "apikey",
        "api_key",
        "accesskey",
        "access_key",
        "privatekey",
        "private_key",
        "jwt",
        "ssn",
        "cvv",
        "seed",
        "mnemonic",
        "passphrase",
        "otp",
        "totp",
    )

    @classmethod
    def _is_secret_field(cls, name: str) -> bool:
        return any(token in name for token in cls._SECRET_FIELD_TOKENS)

    def _target_has_access_control_relevance(self, target: AttackTarget) -> bool:
        if "access_control" in target.security_relevance:
            return True
        return self._is_idor_param(target.parameter)

    _CREDENTIAL_BODY_KEYS = frozenset(
        {"password", "passwd", "pass", "pwd", "otp", "totp", "credential", "credentials"}
    )

    def _request_carries_credentials(self, request: PreparedAttackRequest) -> bool:
        """True when the request itself carries login credentials in its body.

        Such an endpoint (login / authenticate / token / sign-in) is *meant* to
        accept anonymous callers and return a session token, so a 200 under the
        unauthenticated verifier is expected behaviour — not an authorization
        bypass. Detection is structural (a password-like body key), so it holds
        for any framework, not just a specific app's ``/login`` path.
        """
        body = request.json_body if request.json_body is not None else request.data
        return self._body_has_credential_key(body)

    def _body_has_credential_key(self, value: Any) -> bool:
        if isinstance(value, dict):
            for key, child in value.items():
                if str(key).strip().lower() in self._CREDENTIAL_BODY_KEYS:
                    return True
                if self._body_has_credential_key(child):
                    return True
            return False
        if isinstance(value, list):
            return any(self._body_has_credential_key(child) for child in value[:5])
        return False

    def _request_has_object_reference(self, request: PreparedAttackRequest) -> bool:
        parsed = urlparse(request.url)
        if any(_NUMERIC_RE.match(seg) or _UUID_RE.match(seg) for seg in parsed.path.split("/") if seg):
            return True
        if any(self._is_idor_param(name) for name, _ in parse_qsl(parsed.query, keep_blank_values=True)):
            return True
        body = request.json_body if request.json_body is not None else request.data
        return self._body_has_idor_key(body)

    def _body_has_idor_key(self, value: Any) -> bool:
        if isinstance(value, dict):
            return any(self._is_idor_param(str(key)) or self._body_has_idor_key(child) for key, child in value.items())
        if isinstance(value, list):
            return any(self._body_has_idor_key(child) for child in value[:5])
        return False

    def _is_matrix_relevant_param(self, name: str) -> bool:
        return self._is_idor_param(name) or any(
            token in name.lower()
            for token in ("role", "admin", "tenant", "org", "owner", "account", "user")
        )

    def _is_public_resource_response(self, response) -> bool:
        return (
            response.status_code == 200
            and not _looks_like_login_page(response.body)
            and not _looks_like_error_page(response.body)
        )

    @staticmethod
    def _has_placeholder_segment(url: str) -> bool:
        """True when a URL path still contains an unresolved template/placeholder
        segment rather than a concrete value.

        Crawlers frequently capture route templates before the SPA binds real
        data — ``/rest/track-order/:id``, ``/rest/track-order/undefined``,
        ``/api/orders/{orderId}`` — and these are not real, replayable endpoints.
        Detection is structural (segment shape), so it holds for any framework or
        client router, and covers URL-encoded ``:`` (``%3A``) which the simple
        ``/:`` literal check misses.
        """
        path = unquote(urlparse(url).path)
        for segment in path.split("/"):
            if not segment:
                continue
            lowered = segment.lower()
            if lowered in {"undefined", "null", "nan", "none"}:
                return True
            if segment[0] in ":{[" or segment[-1] in "}]":
                return True
        return False

    def _is_replayable_matrix_request(self, request: PreparedAttackRequest) -> bool:
        if not request.url or "{" in request.url or re.search(r"/:[A-Za-z_]", request.url):
            return False
        if self._has_placeholder_segment(request.url):
            return False
        method = request.method.upper()
        if method in {"OPTIONS", "HEAD"}:
            return False
        if method == "DELETE":
            return False
        if method in {"POST", "PUT", "PATCH"} and request.data is None and request.json_body is None:
            return False
        path = urlparse(request.url).path.lower()
        destructive_tokens = ("delete", "remove", "purchase", "checkout", "pay", "transfer", "withdraw")
        settings = get_settings()
        scan_mode = self._scan_config.get_val("scan_mode", getattr(settings, "scan_mode", "verified")) if getattr(self, "_scan_config", None) else getattr(settings, "scan_mode", "verified")
        if scan_mode != "aggressive" and any(token in path for token in destructive_tokens):
            return False
        return True

    def _is_admin_like_url(self, url: str) -> bool:
        lowered = urlparse(url).path.lower()
        return any(token in lowered for token in self.sensitive_path_tokens)

    @staticmethod
    def _canonical_request_url(url: str) -> str:
        parsed = urlparse(url)
        query_names = "&".join(sorted(name for name, _ in parse_qsl(parsed.query, keep_blank_values=True)))
        suffix = f"?{query_names}" if query_names else ""
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}{suffix}".lower()

    def _body_schema_key(self, value: Any) -> str:
        if value is None:
            return ""
        paths: set[str] = set()

        def walk(child: Any, prefix: str = "") -> None:
            if isinstance(child, dict):
                for key, grandchild in child.items():
                    path = f"{prefix}.{key}" if prefix else str(key)
                    paths.add(path)
                    walk(grandchild, path)
            elif isinstance(child, list):
                for item in child[:1]:
                    walk(item, prefix + "[]")

        walk(value)
        return "|".join(sorted(paths))

    @staticmethod
    def _parse_cookie_string(value: object) -> dict[str, str]:
        if isinstance(value, dict):
            return {str(k): str(v) for k, v in value.items()}
        if not isinstance(value, str):
            return {}
        cookies: dict[str, str] = {}
        for cookie in value.split(";"):
            cookie = cookie.strip()
            if "=" in cookie:
                key, val = cookie.split("=", 1)
                cookies[key.strip()] = val.strip()
        return cookies

    @staticmethod
    def _parse_header_string(value: object) -> dict[str, str]:
        if isinstance(value, dict):
            return {str(k): str(v) for k, v in value.items()}
        if not isinstance(value, str) or ":" not in value:
            return {}
        key, val = value.split(":", 1)
        return {key.strip(): val.strip()} if key.strip() and val.strip() else {}

    def _build_auth_material(
        self,
        *,
        label: str,
        cookie_value: object,
        header_value: object,
    ) -> _AuthMaterial:
        return _AuthMaterial(
            label=label,
            cookies=self._parse_cookie_string(cookie_value),
            headers=self._parse_header_string(header_value),
        )

    @staticmethod
    def _normalize_param_name(name: str) -> str:
        return re.sub(r"[^a-z0-9]", "", name.lower())

    # ---------------------------------------------------------------------------
    # Helpers
    # ---------------------------------------------------------------------------

    def _is_idor_param(self, name: str) -> bool:
        """Return True if *name* looks like an object-reference parameter."""
        if not name:
            return False
        lower = name.lower()
        if lower in self.idor_param_tokens:
            return True
        # Substring check: catch camelCase variants like userId, orderId, etc.
        return any(tok in lower for tok in ("id", "user", "account", "order", "record", "uuid"))


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------

def _body_similarity(a: str, b: str) -> float:
    """
    Rough Jaccard similarity between two response bodies using character
    4-grams.  Returns a float in [0, 1].  1 = identical content.

    Used in two places:
      - "too similar" guard: if own and mutated responses are >95% similar
        they are probably the same generic template.
      - "too different" guard: if own and mutated are <10% similar the
        mutated response is probably a generic error page.
      - Public-resource guard: if authed and unauthed mutated responses are
        >85% similar, the mutated resource is publicly accessible.
    """
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0

    def ngrams(text: str, n: int = 4) -> set[str]:
        t = text.lower()
        return {t[i : i + n] for i in range(len(t) - n + 1)}

    sa, sb = ngrams(a), ngrams(b)
    if not sa and not sb:
        return 1.0
    intersection = len(sa & sb)
    union = len(sa | sb)
    return intersection / union if union else 0.0
