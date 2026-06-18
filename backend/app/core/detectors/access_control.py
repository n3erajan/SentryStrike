import asyncio
import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qsl, urlparse, urlunparse

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
    item_count: int = 0
    body_length: int = 0

# ---------------------------------------------------------------------------
# Regex helpers
# ---------------------------------------------------------------------------
_NUMERIC_RE = re.compile(r"^\d+$")
_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE
)

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
    """Return True when the response body appears to be a login/auth wall."""
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

def _differential_idor_verdict(
    *,
    own_body: str,
    mutated_authed_body: str,
    mutated_unauthed_body: str | None,
) -> tuple[bool, float, str]:
    """
    Apply Burp-Suite-style differential analysis to decide whether a response
    to a mutated ID represents a genuine IDOR or a false positive.

    Returns (is_idor, similarity_own_vs_mutated, reason).

    Rules (applied in order):
      R1. If the mutated+authed body looks like an error / not-found page →
          not IDOR (the app rejected the mutated ID gracefully).
      R2. If the mutated+unauthed body is provided and is nearly identical to
          the mutated+authed body → the resource is publicly accessible,
          so this is not a meaningful access-control bypass.
      R3. similarity(own, mutated_authed) > 0.98 → both requests returned the
          same generic template; not a real different object.
      R4. similarity(own, mutated_authed) < 0.10 → the response is so
          different that it is probably a generic error page that slipped
          through the keyword filter.
      R5. Passed all guards → genuine IDOR signal; report with similarity score.

    The similarity thresholds are intentionally conservative to minimise
    false positives at the cost of a slightly higher miss rate.
    """
    # R1: error-page guard
    if _looks_like_error_page(mutated_authed_body):
        return False, 0.0, "mutated response resembles an error/not-found page"

    # R2: public-resource guard
    if mutated_unauthed_body is not None:
        unauth_sim = _body_similarity(mutated_authed_body, mutated_unauthed_body)
        if unauth_sim > 0.85:
            return (
                False,
                0.0,
                f"mutated resource is publicly accessible (authed vs unauthed similarity: {unauth_sim:.0%})",
            )

    # R3 / R4: own-vs-mutated similarity band
    own_sim = _body_similarity(own_body, mutated_authed_body)
    if own_sim > 0.95:
        return False, own_sim, "mutated response is virtually identical to own resource (generic template)"
    if own_sim < 0.10:
        return (
            False,
            own_sim,
            "mutated response is too dissimilar from own resource — likely an error page",
        )

    # Passed all guards
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
            fb_findings, idor_findings, matrix_findings = await asyncio.gather(
                forced_browsing_task,
                idor_task,
                matrix_task,
            )
            findings.extend(fb_findings)
            findings.extend(idor_findings)
            findings.extend(matrix_findings)
        finally:
            await authed_verifier.close()
            await unauthed_verifier.close()
            if privileged_verifier:
                await privileged_verifier.close()
            if second_verifier:
                await second_verifier.close()

        return findings

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

        if (
            unauth_success
            and unauth_sensitive
            and not _looks_like_error_page(unauth.body)
            and (not protected_low or self._profiles_compatible(unauth_profile, low_profile, unauth.body, low.body))
        ):
            findings.append(
                Finding(
                    category=OwaspCategory.a01,
                    vuln_type="Unauthenticated API Data Exposure",
                    severity=SeverityLevel.high if target.admin_like or unauth_profile.sensitive_fields else SeverityLevel.medium,
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
                        unauth_profile, low_profile, second_profile, privileged_profile, target
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
                if _NUMERIC_RE.match(segment) or _UUID_RE.match(segment):
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

    def _baseline_values_for_target(
        self,
        target: AttackTarget,
        response_ids: dict[str, set[str]],
    ) -> list[str]:
        values: list[str] = []
        raw = str(target.value if target.value is not None else "")
        if _is_valid_id_value(raw):
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
    ) -> dict[str, Any]:
        return {
            "source": target.source,
            "parameter_location": target.parameter_location,
            "has_object_reference": target.has_object_reference,
            "admin_like": target.admin_like,
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
        return target.admin_like or bool(profile.sensitive_fields)

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

    def _target_has_access_control_relevance(self, target: AttackTarget) -> bool:
        if "access_control" in target.security_relevance:
            return True
        return self._is_idor_param(target.parameter)

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

    def _is_replayable_matrix_request(self, request: PreparedAttackRequest) -> bool:
        if not request.url or "{" in request.url or re.search(r"/:[A-Za-z_]", request.url):
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
        if getattr(settings, "scan_mode", "verified") != "aggressive" and any(token in path for token in destructive_tokens):
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
