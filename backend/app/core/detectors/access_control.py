import asyncio
import logging
import re
from contextlib import asynccontextmanager
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from app.core.crawler.spa import SpaFallbackDetector
from app.core.detectors.base_detector import BaseDetector, Finding
from app.core.verification.verification_framework import HttpVerifier, URLParameterBuilder
from app.models.vulnerability import OwaspCategory, SeverityLevel

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Regex helpers
# ---------------------------------------------------------------------------
_NUMERIC_RE = re.compile(r"^\d+$")
_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE
)
_SHORT_ALNUM_RE = re.compile(r"^[a-zA-Z0-9]{1,8}$")

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
        session_cookies: dict[str, str] = kwargs.get("session_cookies") or {}
        privileged_cookies: dict[str, str] = kwargs.get("privileged_cookies") or {}
        is_spa = bool(kwargs.get("is_spa", False))
        spa_root_html = str(kwargs.get("spa_root_html") or "")
        root_url = str(kwargs.get("root_url") or "")

        spa_detector: SpaFallbackDetector | None = None
        if is_spa and spa_root_html:
            spa_detector = SpaFallbackDetector()
            spa_detector.configure_root(root_url, spa_root_html)
            if not spa_detector.root_looks_like_spa():
                spa_detector = None

        authed_verifier = HttpVerifier(cookies=session_cookies)
        authed_verifier.set_request_context(module="access_control")

        unauthed_verifier = HttpVerifier()
        unauthed_verifier.set_request_context(module="access_control")

        privileged_verifier: HttpVerifier | None = None
        if privileged_cookies:
            privileged_verifier = HttpVerifier(cookies=privileged_cookies)
            privileged_verifier.set_request_context(module="access_control")

        try:
            forced_browsing_task = self._check_forced_browsing(
                urls, unauthed_verifier, authed_verifier, spa_detector=spa_detector
            )
            idor_task = self._check_idor(
                urls, forms, unauthed_verifier, authed_verifier, privileged_verifier
            )
            fb_findings, idor_findings = await asyncio.gather(
                forced_browsing_task, idor_task
            )
            findings.extend(fb_findings)
            findings.extend(idor_findings)
        finally:
            await authed_verifier.close()
            await unauthed_verifier.close()
            if privileged_verifier:
                await privileged_verifier.close()

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
    ) -> list[Finding]:
        findings: list[Finding] = []
        semaphore = asyncio.Semaphore(self._CONCURRENCY)
        idor_candidates: set[tuple[str, str, str, str]] = set()

        # --- URL params ---
        for url in urls:
            parsed = urlparse(url)
            for param_name, param_value in parse_qsl(parsed.query, keep_blank_values=True):
                if self._is_idor_param(param_name) and _is_valid_id_value(param_value):
                    idor_candidates.add((url, param_name, "GET", param_value))

        # --- Path segment IDs (e.g. /users/42/profile) ---
        # Only consider path segments that are purely numeric or UUIDs — not
        # opaque tokens, which are too ambiguous when embedded in paths.
        for url in urls:
            parsed = urlparse(url)
            segments = [s for s in parsed.path.split("/") if s]
            for i, segment in enumerate(segments):
                if _NUMERIC_RE.match(segment) or _UUID_RE.match(segment):
                    idor_candidates.add((url, f"__path_seg_{i}__:{segment}", "GET", segment))

        # --- Form inputs ---
        for form in forms:
            form_url: str = getattr(form, "action", getattr(form, "page_url", "")) or ""
            form_method: str = getattr(form, "method", "POST").upper()
            for inp in getattr(form, "inputs", []):
                inp_name: str = getattr(inp, "name", "") or ""
                inp_value: str = str(getattr(inp, "value", "") or "")
                if self._is_idor_param(inp_name) and _is_valid_id_value(inp_value):
                    idor_candidates.add((form_url, inp_name, form_method, inp_value))

        if not idor_candidates:
            return findings

        async def _verify(cand: tuple[str, str, str, str]) -> list[Finding]:
            cand_url, param, method, val = cand
            cand_findings: list[Finding] = []

            mutated_vals = _mutate_id(val)

            async with semaphore:
                try:
                    # -------------------------------------------------------
                    # Step 1 (Burp-style): unauthenticated baseline for the
                    # ORIGINAL value.  If the original resource is already
                    # publicly accessible, IDOR is not applicable — any user
                    # can already reach it without credentials.
                    # -------------------------------------------------------
                    unauth_own_url, unauth_own_params, unauth_own_data = URLParameterBuilder.inject_parameter(
                        cand_url, param, val, method
                    )
                    unauth_own_resp = await unauthed_verifier.send_request(
                        unauth_own_url, method, unauth_own_params, unauth_own_data,
                        test_phase="idor_unauth_own"
                    )

                    if (
                        unauth_own_resp.status_code == 200
                        and not _looks_like_login_page(unauth_own_resp.body)
                        and not _looks_like_error_page(unauth_own_resp.body)
                    ):
                        # The original resource is publicly accessible → skip
                        logger.debug(
                            "IDOR skip: original resource is public at %s param=%s val=%s",
                            cand_url, param, val,
                        )
                        return []

                    # -------------------------------------------------------
                    # Step 2: Authenticated request for the ORIGINAL value
                    # (the "own resource" baseline).
                    # -------------------------------------------------------
                    auth_own_url, auth_own_params, auth_own_data = URLParameterBuilder.inject_parameter(
                        cand_url, param, val, method
                    )
                    auth_own_resp = await authed_verifier.send_request(
                        auth_own_url, method, auth_own_params, auth_own_data,
                        test_phase="idor_authed_own"
                    )

                    # If authenticated session cannot reach its own resource,
                    # the session cookie is invalid / expired — skip entirely.
                    if auth_own_resp.status_code not in (200, 201):
                        logger.debug(
                            "IDOR skip: authed session cannot access own resource %s param=%s",
                            cand_url, param,
                        )
                        return []

                    # If the own resource response itself looks like an error
                    # page, we have no meaningful baseline to compare against.
                    if _looks_like_error_page(auth_own_resp.body):
                        logger.debug(
                            "IDOR skip: own resource response looks like an error page %s param=%s",
                            cand_url, param,
                        )
                        return []

                    # -------------------------------------------------------
                    # Step 3 (Burp-style differential): for each mutated ID,
                    # fetch with authenticated session AND unauthenticated
                    # session, then apply the differential verdict.
                    # -------------------------------------------------------
                    for mutated_val in mutated_vals:
                        # Authenticated request for mutated ID
                        auth_mod_url, auth_mod_params, auth_mod_data = URLParameterBuilder.inject_parameter(
                            cand_url, param, mutated_val, method
                        )
                        auth_mod_resp = await authed_verifier.send_request(
                            auth_mod_url, method, auth_mod_params, auth_mod_data,
                            test_phase="idor_authed_mod"
                        )

                        if auth_mod_resp.status_code not in (200, 201):
                            continue
                        if _looks_like_login_page(auth_mod_resp.body):
                            continue

                        # Unauthenticated request for the MUTATED value
                        # (Burp-style: check if the mutated resource is itself public)
                        unauth_mod_url, unauth_mod_params, unauth_mod_data = URLParameterBuilder.inject_parameter(
                            cand_url, param, mutated_val, method
                        )
                        unauth_mod_resp = await unauthed_verifier.send_request(
                            unauth_mod_url, method, unauth_mod_params, unauth_mod_data,
                            test_phase="idor_unauth_mod"
                        )
                        mutated_unauthed_body: str | None = (
                            unauth_mod_resp.body
                            if unauth_mod_resp.status_code == 200
                            and not _looks_like_login_page(unauth_mod_resp.body)
                            and not _looks_like_error_page(unauth_mod_resp.body)
                            else None
                        )

                        # Apply Burp-style differential verdict
                        is_idor, similarity, reason = _differential_idor_verdict(
                            own_body=auth_own_resp.body,
                            mutated_authed_body=auth_mod_resp.body,
                            mutated_unauthed_body=mutated_unauthed_body,
                        )

                        if not is_idor:
                            logger.debug(
                                "IDOR false-positive suppressed at %s param=%s mutated=%s: %s",
                                cand_url, param, mutated_val, reason,
                            )
                            continue

                        cand_findings.append(
                            Finding(
                                category=OwaspCategory.a01,
                                vuln_type="Insecure Direct Object Reference (IDOR)",
                                severity=SeverityLevel.high,
                                url=cand_url,
                                parameter=param,
                                method=method,
                                payload=mutated_val,
                                evidence=(
                                    f"Horizontal privilege escalation: authenticated session accessed "
                                    f"'{param}'={mutated_val} (modified from owned value '{val}'). "
                                    f"Unauthenticated baseline for original value returned HTTP "
                                    f"{unauth_own_resp.status_code}. "
                                    f"Unauthenticated access to mutated value: "
                                    f"{'blocked' if mutated_unauthed_body is None else 'public (skipped)'}. "
                                    f"Body similarity (own vs mutated): {similarity:.0%}. "
                                    f"Differential verdict: {reason}."
                                ),
                                verified=True,
                                verification_request_snippet=auth_mod_resp.request_snippet,
                                verification_response_snippet=auth_mod_resp.response_snippet,
                                reproducible=True,
                            )
                        )
                        # One confirmed finding per param is enough; stop mutating.
                        break

                    # -------------------------------------------------------
                    # Step 4: Vertical privilege escalation (if a high-priv
                    # session was supplied).
                    # -------------------------------------------------------
                    if privileged_verifier and not cand_findings:
                        for mutated_val in mutated_vals:
                            priv_url, priv_params, priv_data = URLParameterBuilder.inject_parameter(
                                cand_url, param, mutated_val, method
                            )
                            priv_resp = await privileged_verifier.send_request(
                                priv_url, method, priv_params, priv_data,
                                test_phase="vertical_priv_check"
                            )
                            auth_check_url, auth_check_params, auth_check_data = URLParameterBuilder.inject_parameter(
                                cand_url, param, mutated_val, method
                            )
                            auth_check_resp = await authed_verifier.send_request(
                                auth_check_url, method, auth_check_params, auth_check_data,
                                test_phase="vertical_authed_check"
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
                                            url=cand_url,
                                            parameter=param,
                                            method=method,
                                            payload=mutated_val,
                                            evidence=(
                                                f"Low-privilege session accessed resource "
                                                f"'{param}'={mutated_val} which is also accessible to a "
                                                f"high-privilege session (body similarity: {similarity:.0%}). "
                                                f"Possible vertical privilege escalation."
                                            ),
                                            verified=True,
                                            verification_request_snippet=auth_check_resp.request_snippet,
                                            verification_response_snippet=auth_check_resp.response_snippet,
                                            reproducible=True,
                                        )
                                    )
                                    break

                except Exception:
                    logger.exception("IDOR verification failed for %s param=%s", cand_url, param)

            return cand_findings

        results = await asyncio.gather(*[_verify(c) for c in idor_candidates])
        for r in results:
            findings.extend(r)
        return findings

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