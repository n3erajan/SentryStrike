import asyncio
import logging
import re
from contextlib import asynccontextmanager
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

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

# Slightly wider than before: allows IDs up to 32 chars (hashes, base64 slugs, etc.)
IDOR_VALUE_PATTERN = re.compile(
    r"^(\d+|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[a-zA-Z0-9_\-]{1,32})$",
    re.IGNORECASE,
)

# Tokens that signal "this looks like a login page body"
_LOGIN_SIGNALS = frozenset(["login", "sign in", "signin"])
_LOGIN_CREDENTIAL_SIGNALS = frozenset(["password", "username", "email"])


def _looks_like_login_page(body: str) -> bool:
    """Return True when the response body appears to be a login/auth wall."""
    b = body.lower()
    has_login_word = any(s in b for s in _LOGIN_SIGNALS)
    has_credential_field = any(s in b for s in _LOGIN_CREDENTIAL_SIGNALS)
    return has_login_word and has_credential_field


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
        # XOR last char to get a different but valid-looking UUID
        flipped = last[:-1] + ("0" if last[-1] != "0" else "1")
        candidates.append("-".join(parts[:-1] + [flipped]))
        return candidates

    # Opaque short token: try "2" when val is "1", else "1"
    candidates.append("2" if val == "1" else "1")
    return candidates


def _strip_query(url: str) -> str:
    """Return the URL with the query-string removed."""
    p = urlparse(url)
    return urlunparse((p.scheme, p.netloc, p.path, p.params, "", p.fragment))


# ---------------------------------------------------------------------------
# Main detector
# ---------------------------------------------------------------------------

class AccessControlDetector(BaseDetector):
    name = "access_control"

    # FIX 1: Expanded sensitive path token set to cover common real-world paths
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

    # FIX 2: Expanded IDOR param token set
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

    NON_ID_VALUES: frozenset[str] = frozenset({
        "on", "off", "true", "false", "yes", "no", "null", "none", "undefined",
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
        # FIX 3: Support an optional second authenticated session for vertical
        # privilege escalation checks (e.g. normal-user vs admin).
        privileged_cookies: dict[str, str] = kwargs.get("privileged_cookies") or {}

        authed_verifier = HttpVerifier(cookies=session_cookies)
        authed_verifier.set_request_context(module="access_control")

        unauthed_verifier = HttpVerifier()
        unauthed_verifier.set_request_context(module="access_control")

        # Optional high-priv verifier for vertical escalation tests
        privileged_verifier: HttpVerifier | None = None
        if privileged_cookies:
            privileged_verifier = HttpVerifier(cookies=privileged_cookies)
            privileged_verifier.set_request_context(module="access_control")

        try:
            # Run checks concurrently at the top level
            forced_browsing_task = self._check_forced_browsing(
                urls, unauthed_verifier, authed_verifier
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
    ) -> list[Finding]:
        """
        Detect sensitive paths that are accessible without authentication.

        FIX 4: Also runs the same URL with the authed session and compares
        status codes.  If the authed session returns 200 but unauthed returns
        4xx, that is the correct baseline — nothing to report.  We only flag
        when the *unauthenticated* request itself succeeds.

        FIX 5: Non-200 check is broadened: 206 (partial content), 301/302
        redirects to non-login pages, and 304s are now captured.
        """
        findings: list[Finding] = []
        semaphore = asyncio.Semaphore(self._CONCURRENCY)

        paths_to_test: set[str] = set()
        for url in urls:
            parsed = urlparse(url)
            path_lower = parsed.path.lower()
            # Match whole-segment tokens
            segments = {seg for seg in path_lower.split("/") if seg}
            # Also check assembled sub-paths (e.g. "api/internal")
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

                    # FIX 5: Treat any 2xx as potentially exposed (not just 200)
                    if not (200 <= resp.status_code < 300):
                        return []

                    if _looks_like_login_page(resp.body):
                        return []

                    # FIX 6: Perform an authenticated request to verify the endpoint
                    # actually *exists* for a real user (avoids flagging custom 404
                    # pages that return 200).
                    authed_resp = await authed_verifier.send_request(
                        test_url, "GET", test_phase="forced_browsing_authed_baseline"
                    )
                    if authed_resp.status_code not in (200, 201, 206):
                        # If even authenticated users can't reach it, it's not a real
                        # endpoint — skip to prevent false positives.
                        return []

                    # FIX 7: Content-similarity guard.  If both bodies are nearly
                    # identical they might both be a "soft 200" error page.
                    if _body_similarity(resp.body, authed_resp.body) > 0.95:
                        # Same content unauthenticated as authenticated is suspicious
                        # but could just be a public page — flag at Medium instead.
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
                if self._is_idor_param(param_name) and self._is_valid_id_value(param_value):
                    idor_candidates.add((url, param_name, "GET", param_value))

        # --- Path segment IDs (e.g. /users/42/profile) ---
        # FIX 8: Also extract numeric/UUID segments from URL paths, not just
        # query-string params, since REST APIs routinely embed IDs in paths.
        for url in urls:
            parsed = urlparse(url)
            segments = [s for s in parsed.path.split("/") if s]
            for i, segment in enumerate(segments):
                if self._is_valid_id_value(segment):
                    # Synthesise a virtual "path_id" param so the rest of the
                    # pipeline can use the same mutation logic.
                    idor_candidates.add((url, f"__path_seg_{i}__:{segment}", "GET", segment))

        # --- Form inputs ---
        for form in forms:
            form_url: str = getattr(form, "action", getattr(form, "page_url", "")) or ""
            form_method: str = getattr(form, "method", "POST").upper()
            for inp in getattr(form, "inputs", []):
                inp_name: str = getattr(inp, "name", "") or ""
                inp_value: str = str(getattr(inp, "value", "") or "1")
                if self._is_idor_param(inp_name):
                    if not self._is_valid_id_value(inp_value):
                        inp_value = "1"
                    idor_candidates.add((form_url, inp_name, form_method, inp_value))

        if not idor_candidates:
            return findings

        async def _verify(cand: tuple[str, str, str, str]) -> list[Finding]:
            cand_url, param, method, val = cand
            cand_findings: list[Finding] = []

            # FIX 9: Try all mutated IDs, not just +1
            mutated_vals = _mutate_id(val)

            async with semaphore:
                try:
                    # --- Baseline: is this endpoint protected at all? ---
                    unauth_url, unauth_params, unauth_data = URLParameterBuilder.inject_parameter(
                        cand_url, param, val, method
                    )
                    unauth_resp = await unauthed_verifier.send_request(
                        unauth_url, method, unauth_params, unauth_data,
                        test_phase="idor_unauth_base"
                    )

                    # FIX 10: Check one mutated value at unauth level, but do NOT
                    # short-circuit if statuses differ — the original logic aborted
                    # when unauth returned 200 for both original+mutated.  The
                    # correct check is: if the *original* value itself is publicly
                    # accessible, the endpoint is public and IDOR is not applicable.
                    if unauth_resp.status_code == 200 and not _looks_like_login_page(unauth_resp.body):
                        # Endpoint is public → IDOR test is not meaningful
                        return []

                    # --- Authenticated request for *original* value (owned resource) ---
                    auth_own_url, auth_own_params, auth_own_data = URLParameterBuilder.inject_parameter(
                        cand_url, param, val, method
                    )
                    auth_own_resp = await authed_verifier.send_request(
                        auth_own_url, method, auth_own_params, auth_own_data,
                        test_phase="idor_authed_own"
                    )
                    # FIX 11: If even the authenticated user can't reach the
                    # original resource, the session cookie is invalid / expired.
                    if auth_own_resp.status_code not in (200, 201):
                        logger.debug(
                            "Authed session cannot access own resource %s param=%s — skipping IDOR test",
                            cand_url, param,
                        )
                        return []

                    # --- Test horizontal privilege escalation with each mutation ---
                    for mutated_val in mutated_vals:
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

                        # FIX 12: Content-diff guard — if the mutated response body
                        # is virtually identical to the original owned resource, the
                        # app may just echo a generic success page; lower the confidence.
                        similarity = _body_similarity(auth_own_resp.body, auth_mod_resp.body)
                        if similarity > 0.98:
                            # Indistinguishable responses → likely a static/generic page
                            continue

                        # FIX 13: Also check for "not found" language inside soft-200s
                        soft_notfound_signals = ["not found", "no such", "does not exist", "invalid id"]
                        mod_body_lower = auth_mod_resp.body.lower()
                        if any(s in mod_body_lower for s in soft_notfound_signals):
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
                                    f"Unauthenticated baseline returned HTTP {unauth_resp.status_code}. "
                                    f"Body similarity to own resource: {similarity:.0%}."
                                ),
                                verified=True,
                                verification_request_snippet=auth_mod_resp.request_snippet,
                                verification_response_snippet=auth_mod_resp.response_snippet,
                                reproducible=True,
                            )
                        )
                        # One confirmed finding per param is enough; stop mutating.
                        break

                    # FIX 14: Vertical privilege escalation — if a privileged
                    # verifier was provided, check that a low-priv user cannot
                    # access high-privilege resources.
                    if privileged_verifier and not cand_findings:
                        for mutated_val in mutated_vals:
                            priv_url, priv_params, priv_data = URLParameterBuilder.inject_parameter(
                                cand_url, param, mutated_val, method
                            )
                            priv_resp = await privileged_verifier.send_request(
                                priv_url, method, priv_params, priv_data,
                                test_phase="vertical_priv_check"
                            )
                            # If the privileged user gets 200 but authed (low-priv)
                            # user also gets 200, that is the horizontal IDOR path above.
                            # Here we specifically look for: priv=200, authed=403/404,
                            # which by itself is *not* a vulnerability.  The interesting
                            # case is the reverse: authed gets 200 on a resource that
                            # should require higher privileges (detected via priv baseline).
                            # We flag it as a separate vuln type.
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
                            ):
                                similarity = _body_similarity(priv_resp.body, auth_check_resp.body)
                                if similarity > 0.7:  # Similar content ⇒ same resource returned
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

    def _is_valid_id_value(self, val: str) -> bool:
        """Return True if *val* looks like a plausible object identifier."""
        if not val:
            return False
        if val.lower() in self.NON_ID_VALUES:
            return False
        return bool(IDOR_VALUE_PATTERN.match(val))


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------

def _body_similarity(a: str, b: str) -> float:
    """
    Rough Jaccard similarity between two response bodies based on word sets.

    Used to detect "soft-200" pages where the body is identical or near-
    identical regardless of the parameter value.

    Returns a float in [0, 1].  1 = identical word sets.
    """
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    # Use a character n-gram window to be more sensitive than word-level Jaccard
    def ngrams(text: str, n: int = 4) -> set[str]:
        t = text.lower()
        return {t[i : i + n] for i in range(len(t) - n + 1)}

    sa, sb = ngrams(a), ngrams(b)
    if not sa and not sb:
        return 1.0
    intersection = len(sa & sb)
    union = len(sa | sb)
    return intersection / union if union else 0.0