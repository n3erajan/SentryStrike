import re
import asyncio
import urllib.parse
import httpx

from app.config import get_settings
from app.core.detectors.base_detector import BaseDetector, Finding
from app.models.vulnerability import OwaspCategory, SeverityLevel
from app.utils.http_logging import make_httpx_response_logger
# ---------------------------------------------------------------------------
# Detection patterns
# ---------------------------------------------------------------------------

# High-severity: leaks DB schema, credentials, file paths, or query internals
_HIGH_PATTERNS: list[re.Pattern] = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"you have an error in your sql syntax",        # MySQL verbose query error
        r"syntax error at or near",                     # PostgreSQL
        r"pg::(?:syntax|unique|constraint|connection)", # PostgreSQL exception class
        r"sqlstate\[",                                  # PDO with state code
        r"ociexception",                                # Oracle
        r"connectionexception",                         # DB connection failure
        r"password\s*=",                                # credential leak in error
        r"db_password|database_password|db_pass",       # config key leak
        r"/var/www/",                                   # Unix web root path
        r"/home/\w+/",                                  # Unix home path
        r"[A-Za-z]:\\\\(?:inetpub|xampp|wamp|www)",    # Windows web root path
        r"app/models/",                                 # MVC model path
        r"app/controllers/",                            # MVC controller path
        r"site-packages/",                              # Python package path
        r"caught exception:",                           # PHP/generic exception dump
        r"mysqli_error\(",                              # raw PHP function name leaking
    ]
]

# Medium-severity: reveals stack trace or framework internals without sensitive data
_MEDIUM_PATTERNS: list[re.Pattern] = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"traceback \(most recent call last\)",         # Python
        r"at \w[\w\.]+\([\w\.]+\.(?:java|kt):\d+\)",   # Java / Kotlin stack frame
        r"system\.exception",                           # .NET
        r"unhandled exception",                         # .NET / generic
        r"microsoft\.aspnetcore",                       # ASP.NET Core
        r"django\.core\.",                              # Django internals
        r"activerecord::",                              # Rails
        r"actioncontroller::",                          # Rails
        r"pdoexception",                                # PHP PDO
        r"fatal error:",                                # PHP fatal
        r"warning:\s+\w",                               # PHP warning
        r"undefined index:",                            # PHP notice
        r"nullreferenceexception",                      # .NET null ref
        r"stack trace:",                                # generic
        r"stack overflow",                              # stack overflow error
        r"errno\s*=?\s*\d+",                            # C/POSIX errno
        r"internal server error",                       # generic 500 body text
        r"exception in thread",                         # Java thread exception
        r"caused by:",                                  # Java chained exception
        r"django.db.utils",                             # Django DB error
        r"laravel\\",                                   # Laravel namespace in trace
        r"illuminate\\",                                # Laravel Illuminate
        r"symfony\\",                                   # Symfony
        r"rails application",                           # Rails error page
    ]
]

# Low-severity: bare application error with no detail but confirms poor handling
_LOW_PATTERNS: list[re.Pattern] = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"something went wrong",
        r"an error has occurred",
        r"application error",
        r"we'll be back soon",
        r"unexpected error",
    ]
]

# HTTP response headers that leak framework / server details on errors
_SENSITIVE_HEADERS = {
    "x-powered-by",
    "x-aspnet-version",
    "x-aspnetmvc-version",
    "x-generator",
    "x-drupal-cache",
    "x-runtime",
    "x-request-id",
}

# Payloads designed to trigger unhandled exceptions in real endpoints.
_FUZZ_PAYLOADS: list[tuple[str, str]] = [
    ("'", "single quote — SQL metacharacter / template error trigger"),
    ("\x00", "null byte — triggers path/string handling errors"),
    ("A" * 8192, "8 KB oversize string — buffer / ORM field-length exception"),
    ("[]", "array notation — type mismatch where scalar expected"),
    ("-1", "negative integer — constraint violations / unsigned cast errors"),
    ("9999999999999999999", "integer overflow probe"),
    ("{{7*7}}", "template expression — SSTI errors in unprotected renderers"),
    ("<script>", "HTML/XML metacharacter — XML parser or sanitiser errors"),
    ("../../../etc/passwd", "path traversal — file-handling errors"),
    ("%00%0d%0a", "URL-encoded null + CRLF — header injection / parser errors"),
]

_DEFAULT_URL_LIMIT = 20
_EVIDENCE_SNIPPET_LEN = 300
_MAX_CONCURRENT = 5

# Status codes that indicate a gateway/proxy error — not application exceptions
_GATEWAY_CODES = {501, 502, 503, 504}
# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------

def _classify_body(body: str) -> tuple[SeverityLevel | None, list[str], list[str]]:
    """
    Check HIGH, then MEDIUM, then LOW patterns against the body.
    Returns (severity, high_hits, medium_hits). Severity is None if no match.
    NOTE: body should be passed as-is (not pre-lowercased) — patterns use IGNORECASE.
    """
    high_hits = [p.pattern for p in _HIGH_PATTERNS if p.search(body)]
    if high_hits:
        return SeverityLevel.high, high_hits, []

    med_hits = [p.pattern for p in _MEDIUM_PATTERNS if p.search(body)]
    if med_hits:
        return SeverityLevel.medium, [], med_hits

    low_hits = [p.pattern for p in _LOW_PATTERNS if p.search(body)]
    if low_hits:
        return SeverityLevel.low, [], low_hits

    return None, [], []
def _extract_snippet(body: str, patterns: list[re.Pattern]) -> str:
    """Return a short excerpt around the first matching pattern."""
    for pattern in patterns:
        m = pattern.search(body)
        if m:
            start = max(0, m.start() - 60)
            end = min(len(body), m.end() + _EVIDENCE_SNIPPET_LEN)
            snippet = body[start:end].strip()
            snippet = re.sub(r"\s{3,}", " ... ", snippet)
            return snippet[:_EVIDENCE_SNIPPET_LEN]
    return body[:_EVIDENCE_SNIPPET_LEN]
def _sensitive_headers_present(headers: httpx.Headers) -> list[str]:
    return [h for h in _SENSITIVE_HEADERS if h in headers]
def _finding_key(url: str, vuln_type: str, severity: SeverityLevel) -> tuple:
    """Deduplication key — same path (no query string) + vuln type + severity."""
    path = url.split("?")[0]
    return (path, vuln_type, severity)
def _build_evidence(
    url: str,
    method: str,
    status: int,
    body: str,
    matched_patterns: list[str],
    sensitive_hdrs: list[str],
    trigger: str = "",
) -> str:
    all_patterns = _HIGH_PATTERNS + _MEDIUM_PATTERNS + _LOW_PATTERNS
    compiled = [p for p in all_patterns if p.pattern in matched_patterns]
    snippet = _extract_snippet(body, compiled) if compiled else body[:_EVIDENCE_SNIPPET_LEN]

    parts = [f"{method} {url} → HTTP {status}"]
    if trigger:
        parts.append(f"Trigger: {trigger}")
    if matched_patterns:
        parts.append(f"Matched: {', '.join(matched_patterns[:3])}")
    if sensitive_hdrs:
        parts.append(f"Sensitive headers: {', '.join(sensitive_hdrs)}")
    parts.append(f"Excerpt: {snippet!r}")
    return " | ".join(parts)
def _replace_param_values(url: str, replacement: str) -> str:
    """Replace all query parameter values in a URL with `replacement`."""
    if "?" not in url:
        return url
    base, qs = url.split("?", 1)
    pairs = []
    for part in qs.split("&"):
        if "=" in part:
            key, _ = part.split("=", 1)
            pairs.append(f"{key}={urllib.parse.quote(replacement, safe='')}")
        else:
            pairs.append(part)
    return f"{base}?{'&'.join(pairs)}"
# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------

class ExceptionHandlingDetector(BaseDetector):
    name = "exception_handling"

    def __init__(self) -> None:
        self.settings = get_settings()

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    async def detect(
        self,
        urls: list[str],
        forms: list[object],
        **kwargs: object,
    ) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[tuple] = set()
        semaphore = asyncio.Semaphore(_MAX_CONCURRENT)

        # Pull auth cookies from kwargs if the scanner has already authenticated.
        # Expected shape: {"PHPSESSID": "abc123", "security": "low"}
        # Callers should pass these in via kwargs["auth_cookies"] after logging in.
        auth_cookies: dict[str, str] = kwargs.get("auth_cookies") or {}

        async with httpx.AsyncClient(
            timeout=self.settings.request_timeout_seconds,
            follow_redirects=False,   # CRITICAL: don't silently follow auth redirects
            cookies=auth_cookies,
            event_hooks={"response": [make_httpx_response_logger("exception_handling", "error_probe")]},
        ) as client:

            # ── Technique 1: 404 / non-existent path probing ─────────────
            url_limit = getattr(self.settings, "exception_url_limit", _DEFAULT_URL_LIMIT)
            probe_urls = _prioritise_urls(urls)[:url_limit]

            tasks_404 = [
                self._probe_404(client, semaphore, url)
                for url in probe_urls
            ]
            results_404 = await asyncio.gather(*tasks_404, return_exceptions=True)
            for result in results_404:
                if isinstance(result, Exception):
                    # Log but don't crash — individual probe failures are non-fatal
                    continue
                if isinstance(result, Finding):
                    _add_finding(result, findings, seen)

            # ── Technique 2: Parameter fuzzing on GET URLs ────────────────
            param_urls = [u for u in urls if "?" in u]
            fuzz_tasks = [
                self._probe_get_params(client, semaphore, url, payload, desc)
                for url in param_urls
                for payload, desc in _FUZZ_PAYLOADS
            ]
            results_fuzz = await asyncio.gather(*fuzz_tasks, return_exceptions=True)
            for result in results_fuzz:
                if isinstance(result, Exception):
                    continue
                if isinstance(result, Finding):
                    _add_finding(result, findings, seen)

            # ── Technique 3: Form field fuzzing (POST / GET forms) ────────
            form_tasks = [
                self._probe_form(client, semaphore, form, payload, desc)
                for form in (forms or [])
                for payload, desc in _FUZZ_PAYLOADS
            ]
            results_forms = await asyncio.gather(*form_tasks, return_exceptions=True)
            for result in results_forms:
                if isinstance(result, Exception):
                    continue
                if isinstance(result, Finding):
                    _add_finding(result, findings, seen)

            # ── Technique 4: Co-parameter fuzzing on GET URLs ─────────────
            # Some endpoints require ALL original parameters to be present for
            # the request to reach application logic (e.g. a Submit=Submit flag
            # alongside the fuzzed field). This technique preserves every existing
            # param at its original value and only replaces one param at a time,
            # so the request is structurally valid and the error path is reached.
            coparam_tasks = [
                self._probe_get_param_single(client, semaphore, url, payload, desc)
                for url in param_urls
                for payload, desc in _FUZZ_PAYLOADS
            ]
            results_coparam = await asyncio.gather(*coparam_tasks, return_exceptions=True)
            for result in results_coparam:
                if isinstance(result, Exception):
                    continue
                if isinstance(result, Finding):
                    _add_finding(result, findings, seen)

        return findings

    # ------------------------------------------------------------------
    # Probing helpers
    # ------------------------------------------------------------------

    async def _probe_404(
        self,
        client: httpx.AsyncClient,
        semaphore: asyncio.Semaphore,
        url: str,
    ) -> Finding | None:
        test_url = f"{url.rstrip('/')}/non-existent-sentry-strike-endpoint-xyzzy"
        async with semaphore:
            try:
                response = await client.get(test_url)
            except Exception:
                return None

        # Auth redirect — we don't have a valid session for this URL
        if response.status_code in {301, 302, 303, 307, 308}:
            return None

        return self._analyse_response(
            url=test_url,
            method="GET",
            status=response.status_code,
            body=response.text,
            headers=response.headers,
            trigger="non-existent path probe",
            require_body_match=True,
        )

    async def _probe_get_params(
        self,
        client: httpx.AsyncClient,
        semaphore: asyncio.Semaphore,
        url: str,
        payload: str,
        payload_desc: str,
    ) -> Finding | None:
        fuzzed_url = _replace_param_values(url, payload)
        if fuzzed_url == url:
            return None

        async with semaphore:
            try:
                response = await client.get(fuzzed_url)
            except Exception:
                return None

        if response.status_code in {301, 302, 303, 307, 308}:
            return None

        return self._analyse_response(
            url=fuzzed_url,
            method="GET",
            status=response.status_code,
            body=response.text,
            headers=response.headers,
            trigger=payload_desc,
        )

    async def _probe_form(
        self,
        client: httpx.AsyncClient,
        semaphore: asyncio.Semaphore,
        form: object,
        payload: str,
        payload_desc: str,
    ) -> Finding | None:
        action = getattr(form, "action", None) or getattr(form, "url", None)
        method = (getattr(form, "method", "post") or "post").upper()
        fields = getattr(form, "fields", None) or getattr(form, "inputs", None) or []

        if not action:
            return None

        data: dict[str, str] = {}
        for field in fields:
            name = getattr(field, "name", None) or (field if isinstance(field, str) else None)
            if not name:
                continue
            if any(kw in name.lower() for kw in ("token", "csrf", "_method", "utf8")):
                data[name] = getattr(field, "value", "") or ""
            else:
                data[name] = payload

        if not data:
            return None

        async with semaphore:
            try:
                if method == "GET":
                    response = await client.get(action, params=data)
                else:
                    response = await client.post(action, data=data)
            except Exception:
                return None

        if response.status_code in {301, 302, 303, 307, 308}:
            return None

        return self._analyse_response(
            url=action,
            method=method,
            status=response.status_code,
            body=response.text,
            headers=response.headers,
            trigger=f"form fuzz — {payload_desc}",
        )

    async def _probe_get_param_single(
        self,
        client: httpx.AsyncClient,
        semaphore: asyncio.Semaphore,
        url: str,
        payload: str,
        payload_desc: str,
    ) -> Finding | None:
        """
        For each query parameter individually: replace ONLY that one param with
        the fuzz payload while leaving all other params at their original crawled
        values.

        This complements _probe_get_params (which replaces ALL params at once).
        It matters for endpoints that require other params to be present and valid
        for the request to actually reach the vulnerable code path — for example,
        an endpoint that needs Submit=Submit alongside the fuzzed field, or a
        pager that needs page=N to stay valid. Technique 2 is blunt-force (every
        param replaced simultaneously); Technique 4 is surgical (one at a time,
        rest preserved at their crawled values). Together they cover both cases.
        """
        if "?" not in url:
            return None

        base, qs = url.split("?", 1)
        original_pairs: list[tuple[str, str]] = []
        for part in qs.split("&"):
            if "=" in part:
                k, v = part.split("=", 1)
                original_pairs.append((k, urllib.parse.unquote_plus(v)))
            else:
                original_pairs.append((part, ""))

        # Skip single-param URLs — Technique 2 already covers those fully
        if len(original_pairs) <= 1:
            return None

        for target_idx, (target_key, _) in enumerate(original_pairs):
            fuzzed_qs_parts = []
            for idx, (k, v) in enumerate(original_pairs):
                if idx == target_idx:
                    fuzzed_qs_parts.append(
                        f"{k}={urllib.parse.quote(payload, safe='')}"
                    )
                else:
                    fuzzed_qs_parts.append(
                        f"{k}={urllib.parse.quote(v, safe='')}"
                    )

            fuzzed_url = f"{base}?{'&'.join(fuzzed_qs_parts)}"

            async with semaphore:
                try:
                    response = await client.get(fuzzed_url)
                except Exception:
                    continue

            if response.status_code in {301, 302, 303, 307, 308}:
                continue

            finding = self._analyse_response(
                url=fuzzed_url,
                method="GET",
                status=response.status_code,
                body=response.text,
                headers=response.headers,
                trigger=f"single-param fuzz on '{target_key}' — {payload_desc}",
            )
            if finding:
                # Return first hit; deduplication in the caller handles the rest
                return finding

        return None

    # ------------------------------------------------------------------
    # Analysis
    # ------------------------------------------------------------------

    def _analyse_response(
        self,
        url: str,
        method: str,
        status: int,
        body: str,
        headers: httpx.Headers,
        trigger: str,
        require_body_match: bool = False,
    ) -> Finding | None:
        # Gateway/proxy errors are not application exceptions
        if status in _GATEWAY_CODES:
            return None

        # Use original body (not lowercased) so snippets are readable
        severity, high_hits, med_hits = _classify_body(body)
        matched = high_hits or med_hits

        sensitive_hdrs = _sensitive_headers_present(headers)
        is_bare_500 = status == 500 and not matched

        if require_body_match and not matched:
            return None

        if not matched and not is_bare_500:
            return None

        if not severity:
            severity = SeverityLevel.low

        # Elevate bare 500 + sensitive headers to medium
        if is_bare_500 and sensitive_hdrs:
            severity = SeverityLevel.medium

        evidence = _build_evidence(
            url=url,
            method=method,
            status=status,
            body=body,
            matched_patterns=matched,
            sensitive_hdrs=sensitive_hdrs,
            trigger=trigger,
        )

        return Finding(
            category=OwaspCategory.a10,
            vuln_type="Verbose Error Handling",
            severity=severity,
            url=url,
            evidence=evidence,
        )

# ---------------------------------------------------------------------------
# Module-level utilities (not methods, so they can be tested independently)
# ---------------------------------------------------------------------------

def _prioritise_urls(urls: list[str]) -> list[str]:
    """URLs with query parameters first (more likely to exercise DB/file logic)."""
    return sorted(urls, key=lambda u: (0 if "?" in u else 1))
def _add_finding(
    finding: Finding,
    findings: list[Finding],
    seen: set[tuple],
) -> None:
    key = _finding_key(finding.url, finding.vuln_type, finding.severity)
    if key not in seen:
        seen.add(key)
        findings.append(finding)