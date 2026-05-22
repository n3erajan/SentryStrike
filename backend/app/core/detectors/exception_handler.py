import re
import asyncio
import httpx

from app.config import get_settings
from app.core.detectors.base_detector import BaseDetector, Finding
from app.models.vulnerability import OwaspCategory, SeverityLevel


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

# HTTP response headers that leak framework / server details specifically on errors
_SENSITIVE_HEADERS = {
    "x-powered-by",
    "x-aspnet-version",
    "x-aspnetmvc-version",
    "x-generator",
    "x-drupal-cache",
    "x-runtime",           # Rails response time (presence confirms Rails)
    "x-request-id",        # can leak internal IDs
}

# Payloads designed to trigger unhandled exceptions in real endpoints.
# Each is a (value, description) pair.  The description goes into evidence.
_FUZZ_PAYLOADS: list[tuple[str, str]] = [
    ("'", "single quote — SQL metacharacter / template error trigger"),
    ("\x00", "null byte — triggers path/string handling errors in many frameworks"),
    ("A" * 8192, "8 KB oversize string — buffer / ORM field-length exception"),
    ("[]", "array notation — type mismatch where scalar expected"),
    ("-1", "negative integer — triggers constraint violations / unsigned cast errors"),
    ("9999999999999999999", "integer overflow probe"),
    ("{{7*7}}", "template expression — triggers SSTI errors in unprotected renderers"),
    ("<script>", "HTML/XML metacharacter — triggers XML parser or sanitiser errors"),
    ("../../../etc/passwd", "path traversal — triggers file-handling errors"),
    ("%00%0d%0a", "URL-encoded null + CRLF — header injection / parser errors"),
]

# How many URLs to probe with 404 technique (configurable via settings fallback)
_DEFAULT_URL_LIMIT = 20

# Max characters of response body to include in evidence snippet
_EVIDENCE_SNIPPET_LEN = 300

# Concurrency cap — avoid hammering the target
_MAX_CONCURRENT = 5


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------

def _classify_body(body: str) -> tuple[SeverityLevel | None, list[str], list[str]]:
    """
    Return (severity, matched_high_labels, matched_medium_labels) or None if
    no patterns matched.  Checks high first so severity is not downgraded.
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
            # Collapse excessive whitespace / newlines for readability
            snippet = re.sub(r"\s{3,}", " ... ", snippet)
            return snippet[:_EVIDENCE_SNIPPET_LEN]
    return body[:_EVIDENCE_SNIPPET_LEN]


def _sensitive_headers_present(headers: httpx.Headers) -> list[str]:
    """Return a list of sensitive header names that are present in the response."""
    return [h for h in _SENSITIVE_HEADERS if h in headers]


def _finding_key(url: str, vuln_type: str, severity: SeverityLevel) -> tuple:
    """Deduplication key — same host + vuln type + severity collapses to one finding."""
    parsed = url.split("?")[0]  # strip query string
    return (parsed, vuln_type, severity)


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
        parts.append(f"Sensitive headers present: {', '.join(sensitive_hdrs)}")
    parts.append(f"Excerpt: {snippet!r}")
    return " | ".join(parts)


# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------

class ExceptionHandlingDetector(BaseDetector):
    name = "exception_handling"

    def __init__(self) -> None:
        self.settings = get_settings()

    # ------------------------------------------------------------------
    # Public interface — signature unchanged for integration compatibility
    # ------------------------------------------------------------------

    async def detect(
        self,
        urls: list[str],
        forms: list[object],
        **kwargs: object,
    ) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[tuple] = set()  # deduplication keys
        semaphore = asyncio.Semaphore(_MAX_CONCURRENT)

        async with httpx.AsyncClient(
            timeout=self.settings.request_timeout_seconds,
            follow_redirects=True,
        ) as client:

            # ── Technique 1: 404 / non-existent path probing ─────────────
            url_limit = getattr(self.settings, "exception_url_limit", _DEFAULT_URL_LIMIT)
            probe_urls = self._prioritise_urls(urls)[:url_limit]

            tasks_404 = [
                self._probe_404(client, semaphore, url)
                for url in probe_urls
            ]
            results_404 = await asyncio.gather(*tasks_404, return_exceptions=True)
            for result in results_404:
                if isinstance(result, Finding):
                    self._add_finding(result, findings, seen)

            # ── Technique 2: Parameter fuzzing on GET URLs ────────────────
            # Only target URLs that already have query parameters — those
            # are most likely to feed into DB queries / file lookups.
            param_urls = [u for u in urls if "?" in u]
            fuzz_tasks = [
                self._probe_get_params(client, semaphore, url, payload, desc)
                for url in param_urls
                for payload, desc in _FUZZ_PAYLOADS
            ]
            results_fuzz = await asyncio.gather(*fuzz_tasks, return_exceptions=True)
            for result in results_fuzz:
                if isinstance(result, Finding):
                    self._add_finding(result, findings, seen)

            # ── Technique 3: Form field fuzzing (POST) ────────────────────
            form_tasks = [
                self._probe_form(client, semaphore, form, payload, desc)
                for form in (forms or [])
                for payload, desc in _FUZZ_PAYLOADS
            ]
            results_forms = await asyncio.gather(*form_tasks, return_exceptions=True)
            for result in results_forms:
                if isinstance(result, Finding):
                    self._add_finding(result, findings, seen)

        return findings

    # ------------------------------------------------------------------
    # Probing helpers — each returns a single Finding or None
    # ------------------------------------------------------------------

    async def _probe_404(
        self,
        client: httpx.AsyncClient,
        semaphore: asyncio.Semaphore,
        url: str,
    ) -> Finding | None:
        """Append a random non-existent path and check the error response."""
        test_url = f"{url.rstrip('/')}/non-existent-sentry-strike-endpoint"
        async with semaphore:
            try:
                response = await client.get(test_url)
            except Exception:
                return None

        return self._analyse_response(
            url=test_url,
            method="GET",
            status=response.status_code,
            body=response.text,
            headers=response.headers,
            trigger="non-existent path probe",
            # 404 is expected — only flag if body leaks details
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
        """Replace every query parameter value with a fuzz payload."""
        fuzzed_url = self._replace_param_values(url, payload)
        if fuzzed_url == url:
            return None  # no substitution possible

        async with semaphore:
            try:
                response = await client.get(fuzzed_url)
            except Exception:
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
        """Submit a form with all fields set to a fuzz payload."""
        action = getattr(form, "action", None) or getattr(form, "url", None)
        method = (getattr(form, "method", "post") or "post").upper()
        fields = getattr(form, "fields", None) or getattr(form, "inputs", None) or []

        if not action:
            return None

        # Build the fuzzed data dict; preserve known-safe field names (tokens etc.)
        data: dict[str, str] = {}
        for field in fields:
            name = getattr(field, "name", None) or (field if isinstance(field, str) else None)
            if not name:
                continue
            # Don't fuzz CSRF tokens or hidden action flags — they break the
            # request before it reaches application logic
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

        return self._analyse_response(
            url=action,
            method=method,
            status=response.status_code,
            body=response.text,
            headers=response.headers,
            trigger=f"form fuzz — {payload_desc}",
        )

    # ------------------------------------------------------------------
    # Analysis helpers
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
        """
        Inspect a response for error disclosure signals.
        Returns a Finding if anything noteworthy is detected, else None.
        """
        body_lower = body.lower()
        severity, high_hits, med_hits = _classify_body(body_lower)
        matched = high_hits or med_hits

        sensitive_hdrs = _sensitive_headers_present(headers)

        # A bare 500 with no body markers is Low if not require_body_match
        is_bare_500 = status == 500 and not matched

        # If we require a body match (e.g. 404 probes) and none found, ignore
        if require_body_match and not matched:
            return None

        # Do not flag non-500 responses unless there's an actual error pattern in the body.
        # Merely having `x-powered-by` on a 200 OK is NOT verbose error handling (it's A05 Info Disclosure).
        if not matched and not is_bare_500:
            return None

        # Determine final severity
        if not severity:
            if is_bare_500:
                severity = SeverityLevel.low
            else:
                severity = SeverityLevel.low

        # Elevate: bare 500 to medium if sensitive headers also present
        if is_bare_500 and sensitive_hdrs:
            severity = SeverityLevel.medium

        # Downgrade 501–504: gateway/network errors, not app exceptions
        if status in {501, 502, 503, 504}:
            return None

        evidence = _build_evidence(
            url=url,
            method=method,
            status=status,
            body=body_lower,
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

    # ------------------------------------------------------------------
    # Utilities
    # ------------------------------------------------------------------

    @staticmethod
    def _prioritise_urls(urls: list[str]) -> list[str]:
        """
        Sort URLs so those with query parameters (more likely to feed into
        DB/file logic) are probed first.  Stable sort preserves original
        order within each group.
        """
        return sorted(urls, key=lambda u: (0 if "?" in u else 1))

    @staticmethod
    def _replace_param_values(url: str, replacement: str) -> str:
        """Replace all query parameter values in a URL with `replacement`."""
        if "?" not in url:
            return url
        base, qs = url.split("?", 1)
        pairs = []
        for part in qs.split("&"):
            if "=" in part:
                key, _ = part.split("=", 1)
                pairs.append(f"{key}={httpx.utils.urllib.parse.quote(replacement, safe='')}")
            else:
                pairs.append(part)
        return f"{base}?{'&'.join(pairs)}"

    @staticmethod
    def _add_finding(
        finding: Finding,
        findings: list[Finding],
        seen: set[tuple],
    ) -> None:
        """Add a finding only if its deduplication key hasn't been seen."""
        key = _finding_key(finding.url, finding.vuln_type, finding.severity)
        if key not in seen:
            seen.add(key)
            findings.append(finding)