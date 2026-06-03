import re
import asyncio
import urllib.parse
import httpx

from app.config import get_settings
from app.core.detectors.base_detector import BaseDetector, Finding
from app.core.verification.response_analyzer import ResponseAnalyzer
from app.models.vulnerability import OwaspCategory, SeverityLevel
from app.utils.http_logging import make_httpx_response_logger
from app.utils.scan_http import create_scan_client

# ---------------------------------------------------------------------------
# Detection patterns
# ---------------------------------------------------------------------------

_HIGH_PATTERNS: list[re.Pattern] = [
    re.compile(p, re.IGNORECASE)
    for p in [
        # SQL verbose errors (common across stacks)
        r"you have an error in your sql syntax",        # MySQL verbose query error
        r"syntax error at or near",                     # PostgreSQL
        r"pg::(?:syntax|unique|constraint|connection)", # PostgreSQL exception class
        r"sqlstate\[",                                  # PDO with state code
        r"\bsqlstate\b",                                # JDBC/ODBC/PDO state code
        r"\bsqlexception\b",                            # Java/.NET SQL exception
        r"ociexception",                                # Oracle
        r"connectionexception",                         # DB connection failure
        r"sql error",                                   # generic DB error text
        r"database error",                              # generic DB error text
        r"pdoexception",                                # PHP PDO exception dump
        r"check the manual that corresponds to your (?:mysql|mariadb) server version",
        r"\b(?:mysql|mariadb) server version\b",
        r"warning:\s+mysql(?:i)?_",                     # PHP mysql/mysqli warnings
        r"sqlite(?:3)?\.(?:operationalerror|databaseerror|integrityerror)",

        # Full SQL echoes / query execution lines
        r"executing\s*:\s*select\b",                    # common Java/JSP/hibernate echoes
        r"executing\s*:\s*insert\b",
        r"executing\s*:\s*update\b",
        r"executing\s*:\s*delete\b",
        r"select\s+.+\s+from\s+.+where\b",          # query-shaped echo
        r"insert\s+into\s+.+\bvalues\b",          # query-shaped echo

        # Direct credential/config leaks in error output
        r"password\s*=",                                # credential leak in error
        r"db_password|database_password|db_pass",       # config key leak

        # Internal path disclosure
        r"/var/www/",                                   # Unix web root path
        r"/home/\w+/",                                  # Unix home path
        r"/etc/",                                       # common sensitive folder disclosure
        r"/boot/",                                      # boot artifacts
        r"/[A-Za-z0-9_\-]+/www/",                      # weird nested roots sometimes echoed
        r"[A-Za-z]:\\\\(?:inetpub|xampp|wamp|www|rails|django)",    # Windows web root path
        r"app/models/",                                 # MVC model path
        r"app/controllers/",                            # MVC controller path
        r"site-packages/",                              # Python package path
        r"vendor/(?:laravel|symfony)/",                  # Composer vendor disclosure

        # PHP stack traces / exception dumps
        r"caught exception:",                           # PHP/generic exception dump
        r"mysqli_error\(",                              # raw PHP function name leaking
        r"mysql_(?:fetch|query|num_rows|connect)\b",    # raw legacy PHP MySQL call leaking
        r"\b(phpinfo\(|fatal error:|parse error:)\b",  # PHP error output markers

        # IP disclosure hints often appear with stack traces
        r"\b(?:127\.0\.0\.1|localhost)\b",
        r"\b(?:10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[0-1])\.)\d+\.\d+\b",
    ]
]

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

_DEBUG_METRICS_PATTERNS: list[re.Pattern] = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"^#\s*HELP\s+\w+",                         # Prometheus exposition
        r"^#\s*TYPE\s+\w+",                         # Prometheus exposition
        r"jvm_memory_used_bytes|process_cpu_seconds_total|http_server_requests",
        r"\"activeProfiles\"|\"propertySources\"|\"systemProperties\"",  # Spring actuator env
        r"\"heapUsed\"|\"rss\"|\"uptime\"|\"pid\"",  # Node/process dumps
        r"debug\s*=\s*true|app_debug|environment\s*:\s*(dev|debug|local)",
        r"phpinfo\(\)|configuration file \(php\.ini\) path",
        r"server-status|apache server status|scoreboard",
    ]
]

_SENSITIVE_HEADERS = {
    "x-powered-by",
    "x-aspnet-version",
    "x-aspnetmvc-version",
    "x-generator",
    "x-drupal-cache",
    "x-runtime",
    "x-request-id",
}

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

_DEBUG_ENDPOINT_PATHS = [
    "/debug",
    "/debug/vars",
    "/metrics",
    "/status",
    "/server-status",
    "/phpinfo.php",
    "/actuator",
    "/actuator/env",
    "/actuator/metrics",
    "/actuator/health",
    "/actuator/prometheus",
    "/__debug__",
]

_DEFAULT_URL_LIMIT = 20
_EVIDENCE_SNIPPET_LEN = 300
_MAX_CONCURRENT = 5
_GATEWAY_CODES = {501, 502, 503, 504}

# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------

def _get_target_host(target_url: str | None) -> str | None:
    if not target_url:
        return None
    try:
        parsed = urllib.parse.urlparse(target_url)
        host = parsed.hostname or parsed.netloc
        if host and ":" in host:
            host = host.split(":")[0]
        return host
    except Exception:
        return None

def _is_self_reference(matched_str: str, target_host: str | None) -> bool:
    if not target_host:
        return False
    matched_lower = matched_str.lower().strip()
    target_lower = target_host.lower().strip()
    
    if matched_lower == target_lower:
        return True
        
    localhost_ips = {"127.0.0.1", "localhost"}
    if matched_lower in localhost_ips and target_lower in localhost_ips:
        return True
        
    return False

def _classify_body(body: str, target_host: str | None = None) -> tuple[SeverityLevel | None, list[str], list[str]]:
    high_hits = []
    for p in _HIGH_PATTERNS:
        matches = list(p.finditer(body))
        if not matches:
            continue
        is_ip_pattern = p.pattern in (
            r"\b(?:127\.0\.0\.1|localhost)\b",
            r"\b(?:10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[0-1])\.)\d+\.\d+\b"
        )
        if is_ip_pattern and target_host:
            if all(_is_self_reference(m.group(0), target_host) for m in matches):
                continue
        high_hits.append(p.pattern)

    if high_hits:
        return SeverityLevel.high, high_hits, []

    med_hits = []
    for p in _MEDIUM_PATTERNS:
        matches = list(p.finditer(body))
        if not matches:
            continue
        is_ip_pattern = p.pattern in (
            r"\b(?:127\.0\.0\.1|localhost)\b",
            r"\b(?:10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[0-1])\.)\d+\.\d+\b"
        )
        if is_ip_pattern and target_host:
            if all(_is_self_reference(m.group(0), target_host) for m in matches):
                continue
        med_hits.append(p.pattern)

    if med_hits:
        return SeverityLevel.medium, [], med_hits

    low_hits = [p.pattern for p in _LOW_PATTERNS if p.search(body)]
    if low_hits:
        return SeverityLevel.low, [], low_hits

    return None, [], []

def _extract_snippet(body: str, patterns: list[re.Pattern]) -> str:
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
    path = url.split("?")[0]
    return (path, vuln_type, severity)

def _evidence_endpoint_key(finding: Finding) -> tuple[str, str | None, str]:
    parsed = urllib.parse.urlparse(finding.url or "")
    return (
        f"{parsed.scheme}://{parsed.netloc}{parsed.path}".rstrip("/"),
        finding.parameter,
        finding.vuln_type,
    )

def _build_evidence(
    url: str,
    method: str,
    status: int,
    body: str,
    matched_patterns: list[str],
    sensitive_hdrs: list[str],
    trigger: str = "",
) -> str:
    all_patterns = _HIGH_PATTERNS + _MEDIUM_PATTERNS + _LOW_PATTERNS + _DEBUG_METRICS_PATTERNS
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

def _observed_text_from_finding(finding: Finding) -> str:
    # Only evaluate the actual HTTP response body snippet returned by the server
    return finding.verification_response_snippet or ""

def _replace_param_values(url: str, replacement: str) -> str:
    if "?" not in url:
        return url
    base, qs = url.split("?", 1)
    pairs = []
    for part in qs.split("&"):
        if "=" in part:
            key, _ = part.split("=", 1)
            if key.lower() == "submit":
                pairs.append(part)
            else:
                pairs.append(f"{key}={urllib.parse.quote(replacement, safe='')}")
        else:
            pairs.append(part)
    return f"{base}?{'&'.join(pairs)}"

# ---------------------------------------------------------------------------
# Detector Engine
# ---------------------------------------------------------------------------

class ExceptionHandlingDetector(BaseDetector):
    name = "exception_handling"

    def __init__(self) -> None:
        self.settings = get_settings()

    async def detect(
        self,
        urls: list[str],
        forms: list[object],
        **kwargs: object,
    ) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[tuple] = set()
        semaphore = asyncio.Semaphore(_MAX_CONCURRENT)

        auth_cookies: dict[str, str] = kwargs.get("session_cookies") or kwargs.get("auth_cookies") or {}

        default_headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Sentry/2.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        }

        async with create_scan_client(
            timeout=self.settings.request_timeout_seconds,
            follow_redirects=False,   
            cookies=auth_cookies,
            headers=default_headers,
            event_hooks={"response": [make_httpx_response_logger("exception_handling", "error_probe")]},
        ) as client:

            # ── Technique 1: 404 / non-existent path probing ─────────────
            url_limit = getattr(self.settings, "exception_url_limit", _DEFAULT_URL_LIMIT)
            probe_urls = _prioritise_urls(urls)[:url_limit]

            tasks_404 = [self._probe_404(client, semaphore, url) for url in probe_urls]
            results_404 = await asyncio.gather(*tasks_404, return_exceptions=True)
            for result in results_404:
                if isinstance(result, Finding):
                    _add_finding(result, findings, seen)

            # Technique 1b: globally exposed debug/metrics endpoints
            debug_tasks = [
                self._probe_debug_endpoint(client, semaphore, root, path)
                for root in self._target_roots(urls)
                for path in _DEBUG_ENDPOINT_PATHS
            ]
            results_debug = await asyncio.gather(*debug_tasks, return_exceptions=True)
            for result in results_debug:
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
                if isinstance(result, Finding):
                    _add_finding(result, findings, seen)

            # ── Technique 4: Co-parameter surgical fuzzing ─────────────
            coparam_tasks = [
                self._probe_get_param_single(client, semaphore, url, payload, desc)
                for url in param_urls
                for payload, desc in _FUZZ_PAYLOADS
            ]
            results_coparam = await asyncio.gather(*coparam_tasks, return_exceptions=True)
            for result in results_coparam:
                if isinstance(result, Finding):
                    _add_finding(result, findings, seen)

        return findings

    def findings_from_observed_evidence(
        self,
        observed_findings: list[Finding],
        target_url: str | None = None,
    ) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[tuple] = set()
        target_host = _get_target_host(target_url)
        existing_verbose_error_keys = {
            (endpoint, parameter)
            for endpoint, parameter, vuln_type in (
                _evidence_endpoint_key(finding) for finding in (observed_findings or [])
            )
            if vuln_type == "Verbose Error Handling"
        }
        existing_verbose_error_endpoints = {
            endpoint
            for endpoint, _, vuln_type in (
                _evidence_endpoint_key(finding) for finding in (observed_findings or [])
            )
            if vuln_type == "Verbose Error Handling"
        }

        for source in observed_findings or []:
            if source.category == OwaspCategory.a10 and source.vuln_type == "Verbose Error Handling":
                continue
            endpoint, parameter, _ = _evidence_endpoint_key(source)
            if (endpoint, parameter) in existing_verbose_error_keys:
                continue
            if endpoint in existing_verbose_error_endpoints:
                continue

            observed_text = _observed_text_from_finding(source)
            severity, high_hits, med_hits = _classify_body(observed_text, target_host=target_host)
            matched = high_hits or med_hits
            if not matched or not severity:
                continue

            trigger = (
                f"observed during {source.vuln_type} verification"
                if getattr(source, "vuln_type", None)
                else "observed during active verification"
            )
            evidence = _build_evidence(
                url=source.url,
                method=source.method,
                status=200,
                body=observed_text,
                matched_patterns=matched,
                sensitive_hdrs=[],
                trigger=trigger,
            )

            finding = Finding(
                category=OwaspCategory.a10,
                vuln_type="Verbose Error Handling",
                severity=severity,
                url=source.url,
                parameter=source.parameter,
                method=source.method,
                payload=source.payload,
                evidence=evidence,
                confidence_score=95.0 if severity == SeverityLevel.high else 85.0,
                detection_method="observed_exception_evidence",
                detection_evidence={
                    "source_vuln_type": source.vuln_type,
                    "source_detection_method": getattr(source, "detection_method", None),
                    "matched_patterns": matched,
                },
                verified=True,
                reproducible=getattr(source, "reproducible", False),
                verification_request_snippet=getattr(source, "verification_request_snippet", None),
                verification_response_snippet=ResponseAnalyzer.build_evidence_response_snippet(
                    status_code=200,
                    body=observed_text,
                    payload=source.payload or trigger,
                    extra_markers=matched,
                ),
            )
            _add_finding(finding, findings, seen)

        return findings

    @staticmethod
    def _target_roots(urls: list[str]) -> list[str]:
        roots: set[str] = set()
        for url in urls:
            parsed = urllib.parse.urlparse(url)
            if parsed.scheme and parsed.netloc:
                roots.add(f"{parsed.scheme}://{parsed.netloc}")
        return sorted(roots)

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

        if response.status_code in {301, 302, 303, 307, 308}:
            return None

        return self._analyse_response(
            url=test_url, method="GET", status=response.status_code,
            body=response.text, headers=response.headers,
            trigger="non-existent path probe", require_body_match=True,
            parameter=None, payload=None
        )

    async def _probe_debug_endpoint(
        self,
        client: httpx.AsyncClient,
        semaphore: asyncio.Semaphore,
        root: str,
        path: str,
    ) -> Finding | None:
        test_url = f"{root.rstrip('/')}/{path.lstrip('/')}"
        async with semaphore:
            try:
                response = await client.get(test_url)
            except Exception:
                return None

        if response.status_code != 200:
            return None

        matched = [p.pattern for p in _DEBUG_METRICS_PATTERNS if p.search(response.text or "")]
        if not matched:
            return None

        evidence = _build_evidence(
            url=test_url,
            method="GET",
            status=response.status_code,
            body=response.text,
            matched_patterns=matched,
            sensitive_hdrs=_sensitive_headers_present(response.headers),
            trigger="debug/metrics endpoint probe",
        )

        return Finding(
            category=OwaspCategory.a10,
            vuln_type="Debug / Metrics Endpoint Exposed",
            severity=SeverityLevel.medium,
            url=test_url,
            method="GET",
            evidence=evidence,
            confidence_score=90.0,
            verified=True,
            reproducible=True,
            verification_request_snippet=f"GET {test_url} HTTP/1.1\nUser-Agent: Sentry/2.0",
            verification_response_snippet=ResponseAnalyzer.build_evidence_response_snippet(
                status_code=response.status_code,
                body=response.text,
                payload="debug/metrics endpoint probe",
                extra_markers=matched,
            ),
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
            url=fuzzed_url, method="GET", status=response.status_code,
            body=response.text, headers=response.headers, trigger=payload_desc,
            parameter="QueryString", payload=payload
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

        fuzzed_param = "unknown"
        data: dict[str, str] = {}
        for field in fields:
            name = getattr(field, "name", None) or (field if isinstance(field, str) else None)
            if not name:
                continue
            
            if any(kw in name.lower() for kw in ("token", "csrf", "_method", "utf8")):
                data[name] = getattr(field, "value", "") or ""
            elif name.lower() == "submit":
                data[name] = getattr(field, "value", "Submit") or "Submit"
            else:
                data[name] = payload
                fuzzed_param = name

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

        # Build full URI for context logging
        full_uri = str(response.url) if hasattr(response, "url") else action

        return self._analyse_response(
            url=full_uri, method=method, status=response.status_code,
            body=response.text, headers=response.headers, trigger=f"form fuzz — {payload_desc}",
            parameter=fuzzed_param, payload=payload
        )

    async def _probe_get_param_single(
        self,
        client: httpx.AsyncClient,
        semaphore: asyncio.Semaphore,
        url: str,
        payload: str,
        payload_desc: str,
    ) -> Finding | None:
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

        if len(original_pairs) <= 1:
            return None

        for target_idx, (target_key, _) in enumerate(original_pairs):
            if target_key.lower() == "submit":
                continue

            fuzzed_qs_parts = []
            for idx, (k, v) in enumerate(original_pairs):
                if idx == target_idx:
                    fuzzed_qs_parts.append(f"{k}={urllib.parse.quote(payload, safe='')}")
                else:
                    fuzzed_qs_parts.append(f"{k}={urllib.parse.quote(v, safe='')}")

            fuzzed_url = f"{base}?{'&'.join(fuzzed_qs_parts)}"

            async with semaphore:
                try:
                    response = await client.get(fuzzed_url)
                except Exception:
                    continue

            if response.status_code in {301, 302, 303, 307, 308}:
                continue

            finding = self._analyse_response(
                url=fuzzed_url, method="GET", status=response.status_code,
                body=response.text, headers=response.headers,
                trigger=f"single-param fuzz on '{target_key}' — {payload_desc}",
                parameter=target_key, payload=payload
            )
            if finding:
                return finding

        return None

    def _analyse_response(
        self,
        url: str,
        method: str,
        status: int,
        body: str,
        headers: httpx.Headers,
        trigger: str,
        require_body_match: bool = False,
        parameter: str | None = None,
        payload: str | None = None,
    ) -> Finding | None:
        if status in _GATEWAY_CODES:
            return None

        severity, high_hits, med_hits = _classify_body(body, target_host=_get_target_host(url))
        matched = high_hits or med_hits

        sensitive_hdrs = _sensitive_headers_present(headers)
        is_bare_500 = status == 500 and not matched

        if require_body_match and not matched:
            return None

        if not matched and not is_bare_500:
            return None

        if not severity:
            severity = SeverityLevel.low

        if is_bare_500 and sensitive_hdrs:
            severity = SeverityLevel.medium

        evidence = _build_evidence(
            url=url, method=method, status=status, body=body,
            matched_patterns=matched, sensitive_hdrs=sensitive_hdrs, trigger=trigger,
        )

        return Finding(
            category=OwaspCategory.a10,
            vuln_type="Verbose Error Handling",
            severity=severity,
            url=url,
            parameter=parameter,
            method=method,
            payload=payload,
            evidence=evidence,
            confidence_score=100.0 if severity == SeverityLevel.high else 85.0,
            verified=True,
            reproducible=True,
            verification_request_snippet=f"{method} {url} HTTP/1.1\nUser-Agent: Sentry/2.0\nPayload: {payload}",
            verification_response_snippet=ResponseAnalyzer.build_evidence_response_snippet(
                status_code=status,
                body=body,
                payload=payload or trigger,
                extra_markers=[trigger, *matched],
            ),
        )

def _prioritise_urls(urls: list[str]) -> list[str]:
    return sorted(urls, key=lambda u: (0 if "?" in u else 1))

def _add_finding(finding: Finding, findings: list[Finding], seen: set[tuple]) -> None:
    key = _finding_key(finding.url, finding.vuln_type, finding.severity)
    if key not in seen:
        seen.add(key)
        findings.append(finding)
