import re
import asyncio
import urllib.parse
import httpx
import ipaddress

from app.config import get_settings
from app.core.crawler.url_parser import is_static_asset
from app.core.detectors.attack_surface import AttackSurface, AttackTarget
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

        # Path disclosure in error context (e.g. stack traces revealing server paths)
        r"/var/www/",                                   # Unix web root path in trace
        r"/home/\w+/",                                  # Unix home path in trace
        r"[A-Za-z]:\\\\(?:inetpub|xampp|wamp|www|rails|django)",    # Windows web root path in trace

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
        # Node.js / JavaScript / TypeScript stack frames (CWE-550). Two shapes:
        #   at <fn> (/app/file.js:line:col) | at <fn> (node:internal/...:line:col)
        #   at /app/file.js:line:col                     | at node:internal/...:line:col
        r"at \w[\w\.\[\] ]*\s*\([^)]*\.(?:js|mjs|cjs|ts|jsx|tsx):\d+:\d+\)",
        r"at (?:/[\w./-]+|node:[\w/-]+):\d+:\d+",
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



_SENSITIVE_HEADERS = {
    "x-powered-by",
    "x-aspnet-version",
    "x-aspnetmvc-version",
    "x-generator",
    "x-drupal-cache",
    "x-runtime",
    "x-request-id",
}

_PATTERNS_REQUIRING_ERROR_STATUS = frozenset({
    r"\b(?:127\.0\.0\.1|localhost)\b",
    r"\b(?:10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[0-1])\.)\d+\.\d+\b",
    r"/var/www/",
    r"/home/\w+/",
})

_STACK_TRACE_CORROBORATORS: list[re.Pattern] = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"caught exception:",
        r"traceback \(most recent call last\)",
        r"at \w[\w\.]+\([\w\.]+\.(?:java|kt):\d+\)",
        r"at \w[\w\.\[\] ]*\s*\([^)]*\.(?:js|mjs|cjs|ts|jsx|tsx):\d+:\d+\)",
        r"at (?:/[\w./-]+|node:[\w/-]+):\d+:\d+",
        r"fatal error:",
        r"warning:\s+mysql(?:i)?_",
        r"pdoexception",
        r"sqlstate\[",
        r"stack trace:",
    ]
]

_WEAK_STANDALONE = frozenset({
    r"\b(?:127\.0\.0\.1|localhost)\b",
    r"\b(?:10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[0-1])\.)\d+\.\d+\b",
    r"/var/www/",
    r"/home/\w+/",
})

_FUZZ_PAYLOADS: list[tuple[str, str]] = [
    ("'", "single quote - SQL metacharacter / template error trigger"),
    ("\x00", "null byte - triggers path/string handling errors"),
    ("A" * 8192, "8 KB oversize string - buffer / ORM field-length exception"),
    ("[]", "array notation - type mismatch where scalar expected"),
    ("-1", "negative integer - constraint violations / unsigned cast errors"),
    ("9999999999999999999", "integer overflow probe"),
    ("{{7*7}}", "template expression - SSTI errors in unprotected renderers"),
    ("<script>", "HTML/XML metacharacter - XML parser or sanitiser errors"),
    ("%00%0d%0a", "URL-encoded null + CRLF - header injection / parser errors"),
]

_DEFAULT_URL_LIMIT = 20
# Cap on how many shared attack targets are error-fuzzed (targets are already
# ranked by the AttackPlanner, so this keeps the highest-value ones).
_DEFAULT_TARGET_LIMIT = 40
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

    localhost_aliases = {"127.0.0.1", "localhost", "::1"}

    if matched_lower in localhost_aliases:
        try:
            target_addr = ipaddress.ip_address(target_lower)
            if target_addr.is_private or target_addr.is_loopback:
                return True
        except ValueError:
            pass

    if target_lower in localhost_aliases:
        try:
            matched_addr = ipaddress.ip_address(matched_lower)
            if matched_addr.is_loopback:
                return True
        except ValueError:
            pass

    return False

def _classify_body(body: str, target_host: str | None = None, http_status: int | None = None) -> tuple[SeverityLevel | None, list[str], list[str]]:
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
        if p.pattern in _PATTERNS_REQUIRING_ERROR_STATUS:
            if http_status is not None and (http_status < 400 or http_status >= 600):
                continue
        high_hits.append(p.pattern)

    if http_status is not None and high_hits and all(h in _WEAK_STANDALONE for h in high_hits):
        has_corroboration = any(pat.search(body) for pat in _STACK_TRACE_CORROBORATORS)
        if not has_corroboration:
            high_hits = []

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

def _sensitive_headers_present(headers: httpx.Headers, http_status: int | None = None) -> list[str]:
    if http_status is not None and http_status < 400:
        return []
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

def _matched_texts(body: str, matched_patterns: list[str]) -> list[str]:
    """Return the literal text that matched each pattern, for snippet centering."""
    all_patterns = _HIGH_PATTERNS + _MEDIUM_PATTERNS + _LOW_PATTERNS
    results: list[str] = []
    for pattern in all_patterns:
        if pattern.pattern in matched_patterns:
            m = pattern.search(body)
            if m:
                results.append(m.group(0))
    return results


def _build_evidence(
    url: str,
    method: str,
    status: int,
    body: str,
    matched_patterns: list[str],
    sensitive_hdrs: list[str],
    trigger: str = "",
) -> str:
    parts = [f"{method} {url} → HTTP {status}"]
    if trigger:
        parts.append(f"Trigger: {trigger}")
    if matched_patterns:
        parts.append(f"Matched: {', '.join(matched_patterns[:3])}")
    if sensitive_hdrs:
        parts.append(f"Sensitive headers: {', '.join(sensitive_hdrs)}")
    return " | ".join(parts)

def _observed_text_from_finding(finding: Finding) -> str:
    # Only evaluate the actual HTTP response body snippet returned by the server
    return finding.verification_response_snippet or ""

def _reflection_guard(
    body: str,
    payload: str | None,
    matched_patterns: list[str],
) -> list[str]:
    """Filter matched patterns that only match because the payload is reflected in the body.

    If *payload* appears literally in *body*, any pattern that matches only inside the
    reflected payload text is a false positive - the application is echoing input, not
    disclosing an error path.  This guard strips the payload from the body and re-checks
    each pattern.
    """
    if not payload or not matched_patterns or payload not in body:
        return matched_patterns

    stripped_body = body.replace(payload, "")
    surviving: list[str] = []
    for pattern_str in matched_patterns:
        try:
            pattern = re.compile(pattern_str, re.IGNORECASE)
            if pattern.search(stripped_body):
                surviving.append(pattern_str)
        except re.error:
            surviving.append(pattern_str)
    return surviving


def _reclassify_severity(matched: list[str]) -> SeverityLevel | None:
    """Re-derive the highest severity from surviving matched pattern strings."""
    if not matched:
        return None
    high_set = {p.pattern for p in _HIGH_PATTERNS}
    med_set = {p.pattern for p in _MEDIUM_PATTERNS}
    if any(p in high_set for p in matched):
        return SeverityLevel.high
    if any(p in med_set for p in matched):
        return SeverityLevel.medium
    return SeverityLevel.low


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

        # Single source of truth for attack targets. Consume the shared
        # AttackPlanner (built once per scan) — or rebuild the identical
        # AttackSurface when no planner was threaded in — instead of fabricating
        # request shapes from raw urls/forms. This is what keeps the detector from
        # POSTing to SPA client routes (``/#/score-board``) or fuzzing synthetic
        # ``mat-input-N`` DOM fields: the central builder already drops
        # route-fragment URLs, skips transport noise, dedupes, and carries the
        # real observed endpoints/params/bodies. Every other injection detector
        # already sources targets this way — exception handling now matches.
        planner = kwargs.get("attack_planner")
        if planner is not None and hasattr(planner, "targets_for"):
            targets = list(planner.targets_for(self.name))
        else:
            targets = AttackSurface.build(
                urls,
                forms,
                parameters=kwargs.get("parameters") or [],
                api_endpoints=kwargs.get("api_endpoints") or [],
                requests=kwargs.get("requests") or [],
            )
        target_limit = getattr(self.settings, "exception_target_limit", _DEFAULT_TARGET_LIMIT)
        targets = targets[:target_limit]

        async with create_scan_client(
            timeout=self.settings.request_timeout_seconds,
            follow_redirects=False,
            cookies=auth_cookies,
            headers=default_headers,
            event_hooks={"response": [make_httpx_response_logger("exception_handling", "error_probe")]},
        ) as client:

            # ── Technique 1: 404 / non-existent path probing ─────────────
            # URL-level error-template probing on real HTML pages only. Static
            # assets (js/css/txt/…) have no error surface and the crawler already
            # excluded SPA shells, so probe just the genuine pages.
            url_limit = getattr(self.settings, "exception_url_limit", _DEFAULT_URL_LIMIT)
            probe_urls = [u for u in _prioritise_urls(urls) if not is_static_asset(u)][:url_limit]

            tasks_404 = [self._probe_404(client, semaphore, url) for url in probe_urls]
            results_404 = await asyncio.gather(*tasks_404, return_exceptions=True)
            for result in results_404:
                if isinstance(result, Finding):
                    _add_finding(result, findings, seen)

            # ── Technique 2: Parameter/body error fuzzing ────────────────
            # One unified loop over the shared targets (replaces the old separate
            # GET-param / single-param / form passes that each rebuilt requests
            # from raw urls/forms). Each target's own parameter is fuzzed with the
            # error-inducing payloads via the shared ``build_request`` — the exact
            # request shape every other detector uses, against real endpoints.
            fuzz_tasks = [
                self._probe_target(client, semaphore, target, payload, desc)
                for target in targets
                for payload, desc in _FUZZ_PAYLOADS
            ]
            results_fuzz = await asyncio.gather(*fuzz_tasks, return_exceptions=True)
            for result in results_fuzz:
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

            # Apply reflection guard: the source finding's payload might be echoed
            # in the observed text, causing a pattern match that is not a real error.
            matched = _reflection_guard(observed_text, source.payload, matched)
            severity = _reclassify_severity(matched)
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
                    extra_markers=[trigger, *_matched_texts(observed_text, matched)],
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
        baseline_url = url.rstrip('/')

        if test_url == baseline_url:
            return None

        async with semaphore:
            try:
                baseline_response = await client.get(baseline_url)
                probe_response = await client.get(test_url)
            except Exception:
                return None

        if probe_response.status_code in {301, 302, 303, 307, 308}:
            return None

        finding = self._analyse_response(
            url=test_url, method="GET", status=probe_response.status_code,
            body=probe_response.text, headers=probe_response.headers,
            trigger="non-existent path probe", require_body_match=True,
            parameter=None, payload=None
        )

        # Baseline diffing: if both baseline and probe returned 200, suppress
        # patterns already present in normal page content (catch-all templates).
        if (
            finding is not None
            and probe_response.status_code == 200
            and baseline_response.status_code == 200
        ):
            _, baseline_high, baseline_med = _classify_body(
                baseline_response.text,
                target_host=_get_target_host(baseline_url),
            )
            _, probe_high, probe_med = _classify_body(
                probe_response.text,
                target_host=_get_target_host(test_url),
            )
            baseline_set = set(baseline_high + baseline_med)
            probe_set = set(probe_high + probe_med)
            if not (probe_set - baseline_set):
                return None

        # A 404 response to a non-existent path is expected behaviour.
        # Only report if the body reveals real error internals (Medium+).
        if finding is not None and probe_response.status_code == 404 and finding.severity == SeverityLevel.low:
            return None
        return finding

    async def _probe_target(
        self,
        client: httpx.AsyncClient,
        semaphore: asyncio.Semaphore,
        target: AttackTarget,
        payload: str,
        payload_desc: str,
    ) -> Finding | None:
        """Fuzz one shared ``AttackTarget``'s parameter with an error-inducing
        payload and analyse the response for verbose-error disclosure.

        The concrete request is built by ``AttackTarget.build_request`` — the same
        shared builder every detector uses — so the injection point, location
        (query/form/json/path), method, headers and cookies are exactly what the
        crawler observed. No SPA client-route URL can appear here because the
        central AttackSurface already dropped route-fragment targets.
        """
        try:
            prepared = target.build_request(payload)
        except Exception:
            return None

        request_kwargs: dict[str, object] = {}
        if prepared.params:
            request_kwargs["params"] = prepared.params
        if prepared.json_body is not None:
            request_kwargs["json"] = prepared.json_body
        elif prepared.data is not None:
            request_kwargs["data"] = prepared.data
        if prepared.headers:
            request_kwargs["headers"] = prepared.headers
        if prepared.cookies:
            request_kwargs["cookies"] = prepared.cookies

        async with semaphore:
            try:
                response = await client.request(prepared.method, prepared.url, **request_kwargs)
            except Exception:
                return None

        if response.status_code in {301, 302, 303, 307, 308}:
            return None

        return self._analyse_response(
            url=str(getattr(response, "url", prepared.url)),
            method=prepared.method,
            status=response.status_code,
            body=response.text,
            headers=response.headers,
            trigger=f"{target.location.value} fuzz - {payload_desc}",
            parameter=target.parameter,
            payload=payload,
        )

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

        severity, high_hits, med_hits = _classify_body(body, target_host=_get_target_host(url), http_status=status)
        matched = high_hits or med_hits

        # Apply reflection guard: if the matched pattern only appears because the
        # fuzz payload is echoed back in the response body, discard the match.
        matched = _reflection_guard(body, payload, matched)
        severity = _reclassify_severity(matched)

        sensitive_hdrs = _sensitive_headers_present(headers, http_status=status)

        # A response is "verbose error handling" only when its BODY discloses
        # internal detail — a stack trace, server file path, SQL echo, or a
        # framework exception (all captured by the pattern sets). A bare error
        # status with a generic message (``{"message":"internal error"}``) leaks
        # nothing actionable and is NOT a finding, even when the response carries
        # tech-fingerprint headers (``x-powered-by`` …): those are a host-global
        # concern owned by the security-header detector, not a per-endpoint
        # verbose-error signal. Reporting one such 500 per fuzzed parameter was
        # the primary source of low-value error-handling noise.
        if not matched:
            return None

        if not severity:
            severity = SeverityLevel.low

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
                extra_markers=[trigger, *_matched_texts(body, matched)],
            ),
        )

def _prioritise_urls(urls: list[str]) -> list[str]:
    return sorted(urls, key=lambda u: (0 if "?" in u else 1))

def _add_finding(finding: Finding, findings: list[Finding], seen: set[tuple]) -> None:
    key = _finding_key(finding.url, finding.vuln_type, finding.severity)
    if key not in seen:
        seen.add(key)
        findings.append(finding)
