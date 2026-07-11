"""
Response Analyzer: Reusable utilities for comparing responses and detecting evidence of exploitation.

Provides functions for:
- Body similarity comparison
- Timing analysis
- Reflection detection
- Database error detection
- Command output detection
- Differential analysis
"""

import html
import re
from dataclasses import dataclass
from difflib import SequenceMatcher
from typing import Optional
from uuid import uuid4


@dataclass
class ResponseData:
    """Encapsulates HTTP response metadata."""
    status_code: int
    headers: dict[str, str]
    body: str
    response_time_ms: float
    request_snippet: str | None = None
    response_snippet: str | None = None

    @property
    def not_tested(self) -> bool:
        """True when the probe was never sent (governor budget deny).

        ``status_code == -1`` is the "not tested" sentinel set by the request
        governor. Detectors/verifiers must treat this as UNTESTED (no finding,
        no negative verdict), distinct from a real ``0`` (connection error).
        """
        return self.status_code == -1


# Baseline status codes that mean the target is unreachable/unauthorized as sent,
# so there is no exploitable differential to measure. When the UNMODIFIED baseline
# returns one of these, firing the full payload matrix only produces 4xx noise
# (observed as ~27% of scan traffic against Juice Shop). 401/403 = auth wall,
# 404 = dead endpoint or non-existent object, 405 = wrong method for this URL.
# Deliberately excludes 400 (a validation error an injection may still flip) and
# 500 (error-based injection's signal), and login-style flows are unaffected
# because their baseline is a healthy 200 — only the deliberate false-payload
# returns 401.
_DEAD_BASELINE_STATUSES = frozenset({401, 403, 404, 405})


def is_dead_baseline(response: "ResponseData | None") -> bool:
    """True when an unmodified baseline response is structurally unexploitable.

    Used by injection verifiers to abort a target before spending the payload
    budget on a URL that returned 401/403/404/405 to the plain baseline. A
    ``None`` or governor-denied (``not_tested``) baseline is NOT dead — the probe
    simply never ran, which is handled separately.
    """
    if response is None or response.not_tested:
        return False
    return response.status_code in _DEAD_BASELINE_STATUSES


@dataclass
class DifferentialAnalysis:
    """Results of comparing baseline vs injected response."""
    status_code_changed: bool
    body_length_changed: bool
    body_similarity: float  # 0-1, where 1 is identical
    keywords_appeared: list[str]
    keywords_disappeared: list[str]
    error_patterns_detected: list[str]
    reflection_detected: bool
    reflection_locations: list[int]  # Byte offsets where payload was reflected
    is_significant_change: bool


class ResponseAnalyzer:
    """Analyzes responses to detect evidence of injection vulnerability exploitation."""

    # -----------------------------------------------------------------------
    # Database Error Patterns
    # -----------------------------------------------------------------------

    # MySQL error patterns
    MYSQL_ERRORS = re.compile(
        r"(mysql|syntax error|sql syntax|table.*not exist|unknown column|"
        r"column.*not recognized|constraint.*foreign key|"
        r"\"mysql\"|'mysql'|mysql_fetch|mysql_error)",
        re.IGNORECASE
    )

    # MSSQL error patterns
    MSSQL_ERRORS = re.compile(
        r"(mssql|sqlserver|sql server|server error|conversion failed|"
        r"incorrect syntax|object.*not found|permission denied|"
        r"sqlexception|system\.data\.sqlclient)",
        re.IGNORECASE
    )

    # PostgreSQL error patterns
    POSTGRES_ERRORS = re.compile(
        r"(postgresql|postgres|psycopg|pgerror|error.*line|"
        r"relation.*does not exist|column.*does not exist|"
        r"syntax error|unexpected end of input)",
        re.IGNORECASE
    )

    # Oracle error patterns
    ORACLE_ERRORS = re.compile(
        r"(oracle|ora-\d{5}|not a valid month|invalid datatype|"
        r"table or view does not exist|column ambiguously defined)",
        re.IGNORECASE
    )

    # SQLite error patterns
    SQLITE_ERRORS = re.compile(
        r"(sqlite|sql error|near.*syntax error|table.*already exists|"
        r"no such table|no such column)",
        re.IGNORECASE
    )

    # Generic SQL errors
    GENERIC_SQL_ERRORS = re.compile(
        r"(database error|db error|sql exception|jdbc|odbc|"
        r"warning.*mysql|fatal error)",
        re.IGNORECASE
    )

    STRONG_EVIDENCE_MARKERS = [
        # SQL/database proof
        MYSQL_ERRORS,
        MSSQL_ERRORS,
        POSTGRES_ERRORS,
        ORACLE_ERRORS,
        SQLITE_ERRORS,
        GENERIC_SQL_ERRORS,
        # File inclusion proof (local)
        re.compile(r"(root:x:0:0:|daemon:x:|bin:x:|\[boot loader\]|\[fonts\]|/etc/passwd|win\.ini)", re.I),
        # PHP filter / encoded source disclosure proof
        re.compile(r"(PD9waH|aW5jbHVkZ|cmVxdWlyZ|ZnVuY3Rpb24)", re.I),
        # Remote file inclusion proof (example.com content fingerprints)
        re.compile(
            r"(Example Domain|without needing permission|in documentation examples|"
            r"illustrative examples in documents|without prior coordination)",
            re.I,
        ),
        # Per-request canaries are much stronger than generic HTML tags.
        re.compile(r"(sentryprobe_[a-f0-9]{8})", re.I),
        # Command injection proof
        re.compile(r"(uid=\d+.*gid=\d+|nt authority|active connections|/bin/\w+|/usr/bin|c:\\windows)", re.I | re.M),
        # SSRF/internal service proof
        re.compile(r"(localhost|127\.0\.0\.1|169\.254\.169\.254|metadata service|internal host)", re.I),
        # CSRF/auth workflow proof
        re.compile(r"(updated|saved|success|changed|csrf|token|forbidden|unauthorized|access denied)", re.I),
    ]
    GENERIC_EVIDENCE_MARKERS = [
        re.compile(r"(<script|onerror\s*=|onload\s*=|javascript:)", re.I),
    ]

    # -----------------------------------------------------------------------
    # Command Output Patterns
    # -----------------------------------------------------------------------

    # Unix/Linux command output patterns
    UNIX_PATTERNS = {
        r"uid=\d+.*gid=\d+": "id output",
        r"(?:uid|gid)=\d+\((?:root|www-data|nobody|nginx|apache)\)": "Unix username",
        r"^total \d+": "ls -la output",
        r"/bin/\w+|/usr/bin|/sbin": "Unix path",
        r"Linux.*\d+\.\d+": "uname output",
        r"eth\d+|lo|wlan\d+": "ifconfig interface",
    }

    # Windows command output patterns
    WINDOWS_PATTERNS = {
        r"C:\\(?:Windows|Users|Program Files)": "Windows path",
        r"NT AUTHORITY|BUILTIN": "Windows account",
        r"inet addr:|IPv4 Address": "Windows ipconfig",
        r"Active Connections": "netstat output",
    }

    # -----------------------------------------------------------------------
    # Reflection and Injection Detection
    # -----------------------------------------------------------------------

    @staticmethod
    def generate_probe_canary() -> str:
        """Return a unique per-request canary for unambiguous reflection proof."""
        return f"sentryprobe_{uuid4().hex[:8]}"

    @staticmethod
    def verify_reflection(
        payload: str,
        response_body: str,
        *,
        baseline_body: str | None = None,
        canary: str | None = None,
        min_substring_len: int = 6,
    ) -> tuple[bool, dict]:
        """
        Confirm that a payload (or its canary) was reflected by *this* request.

        Rejects matches that already existed in the pre-test baseline body.
        For XSS payloads, requires a meaningful unencoded substring of the
        injected content - not merely a generic tag left by an earlier test.
        """
        evidence: dict = {
            "canary": canary,
            "canary_verified": False,
            "payload_substring_verified": False,
            "pre_existing_in_baseline": False,
        }

        if canary:
            if baseline_body and canary in baseline_body:
                evidence["pre_existing_in_baseline"] = True
                evidence["reason"] = "canary_pre_existing_in_baseline"
                return False, evidence
            if canary not in response_body:
                evidence["reason"] = "canary_not_in_response"
                return False, evidence
            evidence["canary_verified"] = True

        probe = canary or payload
        if not probe:
            evidence["reason"] = "empty_probe"
            return False, evidence

        requires_raw = ResponseAnalyzer._requires_unencoded_match(payload)

        escaped = re.escape(probe)
        if re.search(escaped, response_body):
            if baseline_body and re.search(escaped, baseline_body):
                evidence["pre_existing_in_baseline"] = True
                evidence["reason"] = "probe_pre_existing_in_baseline"
                return False, evidence
            evidence["payload_substring_verified"] = True
            evidence["encoding"] = "raw"
            return True, evidence

        decoded_body = html.unescape(response_body)
        if not requires_raw and re.search(escaped, decoded_body):
            if baseline_body and re.search(escaped, html.unescape(baseline_body)):
                evidence["pre_existing_in_baseline"] = True
                evidence["reason"] = "probe_pre_existing_in_baseline_decoded"
                return False, evidence
            evidence["payload_substring_verified"] = True
            evidence["encoding"] = "html_decoded"
            return True, evidence

        meaningful = ResponseAnalyzer._meaningful_payload_marker(payload, min_substring_len)
        if meaningful and requires_raw and canary is None and "<" not in meaningful:
            meaningful = None

        if meaningful:
            body_variants = [("raw", response_body)]
            if not requires_raw:
                body_variants.append(("html_decoded", decoded_body))

            for label, body_variant in body_variants:
                if meaningful in body_variant:
                    baseline_variant = baseline_body or ""
                    if baseline_variant and meaningful in (
                        baseline_variant if label == "raw" else html.unescape(baseline_variant)
                    ):
                        evidence["pre_existing_in_baseline"] = True
                        evidence["reason"] = "marker_pre_existing_in_baseline"
                        return False, evidence
                    if label == "html_decoded" and requires_raw:
                        evidence["reason"] = "marker_html_encoded"
                        return False, evidence
                    evidence["payload_substring_verified"] = True
                    evidence["encoding"] = label
                    evidence["matched_marker"] = meaningful
                    return True, evidence

        evidence["reason"] = "no_verified_reflection"
        return False, evidence

    @staticmethod
    def _requires_unencoded_match(payload: str) -> bool:
        """XSS/HTML payloads must appear unencoded in the raw response body."""
        lowered = payload.lower()
        return (
            "<" in payload
            or ">" in payload
            or "onerror" in lowered
            or "onload" in lowered
            or lowered.startswith("javascript:")
        )

    @staticmethod
    def _meaningful_payload_marker(payload: str, min_len: int) -> str | None:
        """Pick a distinctive, unencoded substring from an XSS/SQLi payload."""
        candidates: list[str] = []
        for match in re.finditer(r"<script[^>]*>([^<]+)</script>", payload, re.I):
            inner = match.group(1).strip()
            if len(inner) >= min_len:
                candidates.append(inner)
        for match in re.finditer(r"on\w+\s*=\s*([^>\s\"']+)", payload, re.I):
            handler = match.group(1).strip()
            if len(handler) >= min_len:
                candidates.append(handler)
        if "UNION SELECT" in payload.upper():
            for match in re.finditer(r"'([^']{4,})'", payload):
                candidates.append(match.group(1))
        stripped = payload.strip()
        if len(stripped) >= min_len:
            candidates.append(stripped[: max(min_len, min(24, len(stripped)))])

        for candidate in candidates:
            if candidate and not candidate.startswith("&"):
                return candidate
        return None

    @staticmethod
    def detect_payload_reflection(
        payload: str,
        response_body: str,
        threshold: float = 0.8
    ) -> tuple[bool, list[int]]:
        """
        Detect if payload is reflected in response body.

        Args:
            payload: The injected payload
            response_body: The response HTML/content
            threshold: Minimum similarity (0-1) to consider as reflection

        Returns:
            (is_reflected, list of byte offsets where payload appears)
        """
        locations = []
        payload_lower = payload.lower()
        response_lower = response_body.lower()

        # Exact match first
        offset = 0
        while True:
            pos = response_lower.find(payload_lower, offset)
            if pos == -1:
                break
            locations.append(pos)
            offset = pos + 1

        # If exact match found, high confidence reflection
        if locations:
            return True, locations

        # Fuzzy matching for partial/encoded reflections
        chunks = [payload[i:i+5] for i in range(0, len(payload), 5)]
        matched_chunks = 0
        for chunk in chunks:
            if chunk.lower() in response_lower:
                matched_chunks += 1

        if matched_chunks / len(chunks) >= threshold:
            return True, []

        return False, locations

    # -----------------------------------------------------------------------
    # Body Similarity Analysis
    # -----------------------------------------------------------------------

    @staticmethod
    def calculate_similarity(text1: str, text2: str) -> float:
        """
        Calculate similarity between two strings using SequenceMatcher.

        Args:
            text1: First string
            text2: Second string

        Returns:
            Similarity score (0-1, where 1 is identical)
        """
        if not text1 and not text2:
            return 1.0
        if not text1 or not text2:
            return 0.0

        matcher = SequenceMatcher(None, text1, text2)
        return matcher.ratio()

    @staticmethod
    def extract_differences(baseline: str, injected: str, context_chars: int = 100) -> list[str]:
        """
        Extract segments that differ between baseline and injected responses.

        Args:
            baseline: Baseline response body
            injected: Injected response body
            context_chars: Characters of context around differences

        Returns:
            List of difference segments with context
        """
        matcher = SequenceMatcher(None, baseline, injected)
        differences = []

        for tag, i1, i2, j1, j2 in matcher.get_opcodes():
            if tag != "equal":
                start = max(0, i1 - context_chars)
                end = min(len(baseline), i2 + context_chars)
                diff_segment = baseline[start:end]
                differences.append(f"[{tag.upper()}] {diff_segment[:200]}")

        return differences

    # -----------------------------------------------------------------------
    # Timing Analysis
    # -----------------------------------------------------------------------

    @staticmethod
    def calculate_timing_statistics(
        response_times: list[float],
    ) -> dict[str, float]:
        """
        Calculate statistical measures for timing analysis.

        Args:
            response_times: List of response times in milliseconds

        Returns:
            Dict with mean, median, stdev, min, max
        """
        if not response_times:
            return {"mean": 0, "median": 0, "stdev": 0, "min": 0, "max": 0}

        sorted_times = sorted(response_times)
        n = len(sorted_times)

        mean = sum(response_times) / n
        median = sorted_times[n // 2]
        variance = sum((x - mean) ** 2 for x in response_times) / n
        stdev = variance ** 0.5

        return {
            "mean": mean,
            "median": median,
            "stdev": stdev,
            "min": min(response_times),
            "max": max(response_times),
        }

    @staticmethod
    def is_timing_significant(
        baseline_times: list[float],
        injected_times: list[float],
        threshold_ms: float = 2000.0,
        min_stddev: float = 0.5
    ) -> tuple[bool, dict]:
        """
        Determine if timing difference is statistically significant.

        Args:
            baseline_times: Response times for normal requests
            injected_times: Response times for requests with sleep payload
            threshold_ms: Minimum difference (ms) to consider significant
            min_stddev: Minimum standard deviation to consider legitimate variation

        Returns:
            (is_significant, analysis_dict)
        """
        baseline_stats = ResponseAnalyzer.calculate_timing_statistics(baseline_times)
        injected_stats = ResponseAnalyzer.calculate_timing_statistics(injected_times)

        mean_diff = injected_stats["mean"] - baseline_stats["mean"]
        is_significant = mean_diff >= threshold_ms

        analysis = {
            "baseline_mean": baseline_stats["mean"],
            "injected_mean": injected_stats["mean"],
            "diff_ms": mean_diff,
            "is_significant": is_significant,
            "baseline_stats": baseline_stats,
            "injected_stats": injected_stats,
        }

        return is_significant, analysis

    # -----------------------------------------------------------------------
    # Error Detection
    # -----------------------------------------------------------------------

    @staticmethod
    def detect_sql_errors(response_body: str) -> list[str]:
        """
        Detect SQL error patterns in response.

        Returns:
            List of error types detected
        """
        errors = []

        if ResponseAnalyzer.MYSQL_ERRORS.search(response_body):
            errors.append("MySQL")
        if ResponseAnalyzer.MSSQL_ERRORS.search(response_body):
            errors.append("MSSQL")
        if ResponseAnalyzer.POSTGRES_ERRORS.search(response_body):
            errors.append("PostgreSQL")
        if ResponseAnalyzer.ORACLE_ERRORS.search(response_body):
            errors.append("Oracle")
        if ResponseAnalyzer.SQLITE_ERRORS.search(response_body):
            errors.append("SQLite")
        if ResponseAnalyzer.GENERIC_SQL_ERRORS.search(response_body):
            errors.append("Generic SQL")

        return errors

    @staticmethod
    def build_evidence_response_snippet(
        *,
        status_code: int,
        reason_phrase: str = "",
        headers: dict[str, str] | None = None,
        body: str = "",
        payload: str = "",
        extra_markers: list[str] | None = None,
        max_body_chars: int = 1200,
        context_chars: int = 450,
        include_headers: bool = False,
    ) -> str:
        """Build a response snippet centered around proof, not byte zero.

        The report should show the evidence that made the verifier believe the
        finding is real. For long HTML pages, that means selecting an excerpt
        around SQL errors, canaries, command output, file contents, CSRF status
        text, or the injected payload instead of taking the first N chars.
        """
        headers = headers or {}
        body = body or ""
        header_text = f"HTTP/1.1 {status_code} {reason_phrase}".rstrip() if include_headers else ""
        if header_text and headers:
            safe_headers = []
            for key, value in headers.items():
                if key.lower() in {"set-cookie", "cookie", "authorization"}:
                    value = "[redacted]"
                safe_headers.append(f"{key}: {value}")
            header_text += "\n" + "\n".join(safe_headers)

        prefix_text = f"{header_text}\n\n" if header_text else ""

        if not body:
            return header_text

        # Primary: find the actual payload in the response body
        payload_positions: list[int] = []
        if payload:
            pos = body.lower().find(str(payload).lower())
            if pos >= 0:
                payload_positions.append(pos)

        # Module/parameter/phase markers are contextual labels that may
        # accidentally match generic page text (e.g. parameter "name" matching
        # an HTML attribute). Only use them as a last resort.
        extra_positions: list[int] = []
        for marker in (extra_markers or []):
            if marker:
                pos = body.lower().find(str(marker).lower())
                if pos >= 0:
                    extra_positions.append(pos)

        proof_positions: list[int] = []
        proof_positions.extend(ResponseAnalyzer._encoded_source_positions(body))
        for pattern in ResponseAnalyzer.STRONG_EVIDENCE_MARKERS:
            match = pattern.search(body)
            if match:
                proof_positions.append(match.start())

        generic_positions: list[int] = []
        for pattern in ResponseAnalyzer.GENERIC_EVIDENCE_MARKERS:
            match = pattern.search(body)
            if match:
                generic_positions.append(match.start())

        if ResponseAnalyzer._is_xss_like_payload(payload):
            focus_positions = payload_positions or generic_positions or proof_positions or extra_positions
        else:
            focus_positions = proof_positions or payload_positions or generic_positions or extra_positions
        if focus_positions:
            focus = min(focus_positions)
            start = max(0, focus - context_chars)
            end = min(len(body), start + max_body_chars)
            if end - focus < min(context_chars, max_body_chars // 3):
                start = max(0, end - max_body_chars)
            excerpt = body[start:end]
            prefix = "[...snip before proof...]\n" if start > 0 else ""
            suffix = "\n[...snip after proof...]" if end < len(body) else ""
            return f"{prefix_text}{prefix}{excerpt}{suffix}"

        excerpt = body[:max_body_chars]
        suffix = "\n[...snip after excerpt...]" if len(body) > max_body_chars else ""
        return f"{prefix_text}{excerpt}{suffix}"

    @staticmethod
    def _is_xss_like_payload(payload: str) -> bool:
        lowered = (payload or "").lower()
        return any(token in lowered for token in ("<script", "<svg", "<img", "onerror", "onload", "javascript:"))

    @staticmethod
    def _encoded_source_positions(body: str) -> list[int]:
        positions: list[int] = []
        source_markers = ("pd9wah", "aw5jbhvkz", "cmvxdwlyz", "znvuy3rpb24")
        for match in re.finditer(r"[A-Za-z0-9+/]{40,}={0,2}", body or ""):
            candidate = match.group(0)
            lowered = candidate.lower()
            marker_offsets = [lowered.find(marker) for marker in source_markers if marker in lowered]
            if marker_offsets:
                positions.append(match.start() + min(marker_offsets))
            elif len(set(candidate)) >= 12:
                positions.append(match.start())
        return positions

    @staticmethod
    def detect_command_output(response_body: str) -> tuple[bool, list[str], list[str]]:
        """
        Detect Unix/Windows command output patterns.

        Returns:
            (output_detected, unix_patterns_found, windows_patterns_found)
        """
        unix_found = []
        windows_found = []

        for pattern, name in ResponseAnalyzer.UNIX_PATTERNS.items():
            if re.search(pattern, response_body, re.MULTILINE | re.IGNORECASE):
                unix_found.append(pattern)

        for pattern, name in ResponseAnalyzer.WINDOWS_PATTERNS.items():
            if re.search(pattern, response_body, re.MULTILINE | re.IGNORECASE):
                windows_found.append(pattern)

        detected = len(unix_found) > 0 or len(windows_found) > 0
        return detected, unix_found, windows_found

    # -----------------------------------------------------------------------
    # phpinfo / Debug Page Detection
    # -----------------------------------------------------------------------

    # Markers that uniquely identify a phpinfo() output page.
    _PHPINFO_MARKERS = (
        "phpinfo()",
        "php variables",
        "php license",
        "configuration file (php.ini) path",
        "php credits",
        "php version",
    )

    # Generic debug/environment dump markers - require 3+ co-occurring to flag.
    _DEBUG_ENV_MARKERS = (
        "environment variables",
        "server_software",
        "http_host",
        "document_root",
        "request_uri",
        "server_name",
        "server_addr",
    )

    @staticmethod
    def is_phpinfo_or_debug_page(body: str) -> bool:
        """Detect if a response body is a phpinfo() page or debug environment dump.

        phpinfo pages echo every request parameter in their output, causing
        injection detectors to see 'reflection' when it's just phpinfo
        rendering the query string.  Verifiers should skip testing on these
        endpoints entirely.

        Returns True when:
          - 2+ phpinfo-specific markers are found, OR
          - 3+ generic debug/environment markers co-occur.
        """
        if not body:
            return False

        lowered = body.lower()

        # Fast path: phpinfo-specific markers
        phpinfo_hits = sum(1 for m in ResponseAnalyzer._PHPINFO_MARKERS if m in lowered)
        if phpinfo_hits >= 2:
            return True

        # Slower path: generic debug/environment dump
        debug_hits = sum(1 for m in ResponseAnalyzer._DEBUG_ENV_MARKERS if m in lowered)
        if debug_hits >= 3:
            return True

        return False

    @staticmethod
    def is_request_metadata_reflection(body: str, marker: str) -> bool:
        """Detect reflection inside request/environment dump sections.

        Debug pages, diagnostics pages, and server environment dumps often echo
        every query parameter. A canary appearing there is not proof of SQL data
        extraction, XSS execution, or file access.
        """
        if not body or not marker:
            return False
        lowered = body.lower()
        marker_lower = marker.lower()
        pos = lowered.find(marker_lower)
        if pos < 0:
            return False
        window = lowered[max(0, pos - 500): pos + len(marker_lower) + 500]
        request_dump_markers = (
            "query_string",
            "request_uri",
            "script_name",
            "php_self",
            "http_get_vars",
            "$_get",
            "_get",
            "request parameters",
            "request parameter",
            "environment variables",
            "server variables",
            "variable",
            "value",
        )
        return sum(1 for marker_text in request_dump_markers if marker_text in window) >= 2

    # -----------------------------------------------------------------------
    # Differential Analysis (Main Method)
    # -----------------------------------------------------------------------

    @staticmethod
    def analyze_differential(
        baseline: ResponseData,
        injected: ResponseData,
        payload: str,
        significance_keywords: Optional[list[str]] = None
    ) -> DifferentialAnalysis:
        """
        Comprehensive analysis comparing baseline vs injected response.

        Args:
            baseline: Baseline response (normal request)
            injected: Response after injection
            payload: The payload that was injected
            significance_keywords: Keywords that indicate vulnerability if changed

        Returns:
            DifferentialAnalysis object with comprehensive results
        """
        significance_keywords = significance_keywords or []

        # Basic changes
        status_changed = baseline.status_code != injected.status_code
        length_changed = len(baseline.body) != len(injected.body)
        similarity = ResponseAnalyzer.calculate_similarity(baseline.body, injected.body)

        # Reflection analysis
        payload_reflected, reflection_locations = ResponseAnalyzer.detect_payload_reflection(
            payload, injected.body
        )

        # Error detection
        error_patterns = ResponseAnalyzer.detect_sql_errors(injected.body)
        baseline_errors = ResponseAnalyzer.detect_sql_errors(baseline.body)
        new_errors = [e for e in error_patterns if e not in baseline_errors]

        # Keyword tracking
        keywords_appeared = []
        keywords_disappeared = []

        for keyword in significance_keywords:
            in_baseline = keyword.lower() in baseline.body.lower()
            in_injected = keyword.lower() in injected.body.lower()

            if not in_baseline and in_injected:
                keywords_appeared.append(keyword)
            elif in_baseline and not in_injected:
                keywords_disappeared.append(keyword)

        # Determine significance
        # Note: We do NOT include payload_reflected by itself. UNION payloads are often naturally
        # reflected (e.g. in search fields or button values). We require structural changes
        # (status code, significant length difference, similarity drop, errors, or keywords).
        is_significant = (
            status_changed
            or (length_changed and abs(len(injected.body) - len(baseline.body)) > 50)
            or similarity < 0.9
            or len(new_errors) > 0
            or len(keywords_appeared) > 0
        )

        return DifferentialAnalysis(
            status_code_changed=status_changed,
            body_length_changed=length_changed,
            body_similarity=similarity,
            keywords_appeared=keywords_appeared,
            keywords_disappeared=keywords_disappeared,
            error_patterns_detected=new_errors,
            reflection_detected=payload_reflected,
            reflection_locations=reflection_locations,
            is_significant_change=is_significant,
        )

    # -----------------------------------------------------------------------
    # Boolean-Based Blind SQLi Detection
    # -----------------------------------------------------------------------

    @staticmethod
    def analyze_boolean_differential(
        baseline: ResponseData,
        true_payload_response: ResponseData,
        false_payload_response: ResponseData,
    ) -> tuple[bool, dict]:
        """
        Analyze boolean-based blind SQL injection indicators.

        Compares:
        - Baseline response (normal)
        - True condition response (payload that should evaluate to true)
        - False condition response (payload that should evaluate to false)

        Returns:
            (is_vulnerable, analysis_dict)
        """
        analysis = {
            "baseline_length": len(baseline.body),
            "true_length": len(true_payload_response.body),
            "false_length": len(false_payload_response.body),
            "baseline_similarity_to_true": ResponseAnalyzer.calculate_similarity(
                baseline.body, true_payload_response.body
            ),
            "baseline_similarity_to_false": ResponseAnalyzer.calculate_similarity(
                baseline.body, false_payload_response.body
            ),
            "true_vs_false_similarity": ResponseAnalyzer.calculate_similarity(
                true_payload_response.body, false_payload_response.body
            ),
        }

        # Key indicator: true and false responses should differ more than baseline differs from either
        true_false_diff = analysis["true_vs_false_similarity"]
        baseline_to_true = analysis["baseline_similarity_to_true"]
        baseline_to_false = analysis["baseline_similarity_to_false"]

        # Vulnerable if: true and false are different, but one matches baseline
        is_vulnerable = (
            true_false_diff < 0.95  # True and false responses differ
            and (
                (baseline_to_true > 0.8 and baseline_to_false < 0.8)  # Baseline matches true
                or (baseline_to_false > 0.8 and baseline_to_true < 0.8)  # Baseline matches false
            )
        )

        return is_vulnerable, analysis
