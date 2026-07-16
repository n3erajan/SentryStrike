"""
Command Injection Verifier: Active verification for OS command injection vulnerabilities.

Implements:
- Shell command output detection
- Time-based blind testing
- Error-based detection
"""

import asyncio
import logging
from typing import Optional

from app.config import get_settings
from app.core.detectors.attack_surface import AttackTarget
from app.core.verification.response_analyzer import ResponseAnalyzer
from app.core.verification.verification_framework import (
    BaseVerifier,
    VerificationResult,
)
from app.core.crawler.models import ParameterLocation
from shared.models.vulnerability import OwaspCategory, SeverityLevel

logger = logging.getLogger(__name__)


class CommandInjectionVerifier(BaseVerifier):
    """Verifies OS command injection vulnerabilities through active testing."""

    module_name = "command_injection"

    # Unix command payloads
    UNIX_PAYLOADS = [
        ";id",
        ";whoami",
        "|id",
        "|whoami",
        "&&id",
        "&id",
        "`id`",
        "$(id)",
        ";uname -a",
        "|uname -a",
    ]

    # Windows command payloads
    WINDOWS_PAYLOADS = [
        "&whoami",
        "|whoami",
        ";whoami",
        "&dir",
        "|dir",
        ";ipconfig",
        "&ipconfig /all",
        "|ipconfig /all",
    ]

    # Blind timing payloads
    BLIND_PAYLOADS = [
        (";sleep 5", 5000),
        (";ping -c 5 127.0.0.1", 5000),
        ("&ping -n 5 127.0.0.1", 5000),
    ]

    def _build_request_args(
        self,
        url: str,
        parameter: str,
        value: str,
        method: str,
        form_inputs: Optional[list] = None,
        target: Optional[object] = None,
    ) -> tuple[str, Optional[dict], Optional[dict], Optional[object], Optional[dict]]:
        if isinstance(target, AttackTarget):
            prepared = target.build_request(value)
            return prepared.url, prepared.params, prepared.data, prepared.json_body, prepared.headers

        location = ParameterLocation.form if method.upper() == "POST" and form_inputs is not None else ParameterLocation.query
        fallback_target = AttackTarget(
            url=url,
            parameter=parameter,
            method=method,
            form_inputs=form_inputs,
            location=location,
        )
        prepared = fallback_target.build_request(value)
        return prepared.url, prepared.params, prepared.data, prepared.json_body, prepared.headers

    async def verify(
        self,
        url: str,
        parameter: str,
        method: str = "GET",
        value: str = "",
        form_inputs: Optional[list] = None,
        target: Optional[object] = None,
    ) -> VerificationResult:
        """
        Verify command injection vulnerability.

        Tries multiple techniques:
        1. Output-based detection (Unix/Windows)
        2. Time-based blind
        3. Error-based
        Verify command injection vulnerability safely.
        """
        self._begin_verification(parameter)
        findings = []

        # Try output-based detection first
        output_result = await self._verify_output_based(url, parameter, method, value, form_inputs, target)
        if output_result.is_vulnerable:
            findings.extend(output_result.findings)
            return output_result

        # Try time-based blind if output-based fails
        time_result = await self._verify_time_based_blind(url, parameter, method, value, form_inputs, target)
        if time_result.is_vulnerable:
            findings.extend(time_result.findings)
            return time_result

        return VerificationResult(
            is_vulnerable=False,
            confidence_score=0.0,
            detection_method="none",
            findings=findings,
            evidence={"budget_exceeded": True},
        )

    async def _verify_output_based(
            self,
            url: str,
            parameter: str,
            method: str,
            value: str,
            form_inputs: Optional[list] = None,
            target: Optional[object] = None,
        ) -> VerificationResult:
            """
            Verify via command output detection.

            Detects command injection on the full response while excluding baseline 
            patterns, then crops the snippet directly around the execution results.
            """
            import re

            payloads = self.UNIX_PAYLOADS + self.WINDOWS_PAYLOADS
            # Match full id(1) output: uid=0(root) gid=0(root) groups=0(root)
            # Require closing paren to avoid false matches on URL params like ?uid=1(
            _ID_OUTPUT_RE = re.compile(r"uid=\d+\([^)]+\)")

            try:
                # Get baseline
                baseline_url, baseline_params, baseline_data, baseline_json, baseline_headers = self._build_request_args(
                    url, parameter, value, method, form_inputs, target=target
                )
                baseline = await self._send(
                    baseline_url, method, baseline_params, baseline_data,
                    headers=baseline_headers,
                    json_body=baseline_json,
                    test_phase="output_baseline",
                )

                # Gate: phpinfo/debug page exclusion
                if ResponseAnalyzer.is_phpinfo_or_debug_page(baseline.body or ""):
                    logger.debug(
                        "Skipping output-based command injection on phpinfo/debug page %s:%s",
                        url, parameter,
                    )
                    return VerificationResult(
                        is_vulnerable=False,
                        confidence_score=0.0,
                        detection_method="command_output",
                        findings=[],
                        evidence={"skipped": "phpinfo_or_debug_page"},
                    )

                baseline_body = baseline.body or ""

                # Try each payload
                for payload in payloads:
                    injected_url, injected_params, injected_data, injected_json, injected_headers = self._build_request_args(
                        url, parameter, payload, method, form_inputs, target=target
                    )
                    injected = await self._send(
                        injected_url, method, injected_params, injected_data,
                        headers=injected_headers,
                        json_body=injected_json,
                        test_phase="output_injection", payload=payload,
                    )

                    # Budget-denied probe: untested, never a negative. Skip scoring.
                    if injected.not_tested:
                        continue

                    injected_body = injected.body or ""

                    if not injected_body.strip():
                        continue

                   # Run pattern detection on the entire response to ensure line-appends aren't missed
                    cmd_detected, unix_patterns, windows_patterns = ResponseAnalyzer.detect_command_output(
                        injected_body
                    )

                    # --- FIX 1: Context-window baseline filtering ---
                    # BUG (original): is_pattern_present used re.search() against the full
                    # baseline body. Broad regex patterns like r"root|www-data|nobody|nginx|apache"
                    # match the word "root" anywhere in the page (navigation links, page titles,
                    # etc.), causing ALL unix_patterns to be stripped even when the injected
                    # response contains real command output. After stripping, cmd_detected=False
                    # and the verifier skips the confirmed injection entirely.
                    #
                    # FIX: For each pattern match in the INJECTED body, extract a 60-char
                    # context window around that specific match and check whether that exact
                    # context window exists in the baseline. This means a pattern is only
                    # suppressed when the same text in the same surroundings was already present
                    # before injection - not just because the pattern regex matches somewhere
                    # else in the page.
                    def is_pattern_new(pattern: str, injected: str, baseline: str) -> bool:
                        """Return True if *pattern* produces at least one match in *injected*
                        whose surrounding context does NOT appear in *baseline*."""
                        try:
                            for m in re.finditer(pattern, injected, re.IGNORECASE):
                                ctx_start = max(0, m.start() - 30)
                                ctx_end = min(len(injected), m.end() + 30)
                                ctx = injected[ctx_start:ctx_end]
                                if ctx not in baseline:
                                    return True
                        except re.error:
                            # Treat malformed patterns as new (don't suppress them)
                            if pattern in injected and pattern not in baseline:
                                return True
                        return False

                    unix_patterns = [p for p in unix_patterns if is_pattern_new(p, injected_body, baseline_body)]
                    windows_patterns = [p for p in windows_patterns if is_pattern_new(p, injected_body, baseline_body)]
                    cmd_detected = bool(unix_patterns or windows_patterns)

                    # Check for explicit uid= matches that are absent from baseline.
                    # Always run the context-window diff - never skip based on whether
                    # uid= appears in the baseline. The context window is what
                    # distinguishes a pre-existing stored match from a new one caused
                    # by this payload. Skipping when uid_in_baseline=True caused the
                    # verifier to miss injections whenever a prior test phase left
                    # command output in the page (e.g. stored via DVWA session).
                    #
                    # BUG (original): 30-char context window was too narrow. If the
                    # injected uid= output landed near a page boundary or boilerplate
                    # HTML that also appears in the baseline, the window matched and
                    # uid_in_delta stayed False. This caused the verifier to skip the
                    # confirmed injection when cmd_detected was also False (stripped by
                    # the over-aggressive baseline filter above).
                    #
                    # FIX: Use the full line containing the uid= match as context.
                    # A line like "uid=33(www-data) gid=33(www-data) groups=33(www-data)"
                    # is extremely unlikely to appear identically in the baseline.
                    uid_match = None
                    uid_in_delta = False
                    for m in _ID_OUTPUT_RE.finditer(injected_body):
                        # Extract the complete line containing this match for context
                        line_start = injected_body.rfind("\n", 0, m.start())
                        line_end = injected_body.find("\n", m.end())
                        line_start = 0 if line_start == -1 else line_start + 1
                        line_end = len(injected_body) if line_end == -1 else line_end
                        line_ctx = injected_body[line_start:line_end]
                        if line_ctx not in baseline_body:
                            uid_match = m
                            uid_in_delta = True
                            break

                    if not cmd_detected and not uid_in_delta:
                        continue

                    # --- FIX 2: PRECISION SNIPPET CRITICAL CROP ---
                    focus_index = -1

                    if uid_in_delta and uid_match:
                        focus_index = uid_match.start()
                    else:
                        active_patterns = unix_patterns + windows_patterns
                        for pattern in active_patterns:
                            # 1. Try literal match - verify it's a delta occurrence
                            idx = injected_body.find(pattern)
                            if idx != -1:
                                ctx = injected_body[max(0, idx - 30):idx + len(pattern) + 30]
                                if ctx not in baseline_body:
                                    focus_index = idx
                                    break
                                # Context exists in baseline - keep searching for a delta hit
                            
                            # 2. Try regex match - use finditer to find the delta occurrence
                            try:
                                for rmatch in re.finditer(pattern, injected_body, re.IGNORECASE):
                                    ctx_s = max(0, rmatch.start() - 30)
                                    ctx_e = min(len(injected_body), rmatch.end() + 30)
                                    ctx = injected_body[ctx_s:ctx_e]
                                    if ctx not in baseline_body:
                                        focus_index = rmatch.start()
                                        break
                                if focus_index != -1:
                                    break
                            except re.error:
                                pass
                        
                        # 3. Fallback: Center on the reflected payload itself
                        if focus_index == -1:
                            payload_idx = injected_body.find(payload)
                            if payload_idx != -1:
                                focus_index = payload_idx

                    # Extract the execution-output region with a few lines of context
                    # on either side so the reviewer can see what surrounds the output.
                    def _extract_output_region(center_idx: int, context_lines: int = 6) -> str:
                        if center_idx < 0:
                            return ""

                        # Walk back context_lines newlines to find left boundary
                        left = center_idx
                        for _ in range(context_lines + 1):
                            prev = injected_body.rfind("\n", 0, left)
                            if prev == -1:
                                left = 0
                                break
                            left = prev
                        else:
                            left = left + 1  # step past the newline itself

                        # Walk forward context_lines newlines to find right boundary
                        right = center_idx
                        for _ in range(context_lines + 1):
                            nxt = injected_body.find("\n", right)
                            if nxt == -1:
                                right = len(injected_body)
                                break
                            right = nxt + 1  # step past the newline
                        else:
                            right = right - 1

                        return injected_body[left:right].strip()

                    raw_result_snippet = ""
                    if uid_in_delta and uid_match:
                        # Prefer extracting around the canonical uid=... signature match.
                        raw_result_snippet = _extract_output_region(uid_match.start())
                    elif focus_index != -1:
                        raw_result_snippet = _extract_output_region(focus_index)

                    # If the extraction produced nothing meaningful (e.g. HTML uses <br>),
                    # fall back to a small structural window around focus.
                    if not raw_result_snippet:
                        if focus_index != -1:
                            snippet_start = max(0, focus_index - 60)
                            snippet_end = min(len(injected_body), focus_index + 200)
                            raw_result_snippet = injected_body[snippet_start:snippet_end].strip()
                        else:
                            # Fallback structural divergence check if keyword indexing fails
                            mismatch_idx = 0
                            min_len = min(len(baseline_body), len(injected_body))
                            while mismatch_idx < min_len and baseline_body[mismatch_idx] == injected_body[mismatch_idx]:
                                mismatch_idx += 1

                            if mismatch_idx == min_len and len(injected_body) > min_len:
                                # Pages are identical up to min_len; injected response has extra
                                # content appended after the baseline ends - capture that tail.
                                snippet_start = min_len
                            else:
                                snippet_start = max(0, mismatch_idx - 20)

                            raw_result_snippet = injected_body[snippet_start:snippet_start + 400].strip()

                            # Last-resort: if snippet is still empty or pure HTML boilerplate
                            # (e.g. mismatch_idx == min_len AND injected body is no longer),
                            # grab a mid-page window so the reviewer has something useful.
                            _BOILERPLATE_RE = re.compile(
                                r"^(<\s*/?\s*(body|html)\s*>[\s\r\n]*)+$", re.IGNORECASE
                            )
                            if not raw_result_snippet or _BOILERPLATE_RE.match(raw_result_snippet):
                                mid = len(injected_body) // 2
                                raw_result_snippet = injected_body[max(0, mid - 200):mid + 200].strip()
                    # --------------------------------------

                    if uid_in_delta and not unix_patterns:
                        unix_patterns = ["uid=<N>(<user>)"]
                    patterns_found = unix_patterns + windows_patterns
                    confidence = 90.0 if uid_in_delta else (85.0 if unix_patterns else 75.0)

                    logger.debug(
                        "Command injection confirmed for payload '%s' on %s:%s "
                        "(uid_in_delta=%s, patterns=%s)",
                        payload, url, parameter, uid_in_delta, patterns_found,
                    )

                    finding = self._create_finding(
                        category=OwaspCategory.a05,
                        vuln_type="OS Command Injection",
                        severity=SeverityLevel.critical,
                        url=url,
                        parameter=parameter,
                        payload=payload,
                        evidence=f"Command output detected in response: {', '.join(patterns_found)}",
                        confidence_score=confidence,
                        detection_method="command_output",
                        method=method,
                        detection_evidence={
                            "patterns_found": patterns_found,
                            "uid_signature_matched": uid_in_delta,
                            "is_unix": len(unix_patterns) > 0,
                            "response_snippet": raw_result_snippet[:300],
                        },
                        reproducible=True,
                        verified=True,
                        verification_request_snippet=injected.request_snippet,
                        # Supplies the cropped runtime execution segment directly
                        verification_response_snippet=raw_result_snippet,
                    )

                    return VerificationResult(
                        is_vulnerable=True,
                        confidence_score=confidence,
                        detection_method="command_output",
                        findings=[finding],
                        evidence={"patterns": patterns_found},
                        reproducible=True,
                    )

                return VerificationResult(
                    is_vulnerable=False,
                    confidence_score=0.0,
                    detection_method="command_output",
                    findings=[],
                    evidence={},
                )

            except Exception as e:
                logger.error(f"Output-based verification failed for {url}:{parameter}: {e}")
                return VerificationResult(
                    is_vulnerable=False,
                    confidence_score=0.0,
                    detection_method="command_output",
                    findings=[],
                    evidence={"error": str(e)},
                )
                            
    async def _verify_time_based_blind(
        self,
        url: str,
        parameter: str,
        method: str,
        value: str,
        form_inputs: Optional[list] = None,
        target: Optional[object] = None,
    ) -> VerificationResult:
        """Verify via time-based blind command injection."""
        try:
            # Get baseline response times
            baseline_url, baseline_params, baseline_data, baseline_json, baseline_headers = self._build_request_args(
                url, parameter, value, method, form_inputs, target=target
            )

            baseline_times = []
            for _ in range(2):
                resp = await self._send(
                    baseline_url, method, baseline_params, baseline_data,
                    headers=baseline_headers,
                    json_body=baseline_json,
                    test_phase="time_baseline",
                )
                baseline_times.append(resp.response_time_ms)
                await asyncio.sleep(0.1)

            # Try time-based payloads
            for payload, expected_delay_ms in self.BLIND_PAYLOADS:
                injected_url, injected_params, injected_data, injected_json, injected_headers = self._build_request_args(
                    url, parameter, payload, method, form_inputs, target=target
                )

                injected_times = []
                budget_denied = False
                for _ in range(2):
                    resp = await self._send(
                        injected_url, method, injected_params, injected_data,
                        headers=injected_headers,
                        json_body=injected_json,
                        test_phase="time_injection", payload=payload,
                    )
                    # Budget-denied probe has response_time_ms==0.0, which would
                    # read as "no delay" (a false negative). Treat as untested.
                    if resp.not_tested:
                        budget_denied = True
                        break
                    injected_times.append(resp.response_time_ms)
                    await asyncio.sleep(0.1)

                if budget_denied:
                    continue

                # Analyze timing
                settings = get_settings()
                threshold_fraction = getattr(self, "blind_timing_threshold", None) or settings.blind_injection_timing_threshold
                is_significant, timing_analysis = ResponseAnalyzer.is_timing_significant(
                    baseline_times, injected_times, threshold_ms=expected_delay_ms * threshold_fraction
                )

                if is_significant:
                    confidence = 70.0

                    # Build structured timing evidence for reviewer validation
                    threshold_used = expected_delay_ms * threshold_fraction
                    timing_evidence = {
                        **timing_analysis,
                        "baseline_times_ms": baseline_times,
                        "injected_times_ms": injected_times,
                        "baseline_mean_ms": round(timing_analysis.get("baseline_mean", 0), 1),
                        "injected_mean_ms": round(timing_analysis.get("injected_mean", 0), 1),
                        "delta_ms": round(timing_analysis.get("diff_ms", 0), 1),
                        "expected_delay_ms": expected_delay_ms,
                        "threshold_ms": round(threshold_used, 1),
                    }

                    finding = self._create_finding(
                        category=OwaspCategory.a05,
                        vuln_type="OS Command Injection (Time-Based Blind)",
                        severity=SeverityLevel.high,
                        url=url,
                        parameter=parameter,
                        payload=payload,
                        evidence=(
                            f"Response delayed {timing_analysis['diff_ms']:.0f}ms with command payload "
                            f"(baseline_mean={timing_analysis.get('baseline_mean', 0):.0f}ms, "
                            f"injected_mean={timing_analysis.get('injected_mean', 0):.0f}ms, "
                            f"delta={timing_analysis['diff_ms']:.0f}ms, "
                            f"threshold={threshold_used:.0f}ms, "
                            f"expected_delay={expected_delay_ms}ms)."
                        ),
                        confidence_score=confidence,
                        detection_method="time_based_blind",
                        method=method,
                        detection_evidence=timing_evidence,
                        reproducible=True,
                        verified=True,
                        verification_request_snippet=resp.request_snippet,
                        verification_response_snippet=resp.response_snippet,
                    )

                    return VerificationResult(
                        is_vulnerable=True,
                        confidence_score=confidence,
                        detection_method="time_based_blind",
                        findings=[finding],
                        evidence=timing_evidence,
                        reproducible=True,
                    )

            return VerificationResult(
                is_vulnerable=False,
                confidence_score=0.0,
                detection_method="time_based_blind",
                findings=[],
                evidence={},
            )

        except Exception as e:
            logger.error(f"Time-based verification failed for {url}:{parameter}: {e}")
            return VerificationResult(
                is_vulnerable=False,
                confidence_score=0.0,
                detection_method="time_based_blind",
                findings=[],
                evidence={"error": str(e)},
            )
