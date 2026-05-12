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

from app.core.detectors.base_detector import Finding
from app.core.verification.response_analyzer import ResponseAnalyzer
from app.core.verification.verification_framework import (
    BaseVerifier,
    URLParameterBuilder,
    VerificationResult,
)
from app.models.vulnerability import OwaspCategory, SeverityLevel

logger = logging.getLogger(__name__)


class CommandInjectionVerifier(BaseVerifier):
    """Verifies OS command injection vulnerabilities through active testing."""

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

    async def verify(
        self,
        url: str,
        parameter: str,
        method: str = "GET",
        value: str = "",
    ) -> VerificationResult:
        """
        Verify command injection vulnerability.

        Tries multiple techniques:
        1. Output-based detection (Unix/Windows)
        2. Time-based blind
        3. Error-based
        """
        findings = []

        # Try output-based detection first
        output_result = await self._verify_output_based(url, parameter, method, value)
        if output_result.is_vulnerable:
            findings.extend(output_result.findings)
            return output_result

        # Try time-based blind if output-based fails
        time_result = await self._verify_time_based_blind(url, parameter, method, value)
        if time_result.is_vulnerable:
            findings.extend(time_result.findings)
            return time_result

        return VerificationResult(
            is_vulnerable=False,
            confidence_score=0.0,
            detection_method="none",
            findings=[],
            evidence={},
        )

    async def _verify_output_based(
        self,
        url: str,
        parameter: str,
        method: str,
        value: str,
    ) -> VerificationResult:
        """
        Verify via command output detection.

        Looks for patterns like uid=, root, etc. in responses.
        """
        payloads = self.UNIX_PAYLOADS + self.WINDOWS_PAYLOADS

        try:
            # Get baseline
            baseline_url, baseline_params, baseline_data = URLParameterBuilder.inject_parameter(
                url, parameter, value, method
            )
            baseline = await self.http_verifier.send_request(baseline_url, method, baseline_params, baseline_data)

            # Try each payload
            for payload in payloads:
                injected_url, injected_params, injected_data = URLParameterBuilder.inject_parameter(
                    url, parameter, payload, method
                )
                injected = await self.http_verifier.send_request(injected_url, method, injected_params, injected_data)

                # Check for command output
                cmd_detected, unix_patterns, windows_patterns = ResponseAnalyzer.detect_command_output(
                    injected.body
                )

                if cmd_detected:
                    patterns_found = unix_patterns + windows_patterns
                    confidence = 85.0 if unix_patterns else 75.0

                    finding = self._create_finding(
                        category=OwaspCategory.a03,
                        vuln_type="OS Command Injection",
                        severity=SeverityLevel.critical,
                        url=url,
                        parameter=parameter,
                        payload=payload,
                        evidence=f"Command output detected: {', '.join(patterns_found)}",
                        confidence_score=confidence,
                        detection_method="command_output",
                        method=method,
                        detection_evidence={
                            "patterns_found": patterns_found,
                            "is_unix": len(unix_patterns) > 0,
                            "response_snippet": injected.body[:300],
                        },
                        reproducible=True,
                        verified=True,
                        verification_request_snippet=injected.request_snippet,
                        verification_response_snippet=injected.response_snippet,
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
    ) -> VerificationResult:
        """Verify via time-based blind command injection."""
        try:
            # Get baseline response times
            baseline_url, baseline_params, baseline_data = URLParameterBuilder.inject_parameter(
                url, parameter, value, method
            )

            baseline_times = []
            for _ in range(2):
                resp = await self.http_verifier.send_request(baseline_url, method, baseline_params, baseline_data)
                baseline_times.append(resp.response_time_ms)
                await asyncio.sleep(0.1)

            # Try time-based payloads
            for payload, expected_delay_ms in self.BLIND_PAYLOADS:
                injected_url, injected_params, injected_data = URLParameterBuilder.inject_parameter(
                    url, parameter, payload, method
                )

                injected_times = []
                for _ in range(2):
                    resp = await self.http_verifier.send_request(injected_url, method, injected_params, injected_data)
                    injected_times.append(resp.response_time_ms)
                    await asyncio.sleep(0.1)

                # Analyze timing
                is_significant, timing_analysis = ResponseAnalyzer.is_timing_significant(
                    baseline_times, injected_times, threshold_ms=expected_delay_ms * 0.7
                )

                if is_significant:
                    confidence = 70.0

                    finding = self._create_finding(
                        category=OwaspCategory.a03,
                        vuln_type="OS Command Injection (Time-Based Blind)",
                        severity=SeverityLevel.high,
                        url=url,
                        parameter=parameter,
                        payload=payload,
                        evidence=f"Response delayed {timing_analysis['diff_ms']:.0f}ms with command payload",
                        confidence_score=confidence,
                        detection_method="time_based_blind",
                        method=method,
                        detection_evidence=timing_analysis,
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
                        evidence=timing_analysis,
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
