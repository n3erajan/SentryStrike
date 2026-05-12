"""
XSS Verifier: Active verification for Reflected XSS vulnerabilities.

Implements:
- Reflection detection
- Context analysis (HTML, JS, attribute)
- Encoding detection
"""

import asyncio
import logging
import re
from typing import Optional

from app.core.detectors.base_detector import Finding
from app.core.verification.response_analyzer import ResponseAnalyzer, ResponseData
from app.core.verification.verification_framework import (
    BaseVerifier,
    URLParameterBuilder,
    VerificationResult,
)
from app.models.vulnerability import OwaspCategory, SeverityLevel

logger = logging.getLogger(__name__)


class XSSVerifier(BaseVerifier):
    """Verifies Reflected XSS vulnerabilities through active testing."""

    # Payloads designed to be reflected in specific contexts
    XSS_PAYLOADS = {
        "simple": "<script>alert(1)</script>",
        "event": '"><svg/onload=alert(1)>',
        "attribute": "'><img src=x onerror=alert(1)>",
        "jsdouble": '"alert(1)"',
        "jssingle": "'alert(1)'",
        "unicode": "\\u003cscript\\u003ealert(1)\\u003c/script\\u003e",
    }

    # Patterns to detect execution context
    SCRIPT_TAG_CONTEXT = re.compile(r"<script[^>]*>", re.IGNORECASE)
    EVENT_HANDLER_CONTEXT = re.compile(r"\s+on\w+=", re.IGNORECASE)
    HTML_ATTRIBUTE_CONTEXT = re.compile(r'\s+\w+=["\'`]', re.IGNORECASE)
    JS_STRING_CONTEXT = re.compile(r'["\'`]\s*$', re.IGNORECASE)

    async def verify(
        self,
        url: str,
        parameter: str,
        method: str = "GET",
        value: str = "",
    ) -> VerificationResult:
        """
        Verify Reflected XSS vulnerability.

        Tests multiple payloads and analyzes reflection patterns.
        """
        findings = []

        # Check DOM XSS on baseline page
        try:
            baseline_url, baseline_params, baseline_data = URLParameterBuilder.inject_parameter(
                url, parameter, value, method
            )
            baseline = await self.http_verifier.send_request(baseline_url, method, baseline_params, baseline_data)
            dom_finding = self._check_dom_xss(url, baseline.body)
            if dom_finding:
                findings.append(dom_finding)
        except Exception as e:
            logger.debug("Failed to perform DOM XSS check: %s", e)

        for payload_type, payload in self.XSS_PAYLOADS.items():
            result = await self._test_payload(url, parameter, method, value, payload, payload_type)

            if result.is_vulnerable:
                findings.extend(result.findings)

        if findings:
            # Deduplicate by keeping highest confidence
            findings.sort(key=lambda f: f.confidence_score, reverse=True)
            best = findings[0]

            return VerificationResult(
                is_vulnerable=True,
                confidence_score=best.confidence_score,
                detection_method=best.detection_method,
                findings=findings,
                evidence={"payload_type": best.detection_method},
                reproducible=True,
            )

        return VerificationResult(
            is_vulnerable=False,
            confidence_score=0.0,
            detection_method="none",
            findings=[],
            evidence={},
        )

    def _check_dom_xss(self, url: str, html: str) -> Optional[Finding]:
        """Perform basic analysis of HTML/scripts for DOM-based XSS vulnerability indicators."""
        # Common sources: location.hash, location.search, document.URL, document.referrer, window.location
        sources = [r"location\.hash", r"location\.search", r"document\.URL", r"document\.referrer", r"window\.location"]
        # Common sinks: eval, setTimeout, setInterval, document.write, document.writeln, innerHTML, outerHTML
        sinks = [r"eval\(", r"document\.write\(", r"document\.writeln\(", r"\.innerHTML\s*=", r"\.outerHTML\s*="]

        # Scan scripts for sources and sinks
        # First check if any source and sink exist in the code
        found_sources = [src for src in sources if re.search(src, html, re.I)]
        found_sinks = [sink for sink in sinks if re.search(sink, html, re.I)]

        if found_sources and found_sinks:
            evidence = (
                f"Page source contains potential DOM XSS sources {found_sources} "
                f"and sinks {found_sinks}. This indicates client-side JavaScript "
                "might dynamically render unvalidated input."
            )
            return self._create_finding(
                category=OwaspCategory.a03,
                vuln_type="DOM-Based XSS",
                severity=SeverityLevel.medium,
                url=url,
                parameter="javascript",
                payload="location.hash",
                evidence=evidence,
                confidence_score=60.0,
                detection_method="dom_xss_heuristics",
                method="GET",
                detection_evidence={"found_sources": found_sources, "found_sinks": found_sinks},
                reproducible=True,
                verified=False,
            )
        return None

    async def _test_payload(
        self,
        url: str,
        parameter: str,
        method: str,
        value: str,
        payload: str,
        payload_type: str,
    ) -> VerificationResult:
        """Test a single XSS payload."""
        try:
            # Get baseline response
            baseline_url, baseline_params, baseline_data = URLParameterBuilder.inject_parameter(
                url, parameter, value, method
            )
            baseline = await self.http_verifier.send_request(baseline_url, method, baseline_params, baseline_data)

            # Inject XSS payload
            injected_url, injected_params, injected_data = URLParameterBuilder.inject_parameter(
                url, parameter, payload, method
            )
            injected = await self.http_verifier.send_request(injected_url, method, injected_params, injected_data)

            # Check for reflection
            is_reflected, locations = ResponseAnalyzer.detect_payload_reflection(payload, injected.body)
            is_stored = False

            # If not reflected immediately, or for any POST request, verify stored XSS
            if not is_reflected or method.upper() == "POST":
                await asyncio.sleep(0.1)
                stored_resp = await self.http_verifier.send_request(url, "GET")
                stored_reflected, stored_locations = ResponseAnalyzer.detect_payload_reflection(payload, stored_resp.body)
                if stored_reflected:
                    is_reflected = True
                    locations = stored_locations
                    injected = stored_resp
                    is_stored = True

            if not is_reflected:
                return VerificationResult(
                    is_vulnerable=False,
                    confidence_score=0.0,
                    detection_method=payload_type,
                    findings=[],
                    evidence={"reflected": False},
                )

            # Analyze context and encoding
            context_analysis = self._analyze_reflection_context(injected.body, payload, locations)

            # Determine confidence and severity based on context
            confidence_score = self._calculate_xss_confidence(payload, context_analysis)
            severity = self._determine_xss_severity(context_analysis)

            finding = self._create_finding(
                category=OwaspCategory.a03,
                vuln_type="Stored XSS" if is_stored else "Reflected XSS",
                severity=severity,
                url=url,
                parameter=parameter,
                payload=payload,
                evidence=f"Payload reflected in response. Context: {context_analysis['context_type']}. Encoding: {context_analysis['encoding_type']}",
                confidence_score=confidence_score,
                detection_method=f"reflection_{payload_type}",
                method=method,
                detection_evidence=context_analysis,
                reproducible=True,
                verified=True,
                verification_request_snippet=injected.request_snippet,
                verification_response_snippet=injected.response_snippet,
            )

            return VerificationResult(
                is_vulnerable=True,
                confidence_score=confidence_score,
                detection_method=f"reflection_{payload_type}",
                findings=[finding],
                evidence=context_analysis,
                reproducible=True,
            )

        except Exception as e:
            logger.error(f"XSS verification failed for {url}:{parameter}: {e}")
            return VerificationResult(
                is_vulnerable=False,
                confidence_score=0.0,
                detection_method=payload_type,
                findings=[],
                evidence={"error": str(e)},
            )

    def _analyze_reflection_context(
        self,
        response_body: str,
        payload: str,
        locations: list[int],
    ) -> dict:
        """Analyze the context where payload is reflected."""
        analysis = {
            "context_type": "unknown",
            "encoding_type": "unencoded",
            "is_executable": False,
            "locations": locations,
        }

        if not locations:
            return analysis

        # Get context around first reflection
        loc = locations[0]
        context_start = max(0, loc - 50)
        context_end = min(len(response_body), loc + len(payload) + 50)
        context = response_body[context_start:context_end]

        # Check encoding
        if "%" in context or "&#" in context or "\\x" in context:
            analysis["encoding_type"] = "encoded"
        else:
            analysis["encoding_type"] = "unencoded"

        # Check context type
        if self.SCRIPT_TAG_CONTEXT.search(context):
            analysis["context_type"] = "script_tag"
            analysis["is_executable"] = analysis["encoding_type"] == "unencoded"
        elif self.EVENT_HANDLER_CONTEXT.search(context):
            analysis["context_type"] = "event_handler"
            analysis["is_executable"] = analysis["encoding_type"] == "unencoded"
        elif self.HTML_ATTRIBUTE_CONTEXT.search(context):
            analysis["context_type"] = "html_attribute"
            analysis["is_executable"] = False
        elif self.JS_STRING_CONTEXT.search(context):
            analysis["context_type"] = "javascript_string"
            analysis["is_executable"] = analysis["encoding_type"] == "unencoded"
        else:
            analysis["context_type"] = "html_body"
            analysis["is_executable"] = analysis["encoding_type"] == "unencoded"

        return analysis

    @staticmethod
    def _calculate_xss_confidence(payload: str, context: dict) -> float:
        """Calculate XSS confidence based on payload and context."""
        base_confidence = 60.0

        # Boost if executable context
        if context["is_executable"]:
            base_confidence += 25.0
        elif context["encoding_type"] == "encoded":
            base_confidence -= 15.0

        # Boost for harder-to-bypass contexts
        if context["context_type"] == "javascript_string":
            base_confidence += 10.0
        elif context["context_type"] == "event_handler":
            base_confidence += 15.0

        return min(100.0, base_confidence)

    @staticmethod
    def _determine_xss_severity(context: dict) -> SeverityLevel:
        """Determine severity based on context."""
        if context["is_executable"]:
            if context["context_type"] in ["script_tag", "event_handler"]:
                return SeverityLevel.critical
            else:
                return SeverityLevel.high
        elif context["encoding_type"] == "encoded":
            return SeverityLevel.low
        else:
            return SeverityLevel.medium
