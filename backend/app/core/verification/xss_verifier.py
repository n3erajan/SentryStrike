"""
XSS Verifier: Active verification for Reflected XSS vulnerabilities.

Implements:
- Reflection detection (raw + HTML-decoded)
- Context analysis (HTML, JS, attribute)
- Encoding detection
"""

import asyncio
import html
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
    """Verifies Reflected and Stored XSS vulnerabilities through active testing."""

    # Payloads designed to be reflected in specific contexts.
    #
    # BUG 4 FIX (partial): The original "unicode" payload was:
    #   "\\u003cscript\\u003ealert(1)\\u003c/script\\u003e"
    # That Python string contains literal backslash-u sequences, NOT the
    # actual Unicode escape characters. When sent over HTTP the server
    # receives the literal text \u003c, which is rarely useful.
    # Replaced with a JS octal/hex variant that is valid as a sent string
    # and tests JS-context injection without angle brackets.
    XSS_PAYLOADS = {
        "simple":    "<script>alert(1)</script>",
        "event":     '"><svg/onload=alert(1)>',
        "attribute": "'><img src=x onerror=alert(1)>",
        "jsdouble":  '"alert(1)"',
        "jssingle":  "'alert(1)'",
        # Tests JS string context without angle brackets; angle-bracket-free
        # so it bypasses many naive tag-stripping filters.
        "js_noangle": "javascript:alert(1)",
        # Polyglot that works in both HTML body and attribute contexts.
        "polyglot":  "'\"><script>alert(1)</script>",
    }

    # Patterns to detect execution context
    SCRIPT_TAG_CONTEXT    = re.compile(r"<script[^>]*>", re.IGNORECASE)
    EVENT_HANDLER_CONTEXT = re.compile(r"\s+on\w+=", re.IGNORECASE)
    HTML_ATTRIBUTE_CONTEXT = re.compile(r'\s+\w+=["\'`]', re.IGNORECASE)
    JS_STRING_CONTEXT     = re.compile(r'["\'`]\s*$', re.IGNORECASE)

    async def verify(
        self,
        url: str,
        parameter: str,
        method: str = "GET",
        value: str = "",
        form_inputs: Optional[list] = None,
    ) -> VerificationResult:
        """
        Verify XSS vulnerability.

        Tests multiple payloads, checks both raw and HTML-decoded reflection,
        and analyses the reflection context to determine confidence and severity.
        """
        findings: list[Finding] = []

        # Check DOM XSS on baseline page
        try:
            baseline_url, baseline_params, baseline_data = URLParameterBuilder.inject_parameter(
                url, parameter, value, method
            )
            baseline = await self.http_verifier.send_request(
                baseline_url, method, baseline_params, baseline_data
            )
            dom_finding = self._check_dom_xss(url, baseline.body)
            if dom_finding:
                findings.append(dom_finding)
        except Exception as e:
            logger.debug("Failed to perform DOM XSS check: %s", e)

        for payload_type, payload in self.XSS_PAYLOADS.items():
            result = await self._test_payload(
                url, parameter, method, value, payload, payload_type, form_inputs
            )
            if result.is_vulnerable:
                findings.extend(result.findings)

        if findings:
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

    # ---------------------------------------------------------------------- #
    # DOM XSS heuristic
    # ---------------------------------------------------------------------- #

    def _check_dom_xss(self, url: str, html_body: str) -> Optional[Finding]:
        """Perform basic analysis of HTML/scripts for DOM-based XSS indicators."""
        sources = [
            r"location\.hash", r"location\.search",
            r"document\.URL", r"document\.referrer", r"window\.location",
        ]
        sinks = [
            r"eval\(", r"document\.write\(", r"document\.writeln\(",
            r"\.innerHTML\s*=", r"\.outerHTML\s*=",
        ]

        found_sources = [src for src in sources if re.search(src, html_body, re.I)]
        found_sinks   = [sink for sink in sinks if re.search(sink, html_body, re.I)]

        if found_sources and found_sinks:
            evidence = (
                f"Page source contains potential DOM XSS sources {found_sources} "
                f"and sinks {found_sinks}. Client-side JavaScript may dynamically "
                "render unvalidated input."
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

    # ---------------------------------------------------------------------- #
    # Payload testing
    # ---------------------------------------------------------------------- #

    async def _test_payload(
        self,
        url: str,
        parameter: str,
        method: str,
        value: str,
        payload: str,
        payload_type: str,
        form_inputs: Optional[list],
    ) -> VerificationResult:
        """Test a single XSS payload for reflection (immediate and stored)."""
        try:
            # Build and send the injected request
            if method.upper() == "POST" and form_inputs is not None:
                injected_url    = url
                injected_params = None
                injected_data   = self._build_form_payload(form_inputs, parameter, payload)
            else:
                injected_url, injected_params, injected_data = URLParameterBuilder.inject_parameter(
                    url, parameter, payload, method
                )
            injected = await self.http_verifier.send_request(
                injected_url, method, injected_params, injected_data
            )

            # BUG 4 FIX: Check reflection against BOTH the raw response body
            # and the HTML-decoded version of it.
            #
            # The original code only checked raw substring matching, so any
            # server that HTML-encodes output (e.g. returning &lt;script&gt;
            # instead of <script>) would pass the payload through but be
            # missed entirely. html.unescape() converts &lt; → <, &#60; → <,
            # etc., making encoded reflections detectable.
            #
            # We keep track of whether the match came from the decoded body so
            # we can correctly set encoding_type in context analysis.
            is_reflected, locations, was_encoded = self._detect_reflection(payload, injected.body)
            is_stored = False

            # For POST requests or when not immediately reflected, check if
            # the payload was stored and appears on the page via GET.
            if not is_reflected or method.upper() == "POST":
                await asyncio.sleep(0.2)
                display_url = url.split("?")[0]
                stored_resp = await self.http_verifier.send_request(display_url, "GET")
                stored_reflected, stored_locations, stored_was_encoded = self._detect_reflection(
                    payload, stored_resp.body
                )
                if stored_reflected:
                    is_reflected  = True
                    locations     = stored_locations
                    was_encoded   = stored_was_encoded
                    injected      = stored_resp
                    is_stored     = True

            if not is_reflected:
                return VerificationResult(
                    is_vulnerable=False,
                    confidence_score=0.0,
                    detection_method=payload_type,
                    findings=[],
                    evidence={"reflected": False},
                )

            # Analyse context using the appropriate body (raw vs decoded)
            body_for_analysis = (
                html.unescape(injected.body) if was_encoded else injected.body
            )
            context_analysis = self._analyze_reflection_context(body_for_analysis, payload, locations)

            # Override encoding_type if the match required HTML-decoding —
            # even if the decoded context looks executable, the browser would
            # receive encoded characters and may or may not decode them
            # depending on the context.
            if was_encoded:
                context_analysis["encoding_type"] = "html_encoded"
                context_analysis["is_executable"] = False

            confidence_score = self._calculate_xss_confidence(payload, context_analysis)
            severity         = self._determine_xss_severity(context_analysis)

            finding = self._create_finding(
                category=OwaspCategory.a03,
                vuln_type="Stored XSS" if is_stored else "Reflected XSS",
                severity=severity,
                url=url,
                parameter=parameter,
                payload=payload,
                evidence=(
                    f"Payload {'stored and' if is_stored else ''} reflected in response. "
                    f"Context: {context_analysis['context_type']}. "
                    f"Encoding: {context_analysis['encoding_type']}."
                ),
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
            logger.error("XSS verification failed for %s:%s: %s", url, parameter, e)
            return VerificationResult(
                is_vulnerable=False,
                confidence_score=0.0,
                detection_method=payload_type,
                findings=[],
                evidence={"error": str(e)},
            )

    # ---------------------------------------------------------------------- #
    # BUG 4 FIX: Reflection detection with HTML-decode fallback
    # ---------------------------------------------------------------------- #

    @staticmethod
    def _detect_reflection(payload: str, body: str) -> tuple[bool, list[int], bool]:
        """
        Check whether ``payload`` appears in ``body``, trying both raw and
        HTML-decoded forms.

        Returns
        -------
        (is_reflected, locations, was_encoded)
            is_reflected  – True if the payload was found by either method.
            locations     – List of character offsets where the payload starts.
            was_encoded   – True if the match only succeeded after html.unescape().
                            Callers use this to set encoding_type correctly.
        """
        # 1. Raw match — payload appears verbatim (low-security / no encoding)
        raw_locations = [
            i for i in range(len(body))
            if body[i:i + len(payload)] == payload
        ]
        if raw_locations:
            return True, raw_locations, False

        # 2. HTML-decoded match — server encoded < as &lt; etc.
        decoded_body = html.unescape(body)
        decoded_locations = [
            i for i in range(len(decoded_body))
            if decoded_body[i:i + len(payload)] == payload
        ]
        if decoded_locations:
            return True, decoded_locations, True

        return False, [], False

    # ---------------------------------------------------------------------- #
    # Context analysis
    # ---------------------------------------------------------------------- #

    def _analyze_reflection_context(
        self,
        response_body: str,
        payload: str,
        locations: list[int],
    ) -> dict:
        """Analyse the context where the payload is reflected."""
        analysis = {
            "context_type":  "unknown",
            "encoding_type": "unencoded",
            "is_executable": False,
            "locations":     locations,
        }

        if not locations:
            return analysis

        loc           = locations[0]
        context_start = max(0, loc - 50)
        context_end   = min(len(response_body), loc + len(payload) + 50)
        context       = response_body[context_start:context_end]

        # Encoding check on the surrounding context
        if "%" in context or "&#" in context or "&amp;" in context or "\\x" in context:
            analysis["encoding_type"] = "encoded"
        else:
            analysis["encoding_type"] = "unencoded"

        # Context classification
        if self.SCRIPT_TAG_CONTEXT.search(context):
            analysis["context_type"]  = "script_tag"
            analysis["is_executable"] = analysis["encoding_type"] == "unencoded"
        elif self.EVENT_HANDLER_CONTEXT.search(context):
            analysis["context_type"]  = "event_handler"
            analysis["is_executable"] = analysis["encoding_type"] == "unencoded"
        elif self.HTML_ATTRIBUTE_CONTEXT.search(context):
            analysis["context_type"]  = "html_attribute"
            analysis["is_executable"] = False
        elif self.JS_STRING_CONTEXT.search(context):
            analysis["context_type"]  = "javascript_string"
            analysis["is_executable"] = analysis["encoding_type"] == "unencoded"
        else:
            analysis["context_type"]  = "html_body"
            analysis["is_executable"] = analysis["encoding_type"] == "unencoded"

        return analysis

    # ---------------------------------------------------------------------- #
    # Form payload builder
    # ---------------------------------------------------------------------- #

    def _build_form_payload(
        self, form_inputs: list, target_param: str, target_value: str
    ) -> dict:
        payload: dict[str, str] = {}
        for inp in form_inputs:
            name = getattr(inp, "name", "")
            if not name:
                continue
            inp_type = getattr(inp, "input_type", "text").lower()
            if name == target_param:
                payload[name] = target_value
            elif inp_type == "password":
                payload[name] = "sntry_password123"
            elif inp_type in ("submit", "button"):
                payload[name] = "Submit"
            else:
                payload[name] = "sntry_test_val"

        # Ensure the target parameter is always present even if not in form_inputs
        if target_param not in payload:
            payload[target_param] = target_value

        return payload

    # ---------------------------------------------------------------------- #
    # Confidence and severity
    # ---------------------------------------------------------------------- #

    @staticmethod
    def _calculate_xss_confidence(payload: str, context: dict) -> float:
        """Calculate XSS confidence score based on payload and reflection context."""
        base_confidence = 60.0

        if context["is_executable"]:
            base_confidence += 25.0
        elif context["encoding_type"] in ("encoded", "html_encoded"):
            # Reflection exists but characters are escaped — lower confidence
            # that the payload is actually executable in the browser.
            base_confidence -= 15.0

        if context["context_type"] == "javascript_string":
            base_confidence += 10.0
        elif context["context_type"] == "event_handler":
            base_confidence += 15.0

        return min(100.0, max(0.0, base_confidence))

    @staticmethod
    def _determine_xss_severity(context: dict) -> SeverityLevel:
        """Determine severity based on reflection context."""
        if context["is_executable"]:
            if context["context_type"] in ("script_tag", "event_handler"):
                return SeverityLevel.critical
            return SeverityLevel.high
        if context["encoding_type"] in ("encoded", "html_encoded"):
            return SeverityLevel.low
        return SeverityLevel.medium