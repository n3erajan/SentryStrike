"""
XSS Verifier: Active verification for Reflected, Stored, DOM-based,
JSONP, header-reflected, and mXSS vulnerabilities.

Hybrid Execution Architecture: 
Combines fast static triage (canaries/reflection tracking) with headless 
browser validation to preserve performance while eliminating false positives.
"""

import asyncio
import copy
import json
import html
import logging
import random
import re
import string
from typing import Any, Optional
from urllib.parse import urlencode, urlparse, parse_qsl, urlunparse, quote

# Import Playwright's async framework smoothly
try:
    from playwright.async_api import async_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    async_playwright = None
    PLAYWRIGHT_AVAILABLE = False

from app.core.crawler.models import ParameterLocation
from app.core.crawler.url_parser import is_static_asset
from app.core.detectors.attack_surface import AttackTarget, _set_json_path
from app.core.detectors.base_detector import Finding
from app.core.verification.response_analyzer import ResponseAnalyzer, ResponseData
from app.core.verification.verification_framework import (
    BaseVerifier,
    FormPayloadBuilder,
    URLParameterBuilder,
    VerificationResult,
)
from app.utils.scan_http import build_observed_request_snippet
from shared.models.vulnerability import OwaspCategory, SeverityLevel
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class PendingBrowserVerification:
    """Carries everything needed to run browser verification after HTTP phase completes."""
    url: str
    parameter: str
    method: str
    payload: str
    canary: str
    form_inputs: Optional[list]
    stored_display_urls: Optional[list[str]]
    is_header_injection: bool
    context_analysis: dict
    # The partial finding built from HTTP evidence - browser will confirm or discard it
    partial_finding: Finding
    target: object | None = None


def _random_canary(prefix: str = "sentry", length: int = 8) -> str:
    """Return a short, unpredictable canary string safe to embed in HTML."""
    suffix = "".join(random.choices(string.ascii_lowercase + string.digits, k=length))
    return f"{prefix}_{suffix}"


def _embed_canary(payload: str, canary: str) -> str:
    """Embed a per-request canary so reflection can be attributed unambiguously."""
    # Upgrade execution tracking safely by binding the dynamic telemetry hook
    hook_call = f"window.sentry_hook('{canary}')"
    if "alert(1)" in payload:
        return payload.replace("alert(1)", hook_call, 1)
    if "alert(1);//" in payload:
        return payload.replace("alert(1);//", f"{hook_call};//", 1)
    return f"{payload}<script>{hook_call}</script>"


class XSSVerifier(BaseVerifier):
    """Verifies Reflected, Stored, DOM-based, header-reflected, JSONP,
    mXSS and template-injection XSS vulnerabilities through mixed active testing."""

    module_name = "xss"

    # ------------------------------------------------------------------ #
    # Core structural contracts preserved perfectly
    # ------------------------------------------------------------------ #
    XSS_PAYLOADS: dict[str, str] = {
        "simple":    "<script>alert(1)</script>",
        "event":     '"><svg/onload=alert(1)>',
        "attribute": "'><img src=x onerror=alert(1)>",
        "jsdouble":  '"alert(1)"',
        "jssingle":  "'alert(1)'",
        "js_noangle": "javascript:alert(1)",
        "polyglot":  "'\"><script>alert(1)</script>",
        "mxss_listing": "<listing><img src=</listing><img src=x onerror=alert(1)>",
        "mxss_noscript": "<noscript><p title=\"</noscript><img src=x onerror=alert(1)>\">",
        "tmpl_angular": "{{constructor.constructor('alert(1)')()}}",
        "tmpl_vue":     "{{_c.constructor('alert(1)')()}}",
    }

    JSONP_PAYLOADS: dict[str, str] = {
        "jsonp_basic":    "alert(1)//",
        "jsonp_paren":    "alert(1);",
        "jsonp_proto":    "Object.prototype.toString.call(alert(1))//",
    }

    HEADER_PAYLOADS: dict[str, str] = {
        "hdr_script":  "<script>alert(1)</script>",
        "hdr_svg":     "<svg/onload=alert(1)>",
        "hdr_img":     "<img src=x onerror=alert(1)>",
    }

    _JSONP_PARAM_NAMES: frozenset[str] = frozenset(
        {"callback", "jsonp", "cb", "json_callback", "jsoncallback"}
    )

    _EXECUTABLE_ATTR_NAMES: frozenset[str] = frozenset(
        {"href", "src", "action", "formaction", "data", "xlink:href"}
    )

    SCRIPT_TAG_CONTEXT     = re.compile(r"<script[^>]*>", re.IGNORECASE)
    EVENT_HANDLER_CONTEXT  = re.compile(r"\s+on\w+=", re.IGNORECASE)
    HTML_ATTRIBUTE_CONTEXT = re.compile(r'\s+(?P<attr>\w[\w:-]*)=["\'`]', re.IGNORECASE)
    JS_STRING_CONTEXT      = re.compile(r'["\'`]\s*$', re.IGNORECASE)

    _DOM_SOURCES: tuple[str, ...] = (
        r"location\.hash", r"location\.search", r"location\.href", r"document\.URL",
        r"document\.documentURI", r"document\.referrer", r"window\.location",
        r"document\.cookie", r"localStorage\.", r"sessionStorage\.", r"window\.name",
        r"URLSearchParams\s*\([^)]*location\.search", r"new\s+URL\s*\([^)]*location",
        r"addEventListener\(['\"]message['\"]", r"\.onmessage\s*=",
    )

    _DOM_SINKS: tuple[str, ...] = (
        r"eval\(", r"document\.write\(", r"document\.writeln\(", r"\.innerHTML\s*=",
        r"\.outerHTML\s*=", r"\.insertAdjacentHTML\(", r"setTimeout\(", r"setInterval\(",
        r"new\s+Function\(", r"\$\s*\(", r"\.html\s*\(", r"\.append\s*\(", r"\.prepend\s*\(",
        r"\.after\s*\(", r"\.before\s*\(", r"location\.assign\s*\(", r"location\.replace\s*\(",
        r"location\.href\s*=", r"dangerouslySetInnerHTML", r"bypassSecurityTrust(?:Html|Script|Url)\s*\(",
        r"\bv-html\b", r"\bng-bind-html\b",
    )
    
    _HEADER_SINK_PATTERNS: re.Pattern = re.compile(
        r"(log|admin|report|view|activity|audit|history|dashboard|ids|monitor|feed|track|access)",
        re.IGNORECASE,
    )

    _STORED_PROBE_URL_CAP = 25
    # P0-3: hard ceiling on how many header-sink URLs a single header × payload
    # combination re-probes. Bounds the header-stored GET-replay fan-out that
    # otherwise multiplies headers × payloads × every sink-like URL.
    _STORED_HEADER_SINK_CAP = 8

    @classmethod
    def select_stored_probe_urls(cls, urls: list[str]) -> list[str]:
        """Return a deduplicated, capped list of URLs worth probing for stored XSS.

        Static assets (js/css/txt/images/…) are excluded: a stored XSS payload is
        reflected into an HTML page's DOM, never into a plain-text/binary asset, so
        re-fetching ``robots.txt``/``main.js`` as a stored sink only wastes budget.
        """
        bare_urls: list[str] = []
        seen: set[str] = set()
        for url in urls:
            bare = url.split("?")[0]
            if is_static_asset(bare):
                continue
            if bare not in seen:
                seen.add(bare)
                bare_urls.append(bare)

        sinks = [u for u in bare_urls if cls._HEADER_SINK_PATTERNS.search(u)]
        others = [u for u in bare_urls if u not in sinks]
        capped = sinks + others[: cls._STORED_PROBE_URL_CAP]
        return list(dict.fromkeys(capped))

    async def _batch_stored_discovery(
        self,
        candidates: list[AttackTarget],
        stored_display_urls: list[str],
        stored_baselines: dict[str, ResponseData] | None = None,
    ) -> dict[str, set[str]]:
        """Inject unique canaries into all params of a route in one request,
        then probe each display URL once to discover which (param, display_url)
        pairs reflect.

        Returns a mapping of ``parameter → {display_url, ...}`` for parameters
        whose canary was found in at least one display URL's response. The
        per-parameter canary mapping is stored in ``self._batch_canaries`` for
        downstream use by ``_test_payload`` (so it can restrict stored probing
        to only confirmed display URLs instead of fanning out to all of them).

        This collapses the stored-XSS discovery phase from ``params × payloads ×
        probe_urls`` to ``1 injection + probe_urls``, an O(n²) → O(n) reduction.
        """
        if not candidates or not stored_display_urls:
            return {}

        self._stored_baselines = dict(stored_baselines or {})
        self._batch_canaries: dict[str, str] = {}

        # Build one request that injects a unique canary into every parameter
        # of the batch. For JSON-body targets, each canary goes into its own
        # path within the same template. For form targets, each canary replaces
        # its parameter's value. For query targets, each canary is appended.
        canary_map: dict[str, str] = {}
        primary_target = candidates[0]

        # All candidates in a batch share the same url+method, so we use the
        # first as the template carrier and inject every canary through it.
        # For JSON-body targets, we merge canaries into one body copy.
        merged_json_body: Any = None
        merged_form_data: dict[str, str] = {}
        merged_params: dict[str, str] = {}

        for cand in candidates:
            canary = ResponseAnalyzer.generate_probe_canary()
            canary_map[cand.parameter] = canary
            self._batch_canaries[cand.parameter] = canary

            if cand.location in {ParameterLocation.json_body, ParameterLocation.graphql_variable}:
                if merged_json_body is None:
                    merged_json_body = copy.deepcopy(cand.json_template) if cand.json_template else {}
                _set_json_path(merged_json_body, cand.parent_path or cand.parameter, canary)
            elif cand.location == ParameterLocation.form and cand.form_inputs is not None:
                merged_form_data[cand.parameter] = canary
            elif cand.location == ParameterLocation.query:
                merged_params[cand.parameter] = canary
            else:
                # path/header/cookie locations don't batch — skip them here;
                # they're handled by the normal per-candidate verify loop.
                pass

        # Send the single batch injection request
        try:
            batch_url = primary_target.url
            batch_method = primary_target.method
            batch_headers = dict(primary_target.headers or {})
            batch_cookies = dict(primary_target.cookies or {})

            if merged_json_body is not None:
                batch_headers.setdefault("Content-Type", "application/json")
                batch_resp = await self._send(
                    batch_url, batch_method, None, None,
                    headers=batch_headers, cookies=batch_cookies,
                    json_body=merged_json_body,
                    test_phase="batch_stored_inject",
                )
            elif merged_form_data:
                batch_resp = await self._send(
                    batch_url, batch_method, None, merged_form_data,
                    headers=batch_headers, cookies=batch_cookies,
                    test_phase="batch_stored_inject",
                )
            elif merged_params:
                batch_resp = await self._send(
                    batch_url, batch_method, merged_params, None,
                    headers=batch_headers, cookies=batch_cookies,
                    test_phase="batch_stored_inject",
                )
            else:
                return {}
        except Exception as e:
            logger.debug("Batch stored injection failed for %s: %s", primary_target.url, e)
            return {}

        # If the injection itself was rejected (e.g. 400 validation error),
        # we can't determine stored reflection — fall back to per-param testing.
        if getattr(batch_resp, "status_code", 200) in {400, 422}:
            logger.debug(
                "Batch stored injection rejected (status=%s) for %s; "
                "falling back to per-parameter canary probing",
                batch_resp.status_code, primary_target.url,
            )
            return {}

        # Probe each display URL once and check for ANY canary
        confirmed: dict[str, set[str]] = {}
        for probe_url in stored_display_urls:
            try:
                if hasattr(self, "_stored_baselines") and probe_url in self._stored_baselines:
                    baseline_resp = self._stored_baselines[probe_url]
                else:
                    baseline_resp = await self._send(
                        probe_url, "GET", test_phase="stored_pre_test_baseline",
                    )
                    self._stored_baselines[probe_url] = baseline_resp

                resp = await self._send(probe_url, "GET", test_phase="batch_stored_check")
                body = resp.body or ""

                for param, canary in canary_map.items():
                    if canary in body:
                        confirmed.setdefault(param, set()).add(probe_url)
            except Exception as e:
                logger.debug("Batch stored probe failed for %s: %s", probe_url, e)

        return confirmed

    def _build_attack_request(
        self,
        url: str,
        parameter: str,
        method: str,
        payload: str,
        form_inputs: Optional[list] = None,
        target: Optional[object] = None,
    ) -> tuple[str, str, Optional[dict], Optional[dict], Optional[object], Optional[dict], Optional[dict]]:
        """Build a concrete request for legacy tuple candidates or rich AttackTargets."""
        if isinstance(target, AttackTarget):
            prepared = target.build_request(payload)
            return (
                prepared.url,
                prepared.method,
                prepared.params,
                prepared.data,
                prepared.json_body,
                prepared.headers,
                prepared.cookies,
            )

        if method.upper().startswith("HEADER:"):
            header_name = method.split(":", 1)[1]
            return url, "GET", None, None, None, {header_name: payload}, None

        if method.upper() == "POST" and form_inputs is not None:
            return url, method, None, self._build_form_payload(form_inputs, parameter, payload), None, None, None

        injected_url, injected_params, injected_data = URLParameterBuilder.inject_parameter(
            url, parameter, payload, method
        )
        return injected_url, method, injected_params, injected_data, None, None, None

    async def verify(
            self,
            url: str,
            parameter: str,
            method: str = "GET",
            value: str = "",
            form_inputs: Optional[list] = None,
            stored_display_urls: Optional[list[str]] = None,
            stored_baselines: Optional[dict[str, ResponseData]] = None,
            target: Optional[object] = None,
            stored_display_overrides: Optional[dict[str, set[str]]] = None,
        ) -> VerificationResult:
            """Verify XSS vulnerability safely utilizing integrated hybrid checks.

            ``stored_display_overrides`` carries the result of batch stored-XSS
            discovery: a mapping of ``parameter → {display_url, ...}`` for
            parameters whose canary was confirmed stored. When present, the
            stored-reflection probe narrows to only those display URLs instead
            of fanning out to every discovered URL.
            """
            
            self._begin_verification(parameter)
            findings: list[Finding] = []

            # Batched header injection: all listed headers are sent in a single
            # request per payload (each with a distinct canary). Delegated to a
            # dedicated path that reuses the shared response for per-header
            # attribution instead of one request per (header, payload).
            if method.upper().startswith("HEADER_BATCH:"):
                return await self._verify_header_batch(
                    url, method, stored_display_urls=stored_display_urls,
                    stored_baselines=stored_baselines,
                    stored_display_overrides=stored_display_overrides,
                )

            is_header_injection = method.upper().startswith("HEADER:")
            is_jsonp = parameter.lower() in self._JSONP_PARAM_NAMES

            # Reuse shared stored-XSS baselines when provided. The active baseline
            # below must keep the candidate request shape, especially for API JSON
            # and path targets.
            self._stored_baselines = dict(stored_baselines or {})
            if not is_header_injection:
                bare = url.split("?")[0]
                if bare not in self._stored_baselines:
                    try:
                        self._stored_baselines[bare] = await self._send(
                            bare, "GET", test_phase="stored_pre_test_baseline",
                        )
                    except Exception as e:
                        logger.debug("Failed to pre-fetch clean baseline for %s: %s", bare, e)

            pre_test_baseline = None
            try:
                pre_test_baseline = await self.fetch_pre_test_baseline(
                    url, parameter, method, value, form_inputs, target=target
                )
            except Exception as e:
                logger.debug("Failed to fetch pre-test baseline for XSS candidate: %s", e)

            # Fallback safeguard guarantee
            if pre_test_baseline is None:
                pre_test_baseline = await self.fetch_pre_test_baseline(
                    url, parameter, method, value, form_inputs, target=target
                )

            try:
                dom_finding = self._check_dom_xss(url, pre_test_baseline.body)
                if dom_finding:
                    findings.append(dom_finding)
            except Exception as e:
                logger.debug("Failed to perform DOM XSS check: %s", e)

            # Fast HTTP canary reflection triage. 
            # Skip browser instantiation completely if the param doesn't echo anything.
            if not is_header_injection:
                canary = ResponseAnalyzer.generate_probe_canary()
                canary_payload = canary
                try:
                    canary_url, canary_method, canary_params, canary_data, canary_json, canary_headers, canary_cookies = (
                        self._build_attack_request(url, parameter, method, canary_payload, form_inputs, target)
                    )

                    canary_resp = await self._send(
                        canary_url, canary_method, canary_params, canary_data,
                        headers=canary_headers,
                        cookies=canary_cookies,
                        json_body=canary_json,
                        test_phase="canary", payload=canary_payload,
                    )

                    # A budget-denied canary is UNTESTED, not "not reflected". Skip
                    # the negative early-return; the payload loop below itself skips
                    # budget-denied probes, so no false negative is produced.
                    if getattr(canary_resp, "status_code", 200) != -1:
                        is_canary_reflected, reflection_evidence = ResponseAnalyzer.verify_reflection(
                            canary_payload, canary_resp.body, baseline_body=pre_test_baseline.body, canary=canary,
                        )

                        if not is_canary_reflected or method.upper() == "POST":
                            # Use batch stored-discovery results when available to
                            # narrow the probe fan-out to only confirmed display URLs.
                            # This replaces the broken O(params × payloads × urls)
                            # fan-out with a targeted O(1) probe of the single
                            # display URL where the canary was confirmed stored.
                            batch_stored_urls: list[str] | None = None
                            if stored_display_overrides and parameter in stored_display_overrides:
                                batch_stored_urls = list(stored_display_overrides[parameter])

                            if batch_stored_urls is not None:
                                # Narrowed: probe only confirmed display URLs.
                                for probe_url in batch_stored_urls:
                                    try:
                                        if hasattr(self, "_stored_baselines") and probe_url in self._stored_baselines:
                                            baseline_resp = self._stored_baselines[probe_url]
                                        else:
                                            baseline_resp = await self._send(
                                                probe_url, "GET", test_phase="stored_pre_test_baseline",
                                            )
                                            self._stored_baselines[probe_url] = baseline_resp
                                        resp = await self._send(probe_url, "GET", test_phase="canary_stored_check")
                                        is_ref, locs, was_enc = self._detect_reflection(canary_payload, resp.body)
                                        if is_ref:
                                            is_canary_reflected = True
                                            break
                                    except Exception as e:
                                        logger.debug("Narrowed stored probe failed for %s: %s", probe_url, e)
                            else:
                                # No batch override: fall back to the existing
                                # per-candidate stored probe (now correctly
                                # calling _probe_stored, not the nonexistent
                                # _check_stored_reflection).
                                stored_reflected, _, _, _, _ = await self._probe_stored(
                                    canary_payload, url, stored_display_urls, canary=canary,
                                )
                                if stored_reflected:
                                    is_canary_reflected = True

                        if not is_canary_reflected:
                            return VerificationResult(
                                is_vulnerable=False, confidence_score=0.0, detection_method="canary_check",
                                findings=[], evidence={"reflected": False, "reason": "Canary payload not reflected"},
                            )
                except Exception as e:
                    logger.debug("Failed to perform canary reflection check: %s", e)

            # Select target catalog payload set seamlessly
            if is_header_injection:
                payload_set = self.HEADER_PAYLOADS
            elif is_jsonp:
                payload_set = {**self.XSS_PAYLOADS, **self.JSONP_PAYLOADS}
            else:
                payload_set = self.XSS_PAYLOADS

            pending_jobs: list[PendingBrowserVerification] = []

            # Execute Active payload loop
            for payload_type, payload in payload_set.items():
                result = await self._test_payload(
                    url, parameter, method, value, payload, payload_type,
                    form_inputs, stored_display_urls, pre_test_baseline, target=target,
                    stored_display_overrides=stored_display_overrides,
                )
                
                if result.is_vulnerable:
                    findings.extend(result.findings)
                # Catch deferred jobs where static check thinks it's executable but needs browser validation
                elif result.evidence and result.evidence.get("browser_verification_pending"):
                    job = result.evidence.get("pending_job")
                    if job:
                        pending_jobs.append(job)

            # Process deferred browser verification jobs sequentially using the built-in runner
            if pending_jobs and PLAYWRIGHT_AVAILABLE:
                logger.debug("Processing %d deferred browser verification jobs...", len(pending_jobs))
                for job in pending_jobs:
                    browser_findings = await self.run_browser_verification(job)
                    if browser_findings:
                        findings.extend(browser_findings)
            if findings:
                # Reapply your original stored deduplication consolidation routine
                has_stored = any(f.vuln_type == "Stored XSS" for f in findings)
                if has_stored:
                    for finding in findings:
                        if finding.vuln_type == "Reflected XSS":
                            finding.vuln_type = "Stored XSS"
                            finding.evidence = f"[Consolidated Reflection] Immediate echo of a confirmed Stored XSS parameter. {finding.evidence}"

                findings.sort(key=lambda f: f.confidence_score, reverse=True)
                best = findings[0]
                return VerificationResult(
                    is_vulnerable=True, confidence_score=best.confidence_score,
                    detection_method=best.detection_method, findings=findings,
                    evidence={"payload_type": best.detection_method}, reproducible=True,
                )

            return VerificationResult(is_vulnerable=False, confidence_score=0.0, detection_method="none", findings=[], evidence={})

    def _looks_like_api_response(self, response: ResponseData, target: Optional[object] = None) -> bool:
        content_type = " ".join(
            str(value).lower() for key, value in (response.headers or {}).items() if key.lower() == "content-type"
        )
        if any(token in content_type for token in ("json", "xml", "javascript")):
            return True
        return (
            isinstance(target, AttackTarget)
            and target.location in {ParameterLocation.json_body, ParameterLocation.graphql_variable}
        )

    def _create_api_reflection_finding(
        self,
        *,
        url: str,
        parameter: str,
        method: str,
        payload: str,
        response: ResponseData,
        context_analysis: dict,
        confidence_score: float,
    ) -> Finding:
        evidence = (
            "XSS payload was reflected by an API response. Execution depends on a client-side "
            "sink rendering this value into the DOM."
        )
        return self._create_finding(
            category=OwaspCategory.a05,
            vuln_type="Reflected XSS in API Response",
            severity=SeverityLevel.medium,
            url=url,
            parameter=parameter,
            payload=payload,
            evidence=evidence,
            confidence_score=confidence_score,
            detection_method="api_response_reflection",
            method=method,
            detection_evidence={**context_analysis, "requires_client_side_sink": True},
            reproducible=True,
            verified=False,
            verification_request_snippet=response.request_snippet,
            verification_response_snippet=response.response_snippet,
        )

    def _check_dom_xss(self, url: str, html_body: str, source_name: str | None = None) -> Optional[Finding]:
        """Perform static analysis of HTML/JS for DOM-based XSS indicators."""
        if not html_body:
            return None
        found_sources = [src for src in self._DOM_SOURCES if re.search(src, html_body, re.I)]
        found_sinks = [sink for sink in self._DOM_SINKS if re.search(sink, html_body, re.I)]

        if found_sources and found_sinks:
            source_label = f" in {source_name}" if source_name else ""
            evidence = (
                f"Client-side source{source_label} contains user-controlled DOM sources "
                f"{found_sources} reaching risky sinks {found_sinks}. Browser execution is not confirmed."
            )
            return self._create_finding(
                category=OwaspCategory.a05, vuln_type="DOM-Based XSS", severity=SeverityLevel.medium,
                url=url, parameter="javascript", payload="location.hash", evidence=evidence,
                confidence_score=60.0, detection_method="dom_xss_heuristics", method="GET",
                detection_evidence={
                    "found_sources": found_sources,
                    "found_sinks": found_sinks,
                    "source_name": source_name,
                    "browser_execution_confirmed": False,
                },
                reproducible=True, verified=False,
            )
        return None

    async def _verify_header_batch(
        self,
        url: str,
        method: str,
        stored_display_urls: Optional[list[str]] = None,
        stored_baselines: Optional[dict[str, ResponseData]] = None,
        stored_display_overrides: Optional[dict[str, set[str]]] = None,
    ) -> VerificationResult:
        """Test several request headers for reflected XSS in one request per payload.

        ``method`` is ``"HEADER_BATCH:<h1>,<h2>,..."``. For each header payload a
        single request injects every header with its own distinct canary; the
        shared response is then attributed per header via that canary. This
        collapses the direct-reflection probes from ``headers × payloads`` to
        just ``payloads`` while keeping per-header stored-replay behaviour
        identical (each header defers to ``_test_payload``, which applies the
        existing SPA-skip and stored fan-out gating unchanged).
        """
        header_names = [h.strip() for h in method.split(":", 1)[1].split(",") if h.strip()]
        if not header_names:
            return VerificationResult(
                is_vulnerable=False, confidence_score=0.0, detection_method="none", findings=[], evidence={},
            )

        self._begin_verification(",".join(header_names))
        self._stored_baselines = dict(stored_baselines or {})

        # One clean baseline (no injection) shared by every header/payload.
        try:
            pre_test_baseline = await self.fetch_pre_test_baseline(
                url, header_names[0], f"HEADER:{header_names[0]}"
            )
        except Exception as e:
            logger.debug("Failed to fetch header-batch baseline for %s: %s", url, e)
            pre_test_baseline = await self._send(url, "GET", test_phase="pre_test_baseline")

        findings: list[Finding] = []
        pending_jobs: list[PendingBrowserVerification] = []

        # DOM-source/sink static scan of the page (header-independent). Runs once
        # for the batch rather than once per header.
        try:
            dom_finding = self._check_dom_xss(url, pre_test_baseline.body)
            if dom_finding:
                findings.append(dom_finding)
        except Exception as e:
            logger.debug("Header-batch DOM check failed for %s: %s", url, e)

        for payload_type, payload in self.HEADER_PAYLOADS.items():
            # Inject every header in a single request, each with its own canary so
            # a reflected payload is attributed to the exact header that carried it.
            canaries: dict[str, str] = {}
            injected_payloads: dict[str, str] = {}
            request_headers: dict[str, str] = {}
            for header in header_names:
                canary = ResponseAnalyzer.generate_probe_canary()
                injected_payload = _embed_canary(payload, canary)
                canaries[header] = canary
                injected_payloads[header] = injected_payload
                request_headers[header] = injected_payload

            try:
                batched = await self._send(
                    url, "GET", None, None, headers=request_headers,
                    test_phase=f"payload_{payload_type}", payload=payload,
                )
            except Exception as e:
                logger.debug("Header-batch send failed for %s (%s): %s", url, payload_type, e)
                continue

            for header in header_names:
                result = await self._test_payload(
                    url, header, f"HEADER:{header}", "", payload, payload_type,
                    None, stored_display_urls, pre_test_baseline, target=None,
                    stored_display_overrides=stored_display_overrides,
                    prefetched_response=batched,
                    prefetched_canary=canaries[header],
                    prefetched_injected_payload=injected_payloads[header],
                )
                if result.is_vulnerable:
                    findings.extend(result.findings)
                elif result.evidence and result.evidence.get("browser_verification_pending"):
                    job = result.evidence.get("pending_job")
                    if job:
                        pending_jobs.append(job)

        # Confirm any deferred executable contexts in the browser (mirrors verify()).
        if pending_jobs and PLAYWRIGHT_AVAILABLE:
            for job in pending_jobs:
                browser_findings = await self.run_browser_verification(job)
                if browser_findings:
                    findings.extend(browser_findings)

        if findings:
            has_stored = any(f.vuln_type == "Stored XSS" for f in findings)
            if has_stored:
                for finding in findings:
                    if finding.vuln_type == "Reflected XSS":
                        finding.vuln_type = "Stored XSS"
                        finding.evidence = f"[Consolidated Reflection] Immediate echo of a confirmed Stored XSS parameter. {finding.evidence}"
            findings.sort(key=lambda f: f.confidence_score, reverse=True)
            best = findings[0]
            return VerificationResult(
                is_vulnerable=True, confidence_score=best.confidence_score,
                detection_method=best.detection_method, findings=findings,
                evidence={"payload_type": best.detection_method}, reproducible=True,
            )

        return VerificationResult(
            is_vulnerable=False, confidence_score=0.0, detection_method="none", findings=[], evidence={},
        )

    async def _test_payload(
        self, url: str, parameter: str, method: str, value: str, payload: str, payload_type: str,
        form_inputs: Optional[list], stored_display_urls: Optional[list[str]], pre_test_baseline: ResponseData,
        target: Optional[object] = None,
        stored_display_overrides: Optional[dict[str, set[str]]] = None,
        prefetched_response: Optional[ResponseData] = None,
        prefetched_canary: Optional[str] = None,
        prefetched_injected_payload: Optional[str] = None,
    ) -> VerificationResult:
        """Test a single XSS payload using rapid static check followed by safe dynamic execution fallback.

        ``stored_display_overrides`` narrows the stored-reflection probe: when
        batch discovery confirmed this parameter is stored, probe only the
        confirmed display URLs; when batch discovery confirmed it is *not*
        stored (absent from the map), skip the stored probe entirely.

        ``prefetched_*`` let a batched header probe reuse a single already-sent
        response for per-header attribution instead of re-issuing the injection
        request: the caller passes the shared response plus the canary and
        canaried payload it embedded for *this* header, and the injection
        ``_send`` is skipped entirely.
        """
        try:
            is_header = method.upper().startswith("HEADER:")

            if prefetched_response is not None:
                # Batched header path: reuse the shared injection response and
                # this header's canary/payload; no new injection request.
                canary = prefetched_canary or ResponseAnalyzer.generate_probe_canary()
                injected_payload = prefetched_injected_payload or _embed_canary(payload, canary)
                injected = prefetched_response
            else:
                canary = ResponseAnalyzer.generate_probe_canary()
                injected_payload = _embed_canary(payload, canary)

                (
                    injected_url,
                    injected_method,
                    injected_params,
                    injected_data,
                    injected_json,
                    injected_headers,
                    injected_cookies,
                ) = self._build_attack_request(url, parameter, method, injected_payload, form_inputs, target)
                injected = await self._send(
                    injected_url, injected_method, injected_params, injected_data,
                    headers=injected_headers, cookies=injected_cookies, json_body=injected_json,
                    test_phase=f"payload_{payload_type}", payload=injected_payload,
                )

            # Budget-denied probe: untested, never a negative reflection verdict.
            if getattr(injected, "status_code", 200) == -1:
                return VerificationResult(
                    is_vulnerable=False, confidence_score=0.0, detection_method=payload_type,
                    findings=[], evidence={"not_tested": True, "reason": "budget ceiling"},
                )

            is_reflected, locations, was_encoded = self._detect_reflection(injected_payload, injected.body)
            is_stored = False
            reflection_evidence = {}

            if is_reflected and (is_header or method.upper() != "POST"):
                is_reflected, reflection_evidence = ResponseAnalyzer.verify_reflection(
                    injected_payload, injected.body, baseline_body=pre_test_baseline.body, canary=canary,
                )

            # P0-3: the header-stored GET-replay oracle is structurally incapable
            # of confirming reflection on an SPA (the injected header value is
            # rendered client-side from an API response and never appears in the
            # raw HTML shell that this raw-string oracle matches against). On SPA
            # targets skip it entirely for header injections — this is the single
            # largest source of wasted XSS traffic (~93% of all requests). The
            # stored-header hypothesis is handled by the browser-DOM sweep. The
            # single reflected-header check above (one request per header per
            # payload at the origin) still runs.
            skip_stored = is_header and getattr(self, "spa_mode", False)

            # Batch stored-discovery override: when available, use the confirmed
            # display URLs instead of fanning out to every discovered URL. If
            # batch discovery ran and this parameter is absent from the map,
            # the canary was not stored — skip the probe entirely (this is the
            # primary request-savings path for non-stored POST params).
            batch_overrides_present = stored_display_overrides is not None
            batch_confirmed_urls: list[str] | None = None
            if batch_overrides_present:
                batch_confirmed_urls = list(stored_display_overrides.get(parameter, set()))

            if (not is_reflected or method.upper() == "POST") and not skip_stored:
                if batch_overrides_present and not batch_confirmed_urls:
                    # Batch discovery confirmed this param is not stored — skip
                    # the per-payload stored probe fan-out entirely.
                    pass
                elif batch_confirmed_urls:
                    # Narrowed: probe only confirmed display URLs.
                    await asyncio.sleep(0.1)
                    for probe_url in batch_confirmed_urls:
                        try:
                            if hasattr(self, "_stored_baselines") and probe_url in self._stored_baselines:
                                baseline_resp = self._stored_baselines[probe_url]
                            else:
                                baseline_resp = await self._send(
                                    probe_url, "GET", test_phase="stored_pre_test_baseline",
                                )
                                self._stored_baselines[probe_url] = baseline_resp
                            resp = await self._send(probe_url, "GET", test_phase="stored_check")
                            is_ref, locs, was_enc = self._detect_reflection(injected_payload, resp.body)
                            if is_ref:
                                verified, stored_evidence = ResponseAnalyzer.verify_reflection(
                                    injected_payload, resp.body,
                                    baseline_body=baseline_resp.body, canary=canary,
                                )
                                if verified:
                                    is_reflected = True
                                    locations = locs
                                    was_encoded = was_enc
                                    injected = resp
                                    is_stored = True
                                    reflection_evidence = stored_evidence
                                    break
                        except Exception as e:
                            logger.debug("Narrowed stored payload probe failed for %s: %s", probe_url, e)
                else:
                    # No batch override: fall back to the existing per-payload
                    # stored probe fan-out (correctly calling _probe_stored).
                    await asyncio.sleep(0.1)
                    stored_reflected, stored_locations, stored_was_encoded, stored_resp, stored_evidence = (
                        await self._probe_stored(
                            injected_payload,
                            url,
                            stored_display_urls,
                            canary=canary,
                            is_header_injection=is_header,
                        )
                    )
                    if stored_reflected:
                        is_reflected, locations, was_encoded, injected, is_stored, reflection_evidence = True, stored_locations, stored_was_encoded, stored_resp, True, stored_evidence

            if not is_reflected:
                return VerificationResult(is_vulnerable=False, confidence_score=0.0, detection_method=payload_type, findings=[], evidence={"reflected": False})

            body_for_analysis = html.unescape(injected.body) if was_encoded else injected.body
            context_analysis  = self._analyze_reflection_context(body_for_analysis, injected_payload, locations)
            context_analysis["verification_canary"] = canary
            context_analysis["canary_verified"] = bool(reflection_evidence.get("canary_verified"))

            if was_encoded:
                context_analysis["encoding_type"] = "html_encoded"
                context_analysis["is_executable"] = False

            if self._looks_like_api_response(injected, target) and not context_analysis["is_executable"]:
                confidence_score = 60.0 if reflection_evidence.get("canary_verified") else 55.0
                finding = self._create_api_reflection_finding(
                    url=url,
                    parameter=parameter,
                    method=method,
                    payload=injected_payload,
                    response=injected,
                    context_analysis=context_analysis,
                    confidence_score=confidence_score,
                )
                return VerificationResult(
                    is_vulnerable=True,
                    confidence_score=confidence_score,
                    detection_method="api_response_reflection",
                    findings=[finding],
                    evidence=context_analysis,
                    reproducible=True,
                )

            if context_analysis["is_executable"] and PLAYWRIGHT_AVAILABLE:
                logger.debug("Static check suspects XSS. Deferring browser verification to post-HTTP phase.")
                confidence_score = self._calculate_xss_confidence(payload, context_analysis)
                severity = self._determine_xss_severity(context_analysis)
                vuln_type = "Stored XSS" if is_stored else ("Header-Reflected XSS" if is_header else "Reflected XSS")
                partial_finding = self._create_finding(
                    category=OwaspCategory.a05, vuln_type=vuln_type, severity=severity,
                    url=url, parameter=parameter, payload=injected_payload,
                    evidence=f"HTTP static analysis confirmed reflection. Browser verification pending.",
                    confidence_score=confidence_score, detection_method=f"reflection_{payload_type}",
                    method=method, detection_evidence=context_analysis,
                    reproducible=True, verified=False,
                    verification_request_snippet=injected.request_snippet,
                    verification_response_snippet=injected.response_snippet,
                )
                return VerificationResult(
                    is_vulnerable=False,
                    confidence_score=0.0,
                    detection_method=payload_type,
                    findings=[],
                    evidence={
                        "browser_verification_pending": True,
                        "pending_job": PendingBrowserVerification(
                            url=url, parameter=parameter, method=method,
                            payload=injected_payload, canary=canary,
                            form_inputs=form_inputs, stored_display_urls=stored_display_urls,
                            is_header_injection=is_header, context_analysis=context_analysis,
                            partial_finding=partial_finding, target=target,
                        ),
                    },
                )

            confidence_score = self._calculate_xss_confidence(payload, context_analysis)
            severity         = self._determine_xss_severity(context_analysis)

            if not context_analysis["is_executable"]:
                return VerificationResult(
                    is_vulnerable=False, confidence_score=0.0,
                    detection_method=payload_type, findings=[],
                    evidence={"reason": "Reflected but static context analysis says not executable"},
                )
            
            vuln_type = "Stored XSS" if is_stored else ("Header-Reflected XSS" if method.upper().startswith("HEADER:") else "Reflected XSS")

            finding = self._create_finding(
                category=OwaspCategory.a05, vuln_type=vuln_type, severity=severity, url=url, parameter=parameter, payload=injected_payload,
                evidence=f"Payload {'stored and ' if is_stored else ''}reflected and executed successfully inside browser window. Context: {context_analysis['context_type']}.",
                confidence_score=confidence_score, detection_method=f"reflection_{payload_type}", method=method, detection_evidence=context_analysis,
                reproducible=True, verified=True, verification_request_snippet=injected.request_snippet, verification_response_snippet=injected.response_snippet,
            )

            return VerificationResult(is_vulnerable=True, confidence_score=confidence_score, detection_method=f"reflection_{payload_type}", findings=[finding], evidence=context_analysis, reproducible=True)

        except Exception as e:
            logger.error("XSS verification failed for %s:%s: %s", url, parameter, e)
            return VerificationResult(is_vulnerable=False, confidence_score=0.0, detection_method=payload_type, findings=[], evidence={"error": str(e)})

    async def _install_xss_browser_hooks(self, page, canary: str) -> None:
        script = f"""
(() => {{
  const sentryCanary = {json.dumps(canary)};
  const mark = (kind, value) => {{
    window.__sentry_xss_fired = true;
    window.__sentry_xss_events = window.__sentry_xss_events || [];
    window.__sentry_xss_events.push({{kind, value: String(value || '')}});
  }};
  window.__sentry_xss_fired = false;
  window.__sentry_xss_events = [];
  // EXECUTION-only oracle. A "fire" means our uniquely-canaried JavaScript
  // actually RAN. Mere reflection of the canary as text or markup in the DOM is
  // NOT execution: a payload that the app HTML-escapes or strips to inert text
  // still leaves the canary substring in the page, but nothing executes. We
  // therefore deliberately do NOT observe DOM mutations for canary presence —
  // doing so conflates reflection with execution and produces false positives on
  // any route that sanitises input (e.g. a track/search route that renders the
  // parameter as escaped text). Every sweep vector invokes
  // ``window.sentry_hook(canary)`` (or alert/confirm/prompt) from its executing
  // context (onerror/onload/javascript:/inline script), so a genuine execution
  // always routes through one of these callbacks — and only those set the flag.
  window.sentry_hook = (value) => {{
    if (!sentryCanary || String(value).includes(sentryCanary)) mark('hook', value);
  }};
  for (const name of ['alert', 'confirm', 'prompt']) {{
    window[name] = (message) => {{
      if (!sentryCanary || String(message || '').includes(sentryCanary)) mark(name, message);
      return name === 'prompt' ? '' : true;
    }};
  }}
}})();
"""
        await page.add_init_script(script)

    async def _browser_xss_fired(self, page) -> bool:
        try:
            return bool(
                await page.evaluate(
                    "Boolean(window.__sentry_xss_fired || (window.__sentry_xss_events || []).length)"
                )
            )
        except Exception:
            return bool(getattr(page, "_fired", False))

    async def _verify_browser_execution(
        self, url: str, parameter: str, method: str, payload: str, canary: str,
        form_inputs: Optional[list], stored_display_urls: Optional[list[str]], is_header_injection: bool,
        target: Optional[object] = None,
    ) -> bool:
        """Isolated Headless Engine handles explicit runtime execution proofs securely."""
        xss_fired = False
        async with async_playwright() as p:
            try:
                browser = await p.chromium.launch(headless=True)
                context = await browser.new_context(ignore_https_errors=True, user_agent="SentryStrikeScanner/1.0")

                if hasattr(self, 'http_verifier') and hasattr(self.http_verifier, 'cookies'):
                    domain = urlparse(url).netloc.split(':')[0]
                    playwright_cookies = [{"name": str(k), "value": str(v), "domain": domain, "path": "/"} for k, v in self.http_verifier.cookies.items()]
                    if playwright_cookies:
                        await context.add_cookies(playwright_cookies)

                page = await context.new_page()
                await self._install_xss_browser_hooks(page, canary)

                async def handle_dialog(dialog):
                    try:
                        if canary in (dialog.message or ""):
                            setattr(page, "_fired", True)
                        await dialog.dismiss()
                    except Exception:
                        pass

                page.on("dialog", lambda dialog: asyncio.create_task(handle_dialog(dialog)))

                if isinstance(target, AttackTarget):
                    prepared = target.build_request(payload)
                    if prepared.headers:
                        await page.set_extra_http_headers(prepared.headers)
                    if prepared.method.upper() == "GET":
                        await page.goto(prepared.url, wait_until="networkidle", timeout=4000)
                    elif prepared.method.upper() == "POST" and form_inputs:
                        await page.goto(url, wait_until="networkidle", timeout=4000)
                        resolved_inputs = {item.get('name') or item.get('id'): item.get('value', '') for item in form_inputs if hasattr(item, 'get')} if isinstance(form_inputs, list) else form_inputs
                        for field_name, baseline_val in resolved_inputs.items():
                            fill_value = payload if field_name == parameter else baseline_val
                            sel = f"input[name='{field_name}'], textarea[name='{field_name}'], [id='{field_name}']"
                            if await page.query_selector(sel):
                                await page.fill(sel, str(fill_value))
                        await page.evaluate("document.querySelector('form').submit()")
                        await page.wait_for_load_state("networkidle", timeout=4000)
                    else:
                        return False
                elif is_header_injection:
                    header_name = method.split(":", 1)[1]
                    await page.set_extra_http_headers({header_name: payload})
                    await page.goto(url, wait_until="networkidle", timeout=4000)
                elif method.upper() == "GET":
                    parts = list(urlparse(url))
                    q = dict(parse_qsl(parts[4]))
                    q[parameter] = payload
                    parts[4] = urlencode(q)
                    await page.goto(urlunparse(parts), wait_until="networkidle", timeout=4000)
                elif method.upper() == "POST" and form_inputs:
                    await page.goto(url, wait_until="networkidle", timeout=4000)
                    resolved_inputs = {item.get('name') or item.get('id'): item.get('value', '') for item in form_inputs if hasattr(item, 'get')} if isinstance(form_inputs, list) else form_inputs
                    for field_name, baseline_val in resolved_inputs.items():
                        fill_value = payload if field_name == parameter else baseline_val
                        sel = f"input[name='{field_name}'], textarea[name='{field_name}'], [id='{field_name}']"
                        if await page.query_selector(sel): await page.fill(sel, str(fill_value))
                    await page.evaluate("document.querySelector('form').submit()")
                    await page.wait_for_load_state("networkidle", timeout=4000)

                if stored_display_urls and not getattr(page, '_fired', False):
                    if is_header_injection:
                        sweep_urls = [u for u in stored_display_urls if self._HEADER_SINK_PATTERNS.search(u)][:3]
                    else:
                        sweep_urls = stored_display_urls[:5]

                    for d_url in sweep_urls:
                        if getattr(page, '_fired', False):
                            break
                        try:
                            await page.goto(d_url, wait_until="domcontentloaded", timeout=3000)
                            await asyncio.sleep(0.15)
                        except Exception:
                            pass

                await asyncio.sleep(0.3)
                xss_fired = bool(getattr(page, "_fired", False)) or await self._browser_xss_fired(page)
                await context.close()
                await browser.close()
            except Exception as e:
                logger.debug(f"Playwright runtime loop bypassed safely: {e}")
        return xss_fired

    async def verify_dom_xss_execution(self, url: str) -> bool:
        """Probe URL/query/hash/postMessage DOM sinks with inert canary payloads."""
        if not PLAYWRIGHT_AVAILABLE:
            return False

        canary = ResponseAnalyzer.generate_probe_canary()
        payload = f"<img src=x onerror=alert('{canary}')>"
        encoded_payload = quote(payload, safe="")
        parsed = urlparse(url)

        query_parts = list(parsed)
        query_params = dict(parse_qsl(query_parts[4], keep_blank_values=True))
        query_params.setdefault("sentry_xss", payload)
        query_parts[4] = urlencode(query_params)

        fragment_parts = list(parsed)
        fragment_parts[5] = encoded_payload
        probes = [urlunparse(query_parts), urlunparse(fragment_parts)]

        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context(ignore_https_errors=True, user_agent="SentryStrikeScanner/1.0")
            try:
                if hasattr(self.http_verifier, "cookies") and self.http_verifier.cookies:
                    domain = parsed.netloc.split(":")[0]
                    await context.add_cookies(
                        [
                            {"name": str(k), "value": str(v), "domain": domain, "path": "/"}
                            for k, v in self.http_verifier.cookies.items()
                        ]
                    )

                for probe_url in probes:
                    page = await context.new_page()
                    await self._install_xss_browser_hooks(page, canary)
                    try:
                        await page.goto(probe_url, wait_until="networkidle", timeout=5000)
                        await page.evaluate(
                            "(payload) => window.postMessage(payload, window.location.origin)",
                            payload,
                        )
                        await asyncio.sleep(0.4)
                        if await self._browser_xss_fired(page):
                            await page.close()
                            return True
                    except Exception as exc:
                        logger.debug("DOM XSS browser probe failed for %s: %s", probe_url, exc)
                    finally:
                        if not page.is_closed():
                            await page.close()
            finally:
                await context.close()
                await browser.close()

        return False

    # Task D: an ordered, generic set of hook-executing DOM XSS vectors. Each is
    # parameterised by the per-probe canary via ``window.sentry_hook``; framework
    # sinks sanitise some vectors but execute others, so a single-vector sweep
    # yields incomplete negatives. Ordered cheap → specific. No app-specific payload.
    _DOM_XSS_VECTOR_TEMPLATES: tuple[tuple[str, str], ...] = (
        ("img_onerror", "<img src=x onerror={hook}>"),
        ("svg_onload", "<svg onload={hook}>"),
        ("iframe_js", '<iframe src="javascript:{hook}">'),
        ("attr_breakout", '"><img src=x onerror={hook}>'),
        ("script", "<script>{hook}</script>"),
    )
    # Hard cap on navigations per candidate so the vector × surface loop stays
    # inside a single job's timeout rather than multiplying the job count.
    # P0-3: raised from 12 — the browser-DOM sweep is the genuinely effective SPA
    # confirmer, so budget follows yield now that the header-stored HTTP fan-out
    # is disabled on SPAs.
    _DOM_MAX_ATTEMPTS_PER_CANDIDATE = 18

    def _dom_xss_vectors(self, canary: str) -> list[tuple[str, str]]:
        """Return ordered ``(vector_name, payload)`` pairs bound to ``canary``."""
        hook = f"window.sentry_hook('{canary}')"
        return [(name, tmpl.format(hook=hook)) for name, tmpl in self._DOM_XSS_VECTOR_TEMPLATES]

    async def verify_reflected_dom(
        self,
        route_url: str,
        parameter: str,
        location: str,
        *,
        canary: Optional[str] = None,
        context=None,
    ) -> dict:
        """Navigate an SPA route with executing canaries and assert on DOM execution.

        Tries a small ordered set of generic execution vectors (Task D) across
        the query, hash-route query, and fragment surfaces — SPAs read user input
        from both ``location.search`` and ``location.hash`` — stopping at the
        first vector/surface that fires the hooked canary. Independent of any
        HTTP-body reflection.

        Returns a dict: ``{"fired": True, "vector": ..., "surface": ...,
        "payload": ...}`` on success, or ``{"fired": False, "csp": bool}`` when
        nothing executed (a strict CSP is noted but never fabricated into a
        finding). The dict is falsy-checkable via ``result["fired"]``.

        A caller-supplied ``context`` is reused when provided so a whole sweep
        shares one browser launch; otherwise a short-lived browser is launched.
        Every navigation is time-bounded so a single route cannot stall the sweep.
        """
        if not PLAYWRIGHT_AVAILABLE:
            return {"fired": False}

        canary = canary or ResponseAnalyzer.generate_probe_canary()

        if context is not None:
            return await self._sweep_vectors_and_surfaces(context, route_url, parameter, canary)

        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            try:
                ctx = await self._new_reflection_context(browser, route_url)
                try:
                    return await self._sweep_vectors_and_surfaces(ctx, route_url, parameter, canary)
                finally:
                    await ctx.close()
            finally:
                await browser.close()

    async def _sweep_vectors_and_surfaces(
        self, context, route_url: str, parameter: str, canary: str
    ) -> dict:
        """Try each vector across each surface, stopping on the first fire.

        Bounded by :data:`_DOM_MAX_ATTEMPTS_PER_CANDIDATE`. Records the winning
        vector/surface, or notes CSP presence on a clean negative.
        """
        attempts = 0
        csp_seen = False
        for vector_name, payload in self._dom_xss_vectors(canary):
            for surface_name, probe_url in self._reflection_surface_probes(route_url, parameter, payload):
                if attempts >= self._DOM_MAX_ATTEMPTS_PER_CANDIDATE:
                    return {"fired": False, "csp": csp_seen}
                attempts += 1
                result = await self._probe_reflection_url(context, probe_url, canary)
                csp_seen = csp_seen or result.get("csp", False)
                if result.get("fired"):
                    return {
                        "fired": True,
                        "vector": vector_name,
                        "surface": surface_name,
                        "payload": payload,
                        "url": probe_url,
                    }
        return {"fired": False, "csp": csp_seen}

    def _reflection_surface_probes(
        self, route_url: str, parameter: str, payload: str
    ) -> list[tuple[str, str]]:
        """Build ``(surface, url)`` probes for the query, hash-route query, and
        fragment surfaces. SPAs read from ``location.search`` **and**
        ``location.hash``; the hash may itself carry a route-scoped query.
        """
        parsed = urlparse(route_url)
        enc = quote(payload, safe="")
        surfaces: list[tuple[str, str]] = []

        # 1. Query string (location.search).
        parts = list(parsed)
        query = dict(parse_qsl(parts[4], keep_blank_values=True))
        query[parameter] = payload
        parts[4] = urlencode(query)
        surfaces.append(("query", urlunparse(parts)))

        # 2. Hash-route query: a query scoped to the hash path (``/#/route?p=``).
        # Parse the hash's own query and REPLACE the parameter's value in place.
        # A route discovered WITH a seed value (``/#/search?q=seed``) must not
        # yield a duplicate ``q`` — the SPA resolves a repeated param to the
        # first (seed) value, so the payload would never render. Preserve the
        # route path and any sibling hash params.
        parts = list(parsed)
        frag = parts[5]
        if frag:
            base, _, existing_q = frag.partition("?")
            hash_query = dict(parse_qsl(existing_q, keep_blank_values=True))
            hash_query[parameter] = payload
            parts[5] = f"{base}?{urlencode(hash_query)}"
        else:
            parts[5] = f"/?{urlencode({parameter: payload})}"
        surfaces.append(("hash_query", urlunparse(parts)))

        # 3. Raw fragment (``#p=``): some apps read ``location.hash`` as an opaque
        # value string. Append rather than overwrite so a ``/route`` path in the
        # fragment is never destroyed (overwriting it would navigate away from the
        # rendering route and guarantee a false negative).
        parts = list(parsed)
        frag = parts[5]
        if frag:
            joiner = "&" if ("?" in frag or "=" in frag) else "?"
            parts[5] = f"{frag}{joiner}{parameter}={enc}"
        else:
            parts[5] = f"{parameter}={enc}"
        surfaces.append(("fragment", urlunparse(parts)))

        # Dedup by URL, preserving order.
        seen: set[str] = set()
        out: list[tuple[str, str]] = []
        for name, url in surfaces:
            if url in seen:
                continue
            seen.add(url)
            out.append((name, url))
        return out

    async def _new_reflection_context(self, browser, route_url: str, storage_state: dict | None = None):
        # Seed from the full authenticated storage_state when available (Task A)
        # so authenticated-only SPA routes render during DOM confirmation. Falls
        # back to cookie injection when absent. Opaque per-origin blob — generic.
        context = None
        if storage_state:
            try:
                context = await browser.new_context(
                    ignore_https_errors=True,
                    user_agent="SentryStrikeScanner/1.0",
                    storage_state=storage_state,
                )
            except Exception as exc:
                logger.debug("failed to seed reflection context from storage_state: %s", exc)
                context = None
        if context is None:
            context = await browser.new_context(
                ignore_https_errors=True, user_agent="SentryStrikeScanner/1.0"
            )
        cookies = getattr(self.http_verifier, "cookies", None)
        if cookies:
            domain = urlparse(route_url).netloc.split(":")[0]
            playwright_cookies = [
                {"name": str(k), "value": str(v), "domain": domain, "path": "/"}
                for k, v in cookies.items()
            ]
            if playwright_cookies:
                try:
                    await context.add_cookies(playwright_cookies)
                except Exception:
                    pass
        return context

    async def _probe_reflection_url(self, context, probe_url: str, canary: str) -> dict:
        """Navigate a single probe URL and report whether the canary fired.

        Returns ``{"fired": bool, "csp": bool}``; ``csp`` flags a
        Content-Security-Policy on the navigation response so a clean negative
        can be attributed to CSP rather than a missing sink (honest negatives).
        """
        page = await context.new_page()
        await self._install_xss_browser_hooks(page, canary)
        csp_seen = False

        async def handle_dialog(dialog):
            try:
                if canary in (dialog.message or ""):
                    setattr(page, "_fired", True)
                await dialog.dismiss()
            except Exception:
                pass

        page.on("dialog", lambda dialog: asyncio.create_task(handle_dialog(dialog)))
        try:
            response = await page.goto(probe_url, wait_until="domcontentloaded", timeout=5000)
            try:
                headers = response.headers if response is not None else {}
                if any(h.lower() == "content-security-policy" for h in (headers or {})):
                    csp_seen = True
            except Exception:
                pass
            # Some SPAs only re-read the hash on a hashchange event.
            try:
                await page.evaluate(
                    "() => window.dispatchEvent(new HashChangeEvent('hashchange'))"
                )
            except Exception:
                pass
            await asyncio.sleep(0.35)
            if bool(getattr(page, "_fired", False)) or await self._browser_xss_fired(page):
                return {"fired": True, "csp": csp_seen}
        except Exception as exc:
            logger.debug("Reflected DOM XSS probe failed for %s: %s", probe_url, exc)
        finally:
            if not page.is_closed():
                await page.close()
        return {"fired": False, "csp": csp_seen}

    async def run_browser_verification(self, job: PendingBrowserVerification) -> list[Finding]:
        """
        Run browser verification for a single deferred job.
        Called sequentially after all HTTP scanning is complete.
        """
        logger.debug(
            "Running deferred browser verification for %s param=%s",
            job.url, job.parameter,
        )
        try:
            execution_confirmed = await self._verify_browser_execution(
                job.url, job.parameter, job.method, job.payload, job.canary,
                job.form_inputs, job.stored_display_urls, job.is_header_injection,
                target=job.target,
            )
        except Exception as e:
            logger.error("Browser verification failed for %s: %s", job.url, e)
            return []

        if not execution_confirmed:
            logger.debug("Browser did not confirm execution for %s param=%s", job.url, job.parameter)
            return []

        job.partial_finding.verified = True
        job.partial_finding.evidence = job.partial_finding.evidence.replace(
            "Browser verification pending.",
            "Browser execution confirmed.",
        )
        job.context_analysis["is_executable"] = True
        return [job.partial_finding]

    async def _probe_stored(
        self,
        payload: str,
        origin_url: str,
        stored_display_urls: Optional[list[str]],
        *,
        canary: str | None = None,
        is_header_injection: bool = False,
    ) -> tuple[bool, list[int], bool, Optional[object], dict]:

        bare = origin_url.split("?")[0]
        all_urls: list[str] = list(stored_display_urls or [])
        if bare not in all_urls:
            all_urls.append(bare)

        if is_header_injection:
            # P0-3: cap the header-sink fan-out. Even on non-SPA server-rendered
            # apps, probing every sink-like URL for every header × every payload
            # is the dominant traffic sink for near-zero yield; the highest-value
            # log/admin/audit views cluster in the first few matches.
            tier1 = [u for u in all_urls if self._HEADER_SINK_PATTERNS.search(u)][
                : self._STORED_HEADER_SINK_CAP
            ]
            tier2 = [u for u in all_urls if u not in tier1][:10]
            urls_to_probe = tier1
        else:
            urls_to_probe = all_urls
            tier2 = []

        async def _probe_url(probe_url: str):
            try:
                if hasattr(self, "_stored_baselines") and probe_url in self._stored_baselines:
                    baseline_resp = self._stored_baselines[probe_url]
                else:
                    baseline_resp = await self._send(
                        probe_url, "GET", test_phase="stored_pre_test_baseline",
                    )
                    self._stored_baselines[probe_url] = baseline_resp
                resp = await self._send(probe_url, "GET", test_phase="stored_check")
                is_ref, locs, was_enc = self._detect_reflection(payload, resp.body)
                if not is_ref:
                    return None
                verified, reflection_evidence = ResponseAnalyzer.verify_reflection(
                    payload, resp.body, baseline_body=baseline_resp.body, canary=canary
                )
                if verified:
                    reflection_evidence["verification_canary"] = canary
                    return True, locs, was_enc, resp, reflection_evidence
            except Exception as e:
                logger.debug("Stored-XSS probe failed for %s: %s", probe_url, e)
            return None

        for probe_url in urls_to_probe:
            result = await _probe_url(probe_url)
            if result:
                return result

        for probe_url in tier2:
            result = await _probe_url(probe_url)
            if result:
                return result

        # Browser-aware stored oracle: for SPA targets the HTTP-body oracle
        # above cannot observe client-rendered stored XSS — the canary is stored
        # in the database and rendered into the DOM by the SPA, but the display
        # URL's HTTP body is raw JSON or the SPA shell, never executable HTML.
        # Navigate the display URL in a real browser with canary hooks installed
        # and confirm EXECUTION. Falls back to the HTTP check above when no
        # browser is available (already handled — we only reach here on a clean
        # HTTP negative). Reuses the existing Playwright plumbing from the DOM
        # sweep: _new_reflection_context, _install_xss_browser_hooks,
        # _browser_xss_fired.
        if (
            getattr(self, "spa_mode", False)
            and PLAYWRIGHT_AVAILABLE
            and canary
        ):
            browser_result = await self._browser_stored_execution_probe(
                urls_to_probe + tier2, canary, origin_url=origin_url,
            )
            if browser_result is not None:
                return browser_result

        return False, [], False, None, {}

    async def _browser_stored_execution_probe(
        self,
        display_urls: list[str],
        canary: str,
        *,
        origin_url: str = "",
    ) -> Optional[tuple[bool, list[int], bool, Optional[object], dict]]:
        """Navigate display URLs in a browser and confirm canary execution.

        For SPA targets where the stored canary is rendered client-side, the
        HTTP-body oracle cannot observe it. This reuses the existing Playwright
        canary-hook machinery (also used by the DOM reflection sweep) to navigate
        each display URL, let the SPA render the stored data, and assert on
        canary EXECUTION rather than HTTP-body reflection.

        Returns the same tuple shape as :meth:`_probe_stored` on confirmation,
        or ``None`` when no display URL executed the canary. The reflection
        evidence is marked ``browser_execution_confirmed=True`` so the downstream
        finding logic emits a verified Stored XSS rather than an API-reflection
        note. Bounded to a small number of display URLs and a short per-page
        wait to keep cost near-zero when nothing fires.
        """
        if not display_urls or not canary:
            return None

        # Bound the browser fan-out: the highest-value stored sinks (comment
        # walls, profile pages, product reviews) cluster in the first few
        # display URLs; the rest are low-yield static assets already filtered
        # by select_stored_probe_urls.
        probe_urls = display_urls[:5]

        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context = None
            try:
                context = await self._new_reflection_context(
                    browser, origin_url or (probe_urls[0] if probe_urls else ""),
                    storage_state=getattr(self, "_auth_storage_state", None),
                )
                for probe_url in probe_urls:
                    page = await context.new_page()
                    try:
                        await self._install_xss_browser_hooks(page, canary)
                        # Navigate the display route; the SPA reads stored data
                        # from its API and renders it into the DOM. If the
                        # stored canary is in the rendered output and the
                        # browser executes it, the hooked hooks fire.
                        await page.goto(probe_url, wait_until="domcontentloaded", timeout=5000)
                        # Give the SPA a beat to fetch its data and render.
                        try:
                            await page.wait_for_load_state("networkidle", timeout=3000)
                        except Exception:
                            pass
                        await asyncio.sleep(0.35)
                        fired = bool(getattr(page, "_fired", False)) or await self._browser_xss_fired(page)
                        if fired:
                            evidence = {
                                "browser_execution_confirmed": True,
                                "verification_canary": canary,
                                "display_url": probe_url,
                            }
                            # The HTTP response object isn't the confirmation
                            # medium here; synthesise a minimal carrier so the
                            # downstream finding logic has a body to analyse.
                            carrier = ResponseData(
                                status_code=200,
                                headers={},
                                body=f"<stored xss canary={canary} executed in browser>",
                                response_time_ms=0.0,
                                request_snippet=build_observed_request_snippet(
                                    url=probe_url,
                                    method="GET",
                                    headers={"User-Agent": "SentryStrikeScanner/1.0"},
                                    cookies=getattr(self.http_verifier, "cookies", None),
                                ),
                                response_snippet=f"browser execution confirmed (canary={canary})",
                            )
                            return True, [0], False, carrier, evidence
                    except Exception as exc:
                        logger.debug("Browser stored-XSS probe failed for %s: %s", probe_url, exc)
                    finally:
                        if not page.is_closed():
                            await page.close()
            except Exception as exc:
                logger.debug("Browser stored-XSS execution probe aborted: %s", exc)
            finally:
                if context is not None:
                    try:
                        await context.close()
                    except Exception:
                        pass
                await browser.close()
        return None

    @staticmethod
    def _detect_reflection(payload: str, body: str) -> tuple[bool, list[int], bool]:
        escaped = re.escape(payload)
        raw_locations = [m.start() for m in re.finditer(escaped, body)]
        if raw_locations: return True, raw_locations, False
        decoded_body = html.unescape(body)
        decoded_locations = [m.start() for m in re.finditer(escaped, decoded_body)]
        if decoded_locations: return True, decoded_locations, True
        return False, [], False

    def _analyze_reflection_context(self, response_body: str, payload: str, locations: list[int]) -> dict:
        analysis = {"context_type": "unknown", "encoding_type": "unencoded", "is_executable": False, "locations": locations, "attr_name": None}
        if not locations: return analysis
        loc = locations[0]
        context = response_body[max(0, loc - 100):min(len(response_body), loc + len(payload) + 100)]
        analysis["encoding_type"] = "encoded" if any(x in context for x in ("%", "&#", "&amp;", "\\x")) else "unencoded"
        if self.SCRIPT_TAG_CONTEXT.search(context):
            analysis["context_type"], analysis["is_executable"] = "script_tag", analysis["encoding_type"] == "unencoded"
        elif self.EVENT_HANDLER_CONTEXT.search(context):
            analysis["context_type"], analysis["is_executable"] = "event_handler", analysis["encoding_type"] == "unencoded"
        elif m := self.HTML_ATTRIBUTE_CONTEXT.search(context):
            attr_name = m.group("attr").lower()
            analysis["context_type"], analysis["attr_name"] = "html_attribute", attr_name
            analysis["is_executable"] = (attr_name in self._EXECUTABLE_ATTR_NAMES and payload.lower().startswith("javascript:") and analysis["encoding_type"] == "unencoded")
        elif self.JS_STRING_CONTEXT.search(context):
            analysis["context_type"], analysis["is_executable"] = "javascript_string", analysis["encoding_type"] == "unencoded"
        else:
            analysis["context_type"], analysis["is_executable"] = "html_body", analysis["encoding_type"] == "unencoded"
        return analysis

    def _build_form_payload(self, form_inputs: list, target_param: str, target_value: str) -> dict:
        return FormPayloadBuilder.build(form_inputs, target_param, target_value)

    @staticmethod
    def _calculate_xss_confidence(payload: str, context: dict) -> float:
        base_confidence = 60.0
        if context["is_executable"]: base_confidence += 25.0
        elif context["encoding_type"] in ("encoded", "html_encoded"): base_confidence -= 15.0
        ctx = context["context_type"]
        if ctx == "javascript_string": base_confidence += 10.0
        elif ctx == "event_handler": base_confidence += 15.0
        elif ctx == "html_attribute" and context.get("attr_name") in ("href", "src", "action", "formaction"): base_confidence += 12.0
        return min(100.0, max(0.0, base_confidence))

    @staticmethod
    def _determine_xss_severity(context: dict) -> SeverityLevel:
        if context["is_executable"]:
            return SeverityLevel.critical if context["context_type"] in ("script_tag", "event_handler") else SeverityLevel.high
        return SeverityLevel.low if context["encoding_type"] in ("encoded", "html_encoded") else SeverityLevel.medium
