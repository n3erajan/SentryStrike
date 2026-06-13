"""
Verification Framework: Base classes and utilities for active vulnerability testing.

Provides:
- BaseVerifier: Abstract base for verifiers
- HTTP client for sending test payloads
- Generic verification patterns
- Deduplication logic
"""

import asyncio
import json
import logging
import re
import httpx
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlencode, urlparse, parse_qs, parse_qsl, urlunparse

from app.core.detectors.attack_surface import build_json_body
from app.core.detectors.base_detector import Finding
from app.core.crawler.models import ParameterLocation
from app.core.verification.response_analyzer import ResponseAnalyzer, ResponseData
from app.models.vulnerability import OwaspCategory, SeverityLevel
from app.config import get_settings
from app.utils.http_logging import (
    ScanRequestContext,
    infer_payload_from_request,
    log_http_response,
    resolve_request_context,
)
from app.utils.scan_throttle import get_scan_http_semaphore

logger = logging.getLogger(__name__)


@dataclass
class VerificationResult:
    """Result of a verification attempt."""
    is_vulnerable: bool
    confidence_score: float  # 0-100
    detection_method: str  # e.g., "boolean_differential", "error_based"
    findings: list[Finding] = field(default_factory=list)
    evidence: dict = field(default_factory=dict)  # Detailed verification data
    reproducible: bool = field(default=False)


class HttpVerifier:
    """Handles HTTP requests for verification with timing and retry logic."""

    def __init__(
        self,
        timeout_seconds: float = 10.0,
        max_retries: int = 2,
        retry_delay_ms: int = 100,
        cookies: Optional[dict] = None,
        headers: Optional[dict] = None,
        follow_redirects: bool = True,
    ):
        self.timeout_seconds = timeout_seconds
        self.max_retries = max_retries
        self.retry_delay_ms = retry_delay_ms
        self.cookies = cookies or {}
        self.headers = headers or {"User-Agent": "SentryStrikeScanner/1.0"}
        self.follow_redirects = follow_redirects
        self._client: Optional[httpx.AsyncClient] = None
        self.request_context = ScanRequestContext()

    def set_request_context(self, **kwargs: str) -> None:
        """Set default module/parameter context for subsequent requests."""
        updates = {key: value for key, value in kwargs.items() if value}
        if updates:
            self.request_context = ScanRequestContext(
                module=updates.get("module", self.request_context.module),
                parameter=updates.get("parameter", self.request_context.parameter),
                test_phase=updates.get("test_phase", self.request_context.test_phase),
                payload=updates.get("payload", self.request_context.payload),
            )

    async def get_client(self) -> httpx.AsyncClient:
        """Get or create async HTTP client."""
        if self._client is None:
            settings = get_settings()
            pool_size = max(1, settings.scanner_concurrency)
            timeout = httpx.Timeout(
                connect=min(5.0, self.timeout_seconds),
                read=self.timeout_seconds,
                write=self.timeout_seconds,
                pool=min(5.0, self.timeout_seconds),
            )
            self._client = httpx.AsyncClient(
                timeout=timeout,
                limits=httpx.Limits(
                    max_connections=pool_size,
                    max_keepalive_connections=pool_size,
                ),
                cookies=self.cookies,
                headers=self.headers,
                follow_redirects=self.follow_redirects,
            )
        return self._client

    async def close(self):
        """Close HTTP client."""
        if self._client:
            await self._client.aclose()
            self._client = None

    async def send_request(
        self,
        url: str,
        method: str = "GET",
        params: Optional[dict] = None,
        data: Optional[dict] = None,
        capture_timing: bool = True,
        headers: Optional[dict] = None,
        cookies: Optional[dict] = None,
        json_body: Optional[object] = None,
        *,
        module: str = "",
        parameter: str = "",
        test_phase: str = "",
        payload: str = "",
    ) -> ResponseData:
        """
        Send HTTP request and capture response with timing.

        Args:
            url: Target URL
            method: HTTP method
            params: Query parameters
            data: POST body data
            capture_timing: Whether to measure response time
            headers: Dynamic headers for this request
            cookies: Dynamic cookies for this request

        Returns:
            ResponseData object
        """
        client = await self.get_client()
        import time
        from urllib.parse import urlencode, urlparse

        # Prepare request snippet for evidence
        parsed = urlparse(url)
        req_path = parsed.path or "/"
        if parsed.query:
            req_path += f"?{parsed.query}"
        if params:
            req_path += ("&" if "?" in req_path else "?") + urlencode(params)
        
        all_headers = {**self.headers, **(headers or {})}
        headers_str = "\n".join([f"{k}: {v}" for k, v in all_headers.items()])
        body_str = ""
        if json_body is not None:
            body_str = json.dumps(json_body, separators=(",", ":"), default=str)
        elif data:
            body_str = urlencode(data)
        
        request_snippet = f"{method} {req_path} HTTP/1.1\nHost: {parsed.netloc}\n{headers_str}\n\n{body_str}"

        ctx = resolve_request_context(
            instance_context=self.request_context,
            module=module,
            parameter=parameter,
            test_phase=test_phase,
            payload=payload,
        )
        effective_payload = ctx.payload or infer_payload_from_request(
            ctx.parameter, url, params, data
        )

        try:
            start_time = time.time() if capture_timing else None

            # httpx treats params={} as "replace query string with nothing",
            # wiping query params already embedded in *url*. Only pass params/data
            # when there are actual values to send.
            request_kwargs: dict = {"method": method, "url": url}
            if params:
                request_kwargs["params"] = params
            if data:
                request_kwargs["data"] = data
            if json_body is not None:
                request_kwargs["json"] = json_body
            if headers:
                request_kwargs["headers"] = headers
            if cookies:
                request_kwargs["cookies"] = cookies

            async with get_scan_http_semaphore():
                response = await client.request(**request_kwargs)

            end_time = time.time() if capture_timing else None
            response_time_ms = (end_time - start_time) * 1000 if capture_timing else 0

            log_http_response(
                method=method.upper(),
                url=str(response.url),
                status_code=response.status_code,
                module=ctx.module,
                parameter=ctx.parameter,
                test_phase=ctx.test_phase or "request",
                payload=effective_payload,
                response_time_ms=response_time_ms,
            )

            response_snippet = ResponseAnalyzer.build_evidence_response_snippet(
                status_code=response.status_code,
                reason_phrase=response.reason_phrase,
                headers=dict(response.headers),
                body=response.text,
                payload=effective_payload,
                extra_markers=[
                    ctx.module,
                    ctx.parameter,
                    ctx.test_phase,
                ],
            )

            return ResponseData(
                status_code=response.status_code,
                headers=dict(response.headers),
                body=response.text,
                response_time_ms=response_time_ms,
                request_snippet=request_snippet,
                response_snippet=response_snippet,
            )
        except asyncio.TimeoutError:
            log_http_response(
                method=method.upper(),
                url=url,
                status_code=0,
                module=ctx.module,
                parameter=ctx.parameter,
                test_phase=ctx.test_phase or "request",
                payload=effective_payload,
                response_time_ms=self.timeout_seconds * 1000,
            )
            logger.warning(f"Request timeout for {url}")
            return ResponseData(
                status_code=0,
                headers={},
                body="",
                response_time_ms=self.timeout_seconds * 1000,
                request_snippet=request_snippet,
                response_snippet="HTTP/1.1 0 Timeout Error\n\n",
            )
        except Exception as e:
            log_http_response(
                method=method.upper(),
                url=url,
                status_code=0,
                module=ctx.module,
                parameter=ctx.parameter,
                test_phase=ctx.test_phase or "request",
                payload=effective_payload,
            )
            logger.error(f"Request failed for {url}: {e}")
            return ResponseData(
                status_code=0,
                headers={},
                body="",
                response_time_ms=0,
                request_snippet=request_snippet,
                response_snippet=f"HTTP/1.1 0 Error: {str(e)}\n\n",
            )

    async def send_requests_batch(
        self,
        requests: list[tuple[str, str, Optional[dict], Optional[dict]]],
        *,
        test_phase: str = "",
    ) -> list[ResponseData]:
        """
        Send multiple requests concurrently.

        Args:
            requests: List of (url, method, params, data) tuples
            test_phase: Optional phase label applied to each request in the batch

        Returns:
            List of ResponseData objects in same order
        """
        tasks = [
            self.send_request(url, method, params, data, capture_timing=True, test_phase=test_phase)
            for url, method, params, data in requests
        ]
        return await asyncio.gather(*tasks)


class BaseVerifier(ABC):
    """Base class for vulnerability verifiers."""

    module_name: str = "unknown"

    def __init__(self, timeout_seconds: float = 10.0):
        self.http_verifier = HttpVerifier(timeout_seconds=timeout_seconds)
        self.logger = logging.getLogger(self.__class__.__name__)

    def _begin_verification(self, parameter: str) -> None:
        """Set module/parameter context for all requests in this verification."""
        self.http_verifier.set_request_context(
            module=self.module_name,
            parameter=parameter,
        )

    async def _send(
        self,
        url: str,
        method: str = "GET",
        params: Optional[dict] = None,
        data: Optional[dict] = None,
        *,
        headers: Optional[dict] = None,
        cookies: Optional[dict] = None,
        json_body: Optional[object] = None,
        test_phase: str = "request",
        payload: str = "",
    ) -> ResponseData:
        return await self.http_verifier.send_request(
            url,
            method,
            params,
            data,
            headers=headers,
            cookies=cookies,
            json_body=json_body,
            test_phase=test_phase,
            payload=payload,
        )

    async def fetch_pre_test_baseline(
        self,
        url: str,
        parameter: str,
        method: str = "GET",
        value: str = "",
        form_inputs: Optional[list] = None,
        target: Optional[object] = None,
    ) -> ResponseData:
        """
        Fetch a clean snapshot immediately before the first malicious payload.

        Uses benign parameter values only - no injection content.
        """
        if method.upper().startswith("HEADER:"):
            return await self._send(url, "GET", None, None, test_phase="pre_test_baseline")

        if target and target.location in {ParameterLocation.json_body, ParameterLocation.graphql_variable}:
            json_body = build_json_body(getattr(target, "json_template", None), target, value or "")
            headers = target.headers or {}
            return await self._send(
                url,
                method,
                None,
                None,
                headers=headers,
                json_body=json_body,
                test_phase="pre_test_baseline",
            )

        if method.upper() == "POST" and form_inputs is not None:
            clean_data = FormPayloadBuilder.build(form_inputs, parameter, value or "")
            return await self._send(
                url, method, None, clean_data, test_phase="pre_test_baseline"
            )

        clean_url, clean_params, clean_data = URLParameterBuilder.inject_parameter(
            url, parameter, value or "", method, form_inputs=form_inputs
        )
        return await self._send(
            clean_url, method, clean_params, clean_data, test_phase="pre_test_baseline"
        )

    async def close(self):
        """Cleanup resources."""
        await self.http_verifier.close()

    @abstractmethod
    async def verify(
        self,
        url: str,
        parameter: str,
        method: str = "GET",
        value: str = "",
    ) -> VerificationResult:
        """
        Verify if vulnerability exists.

        Returns:
            VerificationResult with findings
        """
        raise NotImplementedError

    def _create_finding(
        self,
        category: OwaspCategory,
        vuln_type: str,
        severity: SeverityLevel,
        url: str,
        parameter: str,
        payload: str,
        evidence: str,
        confidence_score: float,
        detection_method: str,
        method: str = "GET",
        detection_evidence: Optional[dict] = None,
        reproducible: bool = False,
        verified: bool = True,
        verification_request_snippet: Optional[str] = None,
        verification_response_snippet: Optional[str] = None,
    ) -> Finding:
        """Factory method to create Finding with verification fields."""
        return Finding(
            category=category,
            vuln_type=vuln_type,
            severity=severity,
            url=url,
            parameter=parameter,
            method=method,
            payload=payload,
            evidence=evidence,
            confidence_score=confidence_score,
            detection_method=detection_method,
            detection_evidence=detection_evidence or {},
            reproducible=reproducible,
            verified=verified,
            verification_request_snippet=verification_request_snippet,
            verification_response_snippet=verification_response_snippet,
        )


class FindingDeduplicator:
    """Deduplicates and merges findings from multiple verifiers."""

    @staticmethod
    def _canonical_url(url: str) -> str:
        parsed_url = urlparse(url)
        path = parsed_url.path or "/"
        lowered = path.lower()
        for suffix in ("/index.php", "/index.html", "/index.htm", "/default.aspx"):
            if lowered.endswith(suffix):
                path = path[: -len(suffix)] or "/"
                break
        return f"{parsed_url.scheme}://{parsed_url.netloc}{path}".rstrip("/")

    @staticmethod
    def _dedupe_family(vuln_type: str) -> str:
        vt = (vuln_type or "").lower()
        if "verbose error" in vt or "exception handling" in vt or "debug / metrics" in vt:
            return "exception_disclosure"
        if "remote file inclusion" in vt:
            return "remote_file_inclusion"
        if (
            "local file inclusion" in vt
            or "path traversal" in vt
            or "arbitrary file read" in vt
            or "file read" in vt
        ):
            return "file_read_or_inclusion"
        if "admin" in vt or "privileged endpoint" in vt or "sensitive path discovered" in vt:
            return "admin_or_sensitive_endpoint"
        if "csrf" in vt:
            return "csrf"
        if "insecure transport" in vt or "weak tls" in vt or "ssl configuration" in vt:
            return "transport_security"
        if "credential" in vt and ("get" in vt or "url" in vt):
            return "credentials_in_url"
        if "sensitive data in url" in vt:
            return "credentials_in_url"
        return vt

    @staticmethod
    def deduplicate(findings: list[Finding]) -> list[Finding]:
        """
        Merge duplicate findings (same url+parameter+vuln_type).

        Keeps finding with highest confidence and merges evidence.

        Args:
            findings: List of findings

        Returns:
            Deduplicated list
        """
        if not findings:
            return []

        # Group by canonical URL, parameter, and normalized vulnerability family.
        groups: dict[tuple, list[Finding]] = {}
        for finding in findings:
            canonical_url = FindingDeduplicator._canonical_url(finding.url)
            family = FindingDeduplicator._dedupe_family(finding.vuln_type)
            parameter = finding.parameter
            if family in {"csrf", "admin_or_sensitive_endpoint", "transport_security", "exception_disclosure"}:
                parameter = None
            key = (canonical_url, parameter, family)
            if key not in groups:
                groups[key] = []
            groups[key].append(finding)

        # Merge each group, keeping highest confidence
        deduplicated = []
        for group in groups.values():
            # Sort by confidence score descending
            sorted_group = sorted(group, key=lambda f: f.confidence_score, reverse=True)
            best = sorted_group[0]

            # Merge evidence from all findings
            all_evidence = {}
            for f in sorted_group:
                if f.detection_evidence:
                    for key, val in f.detection_evidence.items():
                        if key not in all_evidence:
                            all_evidence[key] = []
                        if val not in all_evidence[key]:
                            all_evidence[key].append(val)

            best.detection_evidence = all_evidence
            best.verified = any(f.verified for f in sorted_group)
            evidence_parts = []
            seen_evidence = set()
            seen_proofs = set()
            for f in sorted_group:
                if f.vuln_type != best.vuln_type:
                    profile_part = f"Supporting finding: {f.vuln_type}"
                    profile_key = profile_part.lower()
                    if profile_key not in seen_evidence:
                        seen_evidence.add(profile_key)
                        evidence_parts.append(profile_part)
                evidence = (f.evidence or "").strip()
                proof_key = FindingDeduplicator._evidence_proof_key(evidence)
                if proof_key and proof_key in seen_proofs:
                    continue
                if proof_key:
                    seen_proofs.add(proof_key)
                evidence_key = " ".join(evidence.lower().split())
                if evidence and evidence_key not in seen_evidence:
                    seen_evidence.add(evidence_key)
                    evidence_parts.append(evidence)
            best.evidence = "\n".join(evidence_parts)
            best.reproducible = any(f.reproducible for f in sorted_group)

            deduplicated.append(best)

        return deduplicated

    @staticmethod
    def _evidence_proof_key(evidence: str) -> str | None:
        text = " ".join(re.sub(r"<[^>]+>", " ", str(evidence or "")).lower().split())
        if not text:
            return None
        if "you have an error in your sql syntax" in text and (
            "mysql server version" in text or "mariadb server version" in text
        ):
            return "mysql_sql_syntax_verbose_error"
        if "sqlstate" in text:
            return "sqlstate_verbose_error"
        if "stack trace:" in text or "traceback (most recent call last)" in text:
            return "stack_trace_verbose_error"
        return None

    @staticmethod
    def filter_by_confidence(findings: list[Finding], min_confidence: float = 50.0) -> list[Finding]:
        """Keep only findings above confidence threshold."""
        return [f for f in findings if f.confidence_score >= min_confidence]


class TestPollutionFilter:
    """Downgrade reflected/similarity findings contaminated by earlier stored injections."""

    _STORED_TYPES = frozenset({"Stored XSS"})
    _REFLECTED_TYPES = frozenset({
        "Reflected XSS",
        "Header-Reflected XSS",
    })
    @staticmethod
    def _canonical_url(url: str) -> str:
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

    @classmethod
    def _has_verified_canary(cls, finding: Finding) -> bool:
        evidence = finding.detection_evidence or {}
        if evidence.get("canary_verified") or evidence.get("canary_proof"):
            return True
        if evidence.get("version_extracted"):
            return True
        return False

    @classmethod
    def _is_pollution_candidate(cls, finding: Finding) -> bool:
        if finding.vuln_type in cls._REFLECTED_TYPES:
            return True
        if not finding.vuln_type.startswith("SQL Injection"):
            return False
        if finding.detection_method == "boolean_differential":
            return True
        if finding.detection_method == "union_based":
            return not cls._has_verified_canary(finding)
        return False

    @classmethod
    def filter_cross_module_contamination(cls, findings: list[Finding]) -> list[Finding]:
        """
        Mark or downgrade findings on URLs with confirmed stored content when
        the reflected/similarity evidence lacks a per-request canary proof.
        """
        if not findings:
            return []

        by_url: dict[str, list[Finding]] = {}
        for finding in findings:
            by_url.setdefault(cls._canonical_url(finding.url), []).append(finding)

        filtered: list[Finding] = []
        for url_findings in by_url.values():
            has_stored = any(f.vuln_type in cls._STORED_TYPES for f in url_findings)
            if not has_stored:
                filtered.extend(url_findings)
                continue

            for finding in url_findings:
                if finding.vuln_type == "Stored XSS":
                    filtered.append(finding)
                    continue

                if not cls._is_pollution_candidate(finding):
                    filtered.append(finding)
                    continue

                if cls._has_verified_canary(finding):
                    filtered.append(finding)
                    continue

                finding.detection_evidence = {
                    **(finding.detection_evidence or {}),
                    "suspected_test_pollution": True,
                    "pollution_reason": "stored_content_on_url_without_canary_proof",
                }
                finding.verified = False
                finding.reproducible = False
                finding.confidence_score = min(finding.confidence_score, 20.0)
                # Preserve original severity for medium/high findings; only downgrade low/info severity
                if finding.severity == SeverityLevel.low:
                    finding.severity = SeverityLevel.low
                else:
                    # Keep original severity but mark as unverified
                    pass
                finding.evidence = (
                    f"[Suspected test pollution] {finding.evidence or ''}".strip()
                )
                filtered.append(finding)

        return filtered


class URLParameterBuilder:
    """Utilities for building URLs with injected parameters."""

    @staticmethod
    def get_parameter_value(url: str, parameter: str) -> str:
        """Return the current value of *parameter* from the URL query string."""
        parsed = urlparse(url)
        for name, val in parse_qsl(parsed.query, keep_blank_values=True):
            if name == parameter:
                return val
        return ""

    @staticmethod
    def inject_parameter(
        base_url: str,
        parameter_name: str,
        parameter_value: str,
        method: str = "GET",
        form_inputs: Optional[list] = None,
    ) -> tuple[str, dict, dict]:
        """
        Build request with injected parameter value.

        Args:
            base_url: Original URL
            parameter_name: Name of parameter to inject into
            parameter_value: Value to inject
            method: HTTP method

        Returns:
            (url, params, data) tuple for httpx request
        """
        parsed = urlparse(base_url)
        query_params = parse_qs(parsed.query, keep_blank_values=True)

        # Flatten single-element lists
        for key in query_params:
            if isinstance(query_params[key], list):
                query_params[key] = query_params[key][0] if query_params[key] else ""

        if form_inputs is not None:
            payload = FormPayloadBuilder.build(form_inputs, parameter_name, parameter_value)
            merged_params = {**query_params, **payload}
            new_query = urlencode(merged_params, doseq=False)
            new_parsed = parsed._replace(query=new_query)
            new_url = urlunparse(new_parsed)

            if method.upper() == "GET":
                return new_url, {}, {}

            return base_url, {}, merged_params

        # Update or add parameter
        query_params[parameter_name] = parameter_value

        # Rebuild URL
        new_query = urlencode(query_params, doseq=False)
        new_parsed = parsed._replace(query=new_query)
        new_url = urlunparse(new_parsed)

        if method.upper() == "GET":
            return new_url, {}, {}
        else:
            # For POST, put params in body
            return base_url, {}, query_params


class FormPayloadBuilder:
    """Shared utility for building full form POST bodies with sibling fields.

    Extracted from XSSVerifier._build_form_payload so that SQLi, XSS, and
    other verifiers all construct form payloads the same way.
    """

    @staticmethod
    def build(
        form_inputs: list,
        target_param: str,
        target_value: str,
    ) -> dict[str, str]:
        """Build a form payload dict from *form_inputs*, injecting
        *target_value* into *target_param* and filling siblings with
        benign defaults.

        Args:
            form_inputs: List of form input objects (must have ``.name``
                and optionally ``.input_type`` / ``.value``).
            target_param: The parameter name to inject into.
            target_value: The value to inject.

        Returns:
            Dict suitable for ``data=`` in an ``httpx`` POST request.
        """
        payload: dict[str, str] = {}
        for inp in form_inputs:
            name = getattr(inp, "name", "")
            if not name:
                continue
            inp_type = getattr(inp, "input_type", "text").lower()
            if name == target_param:
                payload[name] = target_value
            elif inp_type == "password":
                payload[name] = "sentry_password123"
            elif inp_type in ("submit", "button"):
                payload[name] = getattr(inp, "value", "Submit") or "Submit"
            elif inp_type == "hidden":
                # Preserve hidden fields (CSRF tokens, etc.)
                payload[name] = getattr(inp, "value", "")
            else:
                payload[name] = getattr(inp, "value", "") or "sentry_test_val"

        # Ensure the target parameter is always present
        if target_param not in payload:
            payload[target_param] = target_value

        return payload
