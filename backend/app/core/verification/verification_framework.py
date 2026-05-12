"""
Verification Framework: Base classes and utilities for active vulnerability testing.

Provides:
- BaseVerifier: Abstract base for verifiers
- HTTP client for sending test payloads
- Generic verification patterns
- Deduplication logic
"""

import asyncio
import logging
import httpx
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Callable, Optional
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse

from app.core.detectors.base_detector import Finding
from app.core.verification.response_analyzer import ResponseAnalyzer, ResponseData
from app.models.vulnerability import OwaspCategory, SeverityLevel

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

    async def get_client(self) -> httpx.AsyncClient:
        """Get or create async HTTP client."""
        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=self.timeout_seconds,
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
        if data:
            body_str = urlencode(data)
        
        request_snippet = f"{method} {req_path} HTTP/1.1\nHost: {parsed.netloc}\n{headers_str}\n\n{body_str}"

        try:
            start_time = time.time() if capture_timing else None

            response = await client.request(
                method=method,
                url=url,
                params=params,
                data=data,
                headers=headers,
                cookies=cookies,
            )

            end_time = time.time() if capture_timing else None
            response_time_ms = (end_time - start_time) * 1000 if capture_timing else 0

            response_snippet = f"HTTP/1.1 {response.status_code} {response.reason_phrase}\n" + \
                               "\n".join([f"{k}: {v}" for k, v in response.headers.items()]) + \
                               f"\n\n{response.text[:1000]}"

            return ResponseData(
                status_code=response.status_code,
                headers=dict(response.headers),
                body=response.text,
                response_time_ms=response_time_ms,
                request_snippet=request_snippet,
                response_snippet=response_snippet,
            )
        except asyncio.TimeoutError:
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
    ) -> list[ResponseData]:
        """
        Send multiple requests concurrently.

        Args:
            requests: List of (url, method, params, data) tuples

        Returns:
            List of ResponseData objects in same order
        """
        tasks = [
            self.send_request(url, method, params, data, capture_timing=True)
            for url, method, params, data in requests
        ]
        return await asyncio.gather(*tasks)


class BaseVerifier(ABC):
    """Base class for vulnerability verifiers."""

    def __init__(self, timeout_seconds: float = 10.0):
        self.http_verifier = HttpVerifier(timeout_seconds=timeout_seconds)
        self.logger = logging.getLogger(self.__class__.__name__)

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

        # Group by (url, parameter, vuln_type)
        groups: dict[tuple, list[Finding]] = {}
        for finding in findings:
            key = (finding.url, finding.parameter, finding.vuln_type)
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
            best.evidence = "; ".join([f.evidence or "" for f in sorted_group if f.evidence])
            best.reproducible = any(f.reproducible for f in sorted_group)

            deduplicated.append(best)

        return deduplicated

    @staticmethod
    def filter_by_confidence(findings: list[Finding], min_confidence: float = 50.0) -> list[Finding]:
        """Keep only findings above confidence threshold."""
        return [f for f in findings if f.confidence_score >= min_confidence]


class URLParameterBuilder:
    """Utilities for building URLs with injected parameters."""

    @staticmethod
    def inject_parameter(
        base_url: str,
        parameter_name: str,
        parameter_value: str,
        method: str = "GET",
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
