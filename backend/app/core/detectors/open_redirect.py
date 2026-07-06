import asyncio
from urllib.parse import urlparse

from app.core.detectors.attack_surface import AttackSurface, AttackTarget
from app.core.detectors.base_detector import BaseDetector, Finding
from app.core.detectors.param_selection import REDIRECT_NAME_TOKENS, redirect_candidate
from app.core.verification.verification_framework import HttpVerifier
from app.models.vulnerability import OwaspCategory, SeverityLevel
from app.utils.scan_http import build_scan_headers, same_origin_url


class OpenRedirectDetector(BaseDetector):
    name = "open_redirect"

    # Name half of the name-OR-value selection (see param_selection).
    redirect_param_tokens = REDIRECT_NAME_TOKENS

    payloads = (
        "https://sentrystrike.invalid/open-redirect",
        "//sentrystrike.invalid/open-redirect",
        "https:%5c%5csentrystrike.invalid%5copen-redirect",
    )

    async def detect(self, urls: list[str], forms: list[object], **kwargs: object) -> list[Finding]:
        session_cookies = kwargs.get("session_cookies") or {}
        auth_headers = kwargs.get("auth_headers")

        # Build the surface unfiltered, then select on name-OR-value so params
        # whose name is generic but whose value looks like a URL/path qualify.
        candidates = [
            candidate
            for candidate in AttackSurface.build(
                urls,
                forms,
                parameters=kwargs.get("parameters") or [],
                api_endpoints=kwargs.get("api_endpoints") or [],
                requests=kwargs.get("requests") or [],
            )
            if redirect_candidate(candidate.parameter, candidate.value)
        ]
        if not candidates:
            return []

        semaphore = asyncio.Semaphore(4)
        verifier = HttpVerifier(
            cookies=session_cookies,
            headers=build_scan_headers(auth_headers),
            follow_redirects=False,
        )
        verifier.set_request_context(module="open_redirect")

        async def verify_candidate(candidate: AttackTarget) -> list[Finding]:
            async with semaphore:
                verifier.set_request_context(parameter=candidate.parameter)
                baseline_finding = await self._verify_observed_external_redirect(verifier, candidate)
                if baseline_finding:
                    return [baseline_finding]
                for payload in self.payloads:
                    prepared = candidate.build_request(payload)
                    response = await verifier.send_request(
                        prepared.url,
                        prepared.method,
                        prepared.params,
                        prepared.data,
                        headers=prepared.headers,
                        cookies=prepared.cookies,
                        json_body=prepared.json_body,
                        test_phase="open_redirect",
                        payload=payload,
                    )
                    location = self._location_header(response.headers)
                    if response.status_code in {301, 302, 303, 307, 308} and self._is_payload_location(location):
                        return [
                            Finding(
                                category=OwaspCategory.a01,
                                vuln_type="Open Redirect",
                                severity=SeverityLevel.medium,
                                url=candidate.url,
                                parameter=candidate.parameter,
                                method=candidate.method,
                                payload=payload,
                                evidence=f"Parameter redirects to external Location header: {location}",
                                confidence_score=90.0,
                                detection_method="location_header_redirect",
                                reproducible=True,
                                verified=True,
                                verification_request_snippet=response.request_snippet,
                                verification_response_snippet=response.response_snippet,
                                detection_evidence={"location": location},
                            )
                        ]
            return []

        try:
            results = await asyncio.gather(*(verify_candidate(candidate) for candidate in candidates))
        finally:
            await verifier.close()

        findings: list[Finding] = []
        for result in results:
            findings.extend(result)
        return findings

    @staticmethod
    def _location_header(headers: dict) -> str:
        for key, value in (headers or {}).items():
            if key.lower() == "location":
                return str(value)
        return ""

    @staticmethod
    def _is_payload_location(location: str) -> bool:
        if not location:
            return False
        lowered = location.lower()
        if lowered.startswith("//sentrystrike.invalid"):
            return True
        parsed = urlparse(location)
        return parsed.scheme in {"http", "https"} and parsed.netloc.lower() == "sentrystrike.invalid"

    async def _verify_observed_external_redirect(
        self,
        verifier: HttpVerifier,
        candidate: AttackTarget,
    ) -> Finding | None:
        if not self._value_is_external_url(candidate.value):
            return None
        prepared = candidate.build_request(candidate.value)
        response = await verifier.send_request(
            prepared.url,
            prepared.method,
            prepared.params,
            prepared.data,
            headers=prepared.headers,
            cookies=prepared.cookies,
            json_body=prepared.json_body,
            test_phase="open_redirect_observed",
            payload=str(candidate.value),
        )
        location = self._location_header(response.headers)
        if response.status_code not in {301, 302, 303, 307, 308}:
            return None
        if not self._is_external_to_target(location, candidate.url):
            return None
        return Finding(
            category=OwaspCategory.a01,
            vuln_type="Open Redirect",
            severity=SeverityLevel.medium,
            url=candidate.url,
            parameter=candidate.parameter,
            method=candidate.method,
            payload=str(candidate.value),
            evidence=f"Observed redirect parameter sends users to external Location header: {location}",
            confidence_score=92.0,
            detection_method="observed_external_location_redirect",
            reproducible=True,
            verified=True,
            verification_request_snippet=response.request_snippet,
            verification_response_snippet=response.response_snippet,
            detection_evidence={"location": location},
        )

    @staticmethod
    def _value_is_external_url(value: object) -> bool:
        parsed = urlparse(str(value or ""))
        return parsed.scheme in {"http", "https"} and bool(parsed.netloc)

    @staticmethod
    def _is_external_to_target(location: str, target_url: str) -> bool:
        if not location:
            return False
        parsed = urlparse(location)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            return False
        return not same_origin_url(target_url, location)
