import asyncio
from urllib.parse import urlparse

from app.core.detectors.attack_surface import AttackSurface, AttackTarget
from app.core.detectors.base_detector import BaseDetector, Finding
from app.core.verification.verification_framework import HttpVerifier
from app.models.vulnerability import OwaspCategory, SeverityLevel


class OpenRedirectDetector(BaseDetector):
    name = "open_redirect"

    redirect_param_tokens = {
        "next", "return", "return_to", "return_url", "redirect", "redirect_to",
        "redirect_url", "redirect_uri", "callback", "callback_url", "continue",
        "url", "target", "dest", "destination", "goto", "back",
    }

    payloads = (
        "https://sentrystrike.invalid/open-redirect",
        "//sentrystrike.invalid/open-redirect",
        "https:%5c%5csentrystrike.invalid%5copen-redirect",
    )

    async def detect(self, urls: list[str], forms: list[object], **kwargs: object) -> list[Finding]:
        session_cookies = kwargs.get("session_cookies") or {}

        def redirect_filter(param_name: str) -> bool:
            lowered = param_name.lower()
            return lowered in self.redirect_param_tokens or any(
                token in lowered for token in ("redirect", "return", "callback", "next")
            )

        candidates = AttackSurface.build(
            urls,
            forms,
            parameters=kwargs.get("parameters") or [],
            api_endpoints=kwargs.get("api_endpoints") or [],
            requests=kwargs.get("requests") or [],
            filter_fn=redirect_filter,
        )
        if not candidates:
            return []

        semaphore = asyncio.Semaphore(4)
        verifier = HttpVerifier(cookies=session_cookies, follow_redirects=False)
        verifier.set_request_context(module="open_redirect")

        async def verify_candidate(candidate: AttackTarget) -> list[Finding]:
            async with semaphore:
                verifier.set_request_context(parameter=candidate.parameter)
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
                    if response.status_code in {301, 302, 303, 307, 308} and self._is_external_location(location):
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
    def _is_external_location(location: str) -> bool:
        if not location:
            return False
        lowered = location.lower()
        if lowered.startswith("//sentrystrike.invalid"):
            return True
        parsed = urlparse(location)
        return parsed.scheme in {"http", "https"} and parsed.netloc.lower() == "sentrystrike.invalid"
