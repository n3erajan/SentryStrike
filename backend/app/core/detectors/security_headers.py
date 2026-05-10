import httpx

from app.config import get_settings
from app.core.detectors.base_detector import BaseDetector, Finding
from app.models.vulnerability import OwaspCategory, SeverityLevel


class SecurityHeadersDetector(BaseDetector):
    name = "security_headers"

    def __init__(self) -> None:
        self.settings = get_settings()

    async def detect(self, urls: list[str], forms: list[object], **kwargs: object) -> list[Finding]:
        findings: list[Finding] = []
        checked = set()
        required_headers = {
            "content-security-policy",
            "x-content-type-options",
            "strict-transport-security",
            "x-frame-options",
        }
        root_url = str(kwargs.get("root_url") or (urls[0] if urls else ""))

        if not root_url:
            return findings

        async with httpx.AsyncClient(timeout=self.settings.request_timeout_seconds) as client:
            if root_url in checked:
                return findings
            checked.add(root_url)

            try:
                response = await client.get(root_url)
            except Exception:
                return findings

            headers = {k.lower() for k in response.headers.keys()}
            missing = required_headers - headers
            for header in missing:
                findings.append(
                    Finding(
                        category=OwaspCategory.a05,
                        vuln_type="Missing Security Header",
                        severity=SeverityLevel.medium,
                        url=root_url,
                        evidence=f"Header not found: {header}",
                    )
                )

            server_hdr = response.headers.get("server", "")
            if server_hdr and any(c.isdigit() for c in server_hdr):
                findings.append(
                    Finding(
                        category=OwaspCategory.a05,
                        vuln_type="Information Disclosure in Header",
                        severity=SeverityLevel.low,
                        url=root_url,
                        evidence=f"Server header leaks version: {server_hdr}",
                    )
                )

        return findings
