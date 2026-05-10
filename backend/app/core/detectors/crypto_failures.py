from urllib.parse import urlparse

from app.core.detectors.base_detector import BaseDetector, Finding
from app.models.vulnerability import OwaspCategory, SeverityLevel


class CryptoFailuresDetector(BaseDetector):
    name = "crypto_failures"

    async def detect(self, urls: list[str], forms: list[object], **kwargs: object) -> list[Finding]:
        findings: list[Finding] = []
        root_url = str(kwargs.get("root_url") or (urls[0] if urls else ""))
        insecure_transport_reported = False

        if root_url:
            parsed_root = urlparse(root_url)
            if parsed_root.scheme != "https":
                findings.append(
                    Finding(
                        category=OwaspCategory.a02,
                        vuln_type="Insecure Transport",
                        severity=SeverityLevel.high,
                        url=root_url,
                        evidence="Target does not enforce HTTPS.",
                    )
                )
                insecure_transport_reported = True

        for url in urls:
            parsed = urlparse(url)
            if parsed.scheme != "https" and not insecure_transport_reported:
                findings.append(
                    Finding(
                        category=OwaspCategory.a02,
                        vuln_type="Insecure Transport",
                        severity=SeverityLevel.high,
                        url=url,
                        evidence="Endpoint does not enforce HTTPS.",
                    )
                )
                insecure_transport_reported = True

            lowered = url.lower()
            if any(token in lowered for token in ["token=", "password=", "secret="]):
                findings.append(
                    Finding(
                        category=OwaspCategory.a02,
                        vuln_type="Sensitive Data in URL",
                        severity=SeverityLevel.high,
                        url=url,
                        evidence="Potential secret found in query string.",
                    )
                )

        return findings
