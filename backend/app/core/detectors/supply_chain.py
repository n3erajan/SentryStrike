from app.core.detectors.base_detector import BaseDetector, Finding
from app.models.vulnerability import OwaspCategory, SeverityLevel


class SupplyChainDetector(BaseDetector):
    name = "supply_chain"

    async def detect(self, urls: list[str], forms: list[object], **kwargs: object) -> list[Finding]:
        technologies = kwargs.get("technologies", [])
        findings: list[Finding] = []

        for tech in technologies:
            version = (getattr(tech, "version", None) or "").strip()
            cves = getattr(tech, "cves", [])
            if not version:
                findings.append(
                    Finding(
                        category=OwaspCategory.a06,
                        vuln_type="Component Version Unknown",
                        severity=SeverityLevel.low,
                        url=kwargs.get("root_url", urls[0] if urls else ""),
                        evidence=f"Unable to determine version for component {getattr(tech, 'name', 'unknown')}.",
                    )
                )
            if cves:
                findings.append(
                    Finding(
                        category=OwaspCategory.a06,
                        vuln_type="Known Vulnerable Component",
                        severity=SeverityLevel.high,
                        url=kwargs.get("root_url", urls[0] if urls else ""),
                        evidence=f"Component {getattr(tech, 'name', 'unknown')} linked to CVEs: {', '.join(cves[:5])}.",
                    )
                )

        return findings
