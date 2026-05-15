from app.core.detectors.base_detector import BaseDetector, Finding
from app.models.vulnerability import OwaspCategory, SeverityLevel


class SupplyChainDetector(BaseDetector):
    name = "supply_chain"

    async def detect(self, urls: list[str], forms: list[object], **kwargs: object) -> list[Finding]:
        technologies = kwargs.get("technologies", [])
        findings: list[Finding] = []
        root_url = kwargs.get("root_url", urls[0] if urls else "")

        for tech in technologies:
            name = getattr(tech, "name", "unknown")
            version = (getattr(tech, "version", None) or "").strip()
            cves = getattr(tech, "cves", [])
            if not version:
                findings.append(
                    Finding(
                        category=OwaspCategory.a06,
                        vuln_type="Component Version Unknown",
                        severity=SeverityLevel.low,
                        url=root_url,
                        evidence=f"Unable to determine version for component {name}.",
                    )
                )
                continue
            if not cves:
                continue

            for cve_id in cves:
                cve_score = 7.5
                if cve_score >= 9.0:
                    severity = SeverityLevel.critical
                elif cve_score >= 7.0:
                    severity = SeverityLevel.high
                elif cve_score >= 4.0:
                    severity = SeverityLevel.medium
                else:
                    severity = SeverityLevel.low

                findings.append(
                    Finding(
                        category=OwaspCategory.a06,
                        vuln_type=f"Known CVE in {name}",
                        severity=severity,
                        url=root_url,
                        evidence=(
                            f"Component {name} {version} is linked to known vulnerability {cve_id} "
                            f"(estimated CVSS: {cve_score}). Upgrade to a patched version."
                        ),
                        verified=True,
                    )
                )

        return findings
