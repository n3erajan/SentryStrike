from app.core.detectors.base_detector import BaseDetector, Finding
from shared.models.vulnerability import OwaspCategory, SeverityLevel

# Components whose CVE list came from a real assessment. A list left over from a
# failed or skipped lookup is not evidence of anything.
_ASSESSED = "assessed"

# Where a CVE has no published CVSS score, the finding is graded medium and says
# so. The previous default of 7.5 manufactured a high-severity finding out of a
# missing number.
_UNSCORED_SEVERITY = SeverityLevel.medium

_SEVERITY_RANK = {
    SeverityLevel.critical: 0,
    SeverityLevel.high: 1,
    SeverityLevel.medium: 2,
    SeverityLevel.low: 3,
}

_SOURCE_LABELS = {
    "osv": "OSV.dev",
    "nvd-cpe": "NVD (CPE match)",
    "wordfence": "Wordfence Intelligence",
}


class SupplyChainDetector(BaseDetector):
    name = "supply_chain"

    async def detect(self, urls: list[str], forms: list[object], **kwargs: object) -> list[Finding]:
        technologies = kwargs.get("technologies", [])
        findings: list[Finding] = []
        root_url = kwargs.get("root_url", urls[0] if urls else "")

        for tech in technologies:
            name = getattr(tech, "name", "unknown")
            version = (getattr(tech, "version", None) or "").strip()
            cves = getattr(tech, "cves", []) or []

            # A supply-chain finding claims "this version has this vulnerability".
            # That needs a version, a CVE, and a source that actually said so.
            # Reporting a CVE list carried by a component whose lookup was skipped
            # or failed is how another product's CVEs end up in the report.
            if not version or not cves:
                continue
            if getattr(tech, "cve_assessment", _ASSESSED) != _ASSESSED:
                continue

            scores = getattr(tech, "cve_scores", {}) or {}
            kev = set(getattr(tech, "cve_kev", []) or [])
            epss = getattr(tech, "cve_epss", {}) or {}
            source = _SOURCE_LABELS.get(getattr(tech, "cve_source", None) or "", "an unnamed source")

            for cve_id in cves:
                score = scores.get(cve_id)
                exploited = cve_id in kev
                findings.append(
                    Finding(
                        category=OwaspCategory.a03,
                        vuln_type=f"Vulnerable Component: {name}",
                        severity=self._severity(score, exploited),
                        url=root_url,
                        evidence=self._evidence(
                            name, version, cve_id, score, exploited, epss.get(cve_id), source
                        ),
                        verified=True,
                    )
                )

        # Rank rather than truncate: the old lookup kept the five lowest CVE IDs,
        # so the oldest findings displaced anything recent or actively exploited.
        findings.sort(key=lambda f: _SEVERITY_RANK.get(f.severity, 99))
        return findings

    @staticmethod
    def _severity(score: float | None, exploited: bool) -> SeverityLevel:
        """Grade from the real CVSS score, escalating for confirmed exploitation.

        KEV membership means attacks have been observed in the wild, which outranks
        the CVSS band: a 5.0 being actively exploited needs patching before a 9.8
        that nobody has weaponised.
        """
        if exploited:
            return SeverityLevel.critical
        if score is None:
            return _UNSCORED_SEVERITY
        if score >= 9.0:
            return SeverityLevel.critical
        if score >= 7.0:
            return SeverityLevel.high
        if score >= 4.0:
            return SeverityLevel.medium
        return SeverityLevel.low

    @staticmethod
    def _evidence(
        name: str,
        version: str,
        cve_id: str,
        score: float | None,
        exploited: bool,
        epss: float | None,
        source: str,
    ) -> str:
        parts = [f"Component {name} {version} is affected by {cve_id}, per {source}."]
        parts.append(
            f"CVSS base score: {score}." if score is not None
            else "No CVSS base score is published for this advisory; "
                 "severity is reported as medium pending scoring."
        )
        if exploited:
            parts.append(
                "This CVE is in CISA's Known Exploited Vulnerabilities catalogue - "
                "exploitation has been observed in the wild. Patch as a priority."
            )
        if epss is not None:
            parts.append(f"EPSS puts the chance of exploitation in the next 30 days at {epss:.1%}.")
        parts.append("Upgrade to a patched version.")
        return " ".join(parts)
