from app.analyzers.ai_client import OllamaClient
from app.models.vulnerability import Vulnerability, normalize_exploitability
from app.utils.cvss_calculator import CvssCalculator


class VulnerabilityPrioritizer:
    def __init__(self) -> None:
        self.client = OllamaClient()

    async def prioritize(self, vulnerabilities: list[Vulnerability]) -> list[Vulnerability]:
        for idx, vuln in enumerate(vulnerabilities, start=1):
            prompt = (
                "You are a security analyst. Return strict JSON with keys: "
                "exploitability(Easy|Medium|Hard), business_impact, confidence(0-1).\n"
                f"Vulnerability: {vuln.vuln_type} at {vuln.location.url}."
            )
            fallback = {
                "exploitability": "Medium",
                "business_impact": "Could impact confidentiality, integrity, or availability.",
                "confidence": 0.6,
            }
            result = await self.client.generate_json(prompt, fallback=fallback)

            confidence = float(result.get("confidence", 0.6))
            impact = 0.9 if vuln.severity.value in {"Critical", "High"} else 0.5
            cvss = CvssCalculator.from_confidence_impact(confidence=confidence, impact=impact)

            vuln.cvss_score = cvss.score
            vuln.cvss_vector = cvss.vector
            vuln.ai_analysis.priority_rank = idx
            vuln.ai_analysis.exploitability = normalize_exploitability(result.get("exploitability", "Medium"))
            vuln.ai_analysis.business_impact = result.get("business_impact", fallback["business_impact"])

        vulnerabilities.sort(key=lambda v: v.cvss_score, reverse=True)
        for rank, vuln in enumerate(vulnerabilities, start=1):
            vuln.ai_analysis.priority_rank = rank
        return vulnerabilities
