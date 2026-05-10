from app.analyzers.ai_client import OllamaClient
from app.models.vulnerability import Vulnerability


class FalsePositiveFilter:
    def __init__(self) -> None:
        self.client = OllamaClient()

    async def filter(self, vulnerabilities: list[Vulnerability]) -> list[Vulnerability]:
        validated: list[Vulnerability] = []
        for vuln in vulnerabilities:
            prompt = (
                "Assess false-positive likelihood for this web finding. "
                "Return strict JSON with false_positive_probability(0-1) and rationale.\n"
                f"Type: {vuln.vuln_type}; evidence: {vuln.evidence.response_snippet or vuln.evidence.payload or 'n/a'}"
            )
            result = await self.client.generate_json(prompt, fallback={"false_positive_probability": 0.25})
            probability = float(result.get("false_positive_probability", 0.25))
            vuln.ai_analysis.false_positive_probability = probability
            if probability < 0.75:
                validated.append(vuln)
        return validated
