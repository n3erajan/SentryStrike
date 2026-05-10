from app.analyzers.ai_client import OllamaClient
from app.models.vulnerability import Vulnerability


class RemediationGenerator:
    def __init__(self) -> None:
        self.client = OllamaClient()

    async def enrich(self, vulnerability: Vulnerability) -> Vulnerability:
        prompt = (
            "You are an AppSec engineer. Return strict JSON with keys: explanation, attack_scenario, "
            "code_fix_before, code_fix_after, verification_steps(array), references(array), remediation.\n"
            f"Vulnerability: {vulnerability.vuln_type}; category: {vulnerability.category.value}; severity: {vulnerability.severity.value}."
        )
        fallback = {
            "remediation": "Apply input validation, output encoding, and secure-by-default configuration.",
            "explanation": "The flaw allows untrusted input to reach a sensitive sink.",
            "attack_scenario": "An attacker crafts input to trigger unintended behavior.",
            "verification_steps": ["Re-test the endpoint with the same payloads", "Confirm expected sanitization behavior"],
            "references": ["https://owasp.org/www-project-top-ten/"],
        }
        result = await self.client.generate_json(prompt, fallback=fallback)
        vulnerability.ai_analysis.remediation = result.get("remediation", fallback["remediation"])
        return vulnerability

    async def enrich_many(self, vulnerabilities: list[Vulnerability]) -> list[Vulnerability]:
        enriched: list[Vulnerability] = []
        for vulnerability in vulnerabilities:
            enriched.append(await self.enrich(vulnerability))
        return enriched
