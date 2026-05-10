from datetime import datetime, timezone

from app.analyzers.ai_client import OllamaClient
from app.models.scan import Scan


class AiReportGenerator:
    def __init__(self) -> None:
        self.client = OllamaClient()

    async def generate(self, scan: Scan) -> dict:
        prompt = (
            "Generate a security report as strict JSON with these exact keys (all string values): "
            "executive_summary (1-2 sentences), technical_analysis (detailed findings), "
            "recommendations (comma-separated list), overall_risk_assessment (risk level + reasoning).\n"
            f"Scan target: {scan.target_url}, total vulnerabilities: {scan.statistics.total_vulnerabilities}, "
            f"risk score: {scan.overall_risk_score}. "
            f"Severity breakdown: {scan.statistics.severity_breakdown.critical} Critical, "
            f"{scan.statistics.severity_breakdown.high} High, {scan.statistics.severity_breakdown.medium} Medium."
        )
        fallback = {
            "executive_summary": "The scan identified security weaknesses requiring remediation.",
            "technical_analysis": "Multiple findings indicate input handling and configuration risks.",
            "recommendations": "Fix critical and high findings first; add security headers; harden authentication controls; implement secure SDLC checks in CI/CD",
            "overall_risk_assessment": "Moderate to high risk depending on internet exposure.",
        }
        result = await self.client.generate_json(prompt, fallback=fallback)
        result["generated_at"] = datetime.now(timezone.utc).isoformat()
        return result
