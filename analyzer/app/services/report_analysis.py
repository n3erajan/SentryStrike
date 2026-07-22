import json

from app.clients.ai_client import AIClient, ProviderResult
from app.config import get_settings
from app.prompts.report_analysis import REPORT_PROMPT_VERSION, build_report_prompt
from app.schemas.provider_response import ReportAnalysisResponse
from shared.models.scan import Scan


FALLBACK_REPORT_PROMPT_VERSION = "report-fallback-v1"


class ReportAnalysisService:
    def __init__(self, client: AIClient | None = None) -> None:
        self.client = client or AIClient()
        self.settings = get_settings()

    async def analyze(self, scan: Scan) -> tuple[str, ProviderResult]:
        if not self.settings.ai_analysis_enabled:
            summary = self._fallback_summary(scan)
            return summary, ProviderResult(data={"executive_summary": summary})

        report_input = {
            "target_url": scan.target_url,
            "statistics": scan.statistics.model_dump(mode="json"),
            "risk_score": scan.overall_risk_score,
            "risk_level": scan.overall_risk_level,
            "technology_stack": [
                technology.model_dump(mode="json")
                for technology in scan.technology_stack
            ],
            "findings": [
                {
                    "type": finding.vuln_type,
                    "severity": finding.severity.value,
                    "cvss_score": finding.cvss_score,
                    "evidence_strength": finding.evidence_strength.value,
                    "url": finding.location.url,
                }
                for finding in scan.vulnerabilities
            ],
            "coverage_warnings": scan.report_metadata.coverage_warnings,
        }
        serialized = json.dumps(report_input, default=str)[
            : self.settings.analysis_report_input_max_chars
        ]
        result = await self.client.generate_json(build_report_prompt(serialized))
        validated = ReportAnalysisResponse.model_validate(result.data)
        return validated.executive_summary, result

    @staticmethod
    def _fallback_summary(scan: Scan) -> str:
        count = scan.statistics.total_vulnerabilities
        finding_label = "finding" if count == 1 else "findings"
        return (
            f"The deterministic assessment identified {count} security {finding_label}. "
            f"The overall risk level is {scan.overall_risk_level} with a score of "
            f"{scan.overall_risk_score:.1f} out of 100. Review the evidence and prioritize "
            "remediation by severity and exploitability."
        )
