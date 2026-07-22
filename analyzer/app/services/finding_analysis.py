import json

from app.clients.ai_client import AIClient, ProviderResult
from app.config import get_settings
from app.prompts.finding_analysis import FINDING_PROMPT_VERSION, build_finding_prompt
from app.schemas.provider_response import FindingAnalysisResponse
from shared.models.vulnerability import AiAnalysis, AiAnalysisStatus, Vulnerability


FALLBACK_MODEL = "deterministic-fallback"
FALLBACK_FINDING_PROMPT_VERSION = "finding-fallback-v1"


class FindingAnalysisService:
    def __init__(self, client: AIClient | None = None) -> None:
        self.client = client or AIClient()
        self.settings = get_settings()

    async def analyze(
        self,
        vulnerability: Vulnerability,
        *,
        revision: int,
        technology_stack: str,
    ) -> tuple[AiAnalysis, ProviderResult]:
        if not self.settings.ai_analysis_enabled:
            return self._fallback(vulnerability, revision=revision)

        evidence = {
            "type": vulnerability.vuln_type,
            "category": vulnerability.category.value,
            "url": vulnerability.location.url,
            "http_method": vulnerability.location.http_method,
            "parameter": vulnerability.location.parameter,
            "payload": vulnerability.evidence.payload,
            "request_snippet": vulnerability.evidence.request_snippet,
            "response_snippet": vulnerability.evidence.response_snippet,
            "detection_method": vulnerability.evidence.detection_method,
            "detection_evidence": vulnerability.evidence.detection_evidence,
            "evidence_strength": vulnerability.evidence_strength.value,
            "evidence_grade": vulnerability.evidence.evidence_grade,
            "evidence_grade_reason": vulnerability.evidence.evidence_grade_reason,
            "proof_type": vulnerability.evidence.proof_type,
        }
        evidence_json = json.dumps(evidence, default=str)[
            : self.settings.analysis_finding_evidence_max_chars
        ]
        result = await self.client.generate_json(
            build_finding_prompt(
                technology_stack=technology_stack,
                evidence_json=evidence_json,
            )
        )
        validated = FindingAnalysisResponse.model_validate(result.data)
        return (
            AiAnalysis(
                revision=revision,
                description=validated.description,
                exploitability=validated.exploitability,
                exploitability_reasoning=validated.exploitability_reasoning,
                business_impact=validated.business_impact,
                verdict=validated.verdict,
                false_positive_probability=validated.false_positive_probability,
                false_positive_reasoning=validated.false_positive_reasoning,
                remediation=validated.remediation,
                references=validated.references,
                model=self.settings.ai_model,
                prompt_version=FINDING_PROMPT_VERSION,
                ai_analysis_status=AiAnalysisStatus.success,
            ),
            result,
        )

    @staticmethod
    def _fallback(
        vulnerability: Vulnerability,
        *,
        revision: int,
    ) -> tuple[AiAnalysis, ProviderResult]:
        analysis = AiAnalysis(
            revision=revision,
            description=(
                f"The scanner identified a {vulnerability.vuln_type} finding from "
                "deterministic evidence collected during the assessment."
            ),
            exploitability="Hard",
            exploitability_reasoning=(
                "Exploitability was not model-assessed; review the captured evidence "
                "and target context."
            ),
            business_impact=(
                f"This {vulnerability.severity.value.lower()}-severity finding may affect "
                "the confidentiality, integrity, or availability of the application."
            ),
            verdict="uncertain",
            false_positive_probability=0.5,
            false_positive_reasoning=(
                "No model adjudication was requested; the deterministic scanner result "
                "remains unchanged."
            ),
            remediation=(
                f"Review the evidence and apply controls appropriate to "
                f"{vulnerability.vuln_type}. Re-test the affected endpoint after remediation."
            ),
            references=[],
            model=FALLBACK_MODEL,
            prompt_version=FALLBACK_FINDING_PROMPT_VERSION,
            ai_analysis_status=AiAnalysisStatus.success,
        )
        return analysis, ProviderResult(data=analysis.model_dump(mode="json"))
