from __future__ import annotations

import json
import re

from app.clients.ai_client import AIClient, ProviderResult
from app.config import get_settings
from app.prompts.finding_analysis import (
    FINDING_PROMPT_VERSION,
    build_adjudication_prompt,
    build_enrichment_prompt,
)
from app.schemas.provider_response import (
    FindingAdjudicationResponse,
    FindingEnrichmentResponse,
)
from shared.models.vulnerability import (
    AiAnalysis,
    AiAnalysisStatus,
    Vulnerability,
    get_fp_ceiling,
)


FALLBACK_MODEL = "deterministic-fallback"
FALLBACK_FINDING_PROMPT_VERSION = "finding-fallback-v1"


def extract_page_title(html_snippet: str | None) -> str | None:
    if not html_snippet:
        return None
    match = re.search(r"<title[^>]*>(.*?)</title>", html_snippet, re.IGNORECASE | re.DOTALL)
    if match:
        return match.group(1).strip()
    return None


def has_code_blocks(html_snippet: str | None) -> bool:
    if not html_snippet:
        return False
    return bool(re.search(r"<code|<pre|```", html_snippet, re.IGNORECASE))


def compute_fp_probability(
    axes: dict[str, str],
    proof_type: str | None = None,
    vuln_type: str | None = None,
) -> float:
    """Calculate FP probability deterministically from universal generic semantic axes.

    The axes evaluate:
    - EVIDENTIAL_ALIGNMENT: Does the evidence directly support the specific claim of the finding?
    - EXPLAINABLE_BY_NORMAL_BEHAVIOR: Is the response explainable as normal, intended application functionality?
    - CAUSALLY_CONNECTED: Was the evidence causally triggered by the payload?
    """
    norm_axes = {k.upper(): str(v).lower() for k, v in (axes or {}).items()}

    alignment = norm_axes.get("EVIDENTIAL_ALIGNMENT") or norm_axes.get("PROOF_GENUINE")
    explainable_normal = (
        norm_axes.get("EXPLAINABLE_BY_NORMAL_BEHAVIOR")
        or norm_axes.get("CONTENT_IS_DOCUMENTATION")
        or norm_axes.get("ENDPOINT_INTENTIONALLY_PUBLIC")
    )
    causal = norm_axes.get("CAUSALLY_CONNECTED") or norm_axes.get("PROOF_CAUSALLY_CONNECTED")

    # 1. Normal intended application behavior AND proof does not support claim -> Strong FP
    if explainable_normal == "yes" and alignment in ("no", "uncertain"):
        return 0.85

    # 2. Explainable by normal application behavior -> Likely FP
    if explainable_normal == "yes" and alignment != "yes":
        return 0.75

    # 3. Not causally connected (pre-existing text/behavior) -> Likely FP
    if causal == "no":
        return 0.75

    # 4. Proof directly aligns with claim AND is not normal intended behavior -> Confirmed TP
    if alignment == "yes" and explainable_normal == "no":
        return 0.05

    # 5. Proof aligns with claim -> Low FP probability
    if alignment == "yes":
        return 0.10

    # 6. Default conservative baseline
    return 0.25


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

        # Prepare evidence package with extended context (up to max chars)
        response_snippet = vulnerability.evidence.response_snippet or ""
        page_title = extract_page_title(response_snippet)
        code_blocks = has_code_blocks(response_snippet)

        evidence = {
            "type": vulnerability.vuln_type,
            "category": vulnerability.category.value if vulnerability.category else "",
            "url": vulnerability.location.url,
            "http_method": vulnerability.location.http_method,
            "parameter": vulnerability.location.parameter,
            "payload": vulnerability.evidence.payload,
            "request_snippet": vulnerability.evidence.request_snippet,
            "response_snippet": response_snippet[:3000],  # expanded up to 3KB
            "page_title": page_title,
            "has_code_blocks": code_blocks,
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

        # ── PASS 1: Enrichment (Description, Impact, Remediation) ───────────
        enrichment_result = await self.client.generate_json(
            build_enrichment_prompt(
                technology_stack=technology_stack,
                evidence_json=evidence_json,
            )
        )
        enrichment = FindingEnrichmentResponse.model_validate(enrichment_result.data)

        # ── PASS 2: FP Adjudication (Generic Verification & Categorical Axes) ─
        adjudication_result = await self.client.generate_json(
            build_adjudication_prompt(
                proof_type=vulnerability.evidence.proof_type or "heuristic",
                evidence_json=evidence_json,
                vuln_type=vulnerability.vuln_type,
                enrichment_description=enrichment.description,
            )
        )
        adjudication = FindingAdjudicationResponse.model_validate(adjudication_result.data)

        # ── Deterministic Calibration & Ceiling Clamping ─────────────────────
        proof_type = vulnerability.evidence.proof_type or "heuristic"
        ceiling = get_fp_ceiling(proof_type)
        raw_prob = compute_fp_probability(adjudication.fp_axes, proof_type, vuln_type=vulnerability.vuln_type)

        # Clamp calculated probability to the evidence ceiling
        fp_prob = min(raw_prob, ceiling)

        # Conservative default enforcement:
        # Require verdict == likely_false_positive AND fp_prob >= 0.50 AND non-empty reasoning to downgrade
        final_verdict = adjudication.verdict
        if final_verdict.value == "likely_false_positive":
            if fp_prob < 0.50 or not adjudication.false_positive_reasoning or len(adjudication.false_positive_reasoning.strip()) < 20:
                final_verdict = "uncertain"
                fp_prob = min(fp_prob, 0.49)

        # Merge token counts and request IDs
        total_in_tokens = (enrichment_result.input_tokens or 0) + (adjudication_result.input_tokens or 0)
        total_out_tokens = (enrichment_result.output_tokens or 0) + (adjudication_result.output_tokens or 0)
        request_ids = [r for r in (enrichment_result.request_id, adjudication_result.request_id) if r]
        merged_request_id = ",".join(request_ids) if request_ids else None

        combined_provider_result = ProviderResult(
            data={"enrichment": enrichment.model_dump(), "adjudication": adjudication.model_dump()},
            request_id=merged_request_id,
            input_tokens=total_in_tokens,
            output_tokens=total_out_tokens,
        )

        return (
            AiAnalysis(
                revision=revision,
                description=enrichment.description,
                exploitability=enrichment.exploitability,
                exploitability_reasoning=enrichment.exploitability_reasoning,
                business_impact=enrichment.business_impact,
                remediation=enrichment.remediation,
                references=enrichment.references,
                verdict=final_verdict,
                false_positive_probability=round(fp_prob, 2),
                false_positive_reasoning=adjudication.false_positive_reasoning,
                fp_axes=adjudication.fp_axes,
                decisive_axis=adjudication.decisive_axis,
                model=self.settings.ai_model,
                prompt_version=FINDING_PROMPT_VERSION,
                ai_analysis_status=AiAnalysisStatus.success,
            ),
            combined_provider_result,
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
            fp_axes={},
            decisive_axis="",
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
