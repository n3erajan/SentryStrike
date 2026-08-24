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
    get_fp_floor,
)


FALLBACK_MODEL = "deterministic-fallback"
FALLBACK_FINDING_PROMPT_VERSION = "finding-fallback-v1"
RESPONSE_SNIPPET_MAX_CHARS = 3000


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


def compute_fp_probability(axes: dict[str, str]) -> float:
    """Calculate FP probability deterministically from universal semantic axes.

    The axes evaluate:
    - EVIDENTIAL_ALIGNMENT: Does the evidence directly support the scanner's specific claim?
    - SCANNER_CLAIM_CONTRADICTED: Does the evidence contradict the scanner's claim?
    - CAUSALLY_CONNECTED: Was the evidence causally triggered by the scanner's payload?
    """
    norm_axes = {k.upper(): str(v).lower() for k, v in (axes or {}).items()}

    alignment = norm_axes.get("EVIDENTIAL_ALIGNMENT", "uncertain")
    contradicted = norm_axes.get("SCANNER_CLAIM_CONTRADICTED", "uncertain")
    causal = norm_axes.get("CAUSALLY_CONNECTED", "uncertain")

    # ── Backward compat: map old axis names if present ──
    if "EVIDENTIAL_ALIGNMENT" not in norm_axes:
        alignment = norm_axes.get("PROOF_GENUINE", "uncertain")
    if "SCANNER_CLAIM_CONTRADICTED" not in norm_axes:
        # Old axis was inverted: EXPLAINABLE_BY_NORMAL_BEHAVIOR=yes meant "this is FP"
        old = norm_axes.get("EXPLAINABLE_BY_NORMAL_BEHAVIOR") or norm_axes.get("CONTENT_IS_DOCUMENTATION")
        if old:
            contradicted = old

    # 1. Evidence actively contradicts the scanner's claim → Strong FP
    if contradicted == "yes" and alignment in ("no", "uncertain"):
        return 0.85

    # 2. Evidence contradicts claim but alignment is ambiguous → Likely FP
    if contradicted == "yes":
        return 0.75

    # 3. Not causally connected AND alignment is weak → Likely FP
    #    (but only when causal connection is relevant - skip for "not_applicable")
    if causal == "no" and alignment in ("no", "uncertain"):
        return 0.75

    # 4. Evidence aligns with claim AND nothing contradicts it → Confirmed TP
    if alignment == "yes" and contradicted == "no":
        return 0.05

    # 5. Evidence aligns with claim (contradiction uncertain) → Low FP
    if alignment == "yes":
        return 0.10

    # 6. Default conservative baseline
    return 0.25


def build_evidence_json(vulnerability: Vulnerability, max_chars: int) -> str:
    """Serialize finding evidence, truncating only the response snippet.

    The response snippet is the sole unbounded, target-controlled field. Building
    the envelope first and fitting the snippet into the remaining budget keeps the
    detection metadata the adjudicator relies on (detection_method, proof_type,
    evidence_grade) present, and keeps the output valid JSON - slicing the
    serialized string did neither.

    ``matched_text``/``match_location``/``match_entropy`` are promoted out of
    ``detection_evidence`` into named fields because they are the whole basis of
    a pattern-match finding: the adjudicator is asked whether a regex hit is
    genuine, which it cannot answer from a truncated page window that need not
    even contain the hit. Naming them keeps them out of the truncation path and
    lets the prompt refer to them directly.
    """
    response_snippet = vulnerability.evidence.response_snippet or ""
    detection_evidence = vulnerability.evidence.detection_evidence or {}

    def primary(key: str):
        """Deduplication merges evidence values into lists; take the primary."""
        value = detection_evidence.get(key)
        if isinstance(value, list):
            return value[0] if value else None
        return value

    envelope = {
        "type": vulnerability.vuln_type,
        "category": vulnerability.category.value if vulnerability.category else "",
        "url": vulnerability.location.url,
        "http_method": vulnerability.location.http_method,
        "parameter": vulnerability.location.parameter,
        "payload": vulnerability.evidence.payload,
        "request_snippet": vulnerability.evidence.request_snippet,
        "page_title": extract_page_title(response_snippet),
        "has_code_blocks": has_code_blocks(response_snippet),
        "detection_method": vulnerability.evidence.detection_method,
        "detection_evidence": detection_evidence,
        "matched_text": primary("matched"),
        "match_location": primary("match_location"),
        "match_entropy": primary("entropy"),
        "evidence_strength": vulnerability.evidence_strength.value,
        "evidence_grade": vulnerability.evidence.evidence_grade,
        "evidence_grade_reason": vulnerability.evidence.evidence_grade_reason,
        "proof_type": vulnerability.evidence.proof_type,
        "response_snippet": "",
    }
    overhead = len(json.dumps(envelope, default=str))
    budget = max(0, max_chars - overhead)
    envelope["response_snippet"] = response_snippet[: min(budget, RESPONSE_SNIPPET_MAX_CHARS)]
    return json.dumps(envelope, default=str)


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

        evidence_json = build_evidence_json(
            vulnerability,
            self.settings.analysis_finding_evidence_max_chars,
        )

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
                evidence_json=evidence_json,
                enrichment_description=enrichment.description,
                evidence_brief=vulnerability.evidence.evidence_brief or "",
            )
        )
        adjudication = FindingAdjudicationResponse.model_validate(adjudication_result.data)

        # ── Deterministic Calibration & Floor/Ceiling Clamping ────────────────
        proof_type = vulnerability.evidence.proof_type or "heuristic"
        ceiling = get_fp_ceiling(proof_type)
        floor = get_fp_floor(proof_type)
        raw_prob = compute_fp_probability(adjudication.fp_axes)

        # Clamp: ceiling prevents pessimism on strong proof, floor prevents
        # overconfidence on weak proof (e.g. heuristic CVE lookups).
        fp_prob = max(min(raw_prob, ceiling), floor)

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
