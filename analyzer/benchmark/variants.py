"""Prompt variants under test.

baseline - the production prompt, imported directly from app.prompts so the
           measurement tracks real code.
brief    - baseline plus the EvidenceGrader brief (proof summary, weaknesses,
           judge question), read live from the scanner's grader for the same
           reason.
"""
from __future__ import annotations

import json

from app.prompts.finding_analysis import build_adjudication_prompt
from scanner.app.core.evidence_grader import EvidenceGrader as _EvidenceGrader

VARIANTS = ("baseline", "brief", "brief_locus")


_LOCUS_RULE = (
    "LOCUS RULE - judge the MATCH, not the PAGE:\n"
    "A page can host tutorial, documentation, or example content AND still be vulnerable. "
    "What matters is where the matched evidence sits, not what the surrounding page is about.\n"
    "- If detection_evidence reports match_location as 'outside_code_block', "
    "'command_output_block', or 'attribute_value_broken_out', the match is LIVE application "
    "output. A tutorial-looking page title does NOT make it a false positive.\n"
    "- If match_location is 'code_block' AND the surrounding page is documentation, the match "
    "is illustrative text - that IS a false positive.\n"
    "- If detection_evidence shows the evidence is absent from the control request "
    "(control_response_lacks_marker=true, error_absent_in_control_request=true), the payload "
    "caused it. That is a true positive regardless of page topic.\n"
    "- If the evidence is present WITHOUT the payload (identical_without_payload=true, "
    "error_present_in_control_request=true, control_request_also_slow_ms), the scanner's claim "
    "is contradicted - that IS a false positive.\n\n"
)


# Proof-type brief text, read live from the scanner's EvidenceGrader so the
# measurement tracks the prompt production actually sends. These used to be
# hardcoded copies "lifted from" the grader, which meant a change to the shipped
# brief (for example replacing the active_output "do not flag as false positive"
# instruction with a neutral reflection-vs-extraction discriminator) left the
# benchmark scoring the OLD wording - the opposite of a regression check.
_grader = _EvidenceGrader()


def _brief_text(proof_type: str) -> tuple[str, str, str]:
    """(summary, weaknesses, judge question) for a proof type, from the grader.

    ``_proof_summary`` takes a vulnerability for signature compatibility but
    resolves purely from ``proof_type``, so ``None`` is safe here.
    """
    return (
        _grader._proof_summary(proof_type, None),
        _grader._proof_weaknesses(proof_type),
        _grader._judge_question(proof_type),
    )


def _evidence_json(case: dict, max_chars: int = 6000) -> str:
    return json.dumps(case["evidence"], default=str)[:max_chars]


def build_prompt(variant: str, case: dict) -> str:
    ev = _evidence_json(case)
    proof_type = case["proof_type"]

    if variant == "baseline":
        return build_adjudication_prompt(evidence_json=ev)

    if variant in ("brief", "brief_locus"):
        summary, weaknesses, judge = _brief_text(proof_type)
        brief = (
            f"PROOF TYPE: {proof_type}\n"
            f"PROOF SUMMARY: {summary}\n"
            f"PROOF WEAKNESSES: {weaknesses}\n"
            f"JUDGE THIS: {judge}"
        )
        if variant == "brief_locus":
            brief += "\n\n" + _LOCUS_RULE
        return build_adjudication_prompt(evidence_json=ev, evidence_brief=brief)

    raise ValueError(f"unknown variant: {variant}")
