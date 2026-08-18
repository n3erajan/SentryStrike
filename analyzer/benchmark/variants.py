"""Prompt variants under test.

baseline — the production prompt, imported directly from app.prompts so the
           measurement tracks real code.
brief    — baseline plus the EvidenceGrader brief (proof summary, weaknesses,
           judge question) that the scanner already computes but discards.
"""
from __future__ import annotations

import json

from app.prompts.finding_analysis import build_adjudication_prompt

VARIANTS = ("baseline", "brief", "brief_locus")


_LOCUS_RULE = (
    "LOCUS RULE — judge the MATCH, not the PAGE:\n"
    "A page can host tutorial, documentation, or example content AND still be vulnerable. "
    "What matters is where the matched evidence sits, not what the surrounding page is about.\n"
    "- If detection_evidence reports match_location as 'outside_code_block', "
    "'command_output_block', or 'attribute_value_broken_out', the match is LIVE application "
    "output. A tutorial-looking page title does NOT make it a false positive.\n"
    "- If match_location is 'code_block' AND the surrounding page is documentation, the match "
    "is illustrative text — that IS a false positive.\n"
    "- If detection_evidence shows the evidence is absent from the control request "
    "(control_response_lacks_marker=true, error_absent_in_control_request=true), the payload "
    "caused it. That is a true positive regardless of page topic.\n"
    "- If the evidence is present WITHOUT the payload (identical_without_payload=true, "
    "error_present_in_control_request=true, control_request_also_slow_ms), the scanner's claim "
    "is contradicted — that IS a false positive.\n\n"
)


# Proof-type briefs, lifted from scanner/app/core/evidence_grader.py. These are
# already produced by build_evidence_brief() but never reach the analyzer.
_PROOF_SUMMARY = {
    "active_output": "Active exploitation confirmed - the proof is in the response (command output, file contents, or code execution).",
    "error_echo": "A database/framework error string was echoed in the response, causally connected to the injected payload.",
    "structural": "The vulnerability is structural - the observation itself IS the proof (missing header, TLS absence, admin path reachability, etc.).",
    "timing_strong": "Strong timing differential - the response delay is large enough to clearly indicate sleep-based SQL injection.",
    "timing_weak": "Weak timing differential - the response delay is small and could be network jitter rather than SQL injection.",
    "ssrf_differential": "Repeated internal-target versus external-control behavior differed, but no outbound callback or internal response content was observed.",
    "auth_confirmed": "Confirmed authorization differential - distinct users or privilege levels received the same restricted object, fields, or privileged capability.",
    "auth_differential": "Access-control finding - responses from different authentication or user contexts indicate a possible boundary bypass. This is real only when a less-privileged context receives restricted data or the same object as another user.",
    "pattern_match": "A pattern was matched in the response body - this could be a genuine error disclosure, reflected payload text, or normal page content.",
    "heuristic": "Heuristic observation without active exploitation proof - the finding is based on observation alone.",
}

_PROOF_WEAKNESSES = {
    "active_output": "None - the proof is in the response output. This is undeniable.",
    "error_echo": "None - the database error text is causally connected to the payload. This is strong proof.",
    "structural": "Minimal - the observation is the proof. A false positive would require the scanner to have misconfigured its request.",
    "timing_strong": "Time deltas can have non-SQL causes (network jitter, lock contention, background load). But a large delta matching the SLEEP argument is strong. This would be a false positive only if the delta does not scale with the sleep duration.",
    "timing_weak": "The timing delta is small and could be caused by network jitter, database load, or connection overhead rather than SQL SLEEP. If the delta does not clearly exceed normal latency variation, this is likely a false positive.",
    "ssrf_differential": "A timeout, status, or body-length difference can also be caused by URL validation, denylisting, application timeouts, DNS behavior, or upstream filtering. It does not prove that the server issued an outbound request.",
    "auth_confirmed": "The proof compares distinct authenticated identities or roles, not merely HTTP success. Treat it as false only if the evidence shows the sessions were not distinct, the identifiers were not shared, or the returned data was explicitly public.",
    "auth_differential": "For anonymous-access findings, identical anonymous and authenticated responses with no restricted fields can mean the endpoint is public by design. For horizontal or vertical findings, compare authenticated identities or roles instead: shared object identifiers, sensitive fields, or privileged capabilities in the less-privileged response support a real boundary bypass.",
    "pattern_match": "The matched pattern could be (a) a genuine error disclosure, (b) reflected payload text that happens to contain the pattern, or (c) normal page content. If the matched text is the injected payload echoed back, or if it appears in navigation HTML / normal page content, this is a false positive.",
    "heuristic": "The finding is based on observation without active exploitation. Evaluate whether the observation truly constitutes a vulnerability or is a benign application behavior.",
}

_JUDGE_QUESTION = {
    "active_output": "Is the proof in the response genuine? (It should be - do not flag as false positive.)",
    "error_echo": "Is the error string a genuine database/framework error, or could it be a benign message?",
    "structural": "Is this observation a genuine security gap? (It should be - do not flag as false positive.)",
    "timing_strong": "Does the timing delta clearly indicate SQL SLEEP execution, or could it be network noise?",
    "timing_weak": "Is the timing delta clearly caused by SQL SLEEP, or could it be network jitter or normal latency variation?",
    "ssrf_differential": "Do the repeated control and internal samples support a probable server-side fetch, while remaining short of confirmation without an OAST callback or reflected internal content?",
    "auth_confirmed": "Do the markers show distinct identities or roles crossing an object or privilege boundary? Do not require a further exploit chain once that boundary crossing is proven.",
    "auth_differential": "Did a less-privileged context receive genuinely restricted data or the same object/capability as another user or privileged role, or do the responses only show public/benign behavior?",
    "pattern_match": "Is the matched text a genuine error disclosure causally connected to the payload, or could it be reflected payload text or normal page content?",
    "heuristic": "Does this observation constitute a real vulnerability, or is it a benign application behavior?",
}


def _evidence_json(case: dict, max_chars: int = 6000) -> str:
    return json.dumps(case["evidence"], default=str)[:max_chars]


def build_prompt(variant: str, case: dict) -> str:
    ev = _evidence_json(case)
    proof_type = case["proof_type"]

    if variant == "baseline":
        return build_adjudication_prompt(evidence_json=ev)

    if variant in ("brief", "brief_locus"):
        brief = (
            f"PROOF TYPE: {proof_type}\n"
            f"PROOF SUMMARY: {_PROOF_SUMMARY.get(proof_type, '')}\n"
            f"PROOF WEAKNESSES: {_PROOF_WEAKNESSES.get(proof_type, '')}\n"
            f"JUDGE THIS: {_JUDGE_QUESTION.get(proof_type, '')}"
        )
        if variant == "brief_locus":
            brief += "\n\n" + _LOCUS_RULE
        return build_adjudication_prompt(evidence_json=ev, evidence_brief=brief)

    raise ValueError(f"unknown variant: {variant}")
