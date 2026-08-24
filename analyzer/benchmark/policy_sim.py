"""Compare clamping policies against collected results, offline.

Reruns the deterministic layer over saved raw model output, so policy changes
are evaluated without re-querying the model.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from app.services.finding_analysis import compute_fp_probability  # noqa: E402
from shared.models.vulnerability import PROOF_FLOORS  # noqa: E402

CURRENT_CEILINGS = {
    "active_output": 0.05, "error_echo": 0.05, "structural": 0.10,
    "timing_strong": 0.15, "timing_weak": 0.40, "ssrf_differential": 0.49,
    "auth_confirmed": 0.15, "auth_differential": 1.00,
    "pattern_match": 1.00, "heuristic": 0.40,
}

# Proposed: every proof type can reach the 0.50 gate, but strong proof needs
# the model to be decisive (contradiction found), not merely unsure.
PROPOSED_CEILINGS = {
    "active_output": 0.80, "error_echo": 0.80, "structural": 0.85,
    "timing_strong": 0.85, "timing_weak": 0.90, "ssrf_differential": 0.85,
    "auth_confirmed": 0.80, "auth_differential": 1.00,
    "pattern_match": 1.00, "heuristic": 0.90,
}


def apply(policy: dict, results: list[dict], require_contradiction_for_strong: bool) -> dict:
    STRONG = {"active_output", "error_echo", "auth_confirmed", "timing_strong", "structural"}
    caught = missed = killed = kept = 0
    detail = []
    for r in results:
        pt = r["proof_type"]
        axes = r.get("axes") or {}
        raw = compute_fp_probability(axes)
        fp = max(min(raw, policy.get(pt, 1.0)), PROOF_FLOORS.get(pt, 0.05))
        verdict = r["raw_verdict"]
        reasoning = r.get("reasoning") or ""

        if verdict == "likely_false_positive":
            norm = {k.upper(): str(v).lower() for k, v in axes.items()}
            contradicted = norm.get("SCANNER_CLAIM_CONTRADICTED") == "yes"
            gate_ok = fp >= 0.50 and len(reasoning.strip()) >= 20
            if require_contradiction_for_strong and pt in STRONG and not contradicted:
                gate_ok = False
            if not gate_ok:
                verdict = "uncertain"
                fp = min(fp, 0.49)

        flagged = verdict == "likely_false_positive"
        is_fp = r["label"] == "FP"
        if is_fp and flagged:
            caught += 1
        elif is_fp:
            missed += 1
        elif flagged:
            killed += 1
            detail.append(("KILLED_TP", r["id"], round(fp, 2)))
        else:
            kept += 1
    prec = caught / (caught + killed) if (caught + killed) else 0.0
    rec = caught / (caught + missed) if (caught + missed) else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    return {
        "caught_fp": caught, "missed_fp": missed, "killed_tp": killed, "kept_tp": kept,
        "precision": round(prec, 3), "recall": round(rec, 3), "f1": round(f1, 3),
        "detail": detail,
    }


def main() -> None:
    files = sys.argv[1:] or [
        "benchmark/results_brief_gemma4-e4b-it-qat.json",
        "benchmark/results_brief_adversarial_gemma4-e4b-it-qat.json",
    ]
    results = []
    for f in files:
        results.extend(json.load(open(f, encoding="utf-8"))["results"])
    # dedupe repeated runs - keep first run per case
    seen, uniq = set(), []
    for r in results:
        if r["id"] in seen:
            continue
        seen.add(r["id"])
        uniq.append(r)

    print(f"cases: {len(uniq)}  (TP={sum(1 for r in uniq if r['label']=='TP')} "
          f"FP={sum(1 for r in uniq if r['label']=='FP')})\n")

    policies = [
        ("A. raw model (no clamp)", None, False),
        ("B. current ceilings", CURRENT_CEILINGS, False),
        ("C. proposed ceilings", PROPOSED_CEILINGS, False),
        ("D. proposed + contradiction-required on strong proof", PROPOSED_CEILINGS, True),
    ]
    for name, pol, req in policies:
        if pol is None:
            caught = sum(1 for r in uniq if r["label"] == "FP" and r["raw_verdict"] == "likely_false_positive")
            missed = sum(1 for r in uniq if r["label"] == "FP" and r["raw_verdict"] != "likely_false_positive")
            killed = sum(1 for r in uniq if r["label"] == "TP" and r["raw_verdict"] == "likely_false_positive")
            kept = sum(1 for r in uniq if r["label"] == "TP" and r["raw_verdict"] != "likely_false_positive")
            prec = caught / (caught + killed) if (caught + killed) else 0.0
            rec = caught / (caught + missed) if (caught + missed) else 0.0
            f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
            s = {"caught_fp": caught, "missed_fp": missed, "killed_tp": killed,
                 "kept_tp": kept, "precision": round(prec, 3), "recall": round(rec, 3),
                 "f1": round(f1, 3), "detail": []}
        else:
            s = apply(pol, uniq, req)
        print(f"{name}")
        print(f"   FPs caught={s['caught_fp']:<3} missed={s['missed_fp']:<3} "
              f"TPs killed={s['killed_tp']:<3} kept={s['kept_tp']:<3} "
              f"| precision={s['precision']} recall={s['recall']} f1={s['f1']}")
        for d in s["detail"]:
            print(f"      {d[0]} {d[1]} fp={d[2]}")
        print()


if __name__ == "__main__":
    main()
