"""Measure adjudicator accuracy against the labelled corpus.

Runs prompt variants through Ollama and scores:
  - raw model verdict (what the model actually thinks)
  - post-clamp verdict (what production would publish)

Usage:
  python -m benchmark.run_benchmark --variant baseline --model gemma4:e4b-it-qat-16k
  python -m benchmark.run_benchmark --variant brief --runs 3
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
from collections import defaultdict
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from benchmark.corpus import CASES  # noqa: E402
from benchmark.corpus_adversarial import CASES as ADVERSARIAL_CASES  # noqa: E402
from benchmark.variants import build_prompt, VARIANTS  # noqa: E402

BASE_URL = "http://localhost:11434/v1"
CORPORA = {"main": CASES, "adversarial": ADVERSARIAL_CASES, "all": CASES + ADVERSARIAL_CASES}


async def call_model(client: httpx.AsyncClient, model: str, prompt: str) -> dict:
    payload = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "stream": False,
        "temperature": 0.1,
        "response_format": {"type": "json_object"},
    }
    r = await client.post(f"{BASE_URL}/chat/completions", json=payload)
    r.raise_for_status()
    body = r.json()
    content = body["choices"][0]["message"]["content"]
    text = str(content).strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        s, e = text.find("{"), text.rfind("}")
        if s < 0 or e <= s:
            raise
        return json.loads(text[s : e + 1])


def clamp(raw_verdict: str, axes: dict, reasoning: str, proof_type: str) -> tuple[str, float]:
    """Reproduce production clamping from services/finding_analysis.py."""
    from app.services.finding_analysis import compute_fp_probability
    from shared.models.vulnerability import get_fp_ceiling, get_fp_floor

    raw_prob = compute_fp_probability(axes or {})
    fp = max(min(raw_prob, get_fp_ceiling(proof_type)), get_fp_floor(proof_type))
    verdict = raw_verdict
    if verdict == "likely_false_positive":
        if fp < 0.50 or not reasoning or len(reasoning.strip()) < 20:
            verdict = "uncertain"
            fp = min(fp, 0.49)
    return verdict, round(fp, 2)


async def run_variant(model: str, variant: str, runs: int, corpus: str) -> dict:
    results = []
    cases = CORPORA[corpus]
    async with httpx.AsyncClient(timeout=300.0) as client:
        for case in cases:
            for run_idx in range(runs):
                prompt = build_prompt(variant, case)
                t0 = time.time()
                try:
                    data = await call_model(client, model, prompt)
                    err = None
                except Exception as exc:  # noqa: BLE001
                    data, err = {}, f"{type(exc).__name__}: {exc}"
                elapsed = time.time() - t0

                raw_verdict = str(data.get("verdict", "")).strip().lower()
                axes = data.get("fp_axes") or {}
                if not isinstance(axes, dict):
                    axes = {}
                reasoning = str(data.get("false_positive_reasoning", "") or "")
                clamped_verdict, fp_prob = clamp(
                    raw_verdict, axes, reasoning, case["proof_type"]
                )

                results.append({
                    "id": case["id"],
                    "label": case["label"],
                    "proof_type": case["proof_type"],
                    "run": run_idx,
                    "raw_verdict": raw_verdict,
                    "clamped_verdict": clamped_verdict,
                    "fp_prob": fp_prob,
                    "axes": axes,
                    "decisive_axis": data.get("decisive_axis"),
                    "reasoning": reasoning[:300],
                    "seconds": round(elapsed, 1),
                    "error": err,
                })
                status = "OK " if not err else "ERR"
                print(
                    f"  {status} {case['id']:<32} {case['label']}  "
                    f"raw={raw_verdict or '-':<22} clamped={clamped_verdict or '-':<22} "
                    f"fp={fp_prob:.2f}  {elapsed:.0f}s",
                    flush=True,
                )
    return {"model": model, "variant": variant, "runs": runs, "corpus": corpus, "results": results}


def score(results: list[dict], key: str) -> dict:
    """FP-detection scoring. Positive class = 'flagged as likely_false_positive'."""
    tp_flag = fp_flag = fn_flag = tn_flag = 0
    for r in results:
        flagged = r[key] == "likely_false_positive"
        is_fp = r["label"] == "FP"
        if is_fp and flagged:
            tp_flag += 1
        elif is_fp and not flagged:
            fn_flag += 1
        elif not is_fp and flagged:
            fp_flag += 1
        else:
            tn_flag += 1
    prec = tp_flag / (tp_flag + fp_flag) if (tp_flag + fp_flag) else 0.0
    rec = tp_flag / (tp_flag + fn_flag) if (tp_flag + fn_flag) else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    return {
        "caught_fp": tp_flag,
        "missed_fp": fn_flag,
        "killed_tp": fp_flag,
        "kept_tp": tn_flag,
        "precision": round(prec, 3),
        "recall": round(rec, 3),
        "f1": round(f1, 3),
    }


def stability(results: list[dict]) -> dict:
    by_case = defaultdict(list)
    for r in results:
        by_case[r["id"]].append(r["raw_verdict"])
    unstable = {k: v for k, v in by_case.items() if len(set(v)) > 1}
    return {"unstable_cases": unstable, "unstable_count": len(unstable)}


def report(payload: dict) -> None:
    results = payload["results"]
    print(f"\n{'='*78}")
    print(f"MODEL: {payload['model']}   VARIANT: {payload['variant']}   RUNS: {payload['runs']}")
    print("=" * 78)
    errs = [r for r in results if r["error"]]
    if errs:
        print(f"errors: {len(errs)}/{len(results)}")
        for e in errs[:3]:
            print(f"  {e['id']}: {e['error']}")

    for key, title in (("raw_verdict", "RAW MODEL"), ("clamped_verdict", "AFTER PRODUCTION CLAMP")):
        s = score(results, key)
        print(f"\n--- {title} ---")
        print(f"  FPs caught      : {s['caught_fp']}")
        print(f"  FPs missed      : {s['missed_fp']}")
        print(f"  TPs wrongly killed: {s['killed_tp']}")
        print(f"  TPs preserved   : {s['kept_tp']}")
        print(f"  precision={s['precision']}  recall={s['recall']}  f1={s['f1']}")

    if payload["runs"] > 1:
        st = stability(results)
        print(f"\n--- STABILITY ({payload['runs']} runs) ---")
        print(f"  cases with inconsistent verdicts: {st['unstable_count']}")
        for k, v in list(st["unstable_cases"].items())[:8]:
            print(f"    {k}: {v}")

    print("\n--- ERRORS BY CASE (raw) ---")
    for r in results:
        flagged = r["raw_verdict"] == "likely_false_positive"
        if r["label"] == "FP" and not flagged:
            print(f"  MISSED FP  {r['id']:<32} said={r['raw_verdict']}  axes={r['axes']}")
        if r["label"] == "TP" and flagged:
            print(f"  KILLED TP  {r['id']:<32} axes={r['axes']}  why={r['reasoning'][:120]}")


async def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="gemma4:e4b-it-qat-16k")
    ap.add_argument("--variant", default="baseline", choices=list(VARIANTS))
    ap.add_argument("--runs", type=int, default=1)
    ap.add_argument("--corpus", default="main", choices=list(CORPORA))
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    payload = await run_variant(args.model, args.variant, args.runs, args.corpus)
    report(payload)
    out = args.out or f"benchmark/results_{args.variant}_{args.corpus}_{args.model.replace(':','_').replace('/','_')}.json"
    Path(out).parent.mkdir(parents=True, exist_ok=True)
    Path(out).write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(f"\nsaved: {out}")


if __name__ == "__main__":
    asyncio.run(main())
