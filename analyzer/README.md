<div align="center">

# SentryStrike Analyzer

[![Python](https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white)](https://python.org)
[![Ollama](https://img.shields.io/badge/Ollama-local%20LLM-000000?logo=ollama&logoColor=white)](https://ollama.com)
[![OpenAI API](https://img.shields.io/badge/OpenAI--compatible-412991?logo=openai&logoColor=white)](https://ollama.readthedocs.io/en/openai/)

</div>
The AI analysis worker. After a scan completes, the analyzer claims the durable analysis job and sends every finding through a local LLM twice: once to **enrich** it (plain-language description, business impact, exploitability, stack-specific remediation) and once to **adjudicate** it (is this a false positive?). It then writes a whole-scan report summary. All inference runs against an OpenAI-compatible endpoint, by default a local Ollama model, so target data never leaves your infrastructure.

With `AI_ANALYSIS_ENABLED=false` the same pipeline runs in a deterministic fallback mode: no LLM calls, findings publish with curated per-type descriptions and no AI verdicts. The fallback exists so a missing model degrades the product instead of breaking it.

## Running

```bash
pip install -e ..                 # shared package, from the repo root
pip install -r requirements.txt
python -m app.worker
```

Then build the pinned model (see below). In Docker the service is built from `analyzer/Dockerfile`; its healthcheck is process liveness only, since provider misconfiguration fails jobs visibly rather than restart-looping the consumer. Point `AI_BASE_URL` at any OpenAI-compatible server (Ollama's `:11434/v1` by default); `host.docker.internal` is wired up in compose so the container can reach a host-installed Ollama.

## The model, and why it is pinned

`ollama/Modelfile` builds `gemma4:e4b-it-qat-16k`: the upstream `gemma4:e4b-it-qat` weights with two runtime changes.

**Context window.** Ollama does not size the context window to the model's maximum. A stock install loads this model with a 4096-token window, and exceeding it is silent: the overflow is dropped and the model answers confidently from whatever remains. The report prompt alone is ~4,100 tokens. A truncated prompt returns a schema-valid verdict about evidence the model never received, indistinguishable from a real adjudication. `num_ctx` is pinned to **16384**, roughly 4× the largest measured prompt, so the character caps in config cannot silently cross the limit.

**Determinism.** `temperature 0.1`, `top_k 40`, `top_p 0.9`: three benchmark runs over the corpus produced zero verdict flips. The system prompt is pinned resident (`num_keep 64`) so evidence cannot evict the role framing, and it instructs the model to treat `<untrusted_evidence>` content strictly as data.

```bash
ollama pull gemma4:e4b-it-qat
ollama create gemma4:e4b-it-qat-16k -f ollama/Modelfile   # from analyzer/
```

## The two-pass finding pipeline

`app/services/finding_analysis.py` runs per finding:

1. **Enrichment** (`build_enrichment_prompt`): description of the vulnerability _class_ for a mixed audience, concrete business impact referencing the parameter and path, exploitability (`Easy` / `Medium` / `Hard`) with evidence-backed reasoning, and remediation written for the detected technology stack.
2. **Adjudication** (`build_adjudication_prompt`): the model scores three categorical axes: `EVIDENTIAL_ALIGNMENT` (does the response demonstrate the claim?), `SCANNER_CLAIM_CONTRADICTED` (does the evidence prove the claim wrong, for example the "injection" is tutorial text?), and `CAUSALLY_CONNECTED` (was this response caused by our payload?). The scanner's evidence brief rides along as trusted context; raw response content is fenced as untrusted.

The FP probability is then **computed deterministically from the axes**, not taken from the model, and clamped to the per-proof-type floors and ceilings in `shared/models/vulnerability.py` (`PROOF_FLOORS` / `PROOF_CEILINGS`). A finding whose proof is a `pattern_match` can never reach the AI's "confirmed" band, and an `active_output` proof can never be dismissed below its floor. The verdict gates at `false_positive_probability ≥ 0.5` for `likely_false_positive`; the ceilings exist precisely so that verdict stays reachable for weak proof types.

An AI `likely_false_positive` verdict never suppresses a finding by itself. It moves it to `needs_review` for a human (see `refresh_review_status` in the shared model).

Finally `app/services/report_analysis.py` generates the executive summary from a bounded digest of the scan (`ANALYSIS_REPORT_INPUT_MAX_CHARS`).

## Durability: jobs, leases, retries

Analysis is **durable**, not fire-and-forget:

- The scanner's hand-off writes an `AnalysisJob` document and pushes a lightweight wake-up signal to the Redis analysis queue. If Redis is down the worker still finds due jobs by polling MongoDB; a periodic reconciliation pass (`reconcile_missing_analysis_jobs`, also run by the scanner worker) re-creates any completed scan's missing job.
- `claim_next` is an atomic find-and-modify with a **lease** (default 300s, renewed every 60s). Losing the lease, or a newer job revision appearing, aborts publication via `StaleAnalysisRevisionError`, so two workers can never double-publish.
- All writes to the scan's analysis projection go through `ResultApplier`, which checks the expected revision and lease owner on every update.
- Retryable provider errors reschedule with backoff plus jitter (30s, 120s, 600s) up to `max_attempts`; terminal failures mark the job and the projection `failed` with an error code the UI can show.
- On startup the worker recovers jobs whose leases expired mid-run (worker crash): re-queued if attempts remain, terminally failed otherwise.
- Token usage and provider request ids are recorded on the job for observability.

## Configuration

Repo-root `.env` first, then `analyzer/.env`. See `analyzer/.env.example`.

| Variable                                                  | Default                     | Notes                                                          |
| --------------------------------------------------------- | --------------------------- | -------------------------------------------------------------- |
| `AI_ANALYSIS_ENABLED`                                     | `true`                      | `false` = deterministic fallback, no LLM calls                 |
| `AI_BASE_URL`                                             | `http://localhost:11434/v1` | Any OpenAI-compatible endpoint                                 |
| `AI_MODEL`                                                | `gemma4:e4b-it-qat-16k`     | Warns at startup if not installed                              |
| `AI_API_KEY`                                              | none                        | If your endpoint needs one                                     |
| `AI_TIMEOUT_SECONDS` / `AI_MAX_RETRIES`                   | `120` / `3`                 | Per-call                                                       |
| `AI_JSON_MODE` / `AI_REASONING_EFFORT`                    | `true` / `none`             | Provider knobs                                                 |
| `ANALYSIS_LEASE_SECONDS` / `ANALYSIS_LEASE_RENEW_SECONDS` | `300` / `60`                | Job ownership                                                  |
| `ANALYSIS_POLL_SECONDS`                                   | `5`                         | Mongo fallback poll when the queue signal is absent            |
| `ANALYSIS_RECONCILE_INTERVAL_SECONDS`                     | `30`                        | Missing-job repair cadence                                     |
| `ANALYSIS_FINDING_EVIDENCE_MAX_CHARS`                     | `6000`                      | Evidence budget per finding (~2,650-token adjudication prompt) |
| `ANALYSIS_REPORT_INPUT_MAX_CHARS`                         | `24000`                     | Report digest budget (~4,120-token prompt)                     |

The character caps and the model's `num_ctx` are sized together. If you raise a cap, re-measure the prompt tokens (`benchmark/` has the harness) before touching the model.

## Benchmarks

`benchmark/` is the offline harness that calibrated the adjudication policy:

```bash
python -m benchmark.run_benchmark --variant baseline --model gemma4:e4b-it-qat-16k
python -m benchmark.run_benchmark --variant brief --runs 3
```

It replays prompt variants from `benchmark/variants.py` against the labelled corpora (`corpus.py`, 21 cases; `corpus_adversarial.py`, 10) and scores both the raw model verdict and the post-clamp verdict production would publish. Pass `--corpus all` to run both. `policy_sim.py` simulates floor/ceiling changes against recorded model outputs without re-running inference. The floors and ceilings shipped in `shared/models/vulnerability.py` carry their benchmark dates and outcomes in comments; re-run this before changing them.

## Project layout

```
app/
  worker.py                 queue consumer: claim, lease, retry, recover, notify
  config.py                 AnalyzerSettings
  clients/ai_client.py      OpenAI-compatible client, ProviderError taxonomy
  prompts/                  versioned prompt builders (finding, report)
  schemas/                  strict provider-response models
  services/                 finding_analysis, report_analysis, result_applier
benchmark/                  adjudication accuracy harness + labelled corpora
ollama/Modelfile            pinned-context analyzer model
tests/                      unit suite (provider fakes; no live LLM needed)
```
