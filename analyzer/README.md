# SentryStrike Analyzer

The analyzer is a durable background worker that turns scanner evidence into structured finding guidance and a report-level executive summary. It uses local Ollama by default, so evidence remains in the deployment. It can also connect to an OpenAI-compatible chat-completions API when that is explicitly configured. Every provider response is schema-validated, calibrated against deterministic false-positive rules, and published only while the worker owns the current analysis revision.

The analyzer does not discover vulnerabilities. Scanner evidence remains the source of the finding; model output adds explanation, exploitability context, business impact, remediation guidance, and conservative false-positive adjudication.

## Processing model

1. A completed scan receives a durable `AnalysisJob` in MongoDB and a wake-up signal in Redis.
2. A worker atomically claims due work and obtains a renewable lease.
3. Each finding is processed in two provider passes:
   - enrichment for description, exploitability, impact, remediation, and references;
   - adjudication for categorical false-positive axes, verdict, and reasoning. The scanner's evidence brief, which states what the proof type establishes and where it is weak, is supplied as trusted input alongside the untrusted target evidence.
4. Deterministic floors and ceilings bound the provider's false-positive probability by proof type, and a downgrade rule requires a probability of at least 0.50 with supporting reasoning before a `likely_false_positive` verdict is accepted. Ceilings stay above that threshold so the adjudication pass can act on every proof type; they remain ordered by proof quality, so dismissing dynamic exploitation proof requires more than dismissing a pattern match.
5. Progress and per-finding analysis are published with revision and lease guards.
6. A final report summary is generated and the job becomes terminal.

Provider and schema failures use bounded retries. Expired leases are recovered on startup, stale revisions cannot overwrite newer analysis, and MongoDB polling repairs missed or duplicate Redis signals.

## Provider requirements

The default provider is Ollama at `http://localhost:11434/v1`, using the configured `AI_MODEL`. Docker Compose uses `host.docker.internal` to reach Ollama running on the host. With this default, scanner evidence is sent only to the local Ollama service. Any provider implementing an OpenAI-compatible chat-completions API can be used by changing `AI_BASE_URL`, `AI_MODEL`, and credentials when required; its data-handling policy then applies.

Build the default model once before the first scan:

```bash
ollama create gemma4:e4b-it-qat-16k -f analyzer/ollama/Modelfile
```

The Modelfile pins the context window the analyzer's prompts require. An
undersized window is not a visible failure: Ollama drops the overflow and the
model answers from what remains, so a truncated adjudication reaches the API
looking identical to a real one. See [`ollama/README.md`](ollama/README.md) for
the measured prompt sizes and model comparison.

The selected model should reliably return JSON matching the analyzer's Pydantic schemas. Provider request IDs and available token counts are retained on the analysis job for observability.

## Run locally

From the repository root:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e .
python -m pip install -r analyzer/requirements-dev.txt
cp analyzer/.env.example analyzer/.env
```

With MongoDB and Redis running:

```bash
cd analyzer
python -m app.worker
```

The scanner or backend must create analysis jobs before the worker has work to claim.

## Configuration

Shared infrastructure and queue variables live in [`../.env.example`](../.env.example). Analyzer settings live in [`.env.example`](.env.example).

| Variable | Purpose |
| --- | --- |
| `AI_ANALYSIS_ENABLED` | Toggle AI analysis on or off. Default `true`. The backend blocks PDF export until analysis completes, so disabling this makes scans finish faster when no AI provider or Ollama is available. Falls back to deterministic templates |
| `AI_BASE_URL` | OpenAI-compatible API root |
| `AI_MODEL` | Provider model identifier |
| `AI_API_KEY` | Optional bearer credential |
| `AI_TIMEOUT_SECONDS` | Timeout for one provider request |
| `AI_MAX_RETRIES` | Bounded provider retry count |
| `AI_JSON_MODE` | Request structured JSON output when supported |
| `AI_REASONING_EFFORT` | Optional provider reasoning control |
| `ANALYSIS_LEASE_SECONDS` | Job ownership duration |
| `ANALYSIS_LEASE_RENEW_SECONDS` | Lease renewal cadence |
| `ANALYSIS_POLL_SECONDS` | Redis wait and MongoDB polling cadence |
| `ANALYSIS_RECONCILE_INTERVAL_SECONDS` | Missing-job repair cadence |
| `ANALYSIS_FINDING_EVIDENCE_MAX_CHARS` | Per-finding prompt input bound. Detection metadata is always retained; the response excerpt is fitted to the remaining budget |
| `ANALYSIS_REPORT_INPUT_MAX_CHARS` | Report-summary prompt input bound |

## Project structure

```text
app/
├── clients/       OpenAI-compatible HTTP client and provider errors
├── prompts/       Versioned finding and report prompt builders
├── schemas/       Strict provider response schemas
├── services/      Finding analysis, report analysis, and guarded publication
├── config.py
└── worker.py      Claiming, leases, retries, reconciliation, and notifications
```

## Tests

```bash
python -m pytest analyzer/tests
python -m pytest analyzer/tests --cov=analyzer/app --cov-report=term-missing
```

Unit tests mock provider behavior and cover schema validation, deterministic calibration, configuration, two-pass adjudication, and worker recovery paths.
