# SentryStrike Analyzer

The analyzer is a durable background worker that turns scanner evidence into structured finding guidance and a report-level executive summary. It uses Ollama by default and can connect to any OpenAI-compatible chat-completions API. Every provider response is schema-validated, calibrated against deterministic false-positive rules, and published only while the worker owns the current analysis revision.

The analyzer does not discover vulnerabilities. Scanner evidence remains the source of the finding; model output adds explanation, exploitability context, business impact, remediation guidance, and conservative false-positive adjudication.

## Processing model

1. A completed scan receives a durable `AnalysisJob` in MongoDB and a wake-up signal in Redis.
2. A worker atomically claims due work and obtains a renewable lease.
3. Each finding is processed in two provider passes:
   - enrichment for description, exploitability, impact, remediation, and references;
   - adjudication for categorical false-positive axes, verdict, and reasoning.
4. Deterministic floors, ceilings, and downgrade rules calibrate the provider's false-positive probability.
5. Progress and per-finding analysis are published with revision and lease guards.
6. A final report summary is generated and the job becomes terminal.

Provider and schema failures use bounded retries. Expired leases are recovered on startup, stale revisions cannot overwrite newer analysis, and MongoDB polling repairs missed or duplicate Redis signals.

## Provider requirements

The default provider is Ollama at `http://localhost:11434/v1`, using the configured `AI_MODEL`. Docker Compose uses `host.docker.internal` to reach Ollama running on the host. Any provider implementing an OpenAI-compatible chat-completions API can be used by changing `AI_BASE_URL`, `AI_MODEL`, and credentials when required.

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
| `ANALYSIS_FINDING_EVIDENCE_MAX_CHARS` | Per-finding prompt input bound |
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
