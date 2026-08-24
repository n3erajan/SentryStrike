<div align="center">

<img src="frontend/public/sentrystrike-logo.svg" alt="SentryStrike" width="88">

# SentryStrike

**An Evidence-Driven Web Application DAST and Collaborative Vulnerability Management Platform with AI-Powered Finding Analysis and Report Generation**

[![Python](https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/React-19-61DAFB?logo=react&logoColor=black)](https://react.dev)
[![MongoDB](https://img.shields.io/badge/MongoDB-7-47A248?logo=mongodb&logoColor=white)](https://mongodb.com)
[![Redis](https://img.shields.io/badge/Redis-7-DC382D?logo=redis&logoColor=white)](https://redis.io)
[![Playwright](https://img.shields.io/badge/Playwright-1.60-2EAD33?logo=playwright&logoColor=white)](https://playwright.dev)
[![Ollama](https://img.shields.io/badge/Ollama-local%20LLM-000000?logo=ollama&logoColor=white)](https://ollama.com)
[![Docker](https://img.shields.io/badge/Docker-compose-2496ED?logo=docker&logoColor=white)](https://docker.com)

</div>

---

SentryStrike is a dynamic application security testing (DAST) platform. Point it at a running web application and it crawls the attack surface (including JavaScript-heavy single-page apps), fires a battery of vulnerability detectors, verifies each finding with replayable proof, and has a local LLM adjudicate every result so your team triages real issues instead of scanner noise. Findings land in a multi-tenant workspace where your team can assign, discuss, re-verify, and export them as a PDF report.

## Why SentryStrike

Traditional DAST tools drown teams in false positives. SentryStrike is built around one idea: **a finding is only as good as its evidence.**

- **Proof-carrying findings.** Every detector records the exact request, payload, and response that triggered it as an immutable verification target. Any finding can be replayed later, by a human or by the one-click re-verification job, to confirm it still reproduces.
- **Deterministic evidence grading.** Findings are graded by proof type (`active_output`, `timing_strong`, `auth_differential`, and more) with calibrated confidence floors and ceilings, so a regex coincidence can never outrank a confirmed exploit.
- **AI false-positive adjudication.** A local LLM (Ollama) reviews each finding's evidence brief and returns a calibrated false-positive probability. Weak evidence is mathematically capped so the model cannot talk itself into dismissing a real bug or confirming a phantom one.
- **Built for teams.** Organizations, role-based access, seat management, finding assignment, remediation workflow, comments, and audit logging are first-class.

## Architecture

Four services backed by MongoDB and Redis:

<div align="center">
<img src="sentrystrike-architecture.svg" alt="SentryStrike system architecture" width="900">
</div>

The data plane is MongoDB (durable state) and Redis (queues, leases, heartbeats, cancellation signals). The `shared` package holds the models, repositories, and queue clients used by all three Python services, which is what keeps the scan-to-analysis hand-off transactional and crash-safe.

## Components

| Directory                         | What it is                                                                        |
| --------------------------------- | --------------------------------------------------------------------------------- |
| [`backend/`](backend/README.md)   | FastAPI REST API: auth, workspaces, scans, findings, reports, OAST callbacks      |
| [`scanner/`](scanner/README.md)   | Headless DAST worker: crawler, 16 detectors, verifiers, evidence grading          |
| [`analyzer/`](analyzer/README.md) | AI analysis worker: LLM enrichment, false-positive adjudication, report summaries |
| [`frontend/`](frontend/README.md) | React SPA: dashboards, scan launch, triage, team management, reports              |
| [`shared/`](shared/README.md)     | Shared Python package: MongoDB models, repositories, Redis queues, config         |

## Feature tour

- **Crawling.** Depth-limited spider with a Playwright browser engine for SPAs: route extraction from JS bundles, API endpoint discovery, form interaction, workflow exploration, and per-route budgets so a heavy app cannot stall the scan.
- **Detection.** 16 detectors covering the automatable slice of the OWASP Top 10 (2025): A01 Broken Access Control (IDOR, forced browsing, mass assignment, authorization matrix), A02 Security Misconfiguration (security headers, sensitive paths), A03 Supply Chain (technology fingerprinting + NVD CVE lookup), A04 Cryptographic Failures (TLS via SSLyze), A05 Injection (SQLi, NoSQLi, XSS including DOM, command injection, file inclusion, file upload, SSRF, open redirect), A07 Authentication Failures (form/session/JWT/API auth, CSRF), and A10 Mishandling of Exceptional Conditions (stack traces, error pages).
- **Verification.** Raw findings are replayed against a control before they are published, so a result has to survive an attack-versus-benign comparison rather than a single suspicious response. Blind vulnerabilities (SSRF, blind SQLi) are confirmed out-of-band through the built-in OAST collaborator: the scanner mints a unique callback URL, the target's server-side fetch calls home, and the scanner polls the backend for the interaction.
- **Evidence grading.** A deterministic grader scores each finding by proof type and auth context, producing the `confirmed_exploit` through `informational` strength ladder and the false-positive probability floors and ceilings the analyzer must respect.
- **AI analysis.** Per-finding enrichment (plain-language description, business impact, exploitability, stack-specific remediation) plus a second adjudication pass that scores false-positive probability on calibrated axes, then a whole-scan report summary. Fully local via Ollama; no target data leaves your infrastructure.
- **Re-verification.** One click re-runs the stored verification target with fresh credentials and records an immutable outcome (`still_present`, `resolved`, `inconclusive`) with its own evidence.
- **Team workflow.** Findings carry a remediation state machine (`open` → `in_progress` → `fixed_pending_verification` → `verified_fixed`, or `wont_fix`), assignment, threaded comments, and per-org audit logs. Roles (`owner`, `admin`, `analyst`, `developer`, `viewer`) gate actions, not visibility.
- **Reporting.** Per-scan reports with severity rollups, scanner-limitation disclosure, and a generated PDF export.
- **Operations.** Scan cancellation with sub-second Redis pub/sub delivery, per-scan worker leases for dead-worker detection, durable analysis jobs with leases, retry backoff, and crash recovery, scan-data retention purging (30-day compliance floor), Cloudflare Turnstile on public endpoints, and rate-limited invites and access requests.

## Quick start (Docker)

You need Docker. MongoDB and Redis are provided by the compose file.

```bash
git clone <this-repo> && cd SentryStrike
cp .env.example .env                      # set PUBLIC_HOSTNAME; the rest has working defaults
cp backend/.env.example backend/.env      # cookies, SMTP, Turnstile
cp scanner/.env.example scanner/.env      # crawl and request budgets
cp analyzer/.env.example analyzer/.env    # AI provider
docker compose up -d --build
```

Copy all four. Compose loads each service's `.env` only if it exists and otherwise falls back to code defaults, and one of those defaults is wrong in a container: `AI_BASE_URL` defaults to `http://localhost:11434/v1`, which inside the analyzer container is the container itself, not your Ollama host. `analyzer/.env.example` uses `host.docker.internal` instead, which compose maps to the host gateway.

Then open `http://localhost` (port `80` by default, override with `FRONTEND_PORT`).

### Creating the first workspace

Registration is invite-only; there is no self-serve signup. The first owner is approved from the backend CLI by design: owner onboarding is a vendor operation, so it has no HTTP surface to attack.

1. Open `http://localhost/request-access` and submit the form. `backend/.env.example` ships Cloudflare's Turnstile test keys, so the widget passes locally.
2. Approve the request from inside the backend container:

   ```bash
   docker compose exec backend python -m app.cli list
   docker compose exec backend python -m app.cli approve <request-id> --member-limit 10
   ```

   Approval creates the owner invite and prints the signup link, and emails it when SMTP is configured. Locally, use the printed link. `python -m app.cli reject <request-id>` discards a request instead.

3. Register with the invited email. That creates the workspace and the owner account together; the owner then invites teammates from **Team**.

Useful commands:

```bash
docker compose logs -f backend scanner analyzer   # follow the pipeline
docker compose down                               # stop (add -v to drop mongo data)
```

The compose stack is single-origin: the frontend container's nginx serves the SPA and proxies `/api/` and `/oast/` to the backend, so there is nothing else to expose.

### Set PUBLIC_HOSTNAME before you trust a blind finding

`PUBLIC_HOSTNAME` is the one value with no usable default. The scanner derives both OAST URLs from it, and if it is empty they stay unset - the out-of-band checks are skipped rather than failed, so blind SSRF and blind SQL injection quietly go undetected and the scan still reports success. Set it to a base URL the _target_ can reach:

```dotenv
PUBLIC_HOSTNAME=https://sentry.example.com
```

For a public deployment, route `/oast/` at your external reverse proxy to the backend the same way you route `/api/`. Override `OAST_CALLBACK_BASE_URL` (what the target calls) and `OAST_POLL_URL` (what the scanner polls) in the root `.env` when they differ - compose interpolates the root `.env` before service `env_file` values load, so Compose-specific OAST overrides belong there, not in `scanner/.env`. See [DOCKER.md](DOCKER.md#oast-callbacks-in-compose) for the two mistakes that break it.

## Local development

Prerequisites: Python 3.12, Node 20+, MongoDB, Redis, and (for AI analysis) Ollama.

```bash
# 1. Python environment with the shared package installed
python -m venv .venv
.venv\Scripts\activate                       # Windows; or source .venv/bin/activate
pip install -e .                             # the `shared` package
pip install -r backend/requirements-dev.txt -r scanner/requirements-dev.txt -r analyzer/requirements-dev.txt
playwright install chromium                  # scanner browser engine

# 2. Frontend deps
cd frontend && npm install && cd ..

# 3. Environment
cp .env.example .env                         # shared infra + queue keys
cp backend/.env.example backend/.env
cp scanner/.env.example scanner/.env
cp analyzer/.env.example analyzer/.env
cp frontend/.env.example frontend/.env       # VITE_API_URL for the dev server
```

The `-dev` requirement files pull in each service's runtime dependencies plus the test toolchain; production images install `requirements.txt` only, so pytest never ships.

On Windows, `start-dev.ps1` launches all four processes (backend on :8000, scanner worker, analyzer worker, Vite dev server on :5173) in separate terminals, and pre-sets the scanner's two OAST URLs for a localhost backend. On any platform you can start them by hand:

```bash
cd backend  && uvicorn app.main:app --reload --port 8000
cd scanner  && python -m app.worker
cd analyzer && python -m app.worker
cd frontend && npm run dev
```

Starting by hand, give the scanner the OAST URLs yourself (or set `PUBLIC_HOSTNAME`), otherwise the out-of-band checks are skipped:

```dotenv
# scanner/.env
OAST_CALLBACK_BASE_URL=http://host.docker.internal:8000/oast
OAST_POLL_URL=http://localhost:8000/oast/poll
```

Then bootstrap the first workspace exactly as in the Docker flow above, dropping `docker compose exec backend`: run `python -m app.cli list` and `python -m app.cli approve <request-id>` from the `backend/` directory.

### The analyzer model

The analyzer defaults to a custom Ollama model that pins a 16k context window and a low temperature. A stock Ollama install silently truncates the report prompt otherwise, and truncation produces confident verdicts about evidence the model never saw. Build it once:

```bash
ollama pull gemma4:e4b-it-qat
ollama create gemma4:e4b-it-qat-16k -f analyzer/ollama/Modelfile
```

Set `AI_ANALYSIS_ENABLED=false` to run the analyzer in deterministic-fallback mode (no LLM calls; findings are published without AI enrichment).

## API at a glance

All endpoints are under `/api/v1` and return a uniform envelope (`{ success, message, ... }`) with an `X-Request-ID` support reference on every response. Interactive docs are available at `/docs` when `APP_DEBUG=true`.

| Group           | Endpoints                                                                                                                                                       |
| --------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Auth            | `POST /auth/register` (invite-only) · `POST /auth/login` · `POST /auth/logout` · `GET /auth/session` · `GET /auth/me` · `GET /auth/invite` · `GET /auth/config` |
| Access requests | `POST /access-requests` (202, public, rate-limited) · `GET /access-requests/config`                                                                             |
| Applications    | `POST/GET /applications` · `GET/PUT/DELETE /applications/{id}` · `GET /applications/{id}/scans`                                                                 |
| Scans           | `POST /scans` (202, queued) · `GET /scans` · `GET /scans/{id}` · `GET /scans/{id}/status` · `POST /scans/{id}/cancel`                                           |
| Findings        | `GET /scans/{id}/vulnerabilities` · review / assignment / comments / remediation under `…/vulnerabilities/{vid}` · re-verification `POST …/reverifications`     |
| Analysis        | `POST /analysis/scans/{id}/retry`                                                                                                                               |
| Reports         | `GET /reports/{scan_id}` · `GET /reports/{scan_id}/pdf`                                                                                                         |
| Workspace       | members, invites, settings, `GET /workspace/audit-log`, retention                                                                                               |
| Notifications   | list, unread count, mark read, mark all read                                                                                                                    |
| Health          | `GET /health` (liveness + live scanner-worker count)                                                                                                            |
| OAST (no auth)  | `GET /oast/{interaction_id}` (callback) · `GET /oast/poll?id=…`                                                                                                 |

There is also an operator CLI in the backend for access-request approval, invite status, retention purges, and seat management: `python -m app.cli --help`.

## Testing

```bash
pytest backend/tests scanner/tests analyzer/tests        # Python suites
cd frontend && npm test                                  # node --test unit tests
cd frontend && npm run lint
```

## Documentation

- [Docker deployment and operations](DOCKER.md)
- [Frontend guide](frontend/README.md)
- [Backend guide](backend/README.md)
- [Scanner guide](scanner/README.md)
- [Analyzer guide](analyzer/README.md)
- [Shared package guide](shared/README.md)

## Responsible use

SentryStrike is an **active** scanner: it submits forms, fires exploit payloads, and probes sensitive paths. Only run it against applications you own or have explicit written authorization to test. Authenticated scanning uses the test accounts you supply; credentials travel inside the Redis job payload, are removed when a worker claims the job, and are never written to the database.
