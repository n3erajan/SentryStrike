<div align="center">

<img src="frontend/public/sentrystrike-logo.svg" alt="SentryStrike logo" width="112" />

# SentryStrike

**An Evidence-Driven Web Application DAST and Collaborative Vulnerability Management Platform with AI-Powered Finding Analysis and Report Generation**

[![Python 3.12](https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI 0.115](https://img.shields.io/badge/FastAPI-0.115-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![React 19](https://img.shields.io/badge/React-19-61DAFB?logo=react&logoColor=black)](https://react.dev/)
[![Playwright 1.60](https://img.shields.io/badge/Playwright-1.60-2EAD33?logo=playwright&logoColor=white)](https://playwright.dev/python/)
[![MongoDB 7](https://img.shields.io/badge/MongoDB-7-47A248?logo=mongodb&logoColor=white)](https://www.mongodb.com/)
[![Redis 7](https://img.shields.io/badge/Redis-7-DC382D?logo=redis&logoColor=white)](https://redis.io/)
[![Docker Compose](https://img.shields.io/badge/Docker-Compose-2496ED?logo=docker&logoColor=white)](https://docs.docker.com/compose/)

</div>

> [!CAUTION]
> SentryStrike sends active security-testing payloads and can exercise application workflows. Use it only on systems you own or are explicitly authorized to assess. The operator is responsible for scope, test windows, data handling, and legal compliance.

## What SentryStrike is

SentryStrike is an authorized Dynamic Application Security Testing (DAST) platform for web applications. It brings scanning, AI-assisted analysis, finding review, remediation tracking, and reporting into one workspace.

It assesses traditional websites and JavaScript-heavy single-page applications. HTTP crawling maps server-rendered pages. For an SPA, Playwright drives the browser through client-side routes, forms, interactions, and network activity, so the scan can work from the application surface that users actually reach.

Findings include reproducible evidence and an evidence grade. The AI worker uses that context to explain a finding, assess exploitability and business impact, suggest remediation, and flag likely false positives. Teams can then assign findings, discuss them, mark false positives, track remediation, request focused re-verification, and produce reports from the workspace.

SentryStrike supports repeatable web-security checks; it does not replace threat modeling, source review, business-logic testing, or manual penetration testing.

## From scan result to remediation work

Most scanners end at a list of possible issues. SentryStrike keeps the scan, its evidence, the AI analysis, and the work around a finding in the same workspace:

- **Grounded findings.** The scanner retains reproducible request/response evidence and uses response differentials, timing checks, browser execution, and OAST callbacks when the check supports them. Each finding records what the proof does and does not establish.
- **Private, bounded AI analysis.** The default analyzer uses local Ollama. Evidence stays inside the deployment unless the operator deliberately configures an external OpenAI-compatible provider. The analyzer produces structured descriptions, impact, remediation guidance, references, an executive summary, and a calibrated false-positive assessment.
- **Team workflow.** Workspace members can assign a finding, comment on it, mark it as a false positive, update remediation status, or request a focused re-verification.
- **Short-lived test credentials.** Test-account credentials are included only in the Redis scan-job payload and worker memory. The job leaves Redis when a worker claims it; credentials are never written to MongoDB.

## How a team uses it

1. A prospective owner requests access. After CLI approval, accepting the single-use owner invitation creates the workspace; the owner can then invite the people who will manage, analyze, and fix findings.
2. An owner, administrator, analyst, or developer adds an application and starts an authorized scan, optionally supplying dedicated test accounts for that scan. Viewers have read-only access.
3. The scanner builds an attack surface from pages, SPA routes, forms, and browser-observed requests; it then performs bounded checks, verifies candidates, and saves the evidence and scan progress.
4. The analyzer enriches completed findings and prepares the report summary. When AI analysis is intentionally disabled, it publishes deterministic fallback guidance; provider failures are recorded for retry and review.
5. Every workspace member can review evidence and AI output. Owners, administrators, and analysts can assign and triage findings; non-viewers can comment and update non-terminal remediation states.
6. Developers can move work to `fixed_pending_verification`. An owner, administrator, or analyst requests focused re-verification and closes or waives the finding. Any workspace member can export the completed PDF report.

### One assessment, three useful views

The same assessment must make sense to the person accepting the risk, the person fixing the code, and the person checking the security evidence. SentryStrike presents the results with the detail each of them needs:

| View                  | What it provides                                                                                                                                                                   |
| --------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Business owner**    | A plain-language explanation, business impact, severity, overall risk, and an executive summary for decision-making.                                                               |
| **Developer**         | The affected URL, method and parameters, request and response snippets, payload details, remediation guidance, assignment, comments, and fix status.                               |
| **Security reviewer** | Verification method, evidence strength, reproducibility, confidence, CVSS and OWASP mapping, AI false-positive assessment, coverage warnings, and focused re-verification results. |

## Security testing scope

SentryStrike uses HTTP crawling for traditional websites and Playwright for JavaScript-heavy SPAs. Browser observation supplies endpoints, methods, headers, request bodies, and parameters that can be safely replayed as part of the web-application assessment. The scanner can fingerprint technologies and enrich version evidence with NVD CVE data.

Active checks are mapped to the OWASP Top 10 (2025) where a web DAST scan can produce meaningful evidence. They cover authentication and access control, SQL/NoSQL/command injection, XSS, SSRF, CSRF, file inclusion and upload, open redirects, TLS and headers, sensitive paths, known component vulnerabilities, and exposed exceptional conditions.

Three OWASP categories are reported as outside active automated detector scope:

| Category                                        | Why it is outside automated DAST scope                                                                                                                                                                             |
| ----------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **A06: Insecure Design**                        | Identifying a flawed design requires business rules, architecture, trust boundaries, abuse cases, and threat-model context that cannot be inferred reliably from black-box requests and responses.                 |
| **A08: Software or Data Integrity Failures**    | Assessing update trust, build and deployment pipelines, artifact signing, and internal data-integrity controls requires access to development and operational systems beyond the running web application.          |
| **A09: Security Logging and Alerting Failures** | Verifying what the application logs, whether monitoring detects an event, and whether an alert reaches the right responder requires access to server-side logs, monitoring tools, and incident-response processes. |

Coverage still depends on what the target exposes, the configured limits, available authentication, and the evidence that can be gathered safely. Reports include coverage warnings instead of treating untested areas as passes. A clean scan is not proof that an application is secure.

## Architecture

![SentryStrike system architecture](./sentrystrike-architecture.svg)

| Component                | Technology                        | Responsibility                                                                                          |
| ------------------------ | --------------------------------- | ------------------------------------------------------------------------------------------------------- |
| [`frontend/`](frontend/) | React 19, Vite 8, Tailwind CSS 4  | Workspace UI for scans, finding review, collaboration, and reports                                      |
| [`backend/`](backend/)   | FastAPI, Beanie, Motor, ReportLab | Authentication, workspace policy, scan coordination, notifications, PDF reports, and OAST callbacks     |
| [`scanner/`](scanner/)   | Python, Playwright, HTTPX         | Web and SPA discovery, bounded detection, verification, evidence grading, and re-verification           |
| [`analyzer/`](analyzer/) | Python, HTTPX                     | Local-Ollama-first AI enrichment, false-positive assessment, remediation guidance, and report summaries |
| [`shared/`](shared/)     | Pydantic, Beanie, Redis           | Domain models, tenant-scoped repositories, queue contracts, and cross-service policy                    |
| MongoDB                  | Document store                    | Workspaces, users, scans, evidence, analysis jobs, notifications, and audit records                     |
| Redis                    | Ephemeral coordination            | Scan jobs, analysis signals, cancellation keys, leases, and worker heartbeats                           |

The backend creates the scan record before it places a compact job on Redis. A scanner worker claims the job, persists progress and evidence to MongoDB, and creates a durable analysis handoff on completion. Redis wakes an analyzer worker, while MongoDB remains the source of truth for analysis retries and recovery. The frontend accesses this state only through the backend API.

## Repository layout

```text
SentryStrike/
|-- frontend/       React workspace application
|-- backend/        FastAPI control plane and management CLI
|-- scanner/        DAST crawl, detection, verification, and re-verification worker
|-- analyzer/       Durable AI analysis worker
|-- shared/         Shared models, repositories, queues, and policies
|-- docs/assets/    Documentation assets and editable diagrams
|-- docker-compose.yml
|-- start-dev.ps1   Optional Windows multi-service development launcher
`-- .env.example    Shared deployment configuration template
```

## Quick start for local development

### Prerequisites

- Python 3.12
- Node.js 20.19+ or 22.12+
- Docker with Docker Compose for MongoDB and Redis
- A POSIX-compatible shell such as Bash or Zsh (or PowerShell with the equivalent commands)

### 1. Create configuration files

```bash
cp .env.example .env
cp backend/.env.example backend/.env
cp scanner/.env.example scanner/.env
cp analyzer/.env.example analyzer/.env
```

The frontend needs no `.env` file for the normal local setup: Vite proxies `/api` to the backend. Create `frontend/.env` only when the frontend must call an API at a different origin; see [frontend configuration](#configuration).

### 2. Start MongoDB and Redis

```bash
docker compose up -d mongo redis
```

### 3. Install dependencies

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
pip install -r backend/requirements-dev.txt -r scanner/requirements-dev.txt -r analyzer/requirements-dev.txt
python -m playwright install chromium
npm --prefix frontend ci
```

### 4. Start the services

Start each service in a separate terminal from the repository root. Activate the virtual environment in each Python-service terminal first.

```bash
# backend
cd backend && uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload

# scanner
cd scanner && python -m app.worker

# analyzer
cd analyzer && python -m app.worker

# frontend
cd frontend && npm run dev
```

Windows users can instead run `./start-dev.ps1` in PowerShell to open the four services in separate windows.

| Service               | Local URL                             |
| --------------------- | ------------------------------------- |
| Frontend              | <http://localhost:5173>               |
| Backend API           | <http://localhost:8000/api/v1>        |
| OpenAPI documentation | <http://localhost:8000/docs>          |
| Health endpoint       | <http://localhost:8000/api/v1/health> |

### 5. Request and approve the first workspace owner

Registration is invitation-only. With the frontend and backend running, open
<http://localhost:5173/request-access> and submit a workspace-access request.
The development configuration uses Cloudflare Turnstile's official test keys.

Review the pending request and approve it from the backend CLI:

```bash
cd backend
python -m app.cli list
python -m app.cli approve <request-id> --member-limit 10
```

Approval creates the owner invitation, prints its link or token, and attempts to
email it. A rejected request can instead be removed with:

```bash
python -m app.cli reject <request-id>
```

Pending access requests are limited by IP in Redis, deduplicated by normalized
email address, and automatically removed from MongoDB after 30 days. Approved
and rejected requests are removed immediately.

## Configuration

Configuration is split by service so that scanner limits, email credentials, and AI-provider credentials do not end up in one catch-all file. Copy the templates above, then change only what your setup needs.

### Required for a basic local setup

| File                                             | What to set                                     | Notes                                                                                                                                                      |
| ------------------------------------------------ | ----------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Root [`.env.example`](.env.example)              | Usually nothing                                 | The localhost MongoDB, Redis, queue, and port defaults work with the quick start. Set `PUBLIC_HOSTNAME` when invite and OAST links need a public base URL. |
| [`backend/.env.example`](backend/.env.example)   | Usually nothing                                 | Development cookie, CORS, SMTP, and Turnstile test defaults work locally. Production requires real Turnstile keys.                                         |
| [`scanner/.env.example`](scanner/.env.example)   | Usually nothing                                 | Start with the supplied crawl and request limits; lower them for fragile applications.                                                                     |
| [`analyzer/.env.example`](analyzer/.env.example) | `AI_BASE_URL` and `AI_MODEL` only if you use AI | Defaults expect Ollama on the host. Set `AI_ANALYSIS_ENABLED=false` to run without provider calls.                                                         |

### Optional configuration

| Area                                | Variables                                                                                                 | When to change them                                                                                           |
| ----------------------------------- | --------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| Email invitations and notifications | `EMAIL_SMTP_*`, `EMAIL_FROM`                                                                              | Required for delivery by email; otherwise use the locally printed invitation link.                            |
| AI provider                         | `AI_BASE_URL`, `AI_MODEL`, `AI_API_KEY`, `AI_TIMEOUT_SECONDS`, `AI_MAX_RETRIES`, `AI_JSON_MODE`           | Use a hosted or self-hosted OpenAI-compatible provider, choose a model, or tune provider behavior.            |
| Scan safety and capacity            | `CRAWL_*`, `REQUEST_TIMEOUT_SECONDS`, `SCANNER_CONCURRENCY`, request caps, access-control safety settings | Match scan intensity to the authorized target and test window.                                                |
| CVE enrichment                      | `NVD_API_KEY`, `NVD_API_URL`                                                                              | Add an NVD API key if needed for your rate limit.                                                             |
| Deployment security                 | `AUTH_COOKIE_SECURE`, `CORS_ORIGINS`, `PUBLIC_HOSTNAME`                                                   | Set secure cookies, explicit origins, and the public address used for invitation links and backend callbacks. |

For Docker-specific variables, production hardening, OAST routing, scaling, and backup guidance, read [DOCKER.md](DOCKER.md). Treat scan evidence, logs, notifications, and PDF reports as sensitive assessment data.

## Testing

```bash
python -m pytest backend/tests
python -m pytest scanner/tests
python -m pytest analyzer/tests

npm --prefix frontend test
npm --prefix frontend run lint
npm --prefix frontend run build
```

Browser and integration suites may require Chromium, MongoDB, Redis, or isolated network-visible test targets. The component guides include narrower commands and settings.

## Documentation

- [Frontend guide](frontend/README.md)
- [Backend guide](backend/README.md)
- [Scanner guide](scanner/README.md)
- [Analyzer guide](analyzer/README.md)
- [Shared package guide](shared/README.md)
- [Docker deployment guide](DOCKER.md)

## Responsible use

Obtain written authorization, define allowed hosts and methods, agree on test windows, use dedicated accounts and data, and establish escalation contacts before scanning. Review the evidence and coverage manually. A missing automated finding does not prove that a target is secure.
