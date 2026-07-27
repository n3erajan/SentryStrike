# SentryStrike Backend

The backend is SentryStrike's authenticated control plane. It exposes the FastAPI REST API, manages organizations and sessions, persists scan and collaboration state in MongoDB, coordinates Redis-backed work queues, and generates PDF reports.

Scanning and AI analysis run in separate workers; API requests enqueue durable work instead of performing long-running assessments in the web process.

## Responsibilities

- Invite-only registration and HttpOnly session-cookie authentication
- Tenant isolation and role-based authorization for owners, admins, analysts, developers, and viewers
- Web application inventory and scan lifecycle management
- Finding review, assignments, comments, false-positive decisions, remediation tracking, and re-verification requests
- Notifications, audit history, membership, invitations, and retention settings
- JSON report projection and PDF generation
- Public OAST callback collection for blind verification
- Scanner heartbeat reporting through the health endpoint

## Stack

- Python 3.12
- FastAPI and Uvicorn
- Pydantic settings and schemas
- Beanie and Motor for MongoDB
- Redis for scan and analysis signaling
- ReportLab for PDF generation

## Run locally

From the repository root, install the shared package and backend dependencies:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e .
python -m pip install -r backend/requirements-dev.txt
cp backend/.env.example backend/.env
```

The backend also reads the root `.env`. Start MongoDB and Redis, then run:

```bash
cd backend
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

Open <http://localhost:8000/docs> for the generated OpenAPI interface. The health endpoint is available at <http://localhost:8000/api/v1/health>.

## API groups

All application endpoints use the `/api/v1` prefix.

| Prefix           | Purpose                                                                               |
| ---------------- | ------------------------------------------------------------------------------------- |
| `/auth`          | Invitation preview, registration, login, logout, and current user                     |
| `/applications`  | Workspace application inventory and application scan history                          |
| `/scans`         | Submission, listing, detail, status, and cancellation                                 |
| `/analysis`      | Finding detail, review, assignment, comments, remediation, retry, and re-verification |
| `/reports`       | Report data and PDF download                                                          |
| `/workspace`     | Workspace profile, members, invitations, audit log, and retention                     |
| `/notifications` | Notification listing, unread count, and read state                                    |
| `/health`        | API status and active scanner count                                                   |

The OAST routes live at `/oast`, outside `/api/v1`, and are intentionally unauthenticated so tested targets can call back. Interaction IDs are validated before data is stored.

## Response and authentication model

Most JSON endpoints return:

```json
{
  "success": true,
  "message": "optional status message",
  "data": {}
}
```

Login and registration set an HttpOnly session cookie. Production deployments should use HTTPS with `AUTH_COOKIE_SECURE=true`, a restrictive `CORS_ORIGINS` list, and an appropriate `AUTH_COOKIE_SAMESITE` value.

## Management CLI

Run commands from `backend/` with the repository virtual environment active.

```bash
python -m app.cli invite-owner --email owner@example.com --org "Example Security" --member-limit 10
python -m app.cli invite-status --email owner@example.com
python -m app.cli email-check --to operator@example.com
python -m app.cli set-member-limit --org-id <organization-id> --limit 25
python -m app.cli purge-retention
```

Owner onboarding is deliberately CLI-only. The first accepted owner invitation creates the workspace and owner account together.

## Configuration

Start with [`../.env.example`](../.env.example) for MongoDB, Redis, queues, and public-host settings, then [`./.env.example`](.env.example) for backend-specific values.

Important production settings include:

- `CORS_ORIGINS`
- `AUTH_SESSION_TTL_HOURS`, `AUTH_COOKIE_SECURE`, and `AUTH_COOKIE_SAMESITE`
- `EMAIL_SMTP_HOST`, `EMAIL_SMTP_USER`, and `EMAIL_SMTP_PASSWORD`
- invitation lifetime and rate-limit settings
- `RETENTION_PURGE_INTERVAL_SECONDS`

Gmail SMTP requires both a username and app password. Settings validation fails fast when only one credential is supplied or Gmail is selected without credentials.

SMTP is used for invitation and notification delivery. Local development can use the invitation link printed by the management CLI instead.

## Project structure

```text
app/
├── api/routes/       FastAPI routers
├── core/             Auth, invitations, email, errors, and retention
├── schemas/          Request and response models
├── utils/            PDF generation
├── cli.py            Vendor management commands
├── config.py         Backend settings
├── main.py           FastAPI application and lifespan wiring
└── retention_worker.py
```

Database models, repositories, and queue implementations are shared from [`../shared`](../shared/README.md).

## Tests

```bash
python -m pytest backend/tests
python -m pytest backend/tests/unit
python -m pytest backend/tests/integration
python -m pytest backend/tests --cov=backend/app --cov-report=term-missing
```

Run commands from the repository root so both `backend` and `shared` imports resolve consistently.
