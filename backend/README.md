# SentryStrike Backend

The backend is SentryStrike's authenticated control plane. It exposes the FastAPI REST API, manages organizations and sessions, persists scan and collaboration state in MongoDB, coordinates Redis-backed work queues, and generates PDF reports.

Scanning and AI analysis run in separate workers, so the web process does not perform long-running assessments. Scan state is durable in MongoDB, while scan execution is dispatched through a short-lived Redis job. Analysis work is durable in MongoDB and Redis acts only as a wake-up signal.

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

### Workspace role permissions

| Operation | Owner | Admin | Analyst | Developer | Viewer |
| --- | :---: | :---: | :---: | :---: | :---: |
| Read workspace scans, findings, and reports | Yes | Yes | Yes | Yes | Yes |
| Create applications and scans; cancel scans | Yes | Yes | Yes | Yes | No |
| Comment and update non-terminal remediation | Yes | Yes | Yes | Yes | No |
| Assign, review, retry analysis, and request re-verification | Yes | Yes | Yes | No | No |
| Close or waive remediation | Yes | Yes | Yes | No | No |
| Read audit history | Yes | Yes | No | No | No |
| Read retention settings | Yes | Yes | Yes | Yes | Yes |
| Manage members, invitations, and retention settings | Yes | Yes | No | No | No |
| Rename the workspace | Yes | No | No | No | No |

All authenticated operations are scoped to the current organization. The API prevents removing or demoting the owner and prevents a user from changing or removing their own membership.

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
Use `python -m app.cli --help` to see the command overview, or append `--help`
to any command for its arguments, aliases, and an example.

```bash
python -m app.cli list --limit 50
python -m app.cli approve <request-id> --member-limit 10
python -m app.cli reject <request-id>
python -m app.cli status owner@example.com
python -m app.cli email operator@example.com
python -m app.cli set-limit <organization-id> 25
python -m app.cli purge
```

The previous long-form command names remain available as aliases.

Prospective owners submit through the public `/request-access` page, but review
and approval remain CLI-only. Approval creates and emails a single-use owner
invitation using the organization name and email from the request. The first
accepted owner invitation creates the workspace and owner account together.

The public endpoint verifies Cloudflare Turnstile server-side and uses Redis to
allow 3 submissions per IP every 15 minutes and 10 per IP per day (configurable via `ACCESS_REQUEST_IP_LIMIT_PER_FIFTEEN_MINUTES` and `ACCESS_REQUEST_IP_LIMIT_PER_DAY`). Redis
failure returns `503`. Only one pending request is stored per normalized email.
MongoDB removes pending requests after 30 days, while CLI approval and rejection
remove them immediately.

The production Compose stack trusts forwarded client addresses because the
backend port is private and public traffic reaches it only through the bundled
nginx container. If you deploy behind a different proxy, configure Uvicorn's
`FORWARDED_ALLOW_IPS` for that trusted proxy so rate limits use the real client
address. Never trust forwarded headers when the backend is directly exposed.

## Configuration

Start with [`../.env.example`](../.env.example) for MongoDB, Redis, queues, and public-host settings, then [`./.env.example`](.env.example) for backend-specific values.

In production mode (`APP_DEBUG=false`) the backend blocks scan targets that
resolve to private, loopback, or link-local network addresses (``10.x.x.x``,
``192.168.x.x``, ``172.16-31.x.x``, ``127.x.x.x``, ``169.254.x.x``,
``localhost``). Local development is unaffected because ``APP_DEBUG`` defaults
to ``true``.

Important production settings include:

- `CORS_ORIGINS`
- `AUTH_SESSION_TTL_HOURS`, `AUTH_COOKIE_SECURE`, and `AUTH_COOKIE_SAMESITE`
- `TURNSTILE_SITE_KEY` and `TURNSTILE_SECRET_KEY`
- `ACCESS_REQUEST_IP_LIMIT_PER_FIFTEEN_MINUTES` and `ACCESS_REQUEST_IP_LIMIT_PER_DAY`
- `EMAIL_SMTP_HOST`, `EMAIL_SMTP_USER`, and `EMAIL_SMTP_PASSWORD`

The values in `.env.example` are Cloudflare's always-pass Turnstile test keys.
They work only for local development: the backend refuses to start with those
keys when `APP_DEBUG=false`. Create a free Turnstile widget in the Cloudflare
dashboard, add the deployed hostname, and replace both keys before production.
- invitation lifetime and rate-limit settings
- `RETENTION_PURGE_INTERVAL_SECONDS`

Gmail SMTP requires both a username and app password. Settings validation fails fast when only one credential is supplied or Gmail is selected without credentials.

SMTP is used for invitation delivery. In-app notifications are stored in MongoDB and fetched through the notification API. Local development can use the invitation link printed by the management CLI instead.

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
