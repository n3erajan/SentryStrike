<div align="center">

# SentryStrike Backend

[![Python](https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![MongoDB](https://img.shields.io/badge/Beanie-Motor-47A248?logo=mongodb&logoColor=white)](https://beanie-odm.dev)
[![Redis](https://img.shields.io/badge/Redis-queues-DC382D?logo=redis&logoColor=white)](https://redis.io)

</div>
The FastAPI control plane for SentryStrike. It owns every durable record (users, organizations, scans, findings, analysis projections, invites, notifications, audit events) and exposes the REST API the frontend talks to. It also runs the **OAST collaborator endpoint** the scanner uses to confirm blind vulnerabilities out-of-band, and ships an operator **CLI** for workspace administration.

The backend never scans anything itself. It enqueues scan jobs to Redis and projects worker progress onto the scan document the API serves.

## Running

```bash
pip install -e ..                 # the shared package (from the repo root)
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

MongoDB and Redis must be reachable per `.env`. In Docker the service is built from `backend/Dockerfile` (multi-stage, non-root) and is not published to the host; all traffic arrives through the frontend's nginx, which proxies `/api/` and `/oast/`.

## Configuration

Environment is layered: the repo-root `.env` loads first, then `backend/.env` overrides it (see `service_env_files` in `shared/config.py`). Committed `.env.example` files are documentation.

**App**

| Variable                 | Default                          | Notes                                         |
| ------------------------ | -------------------------------- | --------------------------------------------- |
| `APP_NAME` / `APP_DEBUG` | `Sentry Strike Backend` / `true` | Debug enables `/docs` + `/redoc`              |
| `CORS_ORIGINS`           | `["http://localhost:5173"]`      | Must carry credentials for the session cookie |
| `LOG_LEVEL`              | `INFO`                           |                                               |

**Auth and sessions**

| Variable                                                           | Default                | Notes                                                       |
| ------------------------------------------------------------------ | ---------------------- | ----------------------------------------------------------- |
| `AUTH_SESSION_TTL_HOURS`                                           | `168`                  | Server-side sessions; only the SHA-256 token hash is stored |
| `AUTH_COOKIE_NAME` / `AUTH_COOKIE_SECURE` / `AUTH_COOKIE_SAMESITE` | none / `false` / `lax` | Set `SECURE=true` behind HTTPS                              |
| `INVITE_TTL_HOURS`                                                 | `168`                  | Invite links embed `PUBLIC_HOSTNAME`                        |

**Rate limiting and abuse controls**

| Variable                                                                 | Default    | Notes                                    |
| ------------------------------------------------------------------------ | ---------- | ---------------------------------------- |
| `INVITE_WORKSPACE_LIMIT_PER_HOUR` / `INVITE_ACTOR_LIMIT_PER_TEN_MINUTES` | `20` / `5` | Redis-backed                             |
| `ACCESS_REQUEST_IP_LIMIT_PER_FIFTEEN_MINUTES` / `…_PER_DAY`              | none       | Public request-access form               |
| `TURNSTILE_SITE_KEY` / `TURNSTILE_SECRET_KEY`                            | none       | Cloudflare Turnstile on public endpoints |

**Email**: `EMAIL_FROM`, `EMAIL_SMTP_HOST` (default `localhost`), `EMAIL_SMTP_PORT` (default `1025`, a local Mailhog-style sink), `EMAIL_SMTP_USER` / `PASSWORD` / `STARTTLS`.

**Retention**: scan data older than the org's `retention_days` is purged by `app/retention_worker.py`; 30 days is the enforced floor. Trigger manually with the CLI.

Shared infrastructure variables (`MONGODB_URI`, `REDIS_URL`, queue names, lease/heartbeat TTLs, `PUBLIC_HOSTNAME`, `OAST_INTERACTION_TTL_SECONDS`) live in the root `.env` and are documented in `../.env.example`.

## API surface

Everything is under `/api/v1` except OAST. All responses use one envelope (`{ success, message, data?, error_code?, request_id }`) and every response carries an `X-Request-ID` header that is also logged with the request, so users can quote a support reference. Validation failures return per-field messages translated into UI copy, never raw Pydantic internals; unhandled exceptions are sanitized to a generic message with the traceback kept in logs.

| Router            | Prefix                                       | Highlights                                                                            |
| ----------------- | -------------------------------------------- | ------------------------------------------------------------------------------------- |
| `health`          | `/health`                                    | Liveness + count of active scanner workers (from Redis heartbeats)                    |
| `auth`            | `/auth`                                      | register / login / logout / session / me, invite-aware registration, Turnstile config |
| `access_requests` | `/access-requests`                           | public "request access" form (rate-limited, Turnstile)                                |
| `applications`    | `/applications`                              | CRUD for scan targets + per-app default scan config + scan history                    |
| `scan`            | `/scans`                                     | submit (202), list, detail, live status, cancel                                       |
| `analysis`        | `/analysis` + `/scans/{id}/vulnerabilities…` | AI retry, finding review / assignment / comments / remediation, re-verification jobs  |
| `reports`         | `/reports`                                   | JSON report + generated PDF download                                                  |
| `workspace`       | `/workspace`                                 | members, roles, invites, org settings, audit log, retention                           |
| `notifications`   | `/notifications`                             | poll-based inbox, unread count, mark read                                             |
| `oast`            | `/oast` (no `/api/v1`, **unauthenticated**)  | callback catch + scanner poll                                                         |

### OAST collaborator

`GET /oast/{interaction_id}` is the out-of-band callback target. It is deliberately unauthenticated (the vulnerable target's server calls it), and hardened accordingly: only scanner-minted ids matching `^[a-z][a-z0-9_-]{0,31}-[0-9a-f]{32}$` are stored, everything else gets a 404 with no write; the response is a static `ok` and reflects nothing. Interactions expire via a Mongo TTL index (`OAST_INTERACTION_TTL_SECONDS`, default 1h). Scanner workers retrieve callbacks through `GET /oast/poll?id=…` (bounded to 50 records).

## Authorization model

One user belongs to exactly one organization; removing a member deletes their account so cross-tenant access cannot arise. Roles gate **actions, not visibility**: every member sees all org scans and findings.

| Role              | Can                                                                           |
| ----------------- | ----------------------------------------------------------------------------- |
| `owner` / `admin` | everything: workspace settings, members, invites, scans, triage, verify fixes |
| `analyst`         | launch scans, triage findings, confirm `verified_fixed` / `wont_fix`          |
| `developer`       | launch scans, advance remediation up to `fixed_pending_verification`          |
| `viewer`          | read-only                                                                     |

A few workspace routes are narrower than that summary suggests, all enforced by `require_role`:

| Operation                  | Allowed                                |
| -------------------------- | -------------------------------------- |
| `GET /workspace/audit-log` | `owner` / `admin` only — not `analyst` |
| `PUT /workspace` (rename)  | `owner` only                           |
| `GET /workspace/retention` | any member                             |
| `PUT /workspace/retention` | `owner` / `admin` only                 |

The API also refuses to remove or demote the owner, and refuses to let a user change or remove their own membership.

Every mutating route is org-scoped through repositories that take `org_id` on every query; a dedicated test suite (`test_org_isolation.py`) proves tenants cannot see each other.

## Scan lifecycle (the backend's half)

1. `POST /scans` validates the target and config, persists a `queued` scan, pushes a `ScanJob` onto the Redis queue, returns `202`. Supplied test-account credentials ride inside the job payload only; the scan document stores just `auth_roles_provided`.
2. Scanner workers update phase / progress / ETA on the scan document; the frontend polls `GET /scans/{id}/status`.
3. `POST /scans/{id}/cancel` sets a Redis cancel key and publishes on the cancel channel; workers get sub-second delivery plus phase-boundary polling as a fallback.
4. On completion the scan hand-off creates a durable `AnalysisJob`; the analyzer's progress is projected onto the same scan document (`analysis` sub-object) so the UI has one place to poll.

## Operator CLI

```bash
python -m app.cli --help
```

Commands cover the workflows that have no UI: listing / approving / rejecting access requests (approval creates the org and owner account), checking invite status, running a retention purge, setting an org's member limit, and an SMTP smoke test (`email-check`). Aliases exist for the common verbs; see `--help` per command.

Owner onboarding lives here on purpose. There is no self-serve signup and no HTTP endpoint that creates a workspace, so access to the CLI _is_ container access and there is no public surface to secure:

```bash
python -m app.cli list                                     # pending access requests
python -m app.cli approve <request-id> --member-limit 10   # creates the owner invite
python -m app.cli reject <request-id>
python -m app.cli status owner@acme.com                    # invite delivery + acceptance
```

Approval prints the signup link and emails it when a real SMTP backend is configured. The invitee registers with the invited email, which creates the workspace and the owner account together. In Docker, prefix these with `docker compose exec backend`.

## Project layout

```
app/
  main.py            app factory, middleware, exception-to-envelope handlers
  config.py          BackendSettings (pydantic-settings)
  cli.py             operator CLI
  retention_worker.py
  api/
    dependencies.py  auth dependency, repository factories, service singletons
    routes/          one module per API group (see table above)
  core/              auth, invites, access requests, email, turnstile, retention,
                     rate limits, exceptions
  schemas/           request/response models for the API boundary
  utils/pdf_generator.py   reportlab-based PDF report
tests/               pytest: unit/ + integration/ (see conftest.py for fakes)
```

## Testing

```bash
pip install -r requirements-dev.txt
pytest tests/             # from backend/
```

The suite leans on fakes for Redis and Mongo (no live services needed for unit tests) and covers auth, org isolation, rate limits, the analysis hand-off, notification copy, and the error-envelope contract.
