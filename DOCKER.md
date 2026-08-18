# Running SentryStrike with Docker

[![Docker Compose](https://img.shields.io/badge/Docker-compose-2496ED?logo=docker&logoColor=white)](https://docs.docker.com/compose/)
[![MongoDB](https://img.shields.io/badge/MongoDB-7-47A248?logo=mongodb&logoColor=white)](https://mongodb.com)
[![Redis](https://img.shields.io/badge/Redis-7-DC382D?logo=redis&logoColor=white)](https://redis.io)

Operating the compose stack: what each container is, what its healthcheck actually proves, how to scale workers, how to back up, and what to check when something is wrong. For install and first-run, see the [root README](README.md#quick-start-docker).

This is a deployment baseline, not a security boundary. TLS termination, secret management, authenticated data stores, and backups are yours.

## Topology

| Service | Image / build | Published |
|---|---|---|
| `frontend` | Vite build on `node:24-alpine`, served by `nginx-unprivileged` | `${FRONTEND_PORT:-80}` → `8080` |
| `backend` | `python:3.12-slim`, multi-stage | **none** |
| `scanner` | `mcr.microsoft.com/playwright/python:v1.60.0-noble` | none |
| `analyzer` | `python:3.12-slim`, multi-stage | none |
| `mongo` | `mongo:7` | internal |
| `redis` | `redis:7-alpine` | internal |

Only the frontend is reachable from the host. Its nginx serves the SPA and proxies `/api/` and `/oast/` to `backend:8000`, so a single-origin deploy needs nothing else exposed. Every application image runs as a non-root user (`app`, `pwuser`, `nginx`).

MongoDB is the durable source of truth on the `mongo_data` volume. Redis runs with `--save '' --appendonly no` and **has no volume on purpose**: it holds queue payloads, cancel keys, leases, and heartbeats, all TTL'd and all safe to lose. Losing Redis costs you in-flight dispatch, not state.

> [!NOTE]
> `BACKEND_PORT` in `.env.example` is vestigial — the compose file no longer publishes the backend. Set `FRONTEND_PORT` to move the only host-facing port.

## OAST callbacks in compose

This is the setting most likely to be silently wrong. The backend receives target callbacks at `/oast/{interaction_id}` and answers scanner polls at `/oast/poll`. The scanner needs two different addresses for them because they are reached from different places:

```dotenv
# root .env
OAST_CALLBACK_BASE_URL=https://sentry.example.com/oast   # what the TARGET calls
OAST_POLL_URL=http://backend:8000/oast/poll              # what the SCANNER polls
```

Both derive from `PUBLIC_HOSTNAME` when unset. If that is empty too, they stay `None` and the out-of-band checks are **skipped rather than failed** — blind SSRF and blind SQLi go undetected and the scan still reports success.

Two things to get right:

- **The callback goes through nginx, not the backend port.** In this stack nothing listens on host `:8000`, so a callback aimed at `host.docker.internal:8000/oast` cannot connect. Route it at `${FRONTEND_PORT}` or your public hostname; nginx already proxies `/oast/`. (The `host.docker.internal:8000` value commented in `scanner/.env.example` is for host-run development, where uvicorn does bind `:8000`.)
- **Put compose OAST overrides in the root `.env`.** Compose interpolates the root `.env` before service `env_file` values load, so a value set only in `scanner/.env` will not reach the interpolation.

A localhost callback can never be reached by a remote target. Use an authorized public hostname or a controlled tunnel, and restart the scanner after changing it.

## Healthchecks: what they prove

```bash
docker compose ps
curl http://localhost/api/v1/health
```

| Service | Probe | Proves | Does **not** prove |
|---|---|---|---|
| `frontend` | HTTP `:8080/` in-container | nginx serves the bundle | backend reachable |
| `backend` | `GET /api/v1/health` | API responds after Mongo + Redis | — |
| `scanner` | Redis `PING` | container can reach its queue | the worker loop is consuming |
| `analyzer` | signal to PID 1 | process alive | provider is configured or reachable |
| `mongo` | `db.runCommand({ping:1})` | accepts commands | — |
| `redis` | `redis-cli ping` | accepts commands | — |

The last two columns matter. A green `scanner` says nothing about whether scans are progressing — heartbeat keys and worker logs do. A green `analyzer` says nothing about the LLM; provider misconfiguration fails durable jobs visibly instead of restart-looping the worker, which is deliberate.

`GET /api/v1/health` returns the live scanner-worker count from Redis heartbeats. That is the real capacity signal.

## Logs

```bash
docker compose logs -f backend scanner analyzer
docker compose exec scanner sh -c 'tail -n 200 /app/logs/scanner.log'
```

Scanner file logs live in the `scanner_logs` volume at `/app/logs` (set `LOG_FILE` to enable). Replicas share that volume, so prefer container stdout when diagnosing one replica.

Treat logs as sensitive: they carry target URLs and security evidence. Secrets are redacted (`scanner/app/utils/redaction.py`), targets are not.

## Scaling workers

Both workers are safe to scale — they claim from shared queues under leases with revision-guarded writes, so two workers cannot double-publish.

```bash
docker compose up -d --scale scanner=4 --scale analyzer=2
```

Scanner replicas are the expensive ones: each runs Chromium. Watch host memory and target load before raising the count. For browser-heavy work, add an override and validate it with `docker compose config` first:

```yaml
# docker-compose.override.yml
services:
  scanner:
    shm_size: 1gb
    deploy:
      resources:
        limits: { cpus: '2.0', memory: 4g }
```

Analyzer throughput is bounded by your LLM provider, not by replica count. More analyzers against one Ollama instance mostly queues.

## Backup and restore

`mongo_data` holds everything durable. `docker compose down` keeps volumes; `down -v` destroys them.

```bash
# backup
docker compose exec mongo mongodump --db sentrystrike --archive=/tmp/ss.archive --gzip
docker compose cp mongo:/tmp/ss.archive ./ss.archive

# restore
docker compose cp ./ss.archive mongo:/tmp/ss.archive
docker compose exec mongo mongorestore --archive=/tmp/ss.archive --gzip --drop
```

> [!WARNING]
> `--drop` deletes matching collections before restoring. Check which deployment you are pointed at first.

Encrypt backups, store them off the Docker host, and actually test a restore. Retention purging (`retention_worker.py`, 30-day floor) trims scan data on its own schedule — that is not a backup.

## Production hardening

1. Terminate HTTPS at a reverse proxy or ingress in front of the stack.
2. Set `AUTH_COOKIE_SECURE=true`, `APP_DEBUG=false`, and restrict `CORS_ORIGINS` to real origins. Debug mode exposes `/docs`.
3. Replace the Turnstile test keys with real ones — the shipped defaults always pass.
4. Route `/oast/` at the external proxy and set `PUBLIC_HOSTNAME`, or blind detection stays off.
5. Keep Mongo and Redis off public interfaces; add auth appropriate to the environment.
6. Move SMTP and provider credentials to your platform's secret manager, not into images.
7. Keep containers on their non-root users; set CPU, memory, and crawl budgets from measured load.
8. Pin and rescan base images; rebuild on CVE churn.
9. Alert on unhealthy containers, heartbeat loss, repeated analysis failures, and queue growth.
10. Restrict egress to authorized targets, NVD, and your AI provider.

## Troubleshooting

**Build fails.** Build from the repo root; the backend, scanner, and analyzer contexts are `.` because they install the `shared` package. `docker compose build --no-cache <service>`.

**Frontend returns 502.** nginx cannot reach the backend:

```bash
docker compose ps backend && docker compose logs --tail=200 backend
docker compose exec frontend wget -qO- http://backend:8000/api/v1/health
```

**Scans stay queued.** The scanner healthcheck only proves Redis reachability. Check for live heartbeats:

```bash
docker compose exec redis redis-cli --scan --pattern 'sentrystrike:worker:heartbeat:*'
docker compose logs --tail=200 scanner
```

No keys means no worker is running the loop, whatever `docker compose ps` says.

**Worker cannot reach Redis.** Inside containers `REDIS_URL` must use the service name; compose sets `redis://redis:6379/0`. A `localhost` value leaked from a `.env` file is the usual cause.

**AI analysis fails.** Confirm the endpoint resolves from inside the container and the model exists:

```bash
docker compose exec analyzer python -c "import os,urllib.request; print(urllib.request.urlopen(os.environ['AI_BASE_URL'].rstrip('/')+'/models', timeout=10).status)"
```

For host-installed Ollama, `AI_BASE_URL` must use `host.docker.internal`, not `localhost`, and Ollama must accept connections from Docker. Build the pinned model first — see [`analyzer/ollama/README.md`](analyzer/ollama/README.md).

**Analysis verdicts look confident but wrong.** Suspect a truncated prompt. Check `prompt_tokens` on the job; a stock model tag loads a 4096-token window and drops the overflow silently. That is what `gemma4:e4b-it-qat-16k` exists to prevent.

**OAST callbacks never arrive.** See [OAST callbacks in compose](#oast-callbacks-in-compose). Confirm what the scanner is actually minting:

```bash
docker compose exec scanner python -c "import os; print(os.environ.get('OAST_CALLBACK_BASE_URL'), os.environ.get('OAST_POLL_URL'))"
```

**Chromium is killed mid-crawl.** Out of shared memory. Raise `shm_size`, lower `SCANNER_CONCURRENCY` and the `CRAWL_BROWSER_*` budgets. If you changed the scanner base image, its Chromium build must still match the pinned `playwright==1.60.0` wheel.

## Related

- [Project overview](README.md) · [Backend](backend/README.md) · [Scanner](scanner/README.md) · [Analyzer](analyzer/README.md) · [Frontend](frontend/README.md) · [Shared](shared/README.md)
