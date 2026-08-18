<div align="center">

# SentryStrike Shared

[![Python](https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white)](https://python.org)
[![MongoDB](https://img.shields.io/badge/Beanie-ODM-47A248?logo=mongodb&logoColor=white)](https://beanie-odm.dev)
[![Redis](https://img.shields.io/badge/Redis-clients-DC382D?logo=redis&logoColor=white)](https://redis.io)

</div>
The Python package every SentryStrike service depends on. It owns the **single source of truth** for the data plane: MongoDB document models, the repositories that enforce org-scoping on every query, the Redis queue clients, the scan/analysis hand-off contract, and the shared configuration layering. Backend, scanner, and analyzer all import from here; there is no service-to-service import that bypasses it.

Installed editable from the repo root:

```bash
pip install -e .        # pyproject.toml exposes the `shared` package
```

## What's inside

### `models/`: the documents

Beanie (async MongoDB ODM) documents and the nested Pydantic models they carry:

- **`scan.py`**: the scan lifecycle (`queued` → `running` → `completed` / `failed` / `cancelled`), fine-grained `ScanPhase` reporting, `ScanAuthAccount` (test credentials ride the Redis job payload only; the document stores just `auth_roles_provided`), `ScanStatistics`, and the `SpaApiCoverage` metrics that make crawl quality honest.
- **`vulnerability.py`**: the finding model, and the heart of the platform's evidence discipline: the `EvidenceStrength` ladder, `AuthContext`, the immutable `VerificationTarget` captured at detection time, `AiAnalysis` verdicts, and the `PROOF_FLOORS` / `PROOF_CEILINGS` the analyzer's deterministic FP calibration is clamped to. `refresh_review_status()` derives the human-facing review state from evidence strength plus AI verdict; an AI verdict alone can never suppress a finding. Also `OwaspCategory` (2025 taxonomy, with out-of-scope categories documented), `RemediationStatus` (the team workflow state machine), comments, and assignment.
- **`analysis_job.py`**: the durable analysis job: revision, lease owner / expiry, attempt counters, progress, token usage, provider request ids.
- **`organization.py`, `user.py`, `invite.py`**: multi-tenancy: one user to one org, seat accounting (pending invites reserve seats), roles.
- **`reverification.py`**: focused-replay jobs and their immutable outcomes and evidence.
- **`oast_interaction.py`**: out-of-band callback records (TTL-indexed).
- **`notification.py`, `audit.py`, `access_request.py`, `application.py`, `cve.py`**.

### `database/repositories/`: org-scoped data access

Every repository takes `org_id` on every read and write; cross-tenant access is structurally impossible rather than remembered. Includes the atomic `AnalysisJobRepository.claim_next` (find-and-modify with lease), scan projection updates guarded by expected revision and lease owner, and notification creation with idempotent `dedupe_key`s.

### Queues and the scan-to-analysis hand-off

- **`scan_queue.py`**: `RedisScanQueue`: `BLPOP` job dispatch, cancel keys plus a pub/sub cancellation channel, per-scan leases (dead-worker detection), and worker heartbeats (the backend health endpoint counts them).
- **`analysis_queue.py`**: the lightweight wake-up signal queue; durable state lives in the `AnalysisJob` document, so a lost signal is harmless (workers also poll).
- **`analysis_handoff.py`**: `ensure_initial_analysis_job` (create the durable job and nudge the queue) and `reconcile_missing_analysis_jobs` (the periodic repair both workers run).

### `reverification/`, `verification/`, `finding_rollups.py`, `notification_copy.py`

- `reverification/policy.py`: which strategy family replays which finding type.
- `verification/oast.py`: `OastClient`: mints callback URLs, validates interaction ids (`^[a-z][a-z0-9_-]{0,31}-[0-9a-f]{32}$`), polls the backend.
- `finding_rollups.py`: cross-finding rollup rules applied after deduplication.
- `notification_copy.py`: one place for the human wording of scan / analysis / re-verification terminal notifications, shared by both workers.

### `config.py`: layered settings

`service_env_files(service)` returns `(repo-root .env, <service>/.env)` so deployment-wide values load first and each service overrides locally. The mixin settings classes (`InfrastructureSettings`, `ScanQueueSettings`, `AnalysisQueueSettings`, `PublicUrlSettings`, `SharedDocumentSettings`) are composed into each service's own settings, so a queue key name or TTL can never drift between producer and consumer: both read the same field.

### `schemas/`, `utils/`

API-boundary schemas shared across services (`ScanConfig` with its per-scan overrides, vulnerability wire schemas) and the structured logger used by all three Python services.

## Design rules this package enforces

1. **Credentials never persist.** Test-account secrets exist in the Redis job payload and worker memory only; documents carry role markers.
2. **Org scoping is structural.** Repositories require `org_id`; there is no unscoped query helper to accidentally reach for.
3. **Queue payloads are signals, not state.** Durable state lives in MongoDB; Redis holds dispatch payloads, cancel signals, leases, and heartbeats, all with TTLs, all safe to lose.
4. **Calibration lives here.** The FP floors and ceilings and the review-state derivation are defined next to the model so scanner, analyzer, and backend can never disagree.
