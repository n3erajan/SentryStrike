# SentryStrike Shared Package

`shared` is the internal Python package that defines the contracts used by the backend, scanner, and analyzer. It keeps durable models, tenant-scoped repositories, queue payloads, configuration, and cross-service policies consistent without coupling the services to each other's application packages.

It is not a standalone service and has no process entry point.

## Contents

```text
shared/
├── database/
│   ├── connection.py       MongoDB and Beanie initialization
│   └── repositories/       Tenant-scoped persistence operations
├── models/                 Beanie documents and nested Pydantic models
├── reverification/         Finding-family policy and eligibility
├── schemas/                Shared scan and vulnerability transport schemas
├── utils/                  Logging and validation helpers
├── verification/           Shared OAST client behavior
├── analysis_handoff.py     Idempotent scan-to-analysis transition
├── analysis_queue.py       Durable-analysis Redis signaling
├── config.py               Cross-service Pydantic settings
├── finding_rollups.py      Finding statistics and risk aggregation
└── scan_queue.py           Scan jobs, cancellation, leases, and heartbeats
```

## Durable data model

Beanie documents cover access requests, organizations, users and sessions, invitations, applications, scans, analysis jobs, re-verification jobs, notifications, audit events, cached CVE records, and OAST interactions. Vulnerabilities are embedded Pydantic records inside scan documents rather than standalone collections. Repository methods carry organization identifiers where tenant isolation is required.

MongoDB is authoritative for scan and analysis state. Redis transports scan jobs and wake-up signals and holds ephemeral cancellation, lease, and heartbeat keys.

## Queue contracts

- `ScanJob` carries a full-scan or focused re-verification request from the backend to scanner workers. Per-scan credentials exist only in this short-lived payload and are removed when claimed.
- `RedisScanQueue` provides blocking dequeue, cancellation pub/sub and TTL keys, renewable scan leases, and worker heartbeats.
- `AnalysisSignal` wakes an analyzer for a durable MongoDB `AnalysisJob`; duplicate or missed signals are safe because workers also claim due database jobs.
- Analysis handoff helpers create jobs and update scan projections idempotently.

## Installation

Install the package in editable mode from the repository root before running Python services locally:

```bash
python -m pip install -e .
```

The package metadata is defined in [`../pyproject.toml`](../pyproject.toml). Runtime dependencies are installed by the consuming service requirement files.

## Development guidelines

- Keep service-specific business logic in its owning service.
- Treat model and queue changes as cross-service API changes; update every producer, consumer, and test together.
- Preserve tenant scoping in repository methods and compound indexes.
- Do not add persisted secret fields for target credentials.
- Make Redis failure semantics explicit: durable data belongs in MongoDB, while signals and leases should be recoverable.
- Use revision and lease guards for analysis writes so stale workers cannot publish over current results.

## Validation

The shared package is exercised through the backend, scanner, and analyzer test suites:

```bash
python -m pytest backend/tests scanner/tests analyzer/tests
```

Focused queue, repository, model, policy, and handoff tests live primarily under `backend/tests/unit`, with worker-contract coverage in the scanner and analyzer suites.
