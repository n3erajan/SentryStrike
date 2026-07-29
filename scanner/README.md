<div align="center">

# SentryStrike Scanner

**The evidence-driven DAST engine behind SentryStrike.**

Redis-backed workers that crawl authorized targets, run bounded passive and active checks,
verify candidates, grade evidence, and persist reproducible findings to MongoDB.

[![Python 3.12](https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Playwright 1.60](https://img.shields.io/badge/Playwright-1.60-2EAD33?logo=playwright&logoColor=white)](https://playwright.dev/python/)
[![pytest](https://img.shields.io/badge/tested_with-pytest-0A9EDC?logo=pytest&logoColor=white)](https://pytest.org/)

</div>

> [!CAUTION]
> The scanner sends intrusive security payloads and may exercise mutating application workflows. Run it only against targets covered by explicit authorization, using dedicated test data and accounts.

## Role in SentryStrike

The backend owns authorization, tenant workflows, and scan coordination; it does not run detectors. Scanner workers consume short-lived jobs from Redis, execute the DAST pipeline, and store progress and evidence in MongoDB. When a scan finishes, the scanner creates or repairs a durable analysis job for the separate [`analyzer`](../analyzer/) service.

This separation lets scanner throughput scale independently from API traffic and model-backed analysis.

## Scan lifecycle

1. **Claim** — dequeue a tenant-scoped job, acquire a renewable lease, and begin worker heartbeats.
2. **Crawl** — discover same-origin URLs, routes, forms, parameters, SPA interactions, and observed API traffic. HTTP crawling covers traditional sites; Playwright/Chromium covers client-side SPA routes, interactions, and browser-observed API calls.
3. **Fingerprint** — identify technologies and versions, enrich known components through NVD data, and inspect TLS behavior.
4. **Plan** — turn the discovered attack surface into bounded detector work, prioritizing relevant routes and parameters.
5. **Detect** — run passive and active checks under scan-, detector-, and parameter-level request budgets.
6. **Verify** — re-test candidates with type-specific proofs, response differentials, timing evidence, browser execution, or OAST callbacks.
7. **Grade** — remove duplicates and test pollution, assign evidence strength and confidence, calculate CVSS-based severity, and persist coverage metrics.
8. **Hand off** — create durable post-scan analysis state and signal an analyzer worker through Redis.

Progress, phase, ETA, request counts, coverage warnings, cancellation, and terminal state are persisted throughout the run.

## Detector coverage

Detector modules live in [`app/core/detectors/`](app/core/detectors/). Their current OWASP-oriented coverage is:

| Area                          | Current checks                                                                                                       |
| ----------------------------- | -------------------------------------------------------------------------------------------------------------------- |
| Broken access control         | BOLA/IDOR, forced browsing, authorization matrices, mass assignment, and bounded mutating authorization probes       |
| Authentication failures       | Form and API authentication, session behavior, JWT handling and forgery checks, and observed authentication evidence |
| Injection                     | SQL injection, NoSQL injection, command injection, and reflected/browser-verified XSS                                |
| Server-side and file handling | SSRF, file inclusion, file upload, and open redirect                                                                 |
| Request integrity             | CSRF behavior and authentication-bound request analysis                                                              |
| Security configuration        | Security headers, sensitive paths, exception handling, and exposed diagnostic behavior                               |
| Cryptography and transport    | TLS analysis and cryptographic-failure checks                                                                        |
| Software supply chain         | Technology/version fingerprinting, manifest enrichment, and known-CVE correlation                                    |

The [`attack_planner`](app/core/detectors/attack_planner.py), attack-surface model, and parameter selection logic decide what to probe and where. Checks that cannot be exercised are recorded as coverage limitations rather than silently treated as passes.

## Verification and evidence

Candidate findings pass through [`app/core/verification/`](app/core/verification/) before reporting:

- Type-specific SQLi, NoSQLi, command-injection, and XSS verifiers perform targeted re-tests.
- Response analysis compares status, body, headers, markers, and timing behavior against controlled baselines.
- Browser verification confirms execution-dependent XSS evidence where Chromium is available and within budget.
- OAST uses scanner-minted callback identifiers to verify blind classes such as SSRF. The backend validates and stores callback records in MongoDB; the scanner polls them through the shared OAST client.
- Deduplication and pollution filtering collapse repeated signals and remove artifacts produced by the scanner's own probes.

Every stored result carries an evidence-strength grade — `confirmed_exploit`, `confirmed_observation`, `probable`, `possible`, or `informational` — plus confidence, reproducibility, review status, detector attribution, and supporting request/response evidence where available.

> [!NOTE]
> Evidence-driven means the scanner distinguishes an observed signal from a confirmed exploit. It does not mean every vulnerability class can be proven automatically. Review coverage warnings and validate high-impact findings manually.

## Safety and resource controls

Safety boundaries are implemented across orchestration, crawling, and HTTP utilities:

- Active crawl results are restricted to the target's exact origin before detector execution.
- A request governor caps traffic per scan, detector, and parameter.
- Crawl depth, URL count, browser interactions, wall-clock budgets, concurrency, and request timeouts are configurable.
- Mutating authorization confirmation is disabled unless explicitly enabled.
- Captured evidence passes through redaction before durable storage.
- Target credentials travel only in the Redis job payload and worker memory. The job is removed from Redis when a worker claims it, and credentials are never persisted to MongoDB.

Use conservative budgets for fragile systems and coordinate test windows with application owners.

## Integrations

| Integration                   | Purpose                                                                                          |
| ----------------------------- | ------------------------------------------------------------------------------------------------ |
| Playwright / Chromium         | SPA discovery, authenticated browser state, interaction capture, and browser-backed verification |
| HTTPX                         | Async HTTP crawling, probing, verification, and OAST polling                                     |
| SSLyze                        | TLS and transport-security inspection                                                            |
| NVD API                       | Known-CVE enrichment for identified software versions                                            |
| Wappalyzer-style fingerprints | Technology and version identification                                                            |
| Shared OAST client            | Callback generation and polling through the backend collaborator endpoint                        |

NVD enrichment and OAST verification are best-effort capabilities: missing configuration or an unavailable external service reduces coverage but should not corrupt the durable scan state.

## Project structure

```text
scanner/
|-- app/
|   |-- core/
|   |   |-- crawler/              HTTP/browser discovery and authentication
|   |   |-- detectors/            Attack planning and vulnerability checks
|   |   |-- scan_orchestration/   Pipeline, progress, coverage, and processing
|   |   `-- verification/         Type-specific proofs and signal filtering
|   |-- integrations/             NVD, CVE, TLS, and fingerprinting clients
|   |-- reverification_strategies/
|   |-- utils/                    Logging, redaction, throttling, metrics, CVSS
|   |-- config.py
|   |-- reverification.py
|   `-- worker.py
|-- tests/
|-- Dockerfile
`-- requirements.txt
```

Domain models, repositories, queue contracts, analysis handoff, and OAST helpers come from the [`shared`](../shared/) package.

## Run locally

From the repository root:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e .
python -m pip install -r scanner/requirements-dev.txt
python -m playwright install chromium
cp scanner/.env.example scanner/.env
```

Start MongoDB and Redis, run the backend so scans can be submitted and OAST callbacks collected, then launch the worker:

```bash
cd scanner
export OAST_CALLBACK_BASE_URL="http://host.docker.internal:8000/oast"
export OAST_POLL_URL="http://localhost:8000/oast/poll"
python -m app.worker
```

Those OAST overrides match the repository's local Docker development topology. In a deployed environment, set `PUBLIC_HOSTNAME` and override the callback and polling routes only when the network topology requires separate addresses.

## Configuration

Shared MongoDB, Redis, queue, cancellation, lease, heartbeat, and public-host values are documented in the [root configuration template](../.env.example). Scanner-specific controls are in [`.env.example`](.env.example).

| Area            | Important variables                                                                    |
| --------------- | -------------------------------------------------------------------------------------- |
| Crawl scope     | `CRAWL_DEPTH`, `CRAWL_MAX_URLS`, `CRAWL_RATE_LIMIT_PER_SECOND`                         |
| Browser budget  | `CRAWL_BROWSER_MODE`, `CRAWL_BROWSER_MAX_INTERACTIONS`, `CRAWL_BROWSER_BUDGET_SECONDS` |
| Request control | `REQUEST_TIMEOUT_SECONDS`, `SCANNER_CONCURRENCY`, detector and parameter request caps  |
| Safety          | `ACCESS_CONTROL_PROBE_MUTATING_METHODS`, `ALLOW_DESTRUCTIVE_AUTHZ_CONFIRMATION`        |
| Verification    | Timing thresholds, OAST polling, and browser-verification budgets                      |
| Enrichment      | `NVD_API_URL`, `NVD_API_KEY`, `CVE_CACHE_TTL_SECONDS`                                  |
| Observability   | `LOG_LEVEL`, `LOG_FILE`                                                                |

## Tests

```bash
python -m pytest scanner/tests/unit
python -m pytest scanner/tests/integration
python -m pytest scanner/tests --cov=scanner/app --cov-report=term-missing
```

Browser and integration tests may launch Chromium or require MongoDB and Redis. Keep live-target fixtures isolated and never point tests at an unapproved system.

## Container image

The scanner image uses the official Playwright Python base so the pinned Python client and Chromium build stay aligned. When upgrading Playwright, update [`requirements.txt`](requirements.txt) and [`Dockerfile`](Dockerfile) together.
