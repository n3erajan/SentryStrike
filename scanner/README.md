<div align="center">

# SentryStrike Scanner

[![Python](https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white)](https://python.org)
[![Playwright](https://img.shields.io/badge/Playwright-1.60-2EAD33?logo=playwright&logoColor=white)](https://playwright.dev)
[![SSLyze](https://img.shields.io/badge/SSLyze-6.1-blue)](https://github.com/nabla-c0d3/sslyze)
[![OWASP](https://img.shields.io/badge/OWASP-Top%2010%202025-000000?logo=owasp&logoColor=white)](https://owasp.org/Top10/)

</div>
The headless DAST worker. It pulls scan jobs off the Redis queue, crawls the target (including JavaScript-heavy SPAs through a real Chromium browser), runs sixteen vulnerability detectors, verifies each raw finding against controls, grades the evidence deterministically, and hands the completed scan off to the analyzer. It also runs **re-verification jobs**: focused single-finding replays requested from the UI.

There is no HTTP server here. The worker is a long-running asyncio process whose only interfaces are Redis (jobs, cancellation, leases, heartbeats) and MongoDB (scan state).

## Running

```bash
pip install -e ..                 # shared package, from the repo root
pip install -r requirements.txt
playwright install chromium       # browser engine for SPA crawling + DOM XSS
python -m app.worker
```

In Docker the image is based on `mcr.microsoft.com/playwright/python:v1.60.0-noble` so the Chromium build matches the pinned `playwright==1.60.0` wheel; do not bump one without the other. The container healthcheck pings Redis (the worker has no port).

## The scan pipeline

`app/core/scanner.py` (`ScanOrchestrator`) composes one mixin per pipeline stage from `app/core/scan_orchestration/`. A single `run_scan` sequences:

1. **Initializing**: build an isolated per-scan runtime (fresh HTTP clients, cookies, auth state, verifier state) so concurrent scans can never contaminate each other.
2. **Crawling** (`core/crawler/`): depth-limited spider with rate limiting, plus the Playwright browser engine for SPAs: JS bundle route extraction, API endpoint discovery, form discovery and submission, workflow-state exploration, file inputs, and observed-request capture. Per-route and whole-crawl budgets keep a heavy app from stalling the scan, and every discovery metric lands on the scan's `SpaApiCoverage` for honest "what did we actually see" reporting. Authenticated crawling replays login through the supplied test accounts.
3. **Technology detection** (`integrations/wappalyzer*`): fingerprint the stack; versions feed the CVE lookup.
4. **TLS analysis** (`integrations/sslyze_wrapper.py`): protocol / certificate / cipher findings for A04.
5. **Vulnerability detection**: all detectors launched concurrently with per-target payload budgets and an attack planner that matches detectors to the discovered attack surface.
6. **Verification** (`core/verification/`): each raw finding is replayed against a control (for example a benign payload) to prove causality; blind classes (SSRF, blind SQLi) confirm through OAST callbacks. A deduplicator and a test-pollution filter (did our own earlier probe create this artifact?) run here.
7. **Deduplication and rollups**: collapse duplicates, apply cross-finding rollups.
8. **Evidence grading** (`core/evidence_grader.py`): assign each finding a proof type and a position on the `confirmed_exploit` → `confirmed_observation` → `probable` → `possible` → `informational` ladder, with the auth context it was found under. This grade is what the analyzer's FP floors and ceilings key off.
9. **Risk scoring** (`utils/cvss_calculator.py`): CVSS base scores + priority rank.
10. **Hand-off**: persist findings, then `ensure_initial_analysis_job` creates the durable analysis job and nudges the analysis queue. A reconciliation loop in the worker re-creates the job if the hand-off ever fails.

Cancellation is designed to be both fast and safe: a Redis pub/sub watcher cancels the scan task mid-phase (sub-second), the orchestrator also polls the cancel key at phase boundaries, and a Redis outage is treated as "not cancelled" rather than killing a healthy scan. While a scan runs, the worker renews a per-scan lease so a crashed worker leaves the scan detectably orphaned instead of stuck at "running", and a worker heartbeat key lets the backend health endpoint report live scanner capacity.

## Detectors

Sixteen detectors, mapped to the automatable OWASP Top 10 (2025) categories. A06 (Insecure Design), A08, and A09 are explicitly out of scope and disclosed as such on every report. Fifteen are built per scan in `scan_orchestration/runtime.py`; `supply_chain` is constructed alongside them because it reads the technology-detection output instead of sending its own requests.

| OWASP | Detector                                                                                                                                                           | Notes                                                                                                                                                                                              |
| ----- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| A01   | `access_control/`                                                                                                                                                  | IDOR, forced browsing, mass assignment, mutating authorization, and a full authorization matrix across the supplied roles (main / second / admin). Can auto-provision a throwaway second identity. |
| A02   | `security_headers.py`, `sensitive_paths.py`                                                                                                                        | Header analysis; path permutation probing with per-scan caps                                                                                                                                       |
| A03   | `supply_chain.py`                                                                                                                                                  | Detected component versions → CVE match by product identity and version range (see [Vulnerability intelligence](#vulnerability-intelligence))                                                       |
| A04   | `crypto_failures.py`                                                                                                                                               | TLS / HTTPS via SSLyze                                                                                                                                                                             |
| A05   | `sql_injection.py`, `nosql_injection.py`, `xss_detector.py`, `command_injection.py`, `file_inclusion.py`, `file_upload.py`, `ssrf_detector.py`, `open_redirect.py` | Error-based + blind timing SQLi; DOM XSS via browser probes; OAST + in-band timing-differential SSRF                                                                                               |
| A07   | `authentication/`                                                                                                                                                  | Form / session / JWT / API auth, JWT forgery, passive analysis; plus `csrf_detector.py`                                                                                                            |
| A10   | `exception_handler.py`                                                                                                                                             | Stack traces, debug pages, error leakage                                                                                                                                                           |

Every detector emits `Finding` objects (`base_detector.py`) carrying a **verification target**: the exact URL, method, parameter, payload, and control payload needed to replay the finding, plus a scanner-authored _evidence brief_ (what the proof shows, its inherent weaknesses, and the question an adjudicator must answer). That brief is trusted input to the analyzer; raw target content is fenced as untrusted.

### What is out of scope, and why

Three OWASP 2025 categories have no detector, and reports say so rather than letting silence read as a pass. Each needs evidence a black-box HTTP scan cannot obtain:

| Category                                   | Why no detector                                                                                          |
| ------------------------------------------ | -------------------------------------------------------------------------------------------------------- |
| A06 Insecure Design                        | Requires business rules, trust boundaries, and abuse cases - a threat model, not a request/response pair |
| A08 Software or Data Integrity Failures    | Requires build pipelines, artifact signing, and update trust, all outside the running application        |
| A09 Security Logging and Alerting Failures | Requires server-side logs, monitoring, and whether an alert reached a responder                          |

`OwaspCategory` in `shared/models/vulnerability.py` defines all ten so the taxonomy stays complete; detectors never emit the three above. Coverage still depends on what the target exposes, the configured budgets, and the credentials supplied - a clean scan is not proof an application is secure.

## Re-verification

`app/reverification.py` + `app/reverification_strategies/` implement the focused replay behind the UI's "re-verify" button: rebuild the stored verification target (with fresh credentials if supplied), replay attack versus control, and persist an immutable outcome with its own evidence: `still_present`, `resolved`, or `inconclusive`. Strategies are grouped by family (injection, access control, authentication, passive) so each class replays the way it was detected.

## Configuration

Layered env: repo-root `.env`, then `scanner/.env`. See `scanner/.env.example` for the full annotated list; highlights:

| Variable                                                | Default                        | Notes                                                                  |
| ------------------------------------------------------- | ------------------------------ | ---------------------------------------------------------------------- |
| `CRAWL_DEPTH` / `CRAWL_MAX_URLS`                        | `3` / `200`                    | Global crawl bounds                                                    |
| `CRAWL_RATE_LIMIT_PER_SECOND`                           | none                           | Polite crawling                                                        |
| `CRAWL_BROWSER_MODE`                                    | `auto`                         | `auto` = browser only when an SPA is detected; also `always` / `never` |
| `CRAWL_BROWSER_*`                                       | none                           | Interactions, budgets, per-route caps, workers, workflow depth         |
| `SCANNER_CONCURRENCY`                                   | `8`                            | Concurrent HTTP workers during detection                               |
| `SCAN_MODE`                                             | none                           | `verified` / `heuristic` / `aggressive`                                |
| `XSS_BROWSER_DOM_*` / `OPEN_REDIRECT_BROWSER_*`         | none                           | Budgets for browser-based DOM sweeps                                   |
| `BLIND_INJECTION_TIMING_THRESHOLD`                      | none                           | Fraction of expected delay treated as a blind hit                      |
| `SSRF_INBAND_TIMING_DELTA_MS`                           | `1500`                         | Internal-versus-control response delta for in-band SSRF                |
| `OAST_CALLBACK_BASE_URL` / `OAST_POLL_URL`              | derived from `PUBLIC_HOSTNAME` | Callback URL minted into payloads; poll endpoint on the backend        |
| `NVD_API_URL` / `NVD_API_KEY` / `CVE_CACHE_TTL_SECONDS` | none                           | NVD CPE lookups. **Set the key**: unkeyed NVD allows 5 requests / 30s and 403s past that |
| `OSV_API_URL`                                           | `api.osv.dev/v1/query`         | Ecosystem package advisories (keyless)                                 |
| `WORDFENCE_API_URL` / `WORDFENCE_API_KEY`               | v3 production feed / none      | WordPress plugin+theme vulns; without a key they report as not assessed |
| `KEV_FEED_URL` / `EPSS_API_URL`                         | CISA / FIRST                   | Exploited-in-the-wild ranking overlays (keyless)                       |
| `THREAT_INTEL_CACHE_TTL_SECONDS`                        | `21600`                        | KEV catalogue and Wordfence feed cache lifetime                        |
| `LOG_FILE`                                              | none                           | Optional file logging (the compose stack mounts `scanner_logs`)        |

Every crawl and scan knob also has a per-scan override in `ScanConfig` (`shared/schemas/scan_schema.py`), settable from the UI or as an application default. Per-scan values win over env.

## Vulnerability intelligence

Components are matched to CVEs by **product identity and version range**, never by
description keyword. This matters more than it sounds. NVD's `keywordSearch`
parameter is a full-text search over CVE prose, and using it fails in both
directions at once:

- **False positives on loosely-versioned components.** `keywordSearch="WordPress 7.1"`
  returns 84 results, none of which are WordPress core. The top five are CVEs for
  the *wp-google-maps* and *wp-live-chat-support* plugins, matched because their
  descriptions read "before 7.1.03 for WordPress". WordPress 7.1 is the current
  release with no applicable CVEs. Likewise a version-less "PHP" entry returns
  12,324 results starting in 1999, and attaching the first five yields CVEs for
  TYPO3, NoneCms and Selesta Visual Access Manager.
- **Silent false negatives on precisely-versioned ones.** `"Express 4.18.2"`,
  `"Nginx 1.24.0"` and `"Node.js 18.16.0"` each return **zero** results, because NVD
  prose rarely spells out a full patch version — so a vulnerable component is
  reported as clean.

Each component routes to the source that actually covers it:

| Component kind | Source | Why |
| -------------- | ------ | --- |
| Ecosystem package (Express, Django, Laravel, jQuery) | OSV.dev (`osv_client.py`) | Resolves ranges with each ecosystem's own version semantics; lands advisories before NVD assigns CPEs. Keyless. |
| Server, language, CMS core (Nginx, PHP, WordPress) | NVD by CPE (`nvd_client.py`) | `virtualMatchString=cpe:2.3:a:f5:nginx:1.24.0` returns exactly the two CVEs covering that version |
| WordPress plugin / theme | Wordfence Intelligence v3 (`wordfence_client.py`) | Where nearly all WordPress risk lives, and where NVD is weakest. Needs a free key |
| Ranking overlay | CISA KEV + EPSS (`threat_intel.py`) | Rank by real-world exploitation instead of truncating the list. Keyless |

Four rules hold throughout:

1. **No version, no query.** A component whose version was never resolved cannot be
   range-matched, so it is reported `not_assessed` — not as an empty CVE list.
2. **Applicability is re-verified locally.** Every returned `cpeMatch` is re-checked
   against the detected version by `cpe_match.py`, which compares versions
   *numerically* (nginx 1.24.0 is newer than 1.9.5, though it sorts earlier as a
   string) and rejects legacy CPEs carrying no version bounds at all — the reason
   CVE-2007-2627 otherwise matches every WordPress release ever shipped.
3. **An empty list is never ambiguous.** Every component carries
   `cve_assessment` ∈ `assessed` / `not_assessed` / `failed` plus the reason and the
   source that answered. A rate-limited lookup and a genuinely clean component are
   different facts and the report states which one it has.
4. **Nothing is invented.** Missing CVSS scores are computed from the advisory's
   CVSS vector (`cvss.py`) or left absent; the supply-chain detector grades an
   unscored CVE medium and says so rather than defaulting it to 7.5.

WordPress plugin and theme slugs — which the Wordfence feed is keyed on, and which
fingerprints do not supply — are resolved from `/wp-content/plugins/<slug>/` asset
paths by `wordpress_assets.py`. A `?ver=` value is only accepted as the extension's
version when it looks like a version and differs from the WordPress core version,
since WordPress stamps its own version onto assets whose extension declares none.

## Request governance

`core/request_governor.py` plus `utils/scan_throttle.py` and `utils/scan_metrics.py` bound the worker's footprint: global rate limiting, per-host throttling, request counting for the activity log, and redaction of secrets from anything persisted or logged (`utils/redaction.py`).

## Project layout

```
app/
  worker.py                  queue consumer: scan jobs + re-verification jobs,
                             cancellation watcher, leases, heartbeats, reconciliation
  config.py                  ScannerSettings
  reverification.py          focused replay entry point
  core/
    scanner.py               ScanOrchestrator (mixin composition)
    crawler/                 spider, browser engine, auth manager, SPA/API extractors
    detectors/               16 detectors + attack planner/surface + base classes
    verification/            verifiers (sqli, nosqli, xss, command), response analysis,
                             dedup, test-pollution filter
    scan_orchestration/      pipeline, runtime, detector execution, finding processing,
                             coverage, technology enrichment, progress/ETA
    evidence_grader.py       deterministic proof grading
    request_governor.py      rate limiting / governance
    payload_profile.py
  reverification_strategies/ per-family replay strategies
  integrations/              wappalyzer, SSLyze, version probe, error fingerprints
                             cve_database (routing), nvd_client, osv_client,
                             wordfence_client, threat_intel, cpe_match, cvss
  utils/                     cvss_calculator, scan_http, redaction, throttles, metrics
tests/                       unit + integration suites
```

## Testing

```bash
pytest tests/          # from scanner/
```

Fakes replace the browser, HTTP layer, and OAST client, so the suite runs without Chromium or a live target.
