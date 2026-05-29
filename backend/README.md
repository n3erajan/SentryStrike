# Sentry Strike Backend

Production-oriented backend for an intelligent web vulnerability scanner aligned to OWASP Top 10 categories, with AI-assisted analysis via local Ollama.

## Features

- Async REST API powered by FastAPI
- MongoDB persistence with Motor + Beanie ODM
- Modular scanning engine with crawler and detector pipeline
- OWASP detector coverage for access control, injection, crypto, auth, misconfiguration, supply chain, and exception leakage
- Local LLM integration through Ollama (default model: qwen2.5-coder:7b-instruct-q4_K_M)
- AI prioritization, false-positive filtering, remediation guidance, and report synthesis
- JSON and PDF report generation
- Unit and integration test suite

## Project Layout

- backend/app/main.py: API app entrypoint
- backend/app/core/scanner.py: end-to-end scan orchestrator
- backend/app/core/crawler/: crawling utilities
- backend/app/core/detectors/: detector implementations
- backend/app/analyzers/: AI analysis pipeline
- backend/app/integrations/: external integrations (tech, CVE, SSL)
- backend/app/models/: Beanie document and nested models
- backend/app/database/: DB connection + repositories
- backend/app/api/routes/: REST endpoints
- backend/tests/: tests

## Requirements

- Python 3.10+
- MongoDB 6+
- Ollama running locally or reachable by network

## Setup

1. Create and activate environment
   - Windows PowerShell:
     - python -m venv .venv
     - .\.venv\Scripts\Activate.ps1
2. Install dependencies
   - pip install -r requirements.txt
3. Configure environment
   - copy .env.example .env
   - Update MONGODB_URI and OLLAMA_BASE_URL as needed

## Run

- uvicorn app.main:app --host 0.0.0.0 --port 8000

## Docker

- docker compose up --build
- API will be available at http://localhost:8000

Open API docs:

- http://localhost:8000/docs

## Main Endpoints

- POST /api/v1/scans: create scan
- GET /api/v1/scans: list scans
- GET /api/v1/scans/{scan_id}: scan details
- GET /api/v1/scans/{scan_id}/status: scan status
- DELETE /api/v1/scans/{scan_id}: delete scan
- POST /api/v1/scans/{scan_id}/cancel: cancel scan
- GET /api/v1/analysis/scans/{scan_id}/vulnerabilities: list vulnerabilities
- GET /api/v1/analysis/scans/{scan_id}/vulnerabilities/{vulnerability_id}: vulnerability detail
- PATCH /api/v1/analysis/scans/{scan_id}/vulnerabilities/{vulnerability_id}/false-positive: mark false positive
- GET /api/v1/reports/{scan_id}: report data
- POST /api/v1/reports/{scan_id}/generate: generate AI report
- GET /api/v1/reports/{scan_id}/pdf: download PDF report
- GET /api/v1/health
- GET /api/v1/health/owasp-categories

## Scan Workflow

1. Client submits target URL
2. Scan is created with queued status
3. Background task runs crawler
4. Passive checks and technology detection execute
5. Active detectors run in parallel
6. CVE enrichment and AI analysis execute
7. Findings and report metadata are stored
8. Status moves to completed or failed

## Configuration

All key behavior is controlled via environment variables in .env:

- App: APP_ENV, APP_DEBUG, APP_HOST, APP_PORT
- DB: MONGODB_URI, MONGODB_DB_NAME
- AI: OLLAMA_BASE_URL, OLLAMA_MODEL, OLLAMA_TIMEOUT_SECONDS
- Scanner: CRAWL_DEPTH, CRAWL_MAX_URLS, CRAWL_RATE_LIMIT_PER_SECOND, REQUEST_TIMEOUT_SECONDS
- Integrations: NVD_API_URL, NVD_API_KEY, CVE_CACHE_TTL_SECONDS
- Logging: LOG_LEVEL, LOG_FILE

## Testing

- pytest -q
- pytest --cov=app --cov-report=term-missing

## Deployment Notes

- Use production-grade MongoDB credentials and network policies
- Run API behind reverse proxy (Nginx/Traefik) with TLS
- Restrict scan target ranges for legal and safety boundaries
- Configure Ollama host according to deployment topology

## Ethical and Legal Use

Only scan systems you own or are authorized to test.
