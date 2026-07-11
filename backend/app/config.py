from functools import lru_cache
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    app_name: str = "Sentry Strike Backend"
    app_env: str = Field(default="dev", alias="APP_ENV")
    app_debug: bool = Field(default=True, alias="APP_DEBUG")
    app_host: str = Field(default="0.0.0.0", alias="APP_HOST")
    app_port: int = Field(default=8000, alias="APP_PORT")

    mongodb_uri: str = Field(default="mongodb://localhost:27017", alias="MONGODB_URI")
    mongodb_db_name: str = Field(default="sentrystrike", alias="MONGODB_DB_NAME")

    allow_registration: bool = Field(default=False, alias="ALLOW_REGISTRATION")
    auth_session_ttl_hours: int = Field(default=24, ge=1, alias="AUTH_SESSION_TTL_HOURS")
    auth_cookie_name: str = Field(default="sentrystrike_session", min_length=1, alias="AUTH_COOKIE_NAME")
    auth_cookie_secure: bool = Field(default=False, alias="AUTH_COOKIE_SECURE")
    auth_cookie_samesite: str = Field(default="lax", alias="AUTH_COOKIE_SAMESITE")

    # AI / LLM — single OpenAI-compatible client. Works with any provider that
    # speaks the Chat Completions API: local Ollama (set AI_BASE_URL to its /v1
    # endpoint, leave AI_API_KEY empty), OpenAI, Groq, Together, OpenRouter,
    # DeepSeek, Mistral, vLLM, LM Studio, llama.cpp, … Just change the base URL,
    # model, and (for hosted providers) the API key.
    ai_base_url: str = Field(default="http://localhost:11434/v1", alias="AI_BASE_URL")
    ai_model: str = Field(default="gemma4-e4b-8k", alias="AI_MODEL")
    # API key. Optional — local Ollama / unauthenticated local servers need none.
    ai_api_key: str | None = Field(default=None, alias="AI_API_KEY")
    ai_timeout_seconds: float = Field(default=120.0, alias="AI_TIMEOUT_SECONDS")
    ai_max_retries: int = Field(default=3, alias="AI_MAX_RETRIES")
    ai_batch_size: int = Field(default=1, alias="AI_BATCH_SIZE")
    # Send response_format={"type":"json_object"} (OpenAI JSON mode). Most
    # providers support this; disable if yours rejects it — the client still
    # extracts JSON from plain text.
    ai_json_mode: bool = Field(default=True, alias="AI_JSON_MODE")

    crawl_depth: int = Field(default=3, alias="CRAWL_DEPTH")
    crawl_max_urls: int = Field(default=200, alias="CRAWL_MAX_URLS")
    crawl_rate_limit_per_second: float = Field(default=8.0, alias="CRAWL_RATE_LIMIT_PER_SECOND")
    crawl_browser_enabled: bool = Field(default=False, alias="CRAWL_BROWSER_ENABLED")
    # auto = run browser discovery only when the target looks like an SPA;
    # always = run for every target; never = static-only. crawl_browser_enabled
    # (legacy) forces "always" when True for backward compatibility.
    crawl_browser_mode: str = Field(default="auto", alias="CRAWL_BROWSER_MODE")
    crawl_browser_max_interactions: int = Field(default=25, alias="CRAWL_BROWSER_MAX_INTERACTIONS")
    crawl_browser_budget_seconds: float = Field(default=300.0, alias="CRAWL_BROWSER_BUDGET_SECONDS")
    # Task B (value-ordered crawl): the effective browser budget scales with the
    # number of routes to visit — small apps finish fast, large apps get more —
    # bounded by ``crawl_browser_budget_seconds`` as a hard ceiling. Per-route
    # deadline checks still guarantee a clean truncation.
    crawl_browser_per_route_seconds: float = Field(default=6.0, alias="CRAWL_BROWSER_PER_ROUTE_SECONDS")
    crawl_browser_base_seconds: float = Field(default=30.0, alias="CRAWL_BROWSER_BASE_SECONDS")
    # Hard cap on how many routes the browser crawl will visit in one run
    # (the priority queue drops the low-score tail when this is hit).
    crawl_browser_route_cap: int = Field(default=120, alias="CRAWL_BROWSER_ROUTE_CAP")
    # Parallel browser crawl: number of worker coroutines (each its own context +
    # page) sharing the value-ordered route heap. 1 = the legacy serial crawl.
    # N contexts means N× the request rate at the target — browser traffic
    # bypasses the httpx scan semaphore — so keep this conservative.
    crawl_browser_workers: int = Field(default=4, alias="CRAWL_BROWSER_WORKERS")
    # Playwright per-action default timeout (ms) for the crawl context. Bounds any
    # locator op that is not given an explicit timeout (get_attribute/evaluate/…)
    # so it can never inherit Playwright's 30s default and orphan a 30s future
    # after ``_bounded`` cancels it. Keep well below the per-route budget.
    crawl_browser_action_timeout_ms: float = Field(default=2000.0, alias="CRAWL_BROWSER_ACTION_TIMEOUT_MS")
    # Max safe action buttons clicked per in-page pass during button-driven
    # mutation capture (body-coverage #1). Buttons that POST/PUT via a plain
    # click with no <form> (add-to-cart, save, create, rate, redeem, …) are
    # otherwise never exercised. Destructive/navigation labels are always
    # excluded regardless of this cap. Keep modest so a control-dense grid can
    # never dominate the per-route budget.
    crawl_browser_action_click_limit: int = Field(default=15, alias="CRAWL_BROWSER_ACTION_CLICK_LIMIT")
    # How many action-click passes to run per route. A pass re-runs only when the
    # previous one clicked genuinely-new controls (SPA re-render / lazy content);
    # a static page stops after one pass. Cross-route dedup + the crawl deadline
    # are the other two independent stops, so this cannot loop.
    crawl_browser_action_click_passes: int = Field(default=2, alias="CRAWL_BROWSER_ACTION_CLICK_PASSES")
    # Workflow chaining depth (body-coverage #2). Some endpoints only fire after a
    # prerequisite in-page action (add-to-basket → checkout; create address →
    # select at checkout). After the first form+button pass on a route, if new
    # interactive controls appeared, re-run the body-producing pass — up to this
    # many total passes, or until the control signature stops changing, or the
    # deadline hits. 1 disables chaining (single pass, same cost as before).
    crawl_browser_workflow_depth: int = Field(default=2, alias="CRAWL_BROWSER_WORKFLOW_DEPTH")
    # Block non-essential resources (images/media/fonts/stylesheets + known
    # trackers) during browser crawl/auth to speed up settle. Never blocks
    # same-origin script/xhr/fetch/document. Disable if a target renders needed
    # content into CSS/images.
    crawl_browser_block_resources: bool = Field(default=True, alias="CRAWL_BROWSER_BLOCK_RESOURCES")
    # Bounds for the XSS browser-driven DOM reflection sweep (Task 5). Caps the
    # number of route+param probes and the wall-clock spent so the phase can
    # never dominate a scan.
    xss_browser_dom_max_jobs: int = Field(default=12, alias="XSS_BROWSER_DOM_MAX_JOBS")
    xss_browser_dom_budget_seconds: float = Field(default=60.0, alias="XSS_BROWSER_DOM_BUDGET_SECONDS")
    # Bounds for the open-redirect browser-navigation sweep. Client-side SPA
    # redirects (``#/redirect?to=…`` that set window.location in JS) leave no HTTP
    # 302 to observe, so they are confirmed by navigating a real browser and
    # checking the final origin. Same shape/caps as the XSS DOM sweep.
    open_redirect_browser_max_jobs: int = Field(default=10, alias="OPEN_REDIRECT_BROWSER_MAX_JOBS")
    open_redirect_browser_budget_seconds: float = Field(default=45.0, alias="OPEN_REDIRECT_BROWSER_BUDGET_SECONDS")
    request_timeout_seconds: float = Field(default=10.0, alias="REQUEST_TIMEOUT_SECONDS")
    scanner_concurrency: int = Field(default=8, alias="SCANNER_CONCURRENCY")
    sensitive_paths_permutation_cap: int = Field(default=200, alias="SENSITIVE_PATHS_PERMUTATION_CAP")
    # P1-1: request-budget governor. Per-detector and per-(detector,parameter)
    # ceilings act as runaway backstops so no single detector/parameter can
    # dominate scan traffic (0 = unlimited). Defaults are generous — far above a
    # healthy detector's volume — so normal scans are unaffected and only
    # pathological fan-out (e.g. the header-stored XSS explosion) is capped.
    scanner_per_detector_request_cap: int = Field(default=6000, alias="SCANNER_PER_DETECTOR_REQUEST_CAP")
    scanner_per_parameter_request_cap: int = Field(default=600, alias="SCANNER_PER_PARAMETER_REQUEST_CAP")

    # Authorization testing of STATE-CHANGING requests (universal, framework/
    # business-agnostic). When on, the access-control detector probes id-bearing
    # mutating endpoints (DELETE/PUT/PATCH /x/:id) under each auth context using a
    # SYNTHETIC NON-EXISTENT object id, reading only the authorization verdict
    # (401/403 = enforced; processed = missing auth). No real record is ever
    # modified — safe against any target.
    access_control_probe_mutating_methods: bool = Field(
        default=True, alias="ACCESS_CONTROL_PROBE_MUTATING_METHODS"
    )
    # Opt-in higher-fidelity confirmation: additionally fire the mutating method
    # against a REAL object id that OUR OWN session created/observed, to confirm
    # an actual state change (true object-level BOLA). This performs real
    # mutations (only on self-observed data) so it is OFF by default and must be
    # enabled explicitly per authorized engagement.
    allow_destructive_authz_confirmation: bool = Field(
        default=False, alias="ALLOW_DESTRUCTIVE_AUTHZ_CONFIRMATION"
    )

    # Verification / Scanning Settings
    scan_mode: str = Field(default="verified", alias="SCAN_MODE")  # verified / heuristic / aggressive
    authentication_username: str | None = Field(default=None, alias="SCAN_AUTH_USERNAME")
    authentication_password: str | None = Field(default=None, alias="SCAN_AUTH_PASSWORD")
    authentication_cookie: str | None = Field(default=None, alias="SCAN_AUTH_COOKIE")  # Format: "security=low; PHPSESSID=..."
    authentication_header: str | None = Field(default=None, alias="SCAN_AUTH_HEADER")  # Format: "Authorization: Bearer ..."
    authentication_second_cookie: str | None = Field(default=None, alias="SCAN_AUTH_SECOND_COOKIE")
    authentication_second_header: str | None = Field(default=None, alias="SCAN_AUTH_SECOND_HEADER")
    authentication_privileged_cookie: str | None = Field(default=None, alias="SCAN_AUTH_PRIVILEGED_COOKIE")
    authentication_privileged_header: str | None = Field(default=None, alias="SCAN_AUTH_PRIVILEGED_HEADER")
    allow_secondary_provisioning: bool = Field(default=False, alias="ALLOW_SECONDARY_PROVISIONING")
    authentication_login_url: str | None = Field(default=None, alias="SCAN_AUTH_LOGIN_URL")
    authentication_success_url: str | None = Field(default=None, alias="SCAN_AUTH_SUCCESS_URL")
    authentication_success_text: str | None = Field(default=None, alias="SCAN_AUTH_SUCCESS_TEXT")
    authentication_success_regex: str | None = Field(default=None, alias="SCAN_AUTH_SUCCESS_REGEX")
    authentication_failure_text: str | None = Field(default=None, alias="SCAN_AUTH_FAILURE_TEXT")
    authentication_failure_regex: str | None = Field(default=None, alias="SCAN_AUTH_FAILURE_REGEX")
    authentication_validation_url: str | None = Field(default=None, alias="SCAN_AUTH_VALIDATION_URL")
    blind_injection_timing_threshold: float = Field(
        default=0.7,
        alias="BLIND_INJECTION_TIMING_THRESHOLD",
        description=(
            "Fraction of expected delay to use as threshold (0.0-1.0). "
            "Default 0.7 = 70% of expected delay."
        ),
    )
    oast_callback_base_url: str | None = Field(default=None, alias="OAST_CALLBACK_BASE_URL")
    oast_poll_url: str | None = Field(default=None, alias="OAST_POLL_URL")
    # In-band SSRF fallback: minimum consistent response-time delta (ms) between an
    # internal target and the external control before a probable (unverified) SSRF
    # is reported when no OAST callback is configured.
    ssrf_inband_timing_delta_ms: float = Field(default=1500.0, alias="SSRF_INBAND_TIMING_DELTA_MS")

    cors_origins: list[str] = Field(default=["*"], alias="CORS_ORIGINS")

    nvd_api_url: str = Field(default="https://services.nvd.nist.gov/rest/json/cves/2.0", alias="NVD_API_URL")
    nvd_api_key: str | None = Field(default=None, alias="NVD_API_KEY")
    cve_cache_ttl_seconds: int = Field(default=3600, alias="CVE_CACHE_TTL_SECONDS")

    log_level: str = Field(default="INFO", alias="LOG_LEVEL")
    log_file: str = Field(default="logs/app.log", alias="LOG_FILE")

    @field_validator("auth_cookie_samesite")
    @classmethod
    def _validate_cookie_samesite(cls, value: str) -> str:
        normalized = value.lower()
        if normalized not in {"lax", "strict", "none"}:
            raise ValueError("AUTH_COOKIE_SAMESITE must be one of: lax, strict, none")
        return normalized


@lru_cache
def get_settings() -> Settings:
    return Settings()
