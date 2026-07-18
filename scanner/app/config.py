from functools import lru_cache

from pydantic import Field, model_validator

from shared.config import InfrastructureSettings


class ScannerSettings(InfrastructureSettings):
    ai_base_url: str = Field(default="http://localhost:11434/v1", alias="AI_BASE_URL")
    ai_model: str = Field(default="gemma4-e4b-8k", alias="AI_MODEL")
    ai_api_key: str | None = Field(default=None, alias="AI_API_KEY")
    ai_timeout_seconds: float = Field(default=120.0, alias="AI_TIMEOUT_SECONDS")
    ai_max_retries: int = Field(default=3, alias="AI_MAX_RETRIES")
    ai_batch_size: int = Field(default=1, alias="AI_BATCH_SIZE")
    ai_analysis_enabled: bool = Field(default=True, alias="AI_ANALYSIS_ENABLED")
    ai_json_mode: bool = Field(default=True, alias="AI_JSON_MODE")
    ai_reasoning_effort: str | None = Field(default="none", alias="AI_REASONING_EFFORT")

    crawl_depth: int = Field(default=3, alias="CRAWL_DEPTH")
    crawl_max_urls: int = Field(default=200, alias="CRAWL_MAX_URLS")
    crawl_rate_limit_per_second: float = Field(
        default=8.0,
        alias="CRAWL_RATE_LIMIT_PER_SECOND",
    )
    crawl_browser_mode: str = Field(default="auto", alias="CRAWL_BROWSER_MODE")
    crawl_browser_max_interactions: int = Field(
        default=25,
        alias="CRAWL_BROWSER_MAX_INTERACTIONS",
    )
    crawl_browser_budget_seconds: float = Field(
        default=300.0,
        alias="CRAWL_BROWSER_BUDGET_SECONDS",
    )
    crawl_browser_per_route_seconds: float = Field(
        default=6.0,
        alias="CRAWL_BROWSER_PER_ROUTE_SECONDS",
    )
    crawl_browser_route_cap_seconds: float = Field(
        default=60.0,
        alias="CRAWL_BROWSER_ROUTE_CAP_SECONDS",
    )
    crawl_browser_base_seconds: float = Field(
        default=30.0,
        alias="CRAWL_BROWSER_BASE_SECONDS",
    )
    crawl_browser_route_cap: int = Field(default=120, alias="CRAWL_BROWSER_ROUTE_CAP")
    crawl_browser_workers: int = Field(default=4, alias="CRAWL_BROWSER_WORKERS")
    crawl_browser_action_timeout_ms: float = Field(
        default=2000.0,
        alias="CRAWL_BROWSER_ACTION_TIMEOUT_MS",
    )
    crawl_browser_action_click_limit: int = Field(
        default=15,
        alias="CRAWL_BROWSER_ACTION_CLICK_LIMIT",
    )
    crawl_browser_action_click_passes: int = Field(
        default=2,
        alias="CRAWL_BROWSER_ACTION_CLICK_PASSES",
    )
    crawl_browser_workflow_depth: int = Field(
        default=2,
        alias="CRAWL_BROWSER_WORKFLOW_DEPTH",
    )
    crawl_browser_block_resources: bool = Field(
        default=True,
        alias="CRAWL_BROWSER_BLOCK_RESOURCES",
    )

    xss_browser_dom_max_jobs: int = Field(default=12, alias="XSS_BROWSER_DOM_MAX_JOBS")
    xss_browser_dom_budget_seconds: float = Field(
        default=60.0,
        alias="XSS_BROWSER_DOM_BUDGET_SECONDS",
    )
    open_redirect_browser_max_jobs: int = Field(
        default=10,
        alias="OPEN_REDIRECT_BROWSER_MAX_JOBS",
    )
    open_redirect_browser_budget_seconds: float = Field(
        default=45.0,
        alias="OPEN_REDIRECT_BROWSER_BUDGET_SECONDS",
    )

    request_timeout_seconds: float = Field(default=10.0, alias="REQUEST_TIMEOUT_SECONDS")
    scanner_concurrency: int = Field(default=8, alias="SCANNER_CONCURRENCY")
    sensitive_paths_permutation_cap: int = Field(
        default=200,
        alias="SENSITIVE_PATHS_PERMUTATION_CAP",
    )
    scanner_per_detector_request_cap: int = Field(
        default=6000,
        alias="SCANNER_PER_DETECTOR_REQUEST_CAP",
    )
    scanner_per_parameter_request_cap: int = Field(
        default=600,
        alias="SCANNER_PER_PARAMETER_REQUEST_CAP",
    )

    access_control_probe_mutating_methods: bool = Field(
        default=True,
        alias="ACCESS_CONTROL_PROBE_MUTATING_METHODS",
    )
    allow_destructive_authz_confirmation: bool = Field(
        default=False,
        alias="ALLOW_DESTRUCTIVE_AUTHZ_CONFIRMATION",
    )

    scan_mode: str = Field(default="verified", alias="SCAN_MODE")
    # NOTE: Scan credentials (username/password, raw cookies/headers, and the
    # second/privileged test-account material) are NOT read from the environment.
    # They are supplied per-scan with the submission request (``ScanAuthAccount``)
    # and reach the worker via the Redis job payload. Environment-based scan
    # credentials were removed because they would silently authenticate every
    # scan even when the operator submitted none, and the UI cannot edit env vars.
    allow_secondary_provisioning: bool = Field(
        default=False,
        alias="ALLOW_SECONDARY_PROVISIONING",
    )
    authentication_login_url: str | None = Field(default=None, alias="SCAN_AUTH_LOGIN_URL")
    authentication_success_url: str | None = Field(
        default=None,
        alias="SCAN_AUTH_SUCCESS_URL",
    )
    authentication_success_text: str | None = Field(
        default=None,
        alias="SCAN_AUTH_SUCCESS_TEXT",
    )
    authentication_success_regex: str | None = Field(
        default=None,
        alias="SCAN_AUTH_SUCCESS_REGEX",
    )
    authentication_failure_text: str | None = Field(
        default=None,
        alias="SCAN_AUTH_FAILURE_TEXT",
    )
    authentication_failure_regex: str | None = Field(
        default=None,
        alias="SCAN_AUTH_FAILURE_REGEX",
    )
    authentication_validation_url: str | None = Field(
        default=None,
        alias="SCAN_AUTH_VALIDATION_URL",
    )

    blind_injection_timing_threshold: float = Field(
        default=0.7,
        alias="BLIND_INJECTION_TIMING_THRESHOLD",
    )
    # The one knob most deployments need: the backend hostname (or full URL)
    # the target can reach us at, e.g. "sentry.example.com" or
    # "https://sentry.example.com". Both OAST URLs are derived from it using the
    # backend's known route layout (/oast for callbacks, /oast/poll for polling).
    # A bare hostname gets an http:// scheme. The two explicit URLs below are
    # optional overrides for the one split topology that needs them (a host-run
    # scanner probing a dockerized target, where the callback must resolve from
    # inside the target container but polling resolves from the scanner host).
    oast_hostname: str | None = Field(default=None, alias="OAST_HOSTNAME")
    oast_callback_base_url: str | None = Field(default=None, alias="OAST_CALLBACK_BASE_URL")
    oast_poll_url: str | None = Field(default=None, alias="OAST_POLL_URL")
    ssrf_oast_poll_attempts: int = Field(default=5, alias="SSRF_OAST_POLL_ATTEMPTS")
    ssrf_oast_poll_interval_seconds: float = Field(
        default=0.4,
        alias="SSRF_OAST_POLL_INTERVAL_SECONDS",
    )
    ssrf_inband_timing_delta_ms: float = Field(
        default=1500.0,
        alias="SSRF_INBAND_TIMING_DELTA_MS",
    )

    @model_validator(mode="after")
    def _derive_oast_urls_from_hostname(self) -> "ScannerSettings":
        base = (self.oast_hostname or "").strip().rstrip("/")
        if base:
            if "://" not in base:
                base = f"http://{base}"
            if not self.oast_callback_base_url:
                self.oast_callback_base_url = f"{base}/oast"
            if not self.oast_poll_url:
                self.oast_poll_url = f"{base}/oast/poll"
        return self

    nvd_api_url: str = Field(
        default="https://services.nvd.nist.gov/rest/json/cves/2.0",
        alias="NVD_API_URL",
    )
    nvd_api_key: str | None = Field(default=None, alias="NVD_API_KEY")
    cve_cache_ttl_seconds: int = Field(default=3600, alias="CVE_CACHE_TTL_SECONDS")


@lru_cache
def get_settings() -> ScannerSettings:
    return ScannerSettings()
