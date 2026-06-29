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

    ollama_base_url: str = Field(default="http://localhost:11434", alias="OLLAMA_BASE_URL")
    ollama_model: str = Field(default="gemma4-e4b-8k", alias="OLLAMA_MODEL")
    ollama_timeout_seconds: float = Field(default=120.0, alias="OLLAMA_TIMEOUT_SECONDS")
    ai_max_retries: int = Field(default=3, alias="AI_MAX_RETRIES")
    ai_batch_size: int = Field(default=1, alias="AI_BATCH_SIZE")

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
    # Bounds for the XSS browser-driven DOM reflection sweep (Task 5). Caps the
    # number of route+param probes and the wall-clock spent so the phase can
    # never dominate a scan.
    xss_browser_dom_max_jobs: int = Field(default=12, alias="XSS_BROWSER_DOM_MAX_JOBS")
    xss_browser_dom_budget_seconds: float = Field(default=60.0, alias="XSS_BROWSER_DOM_BUDGET_SECONDS")
    request_timeout_seconds: float = Field(default=10.0, alias="REQUEST_TIMEOUT_SECONDS")
    scanner_concurrency: int = Field(default=8, alias="SCANNER_CONCURRENCY")
    sensitive_paths_permutation_cap: int = Field(default=200, alias="SENSITIVE_PATHS_PERMUTATION_CAP")

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
    max_verification_requests_per_param: int = Field(default=10, alias="MAX_VERIFICATION_REQUESTS")
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
