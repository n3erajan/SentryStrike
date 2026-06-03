from functools import lru_cache
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    app_name: str = "Sentry Strike Backend"
    app_env: str = Field(default="dev", alias="APP_ENV")
    app_debug: bool = Field(default=True, alias="APP_DEBUG")
    app_host: str = Field(default="0.0.0.0", alias="APP_HOST")
    app_port: int = Field(default=8000, alias="APP_PORT")

    mongodb_uri: str = Field(default="mongodb://localhost:27017", alias="MONGODB_URI")
    mongodb_db_name: str = Field(default="sentry_strike", alias="MONGODB_DB_NAME")

    ollama_base_url: str = Field(default="http://localhost:11434", alias="OLLAMA_BASE_URL")
    ollama_model: str = Field(default="qwen3:8b", alias="OLLAMA_MODEL")
    ollama_timeout_seconds: float = Field(default=120.0, alias="OLLAMA_TIMEOUT_SECONDS")
    ai_max_retries: int = Field(default=2, alias="AI_MAX_RETRIES")

    crawl_depth: int = Field(default=3, alias="CRAWL_DEPTH")
    crawl_max_urls: int = Field(default=200, alias="CRAWL_MAX_URLS")
    crawl_rate_limit_per_second: float = Field(default=8.0, alias="CRAWL_RATE_LIMIT_PER_SECOND")
    request_timeout_seconds: float = Field(default=10.0, alias="REQUEST_TIMEOUT_SECONDS")
    scanner_concurrency: int = Field(default=8, alias="SCANNER_CONCURRENCY")

    # Verification / Scanning Settings
    scan_mode: str = Field(default="verified", alias="SCAN_MODE")  # verified / heuristic / aggressive
    authentication_username: str | None = Field(default=None, alias="SCAN_AUTH_USERNAME")
    authentication_password: str | None = Field(default=None, alias="SCAN_AUTH_PASSWORD")
    authentication_cookie: str | None = Field(default=None, alias="SCAN_AUTH_COOKIE")  # Format: "security=low; PHPSESSID=..."
    max_verification_requests_per_param: int = Field(default=10, alias="MAX_VERIFICATION_REQUESTS")
    blind_injection_timing_threshold: float = Field(
        default=0.7,
        alias="BLIND_INJECTION_TIMING_THRESHOLD",
        description=(
            "Fraction of expected delay to use as threshold (0.0-1.0). "
            "Default 0.7 = 70% of expected delay."
        ),
    )

    cors_origins: list[str] = Field(default=["*"], alias="CORS_ORIGINS")

    nvd_api_url: str = Field(default="https://services.nvd.nist.gov/rest/json/cves/2.0", alias="NVD_API_URL")
    nvd_api_key: str | None = Field(default=None, alias="NVD_API_KEY")
    cve_cache_ttl_seconds: int = Field(default=3600, alias="CVE_CACHE_TTL_SECONDS")

    log_level: str = Field(default="INFO", alias="LOG_LEVEL")
    log_file: str = Field(default="logs/app.log", alias="LOG_FILE")


@lru_cache
def get_settings() -> Settings:
    return Settings()
