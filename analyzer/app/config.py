from functools import lru_cache

from pydantic import Field
from pydantic_settings import SettingsConfigDict

from shared.config import AnalysisQueueSettings, InfrastructureSettings, service_env_files


class AnalyzerSettings(AnalysisQueueSettings, InfrastructureSettings):
    model_config = SettingsConfigDict(
        env_file=service_env_files("analyzer"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    log_level: str = Field(default="INFO", alias="LOG_LEVEL")
    ai_analysis_enabled: bool = Field(default=True, alias="AI_ANALYSIS_ENABLED")
    ai_base_url: str = Field(default="http://localhost:11434/v1", alias="AI_BASE_URL")
    ai_model: str = Field(default="gemma4-e4b-8k", alias="AI_MODEL")
    ai_api_key: str | None = Field(default=None, alias="AI_API_KEY")
    ai_timeout_seconds: float = Field(default=120.0, gt=0, alias="AI_TIMEOUT_SECONDS")
    ai_max_retries: int = Field(default=3, ge=0, alias="AI_MAX_RETRIES")
    ai_json_mode: bool = Field(default=True, alias="AI_JSON_MODE")
    ai_reasoning_effort: str | None = Field(default="none", alias="AI_REASONING_EFFORT")

    analysis_lease_seconds: int = Field(default=300, ge=30, alias="ANALYSIS_LEASE_SECONDS")
    analysis_lease_renew_seconds: int = Field(
        default=60,
        ge=10,
        alias="ANALYSIS_LEASE_RENEW_SECONDS",
    )
    analysis_poll_seconds: int = Field(default=5, ge=1, alias="ANALYSIS_POLL_SECONDS")
    analysis_reconcile_interval_seconds: int = Field(
        default=30,
        ge=5,
        alias="ANALYSIS_RECONCILE_INTERVAL_SECONDS",
    )
    analysis_finding_evidence_max_chars: int = Field(
        default=6000,
        ge=500,
        alias="ANALYSIS_FINDING_EVIDENCE_MAX_CHARS",
    )
    analysis_report_input_max_chars: int = Field(
        default=24000,
        ge=1000,
        alias="ANALYSIS_REPORT_INPUT_MAX_CHARS",
    )


@lru_cache
def get_settings() -> AnalyzerSettings:
    return AnalyzerSettings()
