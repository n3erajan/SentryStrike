from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class InfrastructureSettings(BaseSettings):
    """Configuration required by code shared between deployed services."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    mongodb_uri: str = Field(default="mongodb://localhost:27017", alias="MONGODB_URI")
    mongodb_db_name: str = Field(default="sentrystrike", alias="MONGODB_DB_NAME")

    redis_url: str = Field(default="redis://localhost:6379/0", alias="REDIS_URL")
    scan_queue_name: str = Field(default="sentrystrike:scans", alias="SCAN_QUEUE_NAME")
    scan_cancel_key_prefix: str = Field(
        default="sentrystrike:scan:cancel",
        alias="SCAN_CANCEL_KEY_PREFIX",
    )
    scan_cancel_ttl_seconds: int = Field(
        default=86400,
        ge=60,
        alias="SCAN_CANCEL_TTL_SECONDS",
    )

    # Both services initialize the same Beanie model and must agree on its TTL.
    oast_interaction_ttl_seconds: int = Field(
        default=3600,
        ge=60,
        alias="OAST_INTERACTION_TTL_SECONDS",
    )

    worker_heartbeat_prefix: str = Field(
        default="sentrystrike:worker:heartbeat",
        alias="WORKER_HEARTBEAT_PREFIX",
    )
    worker_heartbeat_ttl_seconds: int = Field(
        default=20,
        ge=5,
        alias="WORKER_HEARTBEAT_TTL_SECONDS",
    )

    log_level: str = Field(default="INFO", alias="LOG_LEVEL")
    log_file: str = Field(default="logs/app.log", alias="LOG_FILE")


@lru_cache
def get_infrastructure_settings() -> InfrastructureSettings:
    return InfrastructureSettings()
