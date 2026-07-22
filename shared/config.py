from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
ROOT_ENV_FILE = REPOSITORY_ROOT / ".env"


def service_env_files(service_name: str) -> tuple[Path, Path]:
    """Load deployment-wide values first, then service-specific overrides."""
    return ROOT_ENV_FILE, REPOSITORY_ROOT / service_name / ".env"


class _RootSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=ROOT_ENV_FILE,
        env_file_encoding="utf-8",
        extra="ignore",
    )


class InfrastructureSettings(_RootSettings):
    """Connectivity required by every deployed service."""

    mongodb_uri: str = Field(default="mongodb://localhost:27017", alias="MONGODB_URI")
    mongodb_db_name: str = Field(default="sentrystrike", alias="MONGODB_DB_NAME")
    redis_url: str = Field(default="redis://localhost:6379/0", alias="REDIS_URL")


class ScanQueueSettings(_RootSettings):
    """Shared scan queue and scanner-lifecycle key names."""

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
    scan_lease_key_prefix: str = Field(
        default="sentrystrike:scan:lease",
        alias="SCAN_LEASE_KEY_PREFIX",
    )
    scan_lease_ttl_seconds: int = Field(
        default=30,
        ge=10,
        alias="SCAN_LEASE_TTL_SECONDS",
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


class AnalysisQueueSettings(_RootSettings):
    """Redis signal queue shared by analysis producers and consumers."""

    analysis_queue_name: str = Field(
        default="sentrystrike:analysis",
        alias="ANALYSIS_QUEUE_NAME",
    )


class PublicUrlSettings(_RootSettings):
    """Public deployment address shared by backend links and scanner callbacks."""

    public_hostname: str | None = Field(default=None, alias="PUBLIC_HOSTNAME")

    @property
    def public_base_url(self) -> str | None:
        base = (self.public_hostname or "").strip().rstrip("/")
        if not base:
            return None
        if "://" not in base:
            base = f"http://{base}"
        return base


class SharedDocumentSettings(_RootSettings):
    """Options that must match wherever shared database models are registered."""

    oast_interaction_ttl_seconds: int = Field(
        default=3600,
        ge=60,
        alias="OAST_INTERACTION_TTL_SECONDS",
    )


@lru_cache
def get_shared_document_settings() -> SharedDocumentSettings:
    return SharedDocumentSettings()
