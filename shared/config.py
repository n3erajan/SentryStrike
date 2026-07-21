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
    # Pub/Sub channel used to signal an immediate cancel to the worker actively
    # running a scan (the cancel key above remains the durable backstop).
    scan_cancel_channel: str = Field(
        default="sentrystrike:scan:cancel-channel",
        alias="SCAN_CANCEL_CHANNEL",
    )
    # Per-scan lease refreshed by the worker while it actively owns a scan. When
    # the worker dies the lease expires, letting readers detect an orphaned scan
    # that is still marked ``running`` in the database.
    scan_lease_key_prefix: str = Field(
        default="sentrystrike:scan:lease",
        alias="SCAN_LEASE_KEY_PREFIX",
    )
    scan_lease_ttl_seconds: int = Field(
        default=30,
        ge=10,
        alias="SCAN_LEASE_TTL_SECONDS",
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
    # Optional. Empty/unset = console only (typical for the API). Scanner sets a path.
    log_file: str | None = Field(default=None, alias="LOG_FILE")

    # The single public hostname (or full URL) at which this deployment is
    # reachable, e.g. "sentry.example.com" or "https://sentry.example.com".
    # Two things derive from it:
    #   * the OAST callback/poll URLs the scanner hands to a target (route layout
    #     /oast and /oast/poll), and
    #   * the invite links the backend emails (route /register?invite=<token>).
    # A bare hostname is given an http:// scheme. Leave unset for local dev.
    public_hostname: str | None = Field(default=None, alias="PUBLIC_HOSTNAME")

    @property
    def public_base_url(self) -> str | None:
        """The normalized public base URL (scheme + host, no trailing slash), or None.

        A bare hostname is promoted to ``http://``; anything with an explicit
        scheme is preserved so operators can pin ``https://`` in production.
        """
        base = (self.public_hostname or "").strip().rstrip("/")
        if not base:
            return None
        if "://" not in base:
            base = f"http://{base}"
        return base


@lru_cache
def get_infrastructure_settings() -> InfrastructureSettings:
    return InfrastructureSettings()
