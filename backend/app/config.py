from functools import lru_cache

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import SettingsConfigDict

from shared.config import (
    AnalysisQueueSettings,
    InfrastructureSettings,
    PublicUrlSettings,
    ScanQueueSettings,
    service_env_files,
)


class BackendSettings(
    ScanQueueSettings,
    AnalysisQueueSettings,
    PublicUrlSettings,
    InfrastructureSettings,
):
    model_config = SettingsConfigDict(
        env_file=service_env_files("backend"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_name: str = Field(default="Sentry Strike Backend", alias="APP_NAME")
    app_debug: bool = Field(default=True, alias="APP_DEBUG")
    cors_origins: list[str] = Field(default=["*"], alias="CORS_ORIGINS")
    log_level: str = Field(default="INFO", alias="LOG_LEVEL")

    auth_session_ttl_hours: int = Field(default=24, ge=1, alias="AUTH_SESSION_TTL_HOURS")
    auth_cookie_name: str = Field(
        default="sentrystrike_session",
        min_length=1,
        alias="AUTH_COOKIE_NAME",
    )
    auth_cookie_secure: bool = Field(default=False, alias="AUTH_COOKIE_SECURE")
    auth_cookie_samesite: str = Field(default="lax", alias="AUTH_COOKIE_SAMESITE")

    # Invitations. Registration is invite-only: a link is emailed to the invited
    # address and is valid for this many hours. Invite links use the fixed frontend
    # route /register?invite=<token>, built from PUBLIC_HOSTNAME in shared config.
    invite_ttl_hours: int = Field(default=168, ge=1, alias="INVITE_TTL_HOURS")  # 7 days
    invite_workspace_limit_per_hour: int = Field(
        default=20, ge=1, alias="INVITE_WORKSPACE_LIMIT_PER_HOUR"
    )
    invite_actor_limit_per_ten_minutes: int = Field(
        default=5, ge=1, alias="INVITE_ACTOR_LIMIT_PER_TEN_MINUTES"
    )
    invite_rate_limit_key_prefix: str = Field(
        default="sentrystrike:invite-rate", alias="INVITE_RATE_LIMIT_KEY_PREFIX"
    )

    # Email delivery uses SMTP. Gmail: smtp.gmail.com:587 with STARTTLS and an app
    # password as EMAIL_SMTP_PASSWORD.
    email_from: str = Field(default="SentryStrike <no-reply@sentrystrike.local>", alias="EMAIL_FROM")
    email_smtp_host: str = Field(default="smtp.gmail.com", alias="EMAIL_SMTP_HOST")
    email_smtp_port: int = Field(default=587, alias="EMAIL_SMTP_PORT")
    email_smtp_user: str | None = Field(default=None, alias="EMAIL_SMTP_USER")
    email_smtp_password: SecretStr | None = Field(default=None, alias="EMAIL_SMTP_PASSWORD")
    email_smtp_starttls: bool = Field(default=True, alias="EMAIL_SMTP_STARTTLS")

    # Retention purge. The background worker runs a purge pass on this interval,
    # deleting each org's scans older than its retention window. Twelve hours by
    # default: retention is measured in days, so a sub-daily cadence is ample.
    retention_purge_interval_seconds: int = Field(
        default=43200,
        ge=60,
        alias="RETENTION_PURGE_INTERVAL_SECONDS",
    )

    @field_validator("auth_cookie_samesite")
    @classmethod
    def _validate_cookie_samesite(cls, value: str) -> str:
        normalized = value.lower()
        if normalized not in {"lax", "strict", "none"}:
            raise ValueError("AUTH_COOKIE_SAMESITE must be one of: lax, strict, none")
        return normalized

    @model_validator(mode="after")
    def _validate_smtp_credentials(self) -> "BackendSettings":
        has_user = bool(self.email_smtp_user)
        has_password = bool(self.email_smtp_password)
        if has_user != has_password:
            raise ValueError(
                "EMAIL_SMTP_USER and EMAIL_SMTP_PASSWORD must either both be set or both be unset"
            )
        if self.email_smtp_host.lower() == "smtp.gmail.com" and not has_user:
            raise ValueError("Gmail SMTP requires EMAIL_SMTP_USER and EMAIL_SMTP_PASSWORD")
        return self


@lru_cache
def get_settings() -> BackendSettings:
    return BackendSettings()
