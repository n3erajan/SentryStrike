from functools import lru_cache

from pydantic import Field, field_validator

from shared.config import InfrastructureSettings


class BackendSettings(InfrastructureSettings):
    app_name: str = Field(default="Sentry Strike Backend", alias="APP_NAME")
    app_env: str = Field(default="dev", alias="APP_ENV")
    app_debug: bool = Field(default=True, alias="APP_DEBUG")
    app_host: str = Field(default="0.0.0.0", alias="APP_HOST")
    app_port: int = Field(default=8000, alias="APP_PORT")
    cors_origins: list[str] = Field(default=["*"], alias="CORS_ORIGINS")

    auth_session_ttl_hours: int = Field(default=24, ge=1, alias="AUTH_SESSION_TTL_HOURS")
    auth_cookie_name: str = Field(
        default="sentrystrike_session",
        min_length=1,
        alias="AUTH_COOKIE_NAME",
    )
    auth_cookie_secure: bool = Field(default=False, alias="AUTH_COOKIE_SECURE")
    auth_cookie_samesite: str = Field(default="lax", alias="AUTH_COOKIE_SAMESITE")

    # Invitations. Registration is invite-only: a link is emailed to the invited
    # address and is valid for this many hours. The frontend consumes the token
    # at /signup?invite=<token> (built from PUBLIC_HOSTNAME in shared config).
    invite_ttl_hours: int = Field(default=168, ge=1, alias="INVITE_TTL_HOURS")  # 7 days
    invite_signup_path: str = Field(default="/signup", alias="INVITE_SIGNUP_PATH")

    # Email delivery. "console" logs the message (and invite link) for local dev;
    # "smtp" sends via an SMTP server. Gmail: smtp.gmail.com:587 with STARTTLS and
    # an app password as EMAIL_SMTP_PASSWORD.
    email_backend: str = Field(default="console", alias="EMAIL_BACKEND")
    email_from: str = Field(default="SentryStrike <no-reply@sentrystrike.local>", alias="EMAIL_FROM")
    email_smtp_host: str = Field(default="smtp.gmail.com", alias="EMAIL_SMTP_HOST")
    email_smtp_port: int = Field(default=587, alias="EMAIL_SMTP_PORT")
    email_smtp_user: str | None = Field(default=None, alias="EMAIL_SMTP_USER")
    email_smtp_password: str | None = Field(default=None, alias="EMAIL_SMTP_PASSWORD")
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

    @field_validator("email_backend")
    @classmethod
    def _validate_email_backend(cls, value: str) -> str:
        normalized = value.lower()
        if normalized not in {"console", "smtp"}:
            raise ValueError("EMAIL_BACKEND must be one of: console, smtp")
        return normalized


@lru_cache
def get_settings() -> BackendSettings:
    return BackendSettings()
