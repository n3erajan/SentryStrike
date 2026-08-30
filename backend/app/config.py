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

TURNSTILE_TEST_SITE_KEY = "1x00000000000000000000AA"
TURNSTILE_TEST_SECRET_KEY = "1x0000000000000000000000000000000AA"


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
    cors_origins: list[str] = Field(default=["http://localhost:5173"], alias="CORS_ORIGINS")
    log_level: str = Field(default="INFO", alias="LOG_LEVEL")

    auth_session_ttl_hours: int = Field(default=168, ge=1, alias="AUTH_SESSION_TTL_HOURS")
    auth_cookie_name: str = Field(
        default="sentrystrike_session",
        min_length=1,
        alias="AUTH_COOKIE_NAME",
    )
    # None = derive from app_debug (see _default_cookie_secure): Secure in
    # production, not-Secure in dev. A browser silently refuses to SEND a Secure
    # cookie back over plain HTTP, so a Secure session cookie on an http:// dev or
    # LAN deployment (e.g. http://192.168.x.x) is stored but never returned -
    # every post-login request then 401s. Tying the default to app_debug stops the
    # flag from contradicting the environment. An explicit AUTH_COOKIE_SECURE still
    # wins, for the case of a real HTTPS-terminating proxy in front of a debug build.
    auth_cookie_secure: bool | None = Field(default=None, alias="AUTH_COOKIE_SECURE")
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

    # Public workspace-access requests. Cloudflare's documented always-pass keys
    # keep local development runnable, but are rejected when APP_DEBUG is false.
    turnstile_site_key: str = Field(
        default=TURNSTILE_TEST_SITE_KEY,
        min_length=1,
        alias="TURNSTILE_SITE_KEY",
    )
    turnstile_secret_key: SecretStr = Field(
        default=TURNSTILE_TEST_SECRET_KEY,
        alias="TURNSTILE_SECRET_KEY",
    )
    access_request_ttl_days: int = Field(
        default=30,
        ge=1,
        alias="ACCESS_REQUEST_TTL_DAYS",
    )
    access_request_ip_limit_per_fifteen_minutes: int = Field(
        default=3,
        ge=1,
        alias="ACCESS_REQUEST_IP_LIMIT_PER_FIFTEEN_MINUTES",
    )
    access_request_ip_limit_per_day: int = Field(
        default=10,
        ge=1,
        alias="ACCESS_REQUEST_IP_LIMIT_PER_DAY",
    )
    access_request_rate_limit_key_prefix: str = Field(
        default="sentrystrike:access-request-rate",
        alias="ACCESS_REQUEST_RATE_LIMIT_KEY_PREFIX",
    )

    # Local defaults allow the API to boot without external credentials. Point
    # these at a real relay in deployment; Gmail requires an app password.
    email_from: str = Field(default="SentryStrike <no-reply@sentrystrike.local>", alias="EMAIL_FROM")
    email_smtp_host: str = Field(default="localhost", alias="EMAIL_SMTP_HOST")
    email_smtp_port: int = Field(default=1025, alias="EMAIL_SMTP_PORT")
    email_smtp_user: str | None = Field(default=None, alias="EMAIL_SMTP_USER")
    email_smtp_password: SecretStr | None = Field(default=None, alias="EMAIL_SMTP_PASSWORD")
    email_smtp_starttls: bool = Field(default=False, alias="EMAIL_SMTP_STARTTLS")

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
    def _default_cookie_secure(self) -> "BackendSettings":
        """Resolve auth_cookie_secure to a concrete bool.

        Unset -> Secure in production (app_debug false), not-Secure in dev, so a
        plain-HTTP dev/LAN deployment does not set a Secure cookie the browser
        will refuse to send back. An explicit env value is preserved.
        """
        if self.auth_cookie_secure is None:
            self.auth_cookie_secure = not self.app_debug
        return self

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
        if not self.app_debug:
            if self.turnstile_site_key == TURNSTILE_TEST_SITE_KEY:
                raise ValueError("TURNSTILE_SITE_KEY must use a production key when APP_DEBUG is false")
            if self.turnstile_secret_key.get_secret_value() == TURNSTILE_TEST_SECRET_KEY:
                raise ValueError("TURNSTILE_SECRET_KEY must use a production key when APP_DEBUG is false")
        return self


@lru_cache
def get_settings() -> BackendSettings:
    return BackendSettings()
