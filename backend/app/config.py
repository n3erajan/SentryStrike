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

    allow_registration: bool = Field(default=False, alias="ALLOW_REGISTRATION")
    auth_session_ttl_hours: int = Field(default=24, ge=1, alias="AUTH_SESSION_TTL_HOURS")
    auth_cookie_name: str = Field(
        default="sentrystrike_session",
        min_length=1,
        alias="AUTH_COOKIE_NAME",
    )
    auth_cookie_secure: bool = Field(default=False, alias="AUTH_COOKIE_SECURE")
    auth_cookie_samesite: str = Field(default="lax", alias="AUTH_COOKIE_SAMESITE")

    @field_validator("auth_cookie_samesite")
    @classmethod
    def _validate_cookie_samesite(cls, value: str) -> str:
        normalized = value.lower()
        if normalized not in {"lax", "strict", "none"}:
            raise ValueError("AUTH_COOKIE_SAMESITE must be one of: lax, strict, none")
        return normalized


@lru_cache
def get_settings() -> BackendSettings:
    return BackendSettings()
