from app.config import BackendSettings
from shared.config import InfrastructureSettings


def test_backend_defaults_do_not_require_smtp_credentials(monkeypatch) -> None:
    for name in (
        "EMAIL_SMTP_HOST",
        "EMAIL_SMTP_PORT",
        "EMAIL_SMTP_USER",
        "EMAIL_SMTP_PASSWORD",
        "EMAIL_SMTP_STARTTLS",
    ):
        monkeypatch.delenv(name, raising=False)

    settings = BackendSettings(_env_file=None)

    assert settings.email_smtp_host == "localhost"
    assert settings.email_smtp_port == 1025
    assert settings.email_smtp_starttls is False


def test_auth_cookie_secure_defaults_off_in_debug(monkeypatch) -> None:
    """Unset + APP_DEBUG=true -> not Secure, so a plain-HTTP dev/LAN deployment
    sets a cookie the browser will actually send back."""
    monkeypatch.delenv("AUTH_COOKIE_SECURE", raising=False)
    monkeypatch.setenv("APP_DEBUG", "true")

    settings = BackendSettings(_env_file=None)

    assert settings.app_debug is True
    assert settings.auth_cookie_secure is False


def test_auth_cookie_secure_defaults_on_in_production(monkeypatch) -> None:
    """Unset + APP_DEBUG=false -> Secure, so production over HTTPS is hardened."""
    monkeypatch.delenv("AUTH_COOKIE_SECURE", raising=False)
    monkeypatch.setenv("APP_DEBUG", "false")
    # Production also refuses the Turnstile test keys, so supply real-looking ones.
    monkeypatch.setenv("TURNSTILE_SITE_KEY", "0xLIVEsitekey")
    monkeypatch.setenv("TURNSTILE_SECRET_KEY", "0xLIVEsecretkey")

    settings = BackendSettings(_env_file=None)

    assert settings.app_debug is False
    assert settings.auth_cookie_secure is True


def test_auth_cookie_secure_explicit_value_overrides_debug_default(monkeypatch) -> None:
    """An explicit AUTH_COOKIE_SECURE wins (HTTPS-terminating proxy in dev)."""
    monkeypatch.setenv("APP_DEBUG", "true")
    monkeypatch.setenv("AUTH_COOKIE_SECURE", "true")

    settings = BackendSettings(_env_file=None)

    assert settings.app_debug is True
    assert settings.auth_cookie_secure is True


def test_infrastructure_settings_exclude_service_configuration() -> None:
    fields = InfrastructureSettings.model_fields

    assert "mongodb_uri" in fields
    assert "redis_url" in fields
    assert "oast_interaction_ttl_seconds" not in fields
    assert "scan_queue_name" not in fields
    assert "analysis_queue_name" not in fields
    assert "app_name" not in fields
    assert "ai_model" not in fields


def test_backend_settings_exclude_scanner_configuration() -> None:
    fields = BackendSettings.model_fields

    assert "app_name" in fields
    assert "auth_cookie_name" in fields
    assert "scan_queue_name" in fields
    assert "analysis_queue_name" in fields
    assert "public_hostname" in fields
    assert "ai_model" not in fields
    assert "analysis_reconcile_interval_seconds" not in fields
    assert "oast_interaction_ttl_seconds" not in fields
    assert "crawl_depth" not in fields
    assert "authentication_username" not in fields


def test_backend_service_env_overrides_root_env(tmp_path) -> None:
    root_env = tmp_path / "root.env"
    service_env = tmp_path / "backend.env"
    root_env.write_text(
        "MONGODB_DB_NAME=shared-db\nAPP_NAME=shared-name\n",
        encoding="utf-8",
    )
    service_env.write_text(
        "MONGODB_DB_NAME=backend-db\nAPP_NAME=Backend Override\n"
        "EMAIL_SMTP_HOST=localhost\n",
        encoding="utf-8",
    )

    settings = BackendSettings(_env_file=(root_env, service_env))

    assert settings.mongodb_db_name == "backend-db"
    assert settings.app_name == "Backend Override"
