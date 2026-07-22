from app.config import ScannerSettings


def test_scanner_settings_exclude_backend_configuration() -> None:
    fields = ScannerSettings.model_fields

    assert "ai_model" not in fields
    assert "ai_api_key" not in fields
    assert "ai_analysis_enabled" not in fields
    assert "crawl_depth" in fields
    assert "authentication_login_url" in fields
    # Scan credentials are supplied per-scan with the request, never via env.
    assert "authentication_username" not in fields
    assert "authentication_password" not in fields
    assert "authentication_cookie" not in fields
    assert "authentication_second_cookie" not in fields
    assert "app_name" not in fields
    assert "allow_registration" not in fields
    assert "auth_cookie_name" not in fields
    assert "oast_interaction_ttl_seconds" not in fields


def _settings(**overrides) -> ScannerSettings:
    # Init kwargs outrank env, so start every OAST field at None (the conftest
    # autouse fixture sets the hostname + URL vars to "" to block a developer's
    # local .env from leaking in), then apply only what the test wants.
    kwargs = {
        "PUBLIC_HOSTNAME": None,
        "OAST_CALLBACK_BASE_URL": None,
        "OAST_POLL_URL": None,
    }
    kwargs.update(overrides)
    return ScannerSettings(_env_file=None, **kwargs)


def test_public_hostname_derives_both_oast_urls() -> None:
    settings = _settings(PUBLIC_HOSTNAME="sentry.example.com")

    assert settings.oast_callback_base_url == "http://sentry.example.com/oast"
    assert settings.oast_poll_url == "http://sentry.example.com/oast/poll"


def test_public_hostname_preserves_explicit_scheme_and_port() -> None:
    settings = _settings(PUBLIC_HOSTNAME="https://sentry.example.com:9000/")

    assert settings.oast_callback_base_url == "https://sentry.example.com:9000/oast"
    assert settings.oast_poll_url == "https://sentry.example.com:9000/oast/poll"


def test_explicit_oast_urls_override_derived_values() -> None:
    settings = _settings(
        PUBLIC_HOSTNAME="sentry.example.com",
        OAST_POLL_URL="http://poll.internal/x",
    )

    # Callback still derived from the hostname; poll respects the explicit override.
    assert settings.oast_callback_base_url == "http://sentry.example.com/oast"
    assert settings.oast_poll_url == "http://poll.internal/x"


def test_oast_urls_stay_unset_without_hostname() -> None:
    settings = _settings()

    assert settings.oast_callback_base_url is None
    assert settings.oast_poll_url is None


def test_scanner_service_env_overrides_root_env(tmp_path) -> None:
    root_env = tmp_path / "root.env"
    service_env = tmp_path / "scanner.env"
    root_env.write_text(
        "MONGODB_DB_NAME=shared-db\nLOG_LEVEL=INFO\n",
        encoding="utf-8",
    )
    service_env.write_text(
        "MONGODB_DB_NAME=scanner-db\nLOG_LEVEL=DEBUG\n",
        encoding="utf-8",
    )

    settings = ScannerSettings(_env_file=(root_env, service_env))

    assert settings.mongodb_db_name == "scanner-db"
    assert settings.log_level == "DEBUG"
