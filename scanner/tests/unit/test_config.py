from app.config import ScannerSettings


def test_scanner_settings_exclude_backend_configuration() -> None:
    fields = ScannerSettings.model_fields

    assert "ai_model" in fields
    assert "crawl_depth" in fields
    assert "authentication_username" in fields
    assert "app_name" not in fields
    assert "allow_registration" not in fields
    assert "auth_cookie_name" not in fields


def _settings(**overrides) -> ScannerSettings:
    # Init kwargs outrank env, so start every OAST field at None (the conftest
    # autouse fixture sets the two URL vars to "" to block a developer's local
    # .env from leaking in), then apply only what the test wants.
    kwargs = {
        "OAST_HOSTNAME": None,
        "OAST_CALLBACK_BASE_URL": None,
        "OAST_POLL_URL": None,
    }
    kwargs.update(overrides)
    return ScannerSettings(_env_file=None, **kwargs)


def test_oast_hostname_derives_both_urls() -> None:
    settings = _settings(OAST_HOSTNAME="sentry.example.com")

    assert settings.oast_callback_base_url == "http://sentry.example.com/oast"
    assert settings.oast_poll_url == "http://sentry.example.com/oast/poll"


def test_oast_hostname_preserves_explicit_scheme_and_port() -> None:
    settings = _settings(OAST_HOSTNAME="https://sentry.example.com:9000/")

    assert settings.oast_callback_base_url == "https://sentry.example.com:9000/oast"
    assert settings.oast_poll_url == "https://sentry.example.com:9000/oast/poll"


def test_explicit_oast_urls_override_derived_values() -> None:
    settings = _settings(
        OAST_HOSTNAME="sentry.example.com",
        OAST_POLL_URL="http://poll.internal/x",
    )

    # Callback still derived from the hostname; poll respects the explicit override.
    assert settings.oast_callback_base_url == "http://sentry.example.com/oast"
    assert settings.oast_poll_url == "http://poll.internal/x"


def test_oast_urls_stay_unset_without_hostname() -> None:
    settings = _settings()

    assert settings.oast_callback_base_url is None
    assert settings.oast_poll_url is None
