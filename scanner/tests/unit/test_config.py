from app.config import ScannerSettings


def test_scanner_settings_exclude_backend_configuration() -> None:
    fields = ScannerSettings.model_fields

    assert "ai_model" in fields
    assert "crawl_depth" in fields
    assert "authentication_username" in fields
    assert "app_name" not in fields
    assert "allow_registration" not in fields
    assert "auth_cookie_name" not in fields
