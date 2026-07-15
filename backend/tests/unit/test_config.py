from app.config import BackendSettings
from shared.config import InfrastructureSettings


def test_infrastructure_settings_exclude_service_configuration() -> None:
    fields = InfrastructureSettings.model_fields

    assert "mongodb_uri" in fields
    assert "redis_url" in fields
    assert "oast_interaction_ttl_seconds" in fields
    assert "app_name" not in fields
    assert "ai_model" not in fields


def test_backend_settings_exclude_scanner_configuration() -> None:
    fields = BackendSettings.model_fields

    assert "app_name" in fields
    assert "auth_cookie_name" in fields
    assert "ai_model" not in fields
    assert "crawl_depth" not in fields
    assert "authentication_username" not in fields
