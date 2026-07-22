from app.config import AnalyzerSettings


def test_analyzer_settings_exclude_scan_runtime_configuration() -> None:
    fields = AnalyzerSettings.model_fields

    assert "mongodb_uri" in fields
    assert "redis_url" in fields
    assert "analysis_queue_name" in fields
    assert "ai_analysis_enabled" in fields
    assert "scan_queue_name" not in fields
    assert "scan_cancel_key_prefix" not in fields
    assert "scan_lease_key_prefix" not in fields
    assert "worker_heartbeat_prefix" not in fields
    assert "public_hostname" not in fields
    assert "oast_interaction_ttl_seconds" not in fields
    assert "log_file" not in fields


def test_analyzer_service_env_overrides_root_env(tmp_path) -> None:
    root_env = tmp_path / "root.env"
    service_env = tmp_path / "analyzer.env"
    root_env.write_text(
        "MONGODB_DB_NAME=shared-db\nANALYSIS_QUEUE_NAME=shared-analysis\n",
        encoding="utf-8",
    )
    service_env.write_text(
        "MONGODB_DB_NAME=analyzer-db\nANALYSIS_QUEUE_NAME=analyzer-analysis\n",
        encoding="utf-8",
    )

    settings = AnalyzerSettings(_env_file=(root_env, service_env))

    assert settings.mongodb_db_name == "analyzer-db"
    assert settings.analysis_queue_name == "analyzer-analysis"
