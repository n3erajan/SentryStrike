from app.utils.http_logging import (
    ScanRequestContext,
    infer_payload_from_request,
    log_http_response,
    resolve_request_context,
    truncate,
)
from app.utils.scan_metrics import begin_request_counting, end_request_counting, snapshot_request_counts


def test_truncate_shortens_long_payloads():
    assert truncate("a" * 150, max_len=120).endswith("...")
    assert len(truncate("a" * 150, max_len=120)) == 123


def test_infer_payload_from_query_params():
    payload = infer_payload_from_request(
        "id",
        "http://example.com/page.php?id=1&name=test",
        None,
        None,
    )
    assert payload == "1"


def test_infer_payload_from_post_data():
    payload = infer_payload_from_request(
        "username",
        "http://example.com/login.php",
        None,
        {"username": "admin", "password": "secret"},
    )
    assert payload == "admin"


def test_resolve_request_context_prefers_explicit_values():
    ctx = resolve_request_context(
        instance_context=ScanRequestContext(module="sqli", parameter="id"),
        module="xss",
        parameter="q",
        test_phase="boolean_true",
        payload="' OR 1=1--",
    )
    assert ctx.module == "xss"
    assert ctx.parameter == "q"
    assert ctx.test_phase == "boolean_true"
    assert ctx.payload == "' OR 1=1--"


def test_log_http_response_includes_scan_fields(caplog):
    import logging

    caplog.set_level(logging.INFO, logger="sentry.http")
    log_http_response(
        "GET",
        "http://192.168.16.104/dvwa/vulnerabilities/xss_r/?name=test",
        200,
        module="xss",
        parameter="name",
        test_phase="payload_simple",
        payload="<script>alert(1)</script>",
        response_time_ms=42.5,
    )
    assert len(caplog.records) == 1
    message = caplog.records[0].message
    assert "module=xss" in message
    assert "parameter=name" in message
    assert "phase=payload_simple" in message
    assert "payload=<script>alert(1)</script>" in message
    assert "time=42ms" in message


def test_log_http_response_records_detector_request_count():
    begin_request_counting()
    try:
        log_http_response("GET", "http://example.test/", 200, module="xss")
        log_http_response("POST", "http://example.test/login", 403, module="auth")

        assert snapshot_request_counts() == {"xss": 1, "auth": 1}
    finally:
        end_request_counting()
