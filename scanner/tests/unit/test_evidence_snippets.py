from app.core.detectors.base_detector import Finding
from app.core.scanner import ScanOrchestrator
from app.core.verification.response_analyzer import ResponseAnalyzer
from shared.models.vulnerability import OwaspCategory, SeverityLevel


class DummyRepository:
    pass


def test_response_snippet_centers_deep_sql_error() -> None:
    body = "A" * 1800 + "You have an error in your SQL syntax near ''" + "B" * 1800

    snippet = ResponseAnalyzer.build_evidence_response_snippet(
        status_code=500,
        reason_phrase="Internal Server Error",
        headers={"content-type": "text/html"},
        body=body,
        payload="'",
    )

    assert "You have an error in your SQL syntax" in snippet
    assert "[...snip before proof...]" in snippet
    assert "content-type:" not in snippet.lower()
    assert not snippet.startswith("HTTP/1.1")
    assert len(snippet) < len(body)


def test_response_snippet_can_include_headers_when_requested() -> None:
    snippet = ResponseAnalyzer.build_evidence_response_snippet(
        status_code=500,
        reason_phrase="Internal Server Error",
        headers={"server": "Apache/2.4.1", "authorization": "secret"},
        body="You have an error in your SQL syntax near ''",
        payload="'",
        include_headers=True,
    )

    assert snippet.startswith("HTTP/1.1 500 Internal Server Error")
    assert "server: Apache/2.4.1" in snippet
    assert "authorization: [redacted]" in snippet


def test_response_snippet_centers_deep_xss_canary() -> None:
    body = "<html>" + ("A" * 1600) + "<script>sentryprobe_deadbeef</script>" + ("B" * 1600)

    snippet = ResponseAnalyzer.build_evidence_response_snippet(
        status_code=200,
        reason_phrase="OK",
        body=body,
        payload="sentryprobe_deadbeef",
    )

    assert "sentryprobe_deadbeef" in snippet
    assert snippet.index("sentryprobe_deadbeef") < 1500


def test_response_snippet_prefers_payload_canary_over_page_scripts() -> None:
    body = (
        "<html><head><script src='/static/app.js'></script></head><body>"
        + ("A" * 1800)
        + "'><img src=x onerror=window.sentry_hook('sentryprobe_b3a44e58')>"
        + ("B" * 800)
        + "</body></html>"
    )

    snippet = ResponseAnalyzer.build_evidence_response_snippet(
        status_code=200,
        reason_phrase="OK",
        body=body,
        payload="sentryprobe_b3a44e58",
    )

    assert "sentryprobe_b3a44e58" in snippet
    assert "/static/app.js" not in snippet


def test_response_snippet_prefers_xss_payload_over_unrelated_sql_error() -> None:
    payload = "<img src=x onerror=window.sentry_hook('sentryprobe_b3a44e58')>"
    body = (
        "<pre>You have an error in your SQL syntax near old noise</pre>"
        + ("A" * 1800)
        + payload
        + ("B" * 600)
    )

    snippet = ResponseAnalyzer.build_evidence_response_snippet(
        status_code=200,
        reason_phrase="OK",
        body=body,
        payload=payload,
    )

    assert payload in snippet
    assert "old noise" not in snippet


def test_response_snippet_centers_php_filter_base64_output() -> None:
    encoded_php = "PD9waHAKJHBhZ2UgPSAkX0dFVFsncGFnZSddOwppbmNsdWRlKCRwYWdlKTsKPz4="
    body = (
        "<html><head><script src='/static/app.js'></script></head><body>"
        + ("A" * 1500)
        + encoded_php
        + ("B" * 700)
        + "</body></html>"
    )

    snippet = ResponseAnalyzer.build_evidence_response_snippet(
        status_code=200,
        reason_phrase="OK",
        body=body,
        payload="php://filter/convert.base64-encode/resource=index.php",
    )

    assert encoded_php in snippet
    assert "/static/app.js" not in snippet


def test_scanner_response_snippet_starts_with_verification_evidence_for_blind_findings() -> None:
    finding = Finding(
        category=OwaspCategory.a05,
        vuln_type="SQL Injection (Time-Based Blind)",
        severity=SeverityLevel.high,
        url="http://target.test/sqli_blind",
        parameter="id",
        payload="' OR SLEEP(5)--",
        evidence="Response delayed 5100ms with sleep payload.",
        confidence_score=90.0,
        detection_method="time_based",
        verified=True,
        verification_response_snippet="HTTP/1.1 200 OK\n\n<html>normal page</html>",
    )

    vulnerability = ScanOrchestrator(DummyRepository())._to_vulnerability(finding)

    assert vulnerability.evidence.response_snippet.startswith("VERIFICATION EVIDENCE:")
    assert "Response delayed 5100ms" in vulnerability.evidence.response_snippet
    assert "RESPONSE EXCERPT:" not in vulnerability.evidence.response_snippet
    assert "<html>normal page</html>" not in vulnerability.evidence.response_snippet


def test_scanner_omits_html_response_excerpt_for_csrf_findings() -> None:
    finding = Finding(
        category=OwaspCategory.a07,
        vuln_type="Authentication Form Lacks CSRF Protection",
        severity=SeverityLevel.low,
        url="http://target.test/login",
        evidence="Authentication form has no CSRF token parameter.",
        confidence_score=75.0,
        detection_method="missing_csrf_token",
        verified=True,
        verification_response_snippet=(
            "<!doctype html><html><head><title>Login</title></head>"
            "<body><form><input name='username'></form></body></html>"
        ),
    )

    vulnerability = ScanOrchestrator(DummyRepository())._to_vulnerability(finding)

    assert vulnerability.evidence.response_snippet == (
        "VERIFICATION EVIDENCE:\nAuthentication form has no CSRF token parameter."
    )


def test_scanner_includes_response_excerpt_for_bola_cross_identity() -> None:
    # BOLA uses detection_method="authorization_matrix_cross_identity", which
    # was missing from the include allowlist, so its captured response body was
    # dropped even though it's an active finding with real proof.
    finding = Finding(
        category=OwaspCategory.a01,
        vuln_type="Broken Object-Level Authorization",
        severity=SeverityLevel.high,
        url="http://target.test/rest/user/1",
        evidence="Object-scoped resource returned the same object to two identities.",
        confidence_score=90.0,
        detection_method="authorization_matrix_cross_identity",
        verified=True,
        verification_response_snippet='{"status":"success","data":{"id":1,"email":"a@b.c"}}',
    )

    vulnerability = ScanOrchestrator(DummyRepository())._to_vulnerability(finding)

    assert "RESPONSE EXCERPT:" in vulnerability.evidence.response_snippet
    assert '"email":"a@b.c"' in vulnerability.evidence.response_snippet


def test_scanner_includes_response_excerpt_for_large_active_body() -> None:
    # An active finding whose captured body exceeds the old 600-char cap must
    # still show its excerpt; size is not a reason to drop active proof.
    large_body = "<!DOCTYPE html><title>Swagger UI</title>" + ("A" * 900)
    finding = Finding(
        category=OwaspCategory.a05,
        vuln_type="Exposed API Documentation",
        severity=SeverityLevel.medium,
        url="http://target.test/api-docs",
        evidence="OpenAPI/Swagger documentation content is reachable.",
        confidence_score=85.0,
        detection_method="path_content_fingerprint",
        verified=True,
        verification_response_snippet=large_body,
    )

    vulnerability = ScanOrchestrator(DummyRepository())._to_vulnerability(finding)

    assert "RESPONSE EXCERPT:" in vulnerability.evidence.response_snippet
    assert "Swagger UI" in vulnerability.evidence.response_snippet


def test_scanner_caps_oversized_response_excerpt() -> None:
    finding = Finding(
        category=OwaspCategory.a05,
        vuln_type="Exposed API Documentation",
        severity=SeverityLevel.medium,
        url="http://target.test/api-docs",
        evidence="Documentation reachable.",
        confidence_score=85.0,
        detection_method="path_content_fingerprint",
        verified=True,
        verification_response_snippet="X" * 5000,
    )

    vulnerability = ScanOrchestrator(DummyRepository())._to_vulnerability(finding)

    assert "RESPONSE EXCERPT:" in vulnerability.evidence.response_snippet
    assert "[...snip after excerpt...]" in vulnerability.evidence.response_snippet
    assert len(vulnerability.evidence.response_snippet) < 5000


def test_scanner_deduplicates_repeated_verification_evidence() -> None:
    finding = Finding(
        category=OwaspCategory.a07,
        vuln_type="Cross-Site Request Forgery (CSRF)",
        severity=SeverityLevel.medium,
        url="http://target.test/profile",
        evidence=(
            "Form submitted successfully with a tampered/missing CSRF token. "
            "Exploit succeeded even with foreign Origin/Referer.; "
            "Form submitted successfully with a tampered/missing CSRF token. "
            "Exploit succeeded even with foreign Origin/Referer."
        ),
        confidence_score=80.0,
        detection_method="csrf_origin_bypass",
        verified=True,
    )

    vulnerability = ScanOrchestrator(DummyRepository())._to_vulnerability(finding)

    assert vulnerability.evidence.response_snippet.count("Form submitted successfully") == 1
