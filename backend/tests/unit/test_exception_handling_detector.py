import asyncio

import pytest
import httpx

from app.core.detectors.base_detector import Finding
from app.core.detectors.exception_handler import ExceptionHandlingDetector
from app.models.vulnerability import OwaspCategory, SeverityLevel


class FakeMetricsResponse:
    status_code = 200
    text = "# HELP http_requests_total Total requests\n# TYPE http_requests_total counter\nhttp_requests_total 42\n"
    headers = httpx.Headers({"content-type": "text/plain"})


class FakeMetricsClient:
    async def get(self, url: str):
        return FakeMetricsResponse()


@pytest.mark.asyncio
async def test_exception_detector_reports_exposed_metrics_endpoint() -> None:
    detector = ExceptionHandlingDetector()
    finding = await detector._probe_debug_endpoint(
        FakeMetricsClient(),
        asyncio.Semaphore(1),
        "https://example.test",
        "/metrics",
    )

    assert finding is not None
    assert finding.vuln_type == "Debug / Metrics Endpoint Exposed"
    assert "metrics endpoint" in finding.evidence.lower()
    assert "http_requests_total" in finding.verification_response_snippet


def test_exception_detector_derives_a10_from_observed_database_error_evidence() -> None:
    detector = ExceptionHandlingDetector()
    source_finding = Finding(
        category=OwaspCategory.a05,
        vuln_type="SQL Injection (Error-Based)",
        severity=SeverityLevel.critical,
        url="https://example.test/search?id=1",
        parameter="id",
        payload="'",
        method="GET",
        evidence="SQL-engine error triggered and confirmed.",
        detection_method="error_based",
        detection_evidence={
            "errors_detected": [
                "check the manual that corresponds to your MariaDB server version",
            ],
        },
        verification_response_snippet=(
            "HTTP/1.1 200 OK\n\n"
            "You have an error in your SQL syntax; check the manual that "
            "corresponds to your MariaDB server version for the right syntax to use."
        ),
        confidence_score=85.0,
        verified=True,
        reproducible=True,
    )

    findings = detector.findings_from_observed_evidence([source_finding])

    assert len(findings) == 1
    assert findings[0].category == OwaspCategory.a10
    assert findings[0].vuln_type == "Verbose Error Handling"
    assert findings[0].severity == SeverityLevel.high
    assert findings[0].detection_method == "observed_exception_evidence"
    assert "mariadb server version" in findings[0].verification_response_snippet.lower()


def test_exception_detector_does_not_derive_duplicate_when_endpoint_already_has_verbose_error() -> None:
    detector = ExceptionHandlingDetector()
    direct_exception = Finding(
        category=OwaspCategory.a10,
        vuln_type="Verbose Error Handling",
        severity=SeverityLevel.high,
        url="https://example.test/search?id=%27",
        parameter="id",
        evidence="Direct exception fuzz found SQL syntax error.",
        verified=True,
    )
    source_finding = Finding(
        category=OwaspCategory.a05,
        vuln_type="SQL Injection (Error-Based)",
        severity=SeverityLevel.critical,
        url="https://example.test/search",
        parameter="id",
        payload="'",
        detection_method="error_based",
        evidence="SQL-engine error triggered.",
        verification_response_snippet=(
            "You have an error in your SQL syntax; check the manual that "
            "corresponds to your MySQL server version."
        ),
        verified=True,
    )

    findings = detector.findings_from_observed_evidence([direct_exception, source_finding])

    assert findings == []


def test_exception_detector_direct_response_analysis_handles_string_matches() -> None:
    detector = ExceptionHandlingDetector()

    finding = detector._analyse_response(
        url="https://example.test/item?id=%27",
        method="GET",
        status=200,
        body=(
            "Warning: mysqli_fetch_array() expects parameter 1 to be mysqli_result. "
            "You have an error in your SQL syntax near ''' at line 1."
        ),
        headers=httpx.Headers({}),
        trigger="single quote fuzz",
        parameter="id",
        payload="'",
    )

    assert finding is not None
    assert finding.category == OwaspCategory.a10
    assert finding.vuln_type == "Verbose Error Handling"
    assert finding.verification_response_snippet
    assert "sql syntax" in finding.verification_response_snippet.lower()


def test_exception_detector_ignores_self_referencing_target_ip() -> None:
    detector = ExceptionHandlingDetector()
    source_finding = Finding(
        category=OwaspCategory.a07,
        vuln_type="Authentication Form Lacks CSRF Protection",
        severity=SeverityLevel.medium,
        url="http://192.168.16.101/dvwa/login.php",
        parameter=None,
        payload=None,
        evidence="Some evidence info...",
        verification_response_snippet=(
            "HTTP/1.1 200 OK\n\n"
            "<form action=\"http://192.168.16.101/dvwa/login.php\" method=\"post\">"
        ),
        verified=True,
    )
    
    # Passing target_url matches the host IP, so it should be ignored as self-referencing
    findings = detector.findings_from_observed_evidence([source_finding], target_url="http://192.168.16.101/dvwa/")
    assert findings == []

    # But if the IP is different from target_url, it should be detected as a finding!
    findings_diff = detector.findings_from_observed_evidence([source_finding], target_url="http://10.0.0.1/dvwa/")
    assert len(findings_diff) == 1
    assert findings_diff[0].vuln_type == "Verbose Error Handling"


def test_exception_detector_only_analyzes_response_snippet() -> None:
    detector = ExceptionHandlingDetector()
    # evidence and payload contain path "/etc/", but response snippet does not
    source_finding = Finding(
        category=OwaspCategory.a05,
        vuln_type="Local File Inclusion (LFI)",
        severity=SeverityLevel.critical,
        url="http://example.test/file.php",
        parameter="file",
        payload="/etc/passwd",
        evidence="File inclusion verified via /etc/passwd path",
        verification_response_snippet="HTTP/1.1 200 OK\n\nHello World",
        verified=True,
    )
    findings = detector.findings_from_observed_evidence([source_finding])
    assert findings == []
