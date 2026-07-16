import httpx

from app.core.detectors.base_detector import Finding
from app.core.detectors.exception_handler import ExceptionHandlingDetector
from shared.models.vulnerability import OwaspCategory, SeverityLevel


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


def test_bare_500_without_disclosure_is_not_verbose_error() -> None:
    # A 500 whose body carries a generic message (no stack trace, file path,
    # SQL echo or framework exception) is not "verbose error handling" — even
    # when the response ships tech-fingerprint headers. Reporting one such 500
    # per fuzzed parameter was the dominant error-handling noise source.
    detector = ExceptionHandlingDetector()
    finding = detector._analyse_response(
        url="https://example.test/api/Recycles/",
        method="POST",
        status=500,
        body='{"message":"internal error","errors":["SQLITE_CONSTRAINT: FOREIGN KEY constraint failed"]}',
        headers=httpx.Headers({"content-type": "application/json", "x-powered-by": "Express"}),
        trigger="json_body fuzz - single quote",
        parameter="UserId",
        payload="'",
    )
    assert finding is None


def test_500_with_stack_trace_is_still_reported() -> None:
    # A genuine internal disclosure (a language stack trace / SQL echo) is still
    # reported — the tightening only drops content-free error statuses.
    detector = ExceptionHandlingDetector()
    finding = detector._analyse_response(
        url="https://example.test/api/search",
        method="POST",
        status=500,
        body=(
            '{"error":{"message":"boom","stack":"Error\n'
            "    at Query.run SELECT id FROM Users WHERE name = ''"
            '"}}'
        ),
        headers=httpx.Headers({"content-type": "application/json"}),
        trigger="json_body fuzz - single quote",
        parameter="name",
        payload="'",
    )
    assert finding is not None
    assert finding.vuln_type == "Verbose Error Handling"


def test_node_stack_trace_500_is_reported() -> None:
    # A Node/Express stack trace is a server-generated error message containing
    # sensitive information (CWE-550) — it leaks file paths and framework
    # internals — and belongs to A10 regardless of language. The bare-500 noise
    # drop must not swallow a genuine stack trace of any stack.
    detector = ExceptionHandlingDetector()
    finding = detector._analyse_response(
        url="https://example.test/api/Cards/8",
        method="PATCH",
        status=500,
        body=(
            '{"error":{"message":"Cannot read property \\"foo\\" of undefined",'
            '"stack":"TypeError: Cannot read property \'foo\' of undefined\\n'
            "    at /app/routes/cards.js:45:17\\n"
            "    at Layer.handle [as handle_request] "
            "(/node_modules/express/lib/router/layer.js:95:5)\\n"
            '    at processTicksAndRejections (node:internal/process/task_queues:77:11)"}}'
        ),
        headers=httpx.Headers({"content-type": "application/json"}),
        trigger="json_body fuzz - single quote",
        parameter="cardId",
        payload="'",
    )
    assert finding is not None
    assert finding.vuln_type == "Verbose Error Handling"
