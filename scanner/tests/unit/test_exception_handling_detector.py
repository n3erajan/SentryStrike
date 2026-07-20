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


def test_observed_evidence_ignores_bare_sql_query_echo() -> None:
    # A "SELECT ... FROM ... WHERE" echo in a SQLi verifier's OWN response is the
    # A05 injection proof, already owned by that finding - not independent A10
    # verbose-error disclosure. When the observed body contains ONLY a query-shape
    # echo (no engine error, no stack trace), no A10 finding is derived.
    detector = ExceptionHandlingDetector()
    source_finding = Finding(
        category=OwaspCategory.a05,
        vuln_type="SQL Injection (Error-Based)",
        severity=SeverityLevel.critical,
        url="http://target.test/rest/user/login",
        parameter="email",
        payload="'",
        method="POST",
        evidence="Boolean SQLi confirmed.",
        detection_method="boolean_differential",
        verification_response_snippet=(
            "HTTP/1.1 200 OK\n\n"
            "SELECT * FROM Users WHERE email = 'x' AND password = 'y'"
        ),
        verified=True,
    )

    findings = detector.findings_from_observed_evidence([source_finding])
    assert findings == []


def test_direct_fuzz_ignores_bare_query_echo_in_page_content() -> None:
    # A low-specificity "SELECT ... FROM ... WHERE" match against ordinary page
    # prose/HTML (not a DB engine error) must NOT produce an A10 verbose-error
    # finding on the direct fuzz path. This mirrors the observed-evidence path's
    # query-echo exclusion, so the two paths stay consistent. Reproduces the
    # false positive on the stored-XSS guestbook page where benign navigation /
    # instruction text happened to line up "select ... from ... where".
    detector = ExceptionHandlingDetector()

    finding = detector._analyse_response(
        url="http://target.test/dvwa/vulnerabilities/xss_s/",
        method="POST",
        status=200,
        body=(
            "<html><body><h1>Guestbook</h1>"
            "<p>Select a language from the dropdown where available.</p>"
            "<p>Name: sentry_test_val</p></body></html>"
        ),
        headers=httpx.Headers({}),
        trigger="form fuzz - single quote - SQL metacharacter / template error trigger",
        parameter="txtName",
        payload="'",
    )

    assert finding is None


def test_direct_fuzz_still_reports_real_sql_engine_error() -> None:
    # The query-echo exclusion must not suppress a genuine DB engine error that
    # happens to also contain a query echo — the specific engine-error pattern
    # keeps the finding.
    detector = ExceptionHandlingDetector()

    finding = detector._analyse_response(
        url="http://target.test/item",
        method="GET",
        status=200,
        body=(
            "You have an error in your SQL syntax; check the manual. "
            "SELECT * FROM users WHERE id = ''"
        ),
        headers=httpx.Headers({}),
        trigger="single quote fuzz",
        parameter="id",
        payload="'",
    )

    assert finding is not None
    assert finding.vuln_type == "Verbose Error Handling"


def test_direct_fuzz_keeps_query_echo_on_server_error() -> None:
    # A query echo on a genuine 5xx error response IS disclosure (the server threw
    # and dumped the executing statement), so the status-aware exclusion keeps it.
    detector = ExceptionHandlingDetector()

    finding = detector._analyse_response(
        url="http://target.test/api/search",
        method="POST",
        status=500,
        body="Internal error executing: SELECT id FROM accounts WHERE token = ''",
        headers=httpx.Headers({}),
        trigger="json_body fuzz - single quote",
        parameter="q",
        payload="'",
    )

    assert finding is not None
    assert finding.vuln_type == "Verbose Error Handling"


def test_observed_evidence_line_does_not_fabricate_http_200() -> None:
    # The source finding carries no HTTP status, so the derived evidence line must
    # not claim "HTTP 200" (which previously mislabeled 500 error pages).
    detector = ExceptionHandlingDetector()
    source_finding = Finding(
        category=OwaspCategory.a05,
        vuln_type="SQL Injection (Error-Based)",
        severity=SeverityLevel.critical,
        url="http://target.test/api/Feedbacks/",
        parameter="captchaId",
        payload="\x00",
        method="POST",
        evidence="Engine error triggered.",
        detection_method="error_based",
        verification_response_snippet=(
            "SQLITE_ERROR: unrecognized token\n"
            "    at /juice-shop/node_modules/sequelize/lib/sequelize.js:315:28"
        ),
        verified=True,
    )

    findings = detector.findings_from_observed_evidence([source_finding])
    assert len(findings) == 1
    assert "HTTP 200" not in findings[0].evidence
    assert "status unrecorded" in findings[0].evidence
