from app.core.detectors.base_detector import Finding
from app.core.verification.verification_framework import FindingDeduplicator
from app.models.vulnerability import OwaspCategory, SeverityLevel


def test_deduplicate_merges_admin_index_variants() -> None:
    findings = [
        Finding(
            category=OwaspCategory.a01,
            vuln_type="Well-Known Admin / Sensitive Path Discovered",
            severity=SeverityLevel.medium,
            url="https://example.test/phpmyadmin/",
            evidence="Admin path found.",
            confidence_score=60.0,
        ),
        Finding(
            category=OwaspCategory.a01,
            vuln_type="Admin / Privileged Endpoint Discovered",
            severity=SeverityLevel.high,
            url="https://example.test/phpmyadmin/index.php",
            evidence="Privileged endpoint found.",
            confidence_score=90.0,
        ),
    ]

    deduped = FindingDeduplicator.deduplicate(findings)

    assert len(deduped) == 1
    assert deduped[0].vuln_type == "Admin / Privileged Endpoint Discovered"
    assert "Admin path found." in deduped[0].evidence
    assert "Privileged endpoint found." in deduped[0].evidence


def test_deduplicate_merges_auth_csrf_variants() -> None:
    findings = [
        Finding(
            category=OwaspCategory.a07,
            vuln_type="Authentication Form Lacks CSRF Protection",
            severity=SeverityLevel.high,
            url="https://example.test/login.php",
            evidence="No token.",
            confidence_score=90.0,
        ),
        Finding(
            category=OwaspCategory.a07,
            vuln_type="Authentication Form May Lack CSRF Protection",
            severity=SeverityLevel.high,
            url="https://example.test/login.php",
            evidence="No hidden field.",
            confidence_score=10.0,
        ),
    ]

    deduped = FindingDeduplicator.deduplicate(findings)

    assert len(deduped) == 1
    assert deduped[0].vuln_type == "Authentication Form Lacks CSRF Protection"


def test_deduplicate_merges_file_read_and_lfi_on_same_parameter() -> None:
    findings = [
        Finding(
            category=OwaspCategory.a01,
            vuln_type="Path Traversal / Arbitrary File Read",
            severity=SeverityLevel.critical,
            url="https://example.test/view.php?page=home",
            parameter="page",
            payload="../../../../etc/passwd",
            evidence="Read /etc/passwd.",
            confidence_score=95.0,
            verified=True,
        ),
        Finding(
            category=OwaspCategory.a05,
            vuln_type="Local File Inclusion (LFI)",
            severity=SeverityLevel.critical,
            url="https://example.test/view.php?page=home",
            parameter="page",
            payload="php://filter/convert.base64-encode/resource=index.php",
            evidence="Read source through PHP wrapper.",
            confidence_score=98.0,
            verified=True,
        ),
    ]

    deduped = FindingDeduplicator.deduplicate(findings)

    assert len(deduped) == 1
    assert deduped[0].parameter == "page"
    assert deduped[0].vuln_type == "Local File Inclusion (LFI)"
    assert "Supporting finding: Path Traversal / Arbitrary File Read" in deduped[0].evidence
    assert "Read /etc/passwd." in deduped[0].evidence
    assert "Read source through PHP wrapper." in deduped[0].evidence


def test_deduplicate_groups_csrf_forms_by_endpoint() -> None:
    findings = [
        Finding(
            category=OwaspCategory.a07,
            vuln_type="Cross-Site Request Forgery (CSRF)",
            severity=SeverityLevel.high,
            url="https://example.test/profile",
            parameter="missing_token",
            evidence="Profile form accepted foreign origin.",
            confidence_score=90.0,
            verified=True,
        ),
        Finding(
            category=OwaspCategory.a07,
            vuln_type="Cross-Site Request Forgery (CSRF)",
            severity=SeverityLevel.medium,
            url="https://example.test/profile",
            parameter="csrf_token",
            evidence="Email form accepted tampered token.",
            confidence_score=85.0,
            verified=True,
        ),
    ]

    deduped = FindingDeduplicator.deduplicate(findings)

    assert len(deduped) == 1
    assert deduped[0].parameter == "missing_token"
    assert "Profile form accepted foreign origin." in deduped[0].evidence
    assert "Email form accepted tampered token." in deduped[0].evidence


def test_deduplicate_collapses_idor_params_on_same_route() -> None:
    """IDOR is a route-level missing-authorization flaw: mutating any object-reference
    field (UserId, AddressId, message, ...) hits the same broken check, so all fields on
    one route collapse into a single finding that lists every vulnerable parameter."""
    findings = [
        Finding(
            category=OwaspCategory.a01,
            vuln_type="Insecure Direct Object Reference (IDOR)",
            severity=SeverityLevel.high,
            url="http://localhost:3000/api/Recycles/",
            parameter="UserId",
            method="POST",
            payload="25",
            evidence="Horizontal IDOR confirmed: second user accessed 'UserId'=25.",
            confidence_score=95.0,
            detection_method="second_user_idor",
            verified=True,
        ),
        Finding(
            category=OwaspCategory.a01,
            vuln_type="Insecure Direct Object Reference (IDOR)",
            severity=SeverityLevel.high,
            url="http://localhost:3000/api/Recycles/",
            parameter="AddressId",
            method="POST",
            payload="8",
            evidence="Horizontal IDOR confirmed: second user accessed 'AddressId'=8.",
            confidence_score=90.0,
            detection_method="second_user_idor",
            verified=True,
        ),
    ]

    deduped = FindingDeduplicator.deduplicate(findings)

    assert len(deduped) == 1
    assert deduped[0].vuln_type == "Insecure Direct Object Reference (IDOR)"
    # Highest-confidence param is primary and first in the list.
    assert deduped[0].parameter == "UserId"
    assert deduped[0].affected_parameters == ["UserId", "AddressId"]
    assert "'UserId'=25" in deduped[0].evidence
    assert "'AddressId'=8" in deduped[0].evidence


def test_deduplicate_groups_sqli_params_on_same_route() -> None:
    """Login page with both email and password SQL-injectable becomes one finding that
    lists both vulnerable parameters (the user's canonical example)."""
    findings = [
        Finding(
            category=OwaspCategory.a05,
            vuln_type="SQL Injection (Error-Based)",
            severity=SeverityLevel.critical,
            url="http://localhost:3000/rest/user/login",
            parameter="email",
            method="POST",
            payload="' OR '1'='1",
            evidence="SQL error triggered via email.",
            confidence_score=90.0,
            detection_method="error_based",
            verified=True,
        ),
        Finding(
            category=OwaspCategory.a05,
            vuln_type="SQL Injection (Error-Based)",
            severity=SeverityLevel.critical,
            url="http://localhost:3000/rest/user/login",
            parameter="password",
            method="POST",
            payload="' OR '1'='1",
            evidence="SQL error triggered via password.",
            confidence_score=85.0,
            detection_method="error_based",
            verified=True,
        ),
    ]

    deduped = FindingDeduplicator.deduplicate(findings)

    assert len(deduped) == 1
    assert deduped[0].affected_parameters == ["email", "password"]
    assert "SQL error triggered via email." in deduped[0].evidence
    assert "SQL error triggered via password." in deduped[0].evidence


def test_deduplicate_keeps_idor_findings_on_distinct_routes() -> None:
    """Collapsing is per-route: different endpoints remain separate findings."""
    findings = [
        Finding(
            category=OwaspCategory.a01,
            vuln_type="Insecure Direct Object Reference (IDOR)",
            severity=SeverityLevel.high,
            url="http://localhost:3000/api/Recycles/",
            parameter="UserId",
            method="POST",
            evidence="IDOR on Recycles.",
            confidence_score=95.0,
            verified=True,
        ),
        Finding(
            category=OwaspCategory.a01,
            vuln_type="Insecure Direct Object Reference (IDOR)",
            severity=SeverityLevel.high,
            url="http://localhost:3000/api/Complaints/",
            parameter="UserId",
            method="POST",
            evidence="IDOR on Complaints.",
            confidence_score=95.0,
            verified=True,
        ),
    ]

    deduped = FindingDeduplicator.deduplicate(findings)

    assert len(deduped) == 2


def test_deduplicate_keeps_vertical_and_horizontal_idor_separate() -> None:
    """Vertical privilege escalation (critical) is a distinct family from horizontal
    IDOR (high) even on the same route, so it is not merged away."""
    findings = [
        Finding(
            category=OwaspCategory.a01,
            vuln_type="Insecure Direct Object Reference (IDOR)",
            severity=SeverityLevel.high,
            url="http://localhost:3000/api/Recycles/",
            parameter="UserId",
            method="POST",
            evidence="Horizontal IDOR.",
            confidence_score=95.0,
            verified=True,
        ),
        Finding(
            category=OwaspCategory.a01,
            vuln_type="Vertical Privilege Escalation (IDOR)",
            severity=SeverityLevel.critical,
            url="http://localhost:3000/api/Recycles/",
            parameter="UserId",
            method="POST",
            evidence="Vertical priv-esc.",
            confidence_score=90.0,
            verified=True,
        ),
    ]

    deduped = FindingDeduplicator.deduplicate(findings)

    assert len(deduped) == 2
    severities = {f.severity for f in deduped}
    assert SeverityLevel.critical in severities
    assert SeverityLevel.high in severities


def test_deduplicate_collapses_repeated_verbose_sql_error_evidence() -> None:
    findings = [
        Finding(
            category=OwaspCategory.a10,
            vuln_type="Verbose Error Handling",
            severity=SeverityLevel.high,
            url="http://target.test/dvwa/vulnerabilities/sqli/?id=%27&Submit=Submit",
            parameter="id",
            evidence=(
                "GET http://target.test/dvwa/vulnerabilities/sqli/?id=%27&Submit=Submit -> HTTP 200 | "
                "Trigger: form fuzz | Excerpt: \"<pre>You have an error in your SQL syntax; "
                "check the manual that corresponds to your MySQL server version for the right syntax "
                "to use near ''''' at line 1</pre>\""
            ),
            confidence_score=100.0,
            verified=True,
        ),
        Finding(
            category=OwaspCategory.a10,
            vuln_type="Verbose Error Handling",
            severity=SeverityLevel.high,
            url="http://target.test/dvwa/vulnerabilities/sqli/",
            parameter="id",
            evidence=(
                "GET http://target.test/dvwa/vulnerabilities/sqli/ -> HTTP 200 | "
                "Trigger: observed during SQL Injection (Error-Based) verification | "
                "Excerpt: \"<pre>You have an error in your SQL syntax; check the manual that "
                "corresponds to your MySQL server version for the right syntax to use near ''' at line 1</pre>\""
            ),
            confidence_score=95.0,
            detection_method="observed_exception_evidence",
            verified=True,
        ),
    ]

    deduped = FindingDeduplicator.deduplicate(findings)

    assert len(deduped) == 1
    assert deduped[0].evidence.count("You have an error in your SQL syntax") == 1
