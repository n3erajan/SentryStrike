from app.core.detectors.base_detector import Finding
from app.core.verification.verification_framework import FindingDeduplicator
from shared.models.vulnerability import OwaspCategory, SeverityLevel


def test_deduplicate_collapses_path_variable_file_sink() -> None:
    """A REST path-variable file sink (/ftp/:file) is ONE vulnerability even when
    demonstrated on several files: the parameter equals the last path segment, so
    each file yields a distinct full URL but the same sink. They must collapse into
    one finding whose affected_parameters lists every file read."""
    files = ["package.json.bak", "coupons_2013.md.bak", "encrypt.pyc"]
    findings = [
        Finding(
            category=OwaspCategory.a05,
            vuln_type="Path Traversal / Arbitrary File Read (poison null byte)",
            severity=SeverityLevel.high,
            url=f"http://localhost:3000/ftp/{f}",
            parameter=f,
            method="GET",
            evidence=f"Read {f} via null-byte bypass.",
            confidence_score=90.0,
            verified=True,
        )
        for f in files
    ]

    deduped = FindingDeduplicator.deduplicate(findings)

    assert len(deduped) == 1
    assert deduped[0].affected_parameters == files
    for f in files:
        assert f"Read {f} via null-byte bypass." in deduped[0].evidence


def test_deduplicate_keeps_distinct_path_variable_routes_separate() -> None:
    """Path-variable collapse must not merge different directories: a file read
    under /ftp/ and one under /backups/ are different sinks."""
    findings = [
        Finding(
            category=OwaspCategory.a05,
            vuln_type="Path Traversal / Arbitrary File Read",
            severity=SeverityLevel.high,
            url="http://localhost:3000/ftp/package.json.bak",
            parameter="package.json.bak",
            method="GET",
            evidence="Read via /ftp.",
            confidence_score=90.0,
            verified=True,
        ),
        Finding(
            category=OwaspCategory.a05,
            vuln_type="Path Traversal / Arbitrary File Read",
            severity=SeverityLevel.high,
            url="http://localhost:3000/backups/secret.key",
            parameter="secret.key",
            method="GET",
            evidence="Read via /backups.",
            confidence_score=90.0,
            verified=True,
        ),
    ]

    deduped = FindingDeduplicator.deduplicate(findings)

    assert len(deduped) == 2


def test_deduplicate_collapses_object_id_path_instances() -> None:
    """A BOLA/IDOR on /rest/basket/:id is ONE vulnerability even when demonstrated
    against several object ids in the URL path (parameter is None — the id is not a
    captured parameter). The numeric id segments must normalize so the instances
    collapse; the concrete urls survive in merged evidence."""
    findings = [
        Finding(
            category=OwaspCategory.a01,
            vuln_type="Broken Object-Level Authorization",
            severity=SeverityLevel.high,
            url=f"http://localhost:3000/rest/basket/{oid}",
            parameter=None,
            method="GET",
            evidence=f"Cross-identity read of basket {oid}.",
            confidence_score=80.0,
            verified=True,
        )
        for oid in (1, 6, 7)
    ]

    deduped = FindingDeduplicator.deduplicate(findings)

    assert len(deduped) == 1
    for oid in (1, 6, 7):
        assert f"Cross-identity read of basket {oid}." in deduped[0].evidence


def test_deduplicate_keeps_distinct_id_routes_separate() -> None:
    """Object-id normalization must not merge different resource routes: a BOLA on
    /api/Users/1 and one on /rest/basket/1 are different endpoints."""
    findings = [
        Finding(
            category=OwaspCategory.a01,
            vuln_type="Broken Object-Level Authorization",
            severity=SeverityLevel.high,
            url="http://localhost:3000/api/Users/1",
            parameter=None,
            method="GET",
            evidence="User read.",
            confidence_score=80.0,
            verified=True,
        ),
        Finding(
            category=OwaspCategory.a01,
            vuln_type="Broken Object-Level Authorization",
            severity=SeverityLevel.high,
            url="http://localhost:3000/rest/basket/1",
            parameter=None,
            method="GET",
            evidence="Basket read.",
            confidence_score=80.0,
            verified=True,
        ),
    ]

    deduped = FindingDeduplicator.deduplicate(findings)

    assert len(deduped) == 2


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


def test_deduplicate_merges_idor_and_bola_on_same_endpoint() -> None:
    """IDOR and Broken Object-Level Authorization are the same class under different
    module names. When two access-control modules flag the SAME endpoint (a
    differential-IDOR verifier and the authorization-matrix BOLA probe both on
    POST /api/Complaints), they must collapse into one finding, not two."""
    findings = [
        Finding(
            category=OwaspCategory.a01,
            vuln_type="Insecure Direct Object Reference (IDOR)",
            severity=SeverityLevel.medium,
            url="http://localhost:3000/api/Complaints/",
            parameter="UserId",
            method="POST",
            evidence="Second-user IDOR on Complaints.",
            confidence_score=95.0,
            verified=True,
        ),
        Finding(
            category=OwaspCategory.a01,
            vuln_type="Broken Object-Level Authorization",
            severity=SeverityLevel.medium,
            url="http://localhost:3000/api/Complaints/",
            parameter=None,
            method="POST",
            evidence="Authorization-matrix cross-identity on Complaints.",
            confidence_score=85.0,
            verified=True,
        ),
    ]

    deduped = FindingDeduplicator.deduplicate(findings)

    assert len(deduped) == 1
    assert "Second-user IDOR on Complaints." in deduped[0].evidence
    assert "Authorization-matrix cross-identity on Complaints." in deduped[0].evidence


def test_deduplicate_keeps_horizontal_authz_on_distinct_routes_separate() -> None:
    """The object-level-authz family merge is still per-route: a BOLA on one endpoint
    and a Horizontal Authorization Bypass on a different endpoint stay separate."""
    findings = [
        Finding(
            category=OwaspCategory.a01,
            vuln_type="Broken Object-Level Authorization",
            severity=SeverityLevel.medium,
            url="http://localhost:3000/api/Users/1",
            parameter=None,
            method="GET",
            evidence="BOLA on user object.",
            confidence_score=85.0,
            verified=True,
        ),
        Finding(
            category=OwaspCategory.a01,
            vuln_type="Horizontal Authorization Bypass",
            severity=SeverityLevel.medium,
            url="http://localhost:3000/rest/user/authentication-details",
            parameter=None,
            method="GET",
            evidence="Horizontal authz bypass on auth details.",
            confidence_score=90.0,
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


def test_deduplicate_collapses_verbose_errors_across_endpoints_but_not_metrics() -> None:
    """Verbose error / stack-trace disclosure is one app-wide misconfiguration (a
    single global error handler): it collapses to one finding per origin across
    every endpoint that trips it. A Debug/Metrics Endpoint Exposed finding shares
    the exception_disclosure family but is a distinct vuln on its own path and must
    stay separate."""
    endpoints = [
        ("http://t.test/api/Feedbacks/", "captchaId"),
        ("http://t.test/api/BasketItems/", "ProductId"),
        ("http://t.test/api/Cards/121", "fullName"),
        ("http://t.test/rest/user/login", "email"),
    ]
    findings = [
        Finding(
            category=OwaspCategory.a10,
            vuln_type="Verbose Error Handling",
            severity=SeverityLevel.medium,
            url=url,
            parameter=param,
            evidence=f"POST {url} -> HTTP 500 stack trace leaked",
            confidence_score=90.0,
            verified=True,
        )
        for url, param in endpoints
    ]
    findings.append(
        Finding(
            category=OwaspCategory.a02,
            vuln_type="Debug / Metrics Endpoint Exposed",
            severity=SeverityLevel.medium,
            url="http://t.test/metrics",
            parameter=None,
            evidence="GET http://t.test/metrics -> HTTP 200 prometheus metrics",
            confidence_score=90.0,
            verified=True,
        )
    )

    deduped = FindingDeduplicator.deduplicate(findings)

    by_type = {f.vuln_type: f for f in deduped}
    assert len(deduped) == 2
    assert "Verbose Error Handling" in by_type
    assert "Debug / Metrics Endpoint Exposed" in by_type
    # every affected endpoint survives in the collapsed verbose finding's evidence
    for url, _ in endpoints:
        assert url in by_type["Verbose Error Handling"].evidence
