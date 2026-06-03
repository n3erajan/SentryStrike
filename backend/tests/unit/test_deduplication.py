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
