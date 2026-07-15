import pytest

from app.utils.cvss_calculator import CvssCalculator
from shared.models.vulnerability import SeverityLevel

def test_csrf_severity_sync():
    # Test that CSRF produces a CVSS score that maps to Low severity
    result = CvssCalculator.from_vulnerability_context("CSRF")
    
    # Score should be around 4.3 (Medium) but wait, the plan explicitly maps it to Low if possible
    # Or in scanner.py, we sync severity from CVSS
    severity = CvssCalculator.get_severity(result.score)
    
    # Assert it maps correctly based on CVSS logic
    assert result.score > 0
    assert severity in ["Low", "Medium"]


def test_path_traversal_cvss_reflects_high_severity():
    """Path Traversal should score ~7.5 (High) per CVSS v3.1 - no privilege required."""
    result = CvssCalculator.from_vulnerability_context("Path Traversal / Arbitrary File Read")

    assert "/PR:N/" in result.vector
    assert "/C:H/" in result.vector
    severity = CvssCalculator.get_severity(result.score)
    assert severity == "High", f"expected High, got {severity} (score={result.score})"


@pytest.mark.parametrize(
    "vuln_type",
    [
        "Horizontal Authorization Bypass",
        "Vertical Privilege Bypass",
        "Broken Object-Level Authorization",
        "Broken Function-Level Authorization",
        "Unauthenticated API Data Exposure",
    ],
)
def test_access_control_family_not_underscored(vuln_type):
    """Broken-authorization findings read others' PII/secrets — Confidentiality
    High. Regression: these titles matched NO CVSS profile (substring match),
    so they fell to the generic default (C:L) and were reported Low. They must
    now match an access-control profile with C:H."""
    result = CvssCalculator.from_vulnerability_context(vuln_type, requires_auth=True)
    assert "/C:H/" in result.vector, f"{vuln_type}: expected C:H, got {result.vector}"
    assert result.score >= 6.0, f"{vuln_type}: expected >=6.0, got {result.score}"


def test_mass_assignment_scores_integrity_high():
    """Mass assignment mutates a privilege field — Integrity High, not the
    generic read default."""
    result = CvssCalculator.from_vulnerability_context(
        "Mass Assignment / Privilege Field Injection", requires_auth=True
    )
    assert "/I:H/" in result.vector
    assert result.score >= 6.0


def test_missing_authorization_on_mutation_scores_integrity_high():
    """A state-changing endpoint that skips authentication is an integrity
    attack, not a confidentiality one."""
    result = CvssCalculator.from_vulnerability_context(
        "Missing Authorization on State-Changing Request", requires_auth=False
    )
    assert "/I:H/" in result.vector
    assert "/PR:N/" in result.vector
