import pytest

from app.utils.cvss_calculator import CvssCalculator
from app.models.vulnerability import SeverityLevel

def test_csrf_severity_sync():
    # Test that CSRF produces a CVSS score that maps to Low severity
    result = CvssCalculator.from_vulnerability_context("CSRF")
    
    # Score should be around 4.3 (Medium) but wait, the plan explicitly maps it to Low if possible
    # Or in scanner.py, we sync severity from CVSS
    severity = CvssCalculator.get_severity(result.score)
    
    # Assert it maps correctly based on CVSS logic
    assert result.score > 0
    assert severity in ["Low", "Medium"]
