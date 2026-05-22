import pytest
from app.core.detectors.auth_detector import AuthenticationFailuresDetector

def test_auth_bruteforce_verified():
    detector = AuthenticationFailuresDetector()
    
    # Test that the _finding method sets verified=True
    finding = detector._finding(
        vuln_type="Lack of Brute-Force Protection on Login Form",
        url="http://example.com/login",
        severity="High",
        evidence="Sent 5 rapid attempts",
        verified=True
    )
    
    assert finding.verified is True
