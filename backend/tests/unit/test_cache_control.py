import pytest

from app.core.detectors.security_headers import SecurityHeadersDetector

def test_cache_control_sensitive():
    detector = SecurityHeadersDetector()
    
    # "no-store" present -> False (not vulnerable)
    assert detector._cache_controls_sensitive("no-store, no-cache", "", "") == False
    
    # "no-cache, must-revalidate" present -> False (not vulnerable)
    assert detector._cache_controls_sensitive("no-cache, must-revalidate", "", "") == False
    
    # "private" -> False
    assert detector._cache_controls_sensitive("private", "", "") == False
    
    # Missing hardening -> True (vulnerable)
    assert detector._cache_controls_sensitive("public, max-age=3600", "", "") == True
