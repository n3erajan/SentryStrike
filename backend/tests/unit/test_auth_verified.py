import pytest
from types import SimpleNamespace
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


def test_sensitive_query_params_do_not_flag_non_secret_csrf_values():
    detector = AuthenticationFailuresDetector()

    leaked = detector._sensitive_query_params(
        [("id", "1"), ("user_token", "abc123"), ("step", "confirm")],
        "http://example.test/csrf/",
    )

    assert leaked == set()


def test_burst_stability_accepts_identical_fast_responses():
    detector = AuthenticationFailuresDetector()
    responses = [
        SimpleNamespace(status_code=200, body="Invalid login", response_time_ms=50.0)
        for _ in range(10)
    ]
    burst_results = [{"size": 10, "responses": responses, "mean_ms": 50.0, "stdev_ms": 0.0}]

    assert detector._burst_responses_stable(burst_results) is True
    assert detector._rate_limit_signals_present(responses) is False


def test_rate_limit_signal_suppresses_burst_finding():
    detector = AuthenticationFailuresDetector()
    responses = [
        SimpleNamespace(status_code=200, body="Invalid login", response_time_ms=50.0),
        SimpleNamespace(status_code=429, body="Too many requests", response_time_ms=55.0),
    ]

    assert detector._rate_limit_signals_present(responses) is True
