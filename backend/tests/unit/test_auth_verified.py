import pytest
from types import SimpleNamespace
from app.config import get_settings
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


@pytest.mark.asyncio
async def test_verified_mode_suppresses_passive_url_only_auth_hints():
    settings = get_settings()
    original_mode = settings.scan_mode
    settings.scan_mode = "verified"

    try:
        detector = AuthenticationFailuresDetector()
        findings = await detector.detect(
            urls=[
                "http://example.test/login",
                "http://example.test/forgot-password",
                "http://example.test/change-password",
            ],
            forms=[],
        )
    finally:
        settings.scan_mode = original_mode

    vuln_types = {finding.vuln_type for finding in findings}
    assert "Authentication Endpoint Served Over Plaintext HTTP" not in vuln_types
    assert "Password Reset Endpoint Without Token Parameter" not in vuln_types


@pytest.mark.asyncio
async def test_heuristic_mode_keeps_passive_url_only_auth_hints():
    settings = get_settings()
    original_mode = settings.scan_mode
    settings.scan_mode = "heuristic"

    try:
        detector = AuthenticationFailuresDetector()
        findings = await detector.detect(
            urls=[
                "http://example.test/login",
                "http://example.test/forgot-password",
            ],
            forms=[],
        )
    finally:
        settings.scan_mode = original_mode

    vuln_types = {finding.vuln_type for finding in findings}
    assert "Authentication Endpoint Served Over Plaintext HTTP" in vuln_types
    assert "Password Reset Endpoint Without Token Parameter" in vuln_types


@pytest.mark.asyncio
async def test_verified_mode_still_emits_observable_admin_path_findings():
    settings = get_settings()
    original_mode = settings.scan_mode
    settings.scan_mode = "verified"

    try:
        detector = AuthenticationFailuresDetector()
        findings = await detector.detect(
            urls=[
                "http://example.test/administration",
                "http://example.test/.env",
            ],
            forms=[],
        )
    finally:
        settings.scan_mode = original_mode

    vuln_types = {finding.vuln_type for finding in findings}
    assert "Admin / Privileged Endpoint Discovered" in vuln_types
    assert "Well-Known Admin / Sensitive Path Discovered" in vuln_types
    assert "Authentication Endpoint Served Over Plaintext HTTP" not in vuln_types
