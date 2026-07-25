import pytest

from app import reverification
from app.core.detectors.base_detector import Finding
from app.core.detectors.security_headers import SecurityHeadersDetector
from app.core.verification.verification_framework import VerificationResult
from app.reverification_strategies import ResolvedSessions
from app.reverification_strategies.injection import _VerifierStrategy
from app.reverification_strategies.passive import _DetectStrategy
from shared.models.reverification import ReverificationOutcome
from shared.models.vulnerability import AuthContext, OwaspCategory, SeverityLevel, VerificationTarget
from shared.reverification.policy import ReverifyFamily


def test_exact_replay_preserves_captured_json_body() -> None:
    target = VerificationTarget(
        detector_id="access_control",
        url="https://target.example/api/profile",
        method="POST",
        parameter="userId",
        parameter_location="json_body",
        payload="2",
        request_template={
            "replay_exact": True,
            "json_body": {"userId": "2", "include": "summary"},
        },
    )

    url, kwargs = reverification._build_request(target, target.payload)

    assert url == target.url
    assert kwargs == {"json": {"userId": "2", "include": "summary"}}


@pytest.mark.asyncio
async def test_focused_reverification_uses_detector_strategy(monkeypatch) -> None:
    async def fake_run(self, target, *, sessions, auth_accounts, vuln_type=None):
        _ = self, sessions, auth_accounts
        assert target.parameter == "q"
        assert vuln_type == "Missing Security Header"
        return (ReverificationOutcome.reproduced, [])

    monkeypatch.setattr(_DetectStrategy, "run", fake_run)
    target = VerificationTarget(
        detector_id="security_headers",
        url="https://target.example/",
        method="GET",
        parameter="q",
        vuln_type="Missing Security Header",
        auth_context=AuthContext.unauthenticated,
    )

    outcome, _evidence = await reverification.run_focused_reverification(
        target, [], vuln_type="Missing Security Header"
    )

    assert outcome == ReverificationOutcome.reproduced


@pytest.mark.asyncio
async def test_security_headers_strategy_matches_detector_output(monkeypatch) -> None:
    async def fake_detect(self, urls, forms, **kwargs):
        _ = self, forms, kwargs
        return [
            Finding(
                category=OwaspCategory.a02,
                vuln_type="Missing Security Header",
                severity=SeverityLevel.medium,
                url=urls[0],
                evidence="Header not found: content-security-policy",
                verified=True,
            )
        ]

    monkeypatch.setattr(SecurityHeadersDetector, "detect", fake_detect)
    strategy = _DetectStrategy(ReverifyFamily.security_headers, SecurityHeadersDetector)
    target = VerificationTarget(
        detector_id="security_headers",
        url="https://target.example/",
        vuln_type="Missing Security Header",
    )
    sessions = ResolvedSessions(
        main_cookies={},
        main_headers={},
        second_cookies={},
        second_headers={},
        admin_cookies={},
        admin_headers={},
    )

    outcome, evidence = await strategy.run(
        target, sessions=sessions, auth_accounts=[], vuln_type="Missing Security Header"
    )

    assert outcome == ReverificationOutcome.reproduced
    assert evidence[0].proof_matched is True


@pytest.mark.asyncio
async def test_authenticated_target_without_credentials_is_inconclusive() -> None:
    target = VerificationTarget(
        detector_id="idor_detector",
        url="https://target.example/api/items/2",
        vuln_type="IDOR",
        auth_context=AuthContext.authenticated,
    )

    outcome, evidence = await reverification.run_focused_reverification(target, [])

    assert outcome == ReverificationOutcome.inconclusive
    assert "requires authentication" in evidence[0].reason.lower()


@pytest.mark.asyncio
async def test_injection_verifier_strategy_maps_result() -> None:
    class FakeHttp:
        async def configure_auth(self, **kwargs):
            _ = kwargs

    class FakeVerifier:
        def __init__(self):
            self.http_verifier = FakeHttp()

        async def verify(self, *args, **kwargs):
            _ = args, kwargs
            return VerificationResult(
                is_vulnerable=True,
                confidence_score=90.0,
                detection_method="boolean_differential",
                findings=[],
            )

        async def close(self):
            return None

    strategy = _VerifierStrategy(ReverifyFamily.sql_injection, FakeVerifier)
    target = VerificationTarget(
        detector_id="injection_sql_command",
        url="https://target.example/item",
        method="GET",
        parameter="id",
        parameter_location="query",
        vuln_type="SQL Injection",
    )
    sessions = ResolvedSessions(
        main_cookies={},
        main_headers={},
        second_cookies={},
        second_headers={},
        admin_cookies={},
        admin_headers={},
        main_usable=True,
    )

    outcome, evidence = await strategy.run(
        target, sessions=sessions, auth_accounts=[], vuln_type="SQL Injection"
    )

    assert outcome == ReverificationOutcome.reproduced
    assert "boolean_differential" in evidence[0].reason
