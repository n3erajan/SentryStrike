import pytest

from app import reverification
from app.core.detectors.base_detector import Finding
from app.core.detectors.security_headers import SecurityHeadersDetector
from app.core.verification.verification_framework import VerificationResult
from app.reverification_strategies import ResolvedSessions
from app.reverification_strategies import injection as injection_strategies
from app.reverification_strategies.common import finding_matches
from app.reverification_strategies.injection import _VerifierStrategy, _XSSStrategy
from app.reverification_strategies.passive import _DetectStrategy
from shared.models.reverification import ReverificationOutcome
from shared.models.vulnerability import AuthContext, OwaspCategory, SeverityLevel, VerificationTarget
from shared.reverification.policy import ReverifyFamily


def _sessions(*, main_usable: bool = False) -> ResolvedSessions:
    return ResolvedSessions(
        main_cookies={},
        main_headers={},
        second_cookies={},
        second_headers={},
        admin_cookies={},
        admin_headers={},
        main_usable=main_usable,
    )


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


def test_finding_match_treats_redirect_slash_and_query_as_same_resource() -> None:
    finding = Finding(
        category=OwaspCategory.a02,
        vuln_type="Exposed API Documentation",
        severity=SeverityLevel.medium,
        url="https://target.example/api-docs",
    )

    assert finding_matches(
        finding,
        url="https://TARGET.example:443/api-docs/?source=crawler#section",
        vuln_type="Exposed API Documentation",
        parameter=None,
    )


@pytest.mark.asyncio
async def test_sensitive_path_reverification_replays_exact_url_from_site_origin() -> None:
    captured: dict[str, object] = {}

    class ExactPathDetector:
        async def detect(self, urls, forms, **kwargs):
            _ = self, forms
            captured.update(kwargs)
            return [
                Finding(
                    category=OwaspCategory.a02,
                    vuln_type="Exposed API Documentation",
                    severity=SeverityLevel.medium,
                    url=urls[0],
                    verified=True,
                )
            ]

    strategy = _DetectStrategy(ReverifyFamily.sensitive_paths, ExactPathDetector)
    target = VerificationTarget(
        detector_id="sensitive_paths",
        url="https://target.example/custom/internal/api-docs/",
        vuln_type="Exposed API Documentation",
    )

    outcome, _ = await strategy.run(
        target,
        sessions=_sessions(),
        auth_accounts=[],
        vuln_type=target.vuln_type,
    )

    assert outcome == ReverificationOutcome.reproduced
    assert captured["root_url"] == "https://target.example/"
    assert captured["focused_probe_urls"] == [target.url]


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


@pytest.mark.asyncio
async def test_dom_xss_reverification_uses_browser_surface_probe(monkeypatch) -> None:
    captured: dict[str, object] = {}

    class FakeHttp:
        async def configure_auth(self, **kwargs):
            captured["auth"] = kwargs

    class FakeXSSVerifier:
        def __init__(self):
            self.http_verifier = FakeHttp()

        async def verify_reflected_dom(self, url, parameter, location):
            captured.update(url=url, parameter=parameter, location=location)
            return {
                "fired": True,
                "surface": "hash_route_query",
                "url": f"{url}?{parameter}=payload",
            }

        async def close(self):
            captured["closed"] = True

    monkeypatch.setattr(injection_strategies, "PLAYWRIGHT_AVAILABLE", True)
    monkeypatch.setattr(injection_strategies, "XSSVerifier", FakeXSSVerifier)
    target = VerificationTarget(
        detector_id="xss",
        url="https://target.example/#/search",
        method="GET",
        parameter="q",
        parameter_location="query",
        proof_type="dom_xss_browser_execution",
        vuln_type="DOM-Based XSS",
    )

    outcome, evidence = await _XSSStrategy().run(
        target,
        sessions=_sessions(main_usable=True),
        auth_accounts=[],
        vuln_type=target.vuln_type,
    )

    assert outcome == ReverificationOutcome.reproduced
    assert evidence[0].proof_matched is True
    assert captured["parameter"] == "q"
    assert captured["closed"] is True


@pytest.mark.asyncio
async def test_xss_reverification_runs_deferred_browser_confirmation(monkeypatch) -> None:
    pending_job = object()

    class FakeHttp:
        async def configure_auth(self, **kwargs):
            _ = kwargs

    class BrowserFinding:
        verification_response_snippet = None
        evidence = "execution canary fired"

    class FakeXSSVerifier:
        def __init__(self):
            self.http_verifier = FakeHttp()

        async def verify(self, **kwargs):
            _ = kwargs
            return VerificationResult(
                is_vulnerable=False,
                confidence_score=75.0,
                detection_method="browser_pending",
                evidence={"pending_jobs": [pending_job]},
            )

        async def run_browser_verification(self, job):
            assert job is pending_job
            return [BrowserFinding()]

        async def close(self):
            return None

    monkeypatch.setattr(injection_strategies, "PLAYWRIGHT_AVAILABLE", True)
    monkeypatch.setattr(injection_strategies, "XSSVerifier", FakeXSSVerifier)
    target = VerificationTarget(
        detector_id="xss",
        url="https://target.example/search",
        method="GET",
        parameter="q",
        parameter_location="query",
        proof_type="reflected_xss",
        vuln_type="Reflected XSS",
    )

    outcome, evidence = await _XSSStrategy().run(
        target,
        sessions=_sessions(main_usable=True),
        auth_accounts=[],
        vuln_type=target.vuln_type,
    )

    assert outcome == ReverificationOutcome.reproduced
    assert evidence[0].response_snippet == "execution canary fired"


@pytest.mark.asyncio
async def test_xss_browser_runtime_failure_is_inconclusive(monkeypatch) -> None:
    class FakeHttp:
        async def configure_auth(self, **kwargs):
            _ = kwargs

    class FakeXSSVerifier:
        def __init__(self):
            self.http_verifier = FakeHttp()
            self._last_browser_verification_error = None

        async def verify(self, **kwargs):
            _ = kwargs
            return VerificationResult(
                is_vulnerable=False,
                confidence_score=75.0,
                detection_method="browser_pending",
                evidence={"pending_jobs": [object()]},
            )

        async def run_browser_verification(self, job):
            _ = job
            self._last_browser_verification_error = RuntimeError("browser missing")
            return []

        async def close(self):
            return None

    monkeypatch.setattr(injection_strategies, "PLAYWRIGHT_AVAILABLE", True)
    monkeypatch.setattr(injection_strategies, "XSSVerifier", FakeXSSVerifier)
    target = VerificationTarget(
        detector_id="xss",
        url="https://target.example/search",
        parameter="q",
        proof_type="reflected_xss",
        vuln_type="Reflected XSS",
    )

    outcome, evidence = await _XSSStrategy().run(
        target,
        sessions=_sessions(main_usable=True),
        auth_accounts=[],
        vuln_type=target.vuln_type,
    )

    assert outcome == ReverificationOutcome.inconclusive
    assert "browser missing" in evidence[0].reason
