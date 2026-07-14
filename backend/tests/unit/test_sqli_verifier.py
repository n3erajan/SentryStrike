import pytest

from app.core.detectors.sql_injection import SQLInjectionDetector
from app.core.verification.sqli_verifier import SQLiVerifier
from app.core.verification.verification_framework import VerificationResult

def test_sqli_detector_excludes_submit_button():
    detector = SQLInjectionDetector()
    
    class FakeInput:
        def __init__(self, name, type):
            self.name = name
            self.input_type = type
    
    class FakeForm:
        def __init__(self):
            self.method = "POST"
            self.action = "http://example.com/login"
            self.inputs = [
                FakeInput("username", "text"),
                FakeInput("loginBtn", "submit"),
                FakeInput("resetBtn", "reset"),
                FakeInput("imageBtn", "image"),
            ]
            
    # Mock extract_candidates
    candidates = detector._extract_candidates(["http://example.com"], [FakeForm()])
    
    # We should only get candidates for "username", not the buttons
    params = [candidate.parameter for candidate in candidates if candidate.parameter]
    assert "username" in params
    assert "loginBtn" not in params
    assert "resetBtn" not in params
    assert "imageBtn" not in params

from app.core.verification.response_analyzer import ResponseData


@pytest.mark.asyncio
async def test_sqli_detector_configures_verifier_with_auth_headers(monkeypatch):
    detector = SQLInjectionDetector()
    observed: list[tuple[dict, dict]] = []

    async def verify(self, *args, **kwargs):
        observed.append((dict(self.http_verifier.headers), dict(self.http_verifier.cookies)))
        return VerificationResult(False, 0.0, "none")

    monkeypatch.setattr(SQLiVerifier, "verify", verify)

    await detector.detect(
        urls=["https://example.test/api/products?id=1"],
        forms=[],
        session_cookies={"sid": "abc"},
        auth_headers={"Authorization": "Bearer token"},
    )

    assert observed
    headers, cookies = observed[0]
    assert headers["User-Agent"] == "SentryStrikeScanner/1.0"
    assert headers["Authorization"] == "Bearer token"
    assert cookies == {"sid": "abc"}

@pytest.mark.asyncio
async def test_sqli_verifier_union_requires_version_proof():
    verifier = SQLiVerifier()
    
    # Mock _send to simulate responses with no canary and very high similarity (> 0.85)
    async def mock_send(url, method, params=None, data=None, **kwargs):
        body = "Some normal response" * 50
        if kwargs.get("test_phase") == "union_injection":
            # Change length slightly to make it "significant" (>50 diff) but keep similarity > 0.85
            body = ("Some normal response" * 50) + "A" * 55
        return ResponseData(
            status_code=200,
            headers={},
            body=body,
            response_time_ms=10.0,
            request_snippet="",
            response_snippet="",
        )
        
    verifier._send = mock_send
    
    result = await verifier._verify_union_based(
        url="http://example.com",
        parameter="id",
        method="GET",
        value="1",
    )
    
    # Since similarity > 0.85 and no canary was found, it should not be verified or is_vulnerable
    assert not result.is_vulnerable or not any(f.verified for f in result.findings)


@pytest.mark.asyncio
async def test_sqli_verifier_suppresses_null_differential_without_extraction_proof():
    verifier = SQLiVerifier()
    baseline = ResponseData(
        status_code=200,
        headers={},
        body="A" * 1000,
        response_time_ms=10.0,
        request_snippet="",
        response_snippet="",
    )

    async def mock_send(url, method, params=None, data=None, **kwargs):
        phase = kwargs.get("test_phase")
        if phase == "union_canary":
            body = baseline.body
        elif phase in {"union_null", "union_cross_column_confirm"}:
            body = ("A" * 850) + ("B" * 150)
        elif phase == "union_version_extract":
            body = ("A" * 850) + ("C" * 150)
        else:
            body = baseline.body
        return ResponseData(
            status_code=200,
            headers={},
            body=body,
            response_time_ms=10.0,
            request_snippet="",
            response_snippet="",
        )

    verifier._send = mock_send

    result = await verifier._verify_union_based(
        url="http://example.com/search?q=1",
        parameter="q",
        method="GET",
        value="1",
        pre_test_baseline=baseline,
    )

    assert result.is_vulnerable is False
    assert result.findings == []
    assert result.evidence["reason"] == "null_differential_without_extraction_proof"

@pytest.mark.asyncio
async def test_sqli_verifier_boolean_requires_confirmation():
    verifier = SQLiVerifier()
    
    async def mock_send(url, method, params=None, data=None, **kwargs):
        phase = kwargs.get("test_phase")
        if phase == "pre_test_baseline":
            body = "base response"
            status = 200
        elif phase == "boolean_true":
            body = "base response"
            status = 200
        elif phase == "boolean_false":
            body = "different response"
            status = 200
        elif phase == "boolean_confirm_true":
            # Confirmation fails: true response is different (doesn't match baseline/true response)
            body = "different response"
            status = 200
        elif phase == "boolean_confirm_false":
            body = "different response"
            status = 200
        else:
            body = "base response"
            status = 200
            
        return ResponseData(
            status_code=status,
            headers={},
            body=body,
            response_time_ms=10.0,
            request_snippet="",
            response_snippet="",
        )
        
    verifier._send = mock_send
    
    result = await verifier._verify_boolean_based(
        url="http://example.com",
        parameter="id",
        method="GET",
        value="1",
    )
    
    # Since confirmation true/false matched but the second pair confirmation failed, it should not be vulnerable
    assert not result.is_vulnerable


def test_sqli_verifier_prepends_baseline_to_payload():
    verifier = SQLiVerifier()

    url, _, _, _, _ = verifier._build_request_args(
        "http://example.com/sqli?id=1",
        "id",
        "' AND '1'='1",
        "GET",
        None,
        baseline_value="1",
    )

    assert "id=1%27+AND+%271%27%3D%271" in url or "id=1' AND '1'='1" in url


def test_sqli_verifier_resolves_value_from_url():
    verifier = SQLiVerifier()
    resolved = verifier._resolve_baseline_value(
        "http://example.com/sqli?id=1&Submit=Submit",
        "id",
        "",
        None,
    )
    assert resolved == "1"


@pytest.mark.asyncio
async def test_sqli_verifier_aborts_on_dead_baseline():
    """A 401/404 baseline means the endpoint is unreachable as sent — the full
    payload matrix must NOT fire (that was ~55% of wasted SQLi traffic)."""
    verifier = SQLiVerifier()
    phases: list[str] = []

    async def mock_send(url, method="GET", params=None, data=None, **kwargs):
        phase = kwargs.get("test_phase")
        phases.append(phase)
        # Every request (baseline included) is a hard 401 auth wall.
        return ResponseData(
            status_code=401, headers={}, body="Unauthorized",
            response_time_ms=5.0, request_snippet="", response_snippet="",
        )

    verifier._send = mock_send

    result = await verifier.verify(
        url="http://example.com/api/Feedbacks/",
        parameter="UserId",
        method="POST",
        value="1",
    )

    assert result.is_vulnerable is False
    assert result.evidence.get("skipped") == "dead_baseline"
    assert result.evidence.get("baseline_status") == 401
    # Only the baseline probe ran; no injection phase was attempted.
    assert phases == ["pre_test_baseline"]
    assert not any(
        p and ("injection" in p or "boolean" in p or "union" in p or "time" in p)
        for p in phases
    )


@pytest.mark.asyncio
async def test_sqli_verifier_proceeds_on_healthy_baseline_status():
    """A healthy 200 baseline (login-style flow) must NOT be gated — injection
    phases still run so real login SQLi is preserved."""
    verifier = SQLiVerifier()
    phases: list[str] = []

    async def mock_send(url, method="GET", params=None, data=None, **kwargs):
        phase = kwargs.get("test_phase")
        phases.append(phase)
        return ResponseData(
            status_code=200, headers={}, body="ok" * 100,
            response_time_ms=5.0, request_snippet="", response_snippet="",
        )

    verifier._send = mock_send

    result = await verifier.verify(
        url="http://example.com/rest/user/login",
        parameter="email",
        method="POST",
        value="a@b.c",
    )

    # Not gated: the verifier moved past the baseline into real technique phases.
    assert result.evidence.get("skipped") != "dead_baseline"
    assert len(phases) > 1
