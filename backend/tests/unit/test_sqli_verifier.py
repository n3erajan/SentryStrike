import pytest

from app.core.detectors.sql_injection import SQLInjectionDetector
from app.core.verification.sqli_verifier import SQLiVerifier
from app.core.detectors.base_detector import Finding

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
    params = [c[1] for c in candidates if c[1]]
    assert "username" in params
    assert "loginBtn" not in params
    assert "resetBtn" not in params
    assert "imageBtn" not in params

from app.core.verification.response_analyzer import ResponseData

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
    verifier._baseline_value = "1"

    url, _, _ = verifier._build_request_args(
        "http://example.com/sqli?id=1",
        "id",
        "' AND '1'='1",
        "GET",
        None,
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
