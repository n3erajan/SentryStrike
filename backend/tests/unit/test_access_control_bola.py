"""Task 7 — cross-identity BOLA/IDOR + path-id extraction."""

import json

import httpx
import pytest

from app.core.crawler.auth_manager import SmartAuthenticator
from app.core.detectors.access_control import (
    AccessControlDetector,
    _looks_like_path_id_segment,
)
from app.core.verification.response_analyzer import ResponseData
from app.core.verification.verification_framework import HttpVerifier


# ---------------------------------------------------------------------------
# Path-id extraction
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "segment, expected",
    [
        ("1", True),
        ("42", True),
        ("550e8400-e29b-41d4-a716-446655440000", True),  # UUID
        ("507f1f77bcf86cd799439011", True),  # Mongo ObjectId (24 hex)
        ("da39a3ee5e6b4b0d3255bfef95601890afd80709", True),  # SHA-1 (40 hex)
        ("user_42abcd12", True),  # opaque token with digits
        ("basket", False),  # route word
        ("changelog", False),
        ("about", False),
        ("", False),
    ],
)
def test_looks_like_path_id_segment(segment, expected):
    assert _looks_like_path_id_segment(segment) is expected


def test_concrete_path_idor_targets_extracts_int_uuid_hex():
    detector = AccessControlDetector()
    urls = [
        "https://t.test/rest/basket/1",
        "https://t.test/api/users/550e8400-e29b-41d4-a716-446655440000",
        "https://t.test/api/orders/507f1f77bcf86cd799439011",
        "https://t.test/products/list",  # no id segment
    ]
    targets = detector._concrete_path_idor_targets(urls)
    values = {t.value for t in targets}
    assert "1" in values
    assert "550e8400-e29b-41d4-a716-446655440000" in values
    assert "507f1f77bcf86cd799439011" in values
    # A non-id route word must not be extracted.
    assert all(t.source == "path_segment" for t in targets)
    assert "list" not in values


# ---------------------------------------------------------------------------
# Cross-identity BOLA differential
# ---------------------------------------------------------------------------

_OBJECT_A = json.dumps({"id": 1, "userId": 42, "email": "victim@test", "items": ["a"]})


def _resp(status: int, body: str) -> ResponseData:
    return ResponseData(
        status,
        {"content-type": "application/json"},
        body,
        1.0,
        request_snippet="GET /rest/basket/1",
        response_snippet=f"HTTP/1.1 {status}",
    )


async def _detect_with_phase_map(monkeypatch, phase_map, default):
    detector = AccessControlDetector()

    async def send_request(self, url, method="GET", params=None, data=None, **kwargs):
        phase = kwargs.get("test_phase")
        status, body = phase_map.get(phase, default)
        return _resp(status, body)

    monkeypatch.setattr(HttpVerifier, "send_request", send_request)
    return await detector.detect(
        urls=["https://t.test/rest/basket/1"],
        forms=[],
        session_cookies={"session": "user-a"},
        second_user_cookies={"session": "user-b"},
        root_url="https://t.test/",
    )


@pytest.mark.asyncio
async def test_second_user_reads_owner_object_is_flagged(monkeypatch):
    # B receives the same object A owns; unauth is blocked -> BOLA.
    findings = await _detect_with_phase_map(
        monkeypatch,
        {
            "idor_unauth_own": (401, '{"error":"unauthorized"}'),
            "idor_authed_own": (200, _OBJECT_A),
            "idor_second_user_own": (200, _OBJECT_A),
        },
        default=(403, '{"error":"forbidden"}'),
    )
    idor = [f for f in findings if f.vuln_type == "Insecure Direct Object Reference (IDOR)"]
    assert idor, "expected a cross-identity IDOR finding"
    assert idor[0].detection_method == "second_user_idor"
    assert idor[0].verified is True


@pytest.mark.asyncio
async def test_public_resource_is_not_flagged(monkeypatch):
    # Unauthenticated access already returns the object -> public, no finding.
    findings = await _detect_with_phase_map(
        monkeypatch,
        {
            "idor_unauth_own": (200, _OBJECT_A),
            "idor_authed_own": (200, _OBJECT_A),
            "idor_second_user_own": (200, _OBJECT_A),
        },
        default=(403, '{"error":"forbidden"}'),
    )
    assert [f for f in findings if "IDOR" in f.vuln_type] == []


@pytest.mark.asyncio
async def test_second_user_blocked_yields_no_finding(monkeypatch):
    # B cannot read A's object -> proper authorization, no finding.
    findings = await _detect_with_phase_map(
        monkeypatch,
        {
            "idor_unauth_own": (401, '{"error":"unauthorized"}'),
            "idor_authed_own": (200, _OBJECT_A),
            "idor_second_user_own": (403, '{"error":"forbidden"}'),
        },
        default=(403, '{"error":"forbidden"}'),
    )
    assert [f for f in findings if "IDOR" in f.vuln_type] == []


# ---------------------------------------------------------------------------
# Secondary identity provisioning
# ---------------------------------------------------------------------------


class _MockSettings:
    authentication_cookie = None
    authentication_username = None
    authentication_password = None
    authentication_failure_text = None
    authentication_failure_regex = None
    authentication_success_text = None
    authentication_success_regex = None
    authentication_success_url = None
    authentication_validation_url = None
    authentication_login_url = None


class _FakeAuthClient:
    """Minimal httpx-like client for the register→session flow."""

    def __init__(self, register_status: int) -> None:
        self.register_status = register_status
        self.cookies = httpx.Cookies()
        self.headers: dict[str, str] = {}
        self.posted: list[str] = []

    async def get(self, url, follow_redirects=False):
        return httpx.Response(
            200,
            headers={"content-type": "text/html"},
            text="<html><body>home, no forms here</body></html>",
            request=httpx.Request("GET", url),
        )

    async def post(self, url, json=None, headers=None, data=None, follow_redirects=False):
        self.posted.append(url)
        if self.register_status in (200, 201):
            self.cookies.set("session", "secondary-sess", domain="t.test")
        return httpx.Response(self.register_status, json={}, request=httpx.Request("POST", url))


@pytest.mark.asyncio
async def test_acquire_secondary_identity_registers_and_authenticates():
    auth = SmartAuthenticator(_MockSettings())
    client = _FakeAuthClient(register_status=201)

    result = await auth.acquire_secondary_identity(client, "https://t.test/")

    assert result is not None
    assert result.authenticated is True
    assert result.cookies.get("session") == "secondary-sess"
    assert client.posted, "registration endpoints should have been probed"


@pytest.mark.asyncio
async def test_acquire_secondary_identity_returns_none_when_registration_impossible():
    auth = SmartAuthenticator(_MockSettings())
    client = _FakeAuthClient(register_status=404)

    result = await auth.acquire_secondary_identity(client, "https://t.test/")

    assert result is None
