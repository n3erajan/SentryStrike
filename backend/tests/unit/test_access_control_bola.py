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


# ---------------------------------------------------------------------------
# Mutating-method authorization (universal, non-destructive)
# ---------------------------------------------------------------------------

from app.core.detectors.access_control import _MUTATING_AUTHZ_METHODS  # noqa: E402
from app.core.detectors.attack_surface import AttackTarget, PreparedAttackRequest  # noqa: E402
from app.core.crawler.models import ParameterLocation, RequestObservation  # noqa: E402


def test_synthetic_nonexistent_id_matches_shape():
    d = AccessControlDetector()
    assert d._synthetic_nonexistent_id("10").isdigit()
    assert d._synthetic_nonexistent_id("10") != "10"
    # UUID in -> valid-shaped UUID out, but a different (never-assigned) value.
    uuid_out = d._synthetic_nonexistent_id("550e8400-e29b-41d4-a716-446655440000")
    assert _looks_like_path_id_segment(uuid_out) and uuid_out.startswith("ffffffff")


def test_request_with_synthetic_id_rewrites_only_id_segment():
    d = AccessControlDetector()
    req = PreparedAttackRequest(url="https://t.test/api/Cards/10", method="DELETE")
    synth = d._request_with_synthetic_id(req)
    assert synth is not None
    assert "/api/Cards/" in synth.url and "/10" not in synth.url
    assert synth.method == "DELETE"
    # An id-less path cannot be rewritten -> None (never fired in safe mode).
    assert d._request_with_synthetic_id(
        PreparedAttackRequest(url="https://t.test/account", method="DELETE")
    ) is None


def test_build_mutating_authz_targets_selects_id_bearing_mutations_only():
    d = AccessControlDetector()
    requests = [
        RequestObservation(url="https://t.test/api/Cards/10", method="DELETE"),
        RequestObservation(url="https://t.test/api/Addresss/7", method="PUT"),
        RequestObservation(url="https://t.test/account", method="DELETE"),  # id-less -> skip
        RequestObservation(url="https://t.test/api/Cards", method="POST"),  # collection -> skip
        RequestObservation(url="https://t.test/api/Cards/10", method="GET"),  # read -> skip
    ]
    pairs = d._build_mutating_authz_targets(requests=requests)
    urls = {p[0].url for p in pairs}
    methods = {p[0].method for p in pairs}
    assert methods == {"DELETE", "PUT"}
    assert all("/10" not in u and "/7" not in u for u in urls)  # ids synthesised away
    # The observed request had a concrete id, so a real-id request is retained for
    # opt-in destructive confirmation.
    assert all(p[1] is not None for p in pairs)


class _V:
    """Minimal HttpVerifier double keyed by ``test_phase``."""

    def __init__(self, by_phase=None, default=(404, "")):
        self.by_phase = by_phase or {}
        self.default = default
        self.calls = []

    async def send_request(self, url, method="GET", params=None, data=None, *,
                           headers=None, cookies=None, json_body=None,
                           test_phase="", parameter=""):
        self.calls.append((method, url, test_phase))
        status, body = self.by_phase.get(test_phase, self.default)
        return _resp(status, body)


@pytest.mark.asyncio
async def test_missing_auth_on_mutating_endpoint_is_flagged():
    d = AccessControlDetector()
    synth = PreparedAttackRequest(url="https://t.test/api/Cards/988000762197", method="DELETE")
    owner = _V(default=(404, ""))   # authed owner reached business logic (not 401/403)
    unauth = _V(default=(404, ""))  # unauth treated identically -> no auth gate
    findings = await d._verify_mutating_authz(synth, None, unauth, owner, None)
    assert findings, "expected a missing-authorization finding"
    f = findings[0]
    assert f.vuln_type == "Missing Authorization on State-Changing Request"
    assert f.severity.name == "high"
    assert f.detection_method == "mutating_authz_differential"


@pytest.mark.asyncio
async def test_protected_mutating_endpoint_yields_no_finding():
    d = AccessControlDetector()
    synth = PreparedAttackRequest(url="https://t.test/api/Cards/988000762197", method="DELETE")
    owner = _V(default=(404, ""))
    unauth = _V(default=(401, '{"error":"unauthorized"}'))  # properly rejected
    findings = await d._verify_mutating_authz(synth, None, unauth, owner, None)
    assert findings == []


@pytest.mark.asyncio
async def test_owner_denied_short_circuits_without_probing_unauth():
    d = AccessControlDetector()
    synth = PreparedAttackRequest(url="https://t.test/api/Cards/988000762197", method="DELETE")
    owner = _V(default=(401, ""))   # even the owner is denied -> inconclusive
    unauth = _V(default=(200, ""))
    findings = await d._verify_mutating_authz(synth, None, unauth, owner, None)
    assert findings == []
    assert unauth.calls == [], "unauth must not be probed once the owner is denied"


@pytest.mark.asyncio
async def test_ambiguous_status_difference_is_not_flagged():
    d = AccessControlDetector()
    synth = PreparedAttackRequest(url="https://t.test/api/Cards/988000762197", method="DELETE")
    owner = _V(default=(204, ""))
    unauth = _V(default=(400, ""))  # different handling -> ambiguous, no finding
    findings = await d._verify_mutating_authz(synth, None, unauth, owner, None)
    assert findings == []


@pytest.mark.asyncio
async def test_destructive_confirmation_upgrades_to_critical():
    d = AccessControlDetector()
    synth = PreparedAttackRequest(url="https://t.test/api/Cards/988000762197", method="DELETE")
    real = PreparedAttackRequest(url="https://t.test/api/Cards/10", method="DELETE")
    owner = _V(default=(404, ""))
    # synth unauth -> 404 (base signal); real-id unauth DELETE -> 204 (actual delete)
    unauth = _V(by_phase={
        "mutating_authz_unauth": (404, ""),
        "mutating_authz_confirm_unauth": (204, ""),
    }, default=(404, ""))
    findings = await d._verify_mutating_authz(synth, real, unauth, owner, None)
    assert findings and findings[0].severity.name == "critical"
    assert findings[0].detection_evidence["destructive_confirmed"] is True


@pytest.mark.asyncio
async def test_idor_baseline_never_fires_destructive_method():
    """The read-oriented IDOR baseline must NOT fire a PUT/PATCH/DELETE on the
    owner's real value (data-loss guard). It returns immediately without probing."""
    d = AccessControlDetector()
    target = AttackTarget(
        url="https://t.test/api/Cards/10",
        parameter="id",
        method="DELETE",
        value="10",
        location=ParameterLocation.path,
        source="api_path_template",
    )
    probe = _V(default=(200, ""))
    findings = await d._verify_idor_baseline(target, "10", probe, probe, None, None)
    assert findings == []
    assert probe.calls == [], "no request may be sent for a destructive IDOR target"


# ---------------------------------------------------------------------------
# Framework-agnostic false-positive guards (unauthenticated data exposure)
# ---------------------------------------------------------------------------
from app.core.detectors.access_control import _MatrixTarget, _ResponseProfile  # noqa: E402
from app.core.detectors.attack_surface import PreparedAttackRequest as _PAR  # noqa: E402


def _profile(sensitive=frozenset(), identifiers=frozenset(), item_count=0):
    return _ResponseProfile(
        status_code=200,
        content_type="application/json",
        success=True,
        is_json=True,
        json_shape=frozenset({"version"}),
        identifiers=identifiers,
        sensitive_fields=sensitive,
        item_count=item_count,
        body_length=32,
    )


def test_admin_like_url_alone_is_not_data_exposure():
    """An /admin/* URL returning a bare public value (no sensitive fields, no
    identifiers, no records) is NOT a data leak — the URL substring is not
    evidence. Prevents e.g. {"version":"x"} on /rest/admin/* being flagged."""
    det = AccessControlDetector()
    req = _PAR(url="http://t/rest/admin/application-version", method="GET")
    target = _MatrixTarget(request=req, source="browser_request", admin_like=True)
    empty = _profile()  # no sensitive fields, no ids, no records
    assert det._profile_exposes_nonpublic_data(target, empty) is False
    # Real sensitive data on the same admin URL still qualifies.
    assert det._profile_exposes_nonpublic_data(
        target, _profile(sensitive=frozenset({"password"}))
    ) is True
    # A record collection or stable identifiers also qualify.
    assert det._profile_exposes_nonpublic_data(target, _profile(item_count=5)) is True
    assert det._profile_exposes_nonpublic_data(
        target, _profile(identifiers=frozenset({"id=1"}))
    ) is True


def test_credential_bearing_request_is_recognised_as_auth_endpoint():
    """A request whose body carries a password-like field authenticates via the
    body, so a 200 under the unauth verifier is expected — not exposure. Keyed on
    the body shape, not any specific /login path."""
    det = AccessControlDetector()
    login = _PAR(
        url="http://t/rest/user/login",
        method="POST",
        json_body={"email": "a@b.co", "password": "secret"},
    )
    assert det._request_carries_credentials(login) is True

    nested = _PAR(url="http://t/x", method="POST", json_body={"user": {"pwd": "z"}})
    assert det._request_carries_credentials(nested) is True

    plain = _PAR(url="http://t/api/products", method="POST", json_body={"name": "x"})
    assert det._request_carries_credentials(plain) is False

    form = _PAR(url="http://t/x", method="POST", data={"credential": "z"})
    assert det._request_carries_credentials(form) is True
