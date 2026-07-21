"""Invite service helpers and token-gated registration route behavior.

The DB-touching methods (create/accept) are exercised at the route layer with a
fake InviteService, matching the house style (no live Mongo in unit tests). The
pure helpers — token hashing and link building — are tested directly.
"""

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.dependencies import get_auth_service, get_invite_service
from app.api.routes import auth
from app.config import get_settings
from app.core.invites import (
    InvalidInviteError,
    InviteEmailMismatchError,
    build_invite_link,
    hash_invite_token,
)
from shared.config import get_infrastructure_settings


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------


def test_hash_invite_token_is_deterministic_and_hides_raw_token() -> None:
    digest = hash_invite_token("super-secret-token")

    assert digest == hash_invite_token("super-secret-token")
    assert hash_invite_token("other") != digest
    assert "super-secret-token" not in digest
    assert len(digest) == 64  # sha256 hex


def test_build_invite_link_uses_public_hostname(monkeypatch) -> None:
    monkeypatch.setenv("PUBLIC_HOSTNAME", "sentry.example.com")
    monkeypatch.setenv("INVITE_SIGNUP_PATH", "/signup")
    get_infrastructure_settings.cache_clear()
    get_settings.cache_clear()
    try:
        link = build_invite_link("abc123")
        assert link == "http://sentry.example.com/signup?invite=abc123"
    finally:
        get_infrastructure_settings.cache_clear()
        get_settings.cache_clear()


def test_build_invite_link_preserves_explicit_scheme(monkeypatch) -> None:
    monkeypatch.setenv("PUBLIC_HOSTNAME", "https://mypage.com")
    get_infrastructure_settings.cache_clear()
    get_settings.cache_clear()
    try:
        link = build_invite_link("tok")
        assert link == "https://mypage.com/signup?invite=tok"
    finally:
        get_infrastructure_settings.cache_clear()
        get_settings.cache_clear()


def test_build_invite_link_returns_none_without_hostname(monkeypatch) -> None:
    monkeypatch.setenv("PUBLIC_HOSTNAME", "")
    get_infrastructure_settings.cache_clear()
    try:
        assert build_invite_link("tok") is None
    finally:
        get_infrastructure_settings.cache_clear()


# ---------------------------------------------------------------------------
# Route-level: preview + token-gated registration
# ---------------------------------------------------------------------------


class FakeInviteService:
    """Stand-in for InviteService with in-memory, DB-free behavior."""

    def __init__(self) -> None:
        self.accepted: dict | None = None
        self.pending = SimpleNamespace(
            email="invitee@example.test",
            role=SimpleNamespace(value="developer"),
            org_name=None,
        )

    async def preview(self, token):
        if token != "good-token":
            raise InvalidInviteError()
        return self.pending

    async def accept(self, *, token, email, password):
        if token != "good-token":
            raise InvalidInviteError()
        if email != self.pending.email:
            raise InviteEmailMismatchError()
        self.accepted = {"token": token, "email": email, "password": password}
        return SimpleNamespace(
            id="user-9",
            email=email,
            org_id="org-1",
            role=SimpleNamespace(value="developer"),
            created_at=datetime(2026, 6, 8, 9, 10, 17, tzinfo=timezone.utc),
        )


class FakeAuthService:
    def __init__(self) -> None:
        now = datetime.now(timezone.utc)
        self.session = SimpleNamespace(created_at=now, expires_at=now + timedelta(hours=24))

    async def create_session(self, user):
        _ = user
        return "session-token", self.session


def _client(invites: FakeInviteService) -> TestClient:
    app = FastAPI()
    app.include_router(auth.router, prefix="/api/v1")
    app.dependency_overrides[get_invite_service] = lambda: invites
    app.dependency_overrides[get_auth_service] = lambda: FakeAuthService()
    return TestClient(app)


def test_preview_invite_returns_pinned_email_and_role() -> None:
    client = _client(FakeInviteService())

    response = client.get("/api/v1/auth/invite", params={"token": "good-token"})

    assert response.status_code == 200
    data = response.json()["data"]
    assert data["email"] == "invitee@example.test"
    assert data["role"] == "developer"


def test_preview_invalid_invite_returns_400() -> None:
    client = _client(FakeInviteService())

    response = client.get("/api/v1/auth/invite", params={"token": "nope"})

    assert response.status_code == 400


def test_register_consumes_invite_and_issues_session() -> None:
    invites = FakeInviteService()
    client = _client(invites)

    response = client.post(
        "/api/v1/auth/register",
        json={
            "invite_token": "good-token",
            "email": "invitee@example.test",
            "password": "password123",
        },
    )

    assert response.status_code == 201
    body = response.json()["data"]
    assert body["access_token"] == "session-token"
    assert body["user"]["email"] == "invitee@example.test"
    assert body["user"]["role"] == "developer"
    assert body["user"]["org_id"] == "org-1"
    assert invites.accepted["token"] == "good-token"
    assert "sentrystrike_session=session-token" in response.headers["set-cookie"]


def test_register_rejects_email_not_matching_invite() -> None:
    client = _client(FakeInviteService())

    response = client.post(
        "/api/v1/auth/register",
        json={
            "invite_token": "good-token",
            "email": "someone-else@example.test",
            "password": "password123",
        },
    )

    assert response.status_code == 400


def test_register_requires_invite_token() -> None:
    client = _client(FakeInviteService())

    response = client.post(
        "/api/v1/auth/register",
        json={"email": "invitee@example.test", "password": "password123"},
    )

    # Missing invite_token fails schema validation before any service call.
    assert response.status_code == 422
