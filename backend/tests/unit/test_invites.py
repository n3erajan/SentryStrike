"""Invite service helpers and token-gated registration route behavior.

DB-touching paths use small ODM fakes so token rotation and uniqueness keys are
covered without requiring a live Mongo instance.
"""

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.dependencies import get_auth_service, get_invite_service
from app.api.routes import auth
from app.core import invites as invite_module
from app.core.invites import (
    InvalidInviteError,
    InviteEmailMismatchError,
    InviteService,
    build_invite_link,
    hash_invite_token,
)
from shared.config import get_infrastructure_settings
from shared.models.invite import InviteEmailStatus, InviteState
from shared.models.user import UserRole


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
    get_infrastructure_settings.cache_clear()
    try:
        link = build_invite_link("abc123")
        assert link == "http://sentry.example.com/register?invite=abc123"
    finally:
        get_infrastructure_settings.cache_clear()


def test_build_invite_link_preserves_explicit_scheme(monkeypatch) -> None:
    monkeypatch.setenv("PUBLIC_HOSTNAME", "https://mypage.com")
    get_infrastructure_settings.cache_clear()
    try:
        link = build_invite_link("tok")
        assert link == "https://mypage.com/register?invite=tok"
    finally:
        get_infrastructure_settings.cache_clear()


def test_build_invite_link_returns_none_without_hostname(monkeypatch) -> None:
    monkeypatch.setenv("PUBLIC_HOSTNAME", "")
    get_infrastructure_settings.cache_clear()
    try:
        assert build_invite_link("tok") is None
    finally:
        get_infrastructure_settings.cache_clear()


class _Field:
    def __eq__(self, other):
        _ = other
        return self


@pytest.mark.asyncio
async def test_owner_invites_use_email_specific_pending_key(monkeypatch) -> None:
    inserted = []

    class FakeUser:
        email = _Field()

        @classmethod
        async def find_one(cls, *args):
            _ = args
            return None

    class FakeInvite:
        def __init__(self, **kwargs):
            self.__dict__.update(kwargs)
            self.id = "invite-1"

        async def insert(self):
            inserted.append(self)

    monkeypatch.setattr(invite_module, "User", FakeUser)
    monkeypatch.setattr(invite_module, "Invite", FakeInvite)
    monkeypatch.setattr(
        invite_module,
        "get_settings",
        lambda: SimpleNamespace(invite_ttl_hours=168),
    )

    _, invite = await InviteService().create_invite(
        email="OWNER@Example.test",
        role=UserRole.owner,
        org_id=None,
        org_name="Acme",
        invited_by_user_id=None,
        member_limit=10,
    )

    assert inserted == [invite]
    assert invite.pending_key == "owner:owner@example.test"


@pytest.mark.asyncio
async def test_failed_pending_owner_invite_rotates_token_on_same_record(monkeypatch) -> None:
    pending = SimpleNamespace(
        id="invite-1",
        email="owner@example.test",
        role=UserRole.owner,
        state=InviteState.pending,
        expires_at=datetime(2030, 1, 1, tzinfo=timezone.utc),
        email_delivery_status=InviteEmailStatus.failed,
        email_delivery_backend="smtp",
        email_delivery_attempted_at=datetime(2026, 7, 21, tzinfo=timezone.utc),
        email_delivery_error="SMTPAuthenticationError",
        token_hash="old-token-hash",
        pending_key=None,
        org_name="Old name",
        member_limit=10,
    )
    updates = []

    class Collection:
        async def update_one(self, query, update):
            updates.append((query, update))
            return SimpleNamespace(modified_count=1)

    class FakeUser:
        email = _Field()

        @classmethod
        async def find_one(cls, *args):
            _ = args
            return None

    class FakeInvite:
        email = _Field()
        role = _Field()
        state = _Field()

        @classmethod
        async def find_one(cls, *args):
            _ = args
            return pending

        @classmethod
        def get_motor_collection(cls):
            return Collection()

    monkeypatch.setattr(invite_module, "User", FakeUser)
    monkeypatch.setattr(invite_module, "Invite", FakeInvite)
    monkeypatch.setattr(invite_module, "_new_token", lambda: "rotated-token")
    monkeypatch.setattr(
        invite_module,
        "get_settings",
        lambda: SimpleNamespace(invite_ttl_hours=168),
    )

    token, invite, retried = await InviteService().create_or_retry_owner_invite(
        email="owner@example.test",
        org_name="Correct name",
        member_limit=25,
    )

    assert token == "rotated-token"
    assert invite is pending
    assert retried is True
    assert pending.pending_key == "owner:owner@example.test"
    assert pending.org_name == "Correct name"
    assert pending.member_limit == 25
    assert pending.email_delivery_status == InviteEmailStatus.not_attempted
    assert updates[0][1]["$set"]["pending_key"] == "owner:owner@example.test"


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

    async def accept(self, *, token, full_name, email, password):
        if token != "good-token":
            raise InvalidInviteError()
        if email != self.pending.email:
            raise InviteEmailMismatchError()
        self.accepted = {
            "token": token,
            "full_name": full_name,
            "email": email,
            "password": password,
        }
        return SimpleNamespace(
            id="user-9",
            full_name=full_name,
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
            "full_name": "Niuradaj   Adhadh",
            "email": "invitee@example.test",
            "password": "password123",
        },
    )

    assert response.status_code == 201
    body = response.json()["data"]
    assert body["access_token"] == "session-token"
    assert body["user"]["full_name"] == "Niuradaj Adhadh"
    assert body["user"]["email"] == "invitee@example.test"
    assert body["user"]["role"] == "developer"
    assert body["user"]["org_id"] == "org-1"
    assert invites.accepted["token"] == "good-token"
    assert invites.accepted["full_name"] == "Niuradaj Adhadh"
    assert "sentrystrike_session=session-token" in response.headers["set-cookie"]


def test_register_rejects_email_not_matching_invite() -> None:
    client = _client(FakeInviteService())

    response = client.post(
        "/api/v1/auth/register",
        json={
            "invite_token": "good-token",
            "full_name": "Niuradaj Adhadh",
            "email": "someone-else@example.test",
            "password": "password123",
        },
    )

    assert response.status_code == 400


def test_register_requires_invite_token() -> None:
    client = _client(FakeInviteService())

    response = client.post(
        "/api/v1/auth/register",
        json={
            "full_name": "Niuradaj Adhadh",
            "email": "invitee@example.test",
            "password": "password123",
        },
    )

    # Missing invite_token fails schema validation before any service call.
    assert response.status_code == 422


def test_register_requires_full_name() -> None:
    client = _client(FakeInviteService())

    response = client.post(
        "/api/v1/auth/register",
        json={
            "invite_token": "good-token",
            "email": "invitee@example.test",
            "password": "password123",
        },
    )

    assert response.status_code == 422
