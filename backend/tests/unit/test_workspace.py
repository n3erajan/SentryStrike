"""Workspace member-management and settings authorization tests.

Phase 3 adds the team-management surface: listing members, inviting and
cancelling invites, removing members (a hard account delete), changing roles,
and the per-org scan-config/retention settings. The security-critical
invariants here are the member-removal guards (never the owner, never self,
always same-org) and the owner/admin gate on every mutating endpoint. Each is
exercised against fakes wired through FastAPI dependency overrides.
"""

from datetime import datetime, timezone
from types import SimpleNamespace

from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from app.api.dependencies import (
    get_audit_repository,
    get_current_user,
    get_invite_service,
    get_member_repository,
    get_organization_repository,
)
from app.api.routes import workspace
from shared.models.audit import AuditAction
from shared.models.invite import InviteState
from shared.models.organization import MIN_RETENTION_DAYS
from shared.models.user import UserRole


class FakeAuditRepository:
    """In-memory audit sink; records the kwargs of each ``record`` call."""

    def __init__(self) -> None:
        self.entries: list[dict] = []

    async def record(self, **kwargs) -> None:
        self.entries.append(kwargs)


class FakeMember:
    def __init__(self, user_id: str, org_id: str, role: UserRole, email: str | None = None) -> None:
        self.id = user_id
        self.org_id = org_id
        self.role = role
        self.email = email or f"{user_id}@example.test"
        self.is_active = True
        self.created_at = datetime(2026, 6, 8, 9, 10, 17, tzinfo=timezone.utc)
        self.deleted = False


class FakeMemberRepository:
    def __init__(self) -> None:
        # org-1 has an owner, an admin, and a developer; org-2 is a separate tenant.
        self.members = {
            "user-owner": FakeMember("user-owner", "org-1", UserRole.owner),
            "user-admin": FakeMember("user-admin", "org-1", UserRole.admin),
            "user-dev": FakeMember("user-dev", "org-1", UserRole.developer),
            "user-other": FakeMember("user-other", "org-2", UserRole.developer),
        }

    async def get_in_org(self, user_id: str, org_id: str):
        member = self.members.get(user_id)
        if member is None or member.org_id != org_id:
            return None
        return member

    async def list_in_org(self, org_id: str):
        return [m for m in self.members.values() if m.org_id == org_id]

    async def set_role(self, user: FakeMember, role: UserRole) -> FakeMember:
        user.role = role
        return user

    async def delete_member(self, user: FakeMember) -> None:
        user.deleted = True
        self.members.pop(str(user.id), None)


class FakeInvite:
    def __init__(self, invite_id: str, org_id: str, email: str, role: UserRole) -> None:
        self.id = invite_id
        self.org_id = org_id
        self.email = email
        self.role = role
        self.state = InviteState.pending
        self.expires_at = datetime(2026, 7, 28, 9, 10, 17, tzinfo=timezone.utc)
        self.created_at = datetime(2026, 7, 21, 9, 10, 17, tzinfo=timezone.utc)
        self.invited_by_user_id = None


class FakeOrg:
    def __init__(self, org_id: str, name: str) -> None:
        self.id = org_id
        self.name = name
        self.retention_days = 90
        self.default_scan_config: dict = {}


class FakeOrganizationRepository:
    def __init__(self) -> None:
        self.orgs = {"org-1": FakeOrg("org-1", "Acme Corp"), "org-2": FakeOrg("org-2", "Globex")}
        self.invites = {
            "invite-1": FakeInvite("invite-1", "org-1", "new@example.test", UserRole.developer),
            "invite-2": FakeInvite("invite-2", "org-2", "other@example.test", UserRole.analyst),
        }

    async def get_by_id(self, org_id: str):
        return self.orgs.get(org_id)

    async def set_default_scan_config(self, org: FakeOrg, config: dict) -> FakeOrg:
        org.default_scan_config = config
        return org

    async def set_retention_days(self, org: FakeOrg, days: int) -> FakeOrg:
        org.retention_days = max(MIN_RETENTION_DAYS, days)
        return org

    async def list_pending_invites(self, org_id: str):
        return [i for i in self.invites.values() if i.org_id == org_id and i.state == InviteState.pending]

    async def get_invite_in_org(self, invite_id: str, org_id: str):
        invite = self.invites.get(invite_id)
        if invite is None or invite.org_id != org_id:
            return None
        return invite


class FakeInviteService:
    def __init__(self) -> None:
        self.created_kwargs: dict | None = None
        self.cancelled: list[str] = []

    async def create_invite(self, *, email, role, org_id, org_name, invited_by_user_id):
        self.created_kwargs = {
            "email": email,
            "role": role,
            "org_id": org_id,
            "org_name": org_name,
            "invited_by_user_id": invited_by_user_id,
        }
        invite = FakeInvite("invite-new", org_id, email, role)
        invite.invited_by_user_id = invited_by_user_id
        return "raw-token", invite

    async def cancel(self, invite: FakeInvite) -> FakeInvite:
        invite.state = InviteState.cancelled
        self.cancelled.append(str(invite.id))
        return invite


class FakeEmailBackend:
    def __init__(self) -> None:
        self.sent: list[dict] = []

    def send(self, *, to: str, subject: str, body_text: str, body_html: str | None = None) -> None:
        self.sent.append({"to": to, "subject": subject})


def _client(
    *,
    members: FakeMemberRepository,
    orgs: FakeOrganizationRepository,
    invites: FakeInviteService,
    email: FakeEmailBackend | None = None,
    audit: FakeAuditRepository | None = None,
    user_id: str = "user-owner",
    org_id: str = "org-1",
    role: UserRole = UserRole.owner,
    monkeypatch=None,
) -> TestClient:
    if email is not None and monkeypatch is not None:
        monkeypatch.setattr(workspace, "get_email_backend", lambda: email)
    audit = audit if audit is not None else FakeAuditRepository()
    app = FastAPI()
    app.include_router(workspace.router, prefix="/api/v1", dependencies=[Depends(get_current_user)])
    app.dependency_overrides[get_member_repository] = lambda: members
    app.dependency_overrides[get_organization_repository] = lambda: orgs
    app.dependency_overrides[get_invite_service] = lambda: invites
    app.dependency_overrides[get_audit_repository] = lambda: audit
    app.dependency_overrides[get_current_user] = lambda: SimpleNamespace(
        id=user_id, email=f"{user_id}@example.test", org_id=org_id, role=role
    )
    return TestClient(app)


def _repos():
    return FakeMemberRepository(), FakeOrganizationRepository(), FakeInviteService()


# ---------------------------------------------------------------------------
# Member listing (any member)
# ---------------------------------------------------------------------------


def test_list_members_returns_only_callers_org() -> None:
    members, orgs, invites = _repos()
    client = _client(members=members, orgs=orgs, invites=invites, role=UserRole.viewer)

    response = client.get("/api/v1/workspace/members")

    assert response.status_code == 200
    ids = {m["id"] for m in response.json()["data"]["items"]}
    assert ids == {"user-owner", "user-admin", "user-dev"}
    assert "user-other" not in ids


# ---------------------------------------------------------------------------
# Member removal guards
# ---------------------------------------------------------------------------


def test_admin_can_remove_a_member() -> None:
    members, orgs, invites = _repos()
    client = _client(members=members, orgs=orgs, invites=invites, user_id="user-admin", role=UserRole.admin)

    response = client.delete("/api/v1/workspace/members/user-dev")

    assert response.status_code == 200
    assert response.json()["data"]["removed"] is True
    assert "user-dev" not in members.members


def test_cannot_remove_the_owner() -> None:
    members, orgs, invites = _repos()
    client = _client(members=members, orgs=orgs, invites=invites, user_id="user-admin", role=UserRole.admin)

    response = client.delete("/api/v1/workspace/members/user-owner")

    assert response.status_code == 403
    assert "user-owner" in members.members


def test_cannot_remove_self() -> None:
    members, orgs, invites = _repos()
    client = _client(members=members, orgs=orgs, invites=invites, user_id="user-admin", role=UserRole.admin)

    response = client.delete("/api/v1/workspace/members/user-admin")

    assert response.status_code == 400
    assert "user-admin" in members.members


def test_cannot_remove_a_member_in_another_org() -> None:
    members, orgs, invites = _repos()
    client = _client(members=members, orgs=orgs, invites=invites, user_id="user-owner", role=UserRole.owner)

    response = client.delete("/api/v1/workspace/members/user-other")

    assert response.status_code == 404
    assert "user-other" in members.members


def test_viewer_cannot_remove_a_member() -> None:
    members, orgs, invites = _repos()
    client = _client(members=members, orgs=orgs, invites=invites, user_id="user-dev", role=UserRole.viewer)

    response = client.delete("/api/v1/workspace/members/user-admin")

    assert response.status_code == 403
    assert "user-admin" in members.members


def test_developer_cannot_remove_a_member() -> None:
    members, orgs, invites = _repos()
    client = _client(members=members, orgs=orgs, invites=invites, user_id="user-dev", role=UserRole.developer)

    response = client.delete("/api/v1/workspace/members/user-admin")

    assert response.status_code == 403


# ---------------------------------------------------------------------------
# Role changes
# ---------------------------------------------------------------------------


def test_admin_can_change_a_member_role() -> None:
    members, orgs, invites = _repos()
    client = _client(members=members, orgs=orgs, invites=invites, user_id="user-admin", role=UserRole.admin)

    response = client.patch("/api/v1/workspace/members/user-dev/role", json={"role": "analyst"})

    assert response.status_code == 200
    assert response.json()["data"]["role"] == "analyst"
    assert members.members["user-dev"].role == UserRole.analyst


def test_cannot_grant_owner_role() -> None:
    members, orgs, invites = _repos()
    client = _client(members=members, orgs=orgs, invites=invites, user_id="user-admin", role=UserRole.admin)

    response = client.patch("/api/v1/workspace/members/user-dev/role", json={"role": "owner"})

    assert response.status_code == 422
    assert members.members["user-dev"].role == UserRole.developer


def test_cannot_change_the_owners_role() -> None:
    members, orgs, invites = _repos()
    client = _client(members=members, orgs=orgs, invites=invites, user_id="user-admin", role=UserRole.admin)

    response = client.patch("/api/v1/workspace/members/user-owner/role", json={"role": "analyst"})

    assert response.status_code == 403
    assert members.members["user-owner"].role == UserRole.owner


def test_cannot_change_own_role() -> None:
    members, orgs, invites = _repos()
    client = _client(members=members, orgs=orgs, invites=invites, user_id="user-admin", role=UserRole.admin)

    response = client.patch("/api/v1/workspace/members/user-admin/role", json={"role": "viewer"})

    assert response.status_code == 400


def test_viewer_cannot_change_a_role() -> None:
    members, orgs, invites = _repos()
    client = _client(members=members, orgs=orgs, invites=invites, user_id="user-dev", role=UserRole.viewer)

    response = client.patch("/api/v1/workspace/members/user-admin/role", json={"role": "viewer"})

    assert response.status_code == 403


# ---------------------------------------------------------------------------
# Invites
# ---------------------------------------------------------------------------


def test_admin_can_invite_a_member_bound_to_their_org(monkeypatch) -> None:
    members, orgs, invites = _repos()
    email = FakeEmailBackend()
    client = _client(
        members=members, orgs=orgs, invites=invites, email=email,
        user_id="user-admin", role=UserRole.admin, monkeypatch=monkeypatch,
    )

    response = client.post("/api/v1/workspace/invites", json={"email": "hire@example.test", "role": "developer"})

    assert response.status_code == 201
    assert invites.created_kwargs["org_id"] == "org-1"
    assert invites.created_kwargs["org_name"] == "Acme Corp"
    assert invites.created_kwargs["role"] == UserRole.developer
    assert invites.created_kwargs["invited_by_user_id"] == "user-admin"
    assert email.sent and email.sent[0]["to"] == "hire@example.test"


def test_cannot_invite_an_owner(monkeypatch) -> None:
    members, orgs, invites = _repos()
    client = _client(members=members, orgs=orgs, invites=invites, role=UserRole.owner, monkeypatch=monkeypatch)

    response = client.post("/api/v1/workspace/invites", json={"email": "boss@example.test", "role": "owner"})

    assert response.status_code == 422
    assert invites.created_kwargs is None


def test_viewer_cannot_invite() -> None:
    members, orgs, invites = _repos()
    client = _client(members=members, orgs=orgs, invites=invites, user_id="user-dev", role=UserRole.viewer)

    response = client.post("/api/v1/workspace/invites", json={"email": "hire@example.test", "role": "developer"})

    assert response.status_code == 403
    assert invites.created_kwargs is None


def test_list_pending_invites_is_org_scoped() -> None:
    members, orgs, invites = _repos()
    client = _client(members=members, orgs=orgs, invites=invites, role=UserRole.admin)

    response = client.get("/api/v1/workspace/invites")

    assert response.status_code == 200
    ids = {i["id"] for i in response.json()["data"]["items"]}
    assert ids == {"invite-1"}


def test_cancel_invite_flips_state() -> None:
    members, orgs, invites = _repos()
    client = _client(members=members, orgs=orgs, invites=invites, role=UserRole.admin)

    response = client.post("/api/v1/workspace/invites/invite-1/cancel")

    assert response.status_code == 200
    assert response.json()["data"]["state"] == "cancelled"
    assert invites.cancelled == ["invite-1"]


def test_cannot_cancel_invite_in_another_org() -> None:
    members, orgs, invites = _repos()
    client = _client(members=members, orgs=orgs, invites=invites, role=UserRole.admin)

    response = client.post("/api/v1/workspace/invites/invite-2/cancel")

    assert response.status_code == 404
    assert invites.cancelled == []


# ---------------------------------------------------------------------------
# Settings — default config & retention
# ---------------------------------------------------------------------------


def test_any_member_can_read_default_config() -> None:
    members, orgs, invites = _repos()
    orgs.orgs["org-1"].default_scan_config = {"crawl_depth": 3}
    client = _client(members=members, orgs=orgs, invites=invites, role=UserRole.viewer)

    response = client.get("/api/v1/workspace/default-config")

    assert response.status_code == 200
    assert response.json()["data"]["config"] == {"crawl_depth": 3}


def test_admin_can_replace_default_config() -> None:
    members, orgs, invites = _repos()
    client = _client(members=members, orgs=orgs, invites=invites, role=UserRole.admin)

    response = client.put("/api/v1/workspace/default-config", json={"config": {"concurrency": 8}})

    assert response.status_code == 200
    assert orgs.orgs["org-1"].default_scan_config == {"concurrency": 8}


def test_viewer_cannot_replace_default_config() -> None:
    members, orgs, invites = _repos()
    client = _client(members=members, orgs=orgs, invites=invites, role=UserRole.viewer)

    response = client.put("/api/v1/workspace/default-config", json={"config": {"concurrency": 8}})

    assert response.status_code == 403


def test_retention_is_readable_by_any_member() -> None:
    members, orgs, invites = _repos()
    client = _client(members=members, orgs=orgs, invites=invites, role=UserRole.viewer)

    response = client.get("/api/v1/workspace/retention")

    assert response.status_code == 200
    assert response.json()["data"]["retention_days"] == 90


def test_retention_update_enforces_compliance_floor() -> None:
    members, orgs, invites = _repos()
    client = _client(members=members, orgs=orgs, invites=invites, role=UserRole.owner)

    response = client.put("/api/v1/workspace/retention", json={"retention_days": 5})

    assert response.status_code == 200
    # Below the floor is silently clamped up, never rejected.
    assert response.json()["data"]["retention_days"] == MIN_RETENTION_DAYS
    assert orgs.orgs["org-1"].retention_days == MIN_RETENTION_DAYS


def test_viewer_cannot_update_retention() -> None:
    members, orgs, invites = _repos()
    client = _client(members=members, orgs=orgs, invites=invites, role=UserRole.viewer)

    response = client.put("/api/v1/workspace/retention", json={"retention_days": 120})

    assert response.status_code == 403


# ---------------------------------------------------------------------------
# Audit trail
# ---------------------------------------------------------------------------


def test_member_removal_is_audited() -> None:
    members, orgs, invites = _repos()
    audit = FakeAuditRepository()
    client = _client(
        members=members, orgs=orgs, invites=invites, audit=audit,
        user_id="user-admin", role=UserRole.admin,
    )

    client.delete("/api/v1/workspace/members/user-dev")

    assert len(audit.entries) == 1
    entry = audit.entries[0]
    assert entry["action"] == AuditAction.member_removed
    assert entry["actor_user_id"] == "user-admin"
    assert entry["target_id"] == "user-dev"


def test_role_change_records_from_and_to() -> None:
    members, orgs, invites = _repos()
    audit = FakeAuditRepository()
    client = _client(
        members=members, orgs=orgs, invites=invites, audit=audit,
        user_id="user-admin", role=UserRole.admin,
    )

    client.patch("/api/v1/workspace/members/user-dev/role", json={"role": "analyst"})

    assert audit.entries[0]["action"] == AuditAction.member_role_changed
    assert audit.entries[0]["metadata"]["from"] == "developer"
    assert audit.entries[0]["metadata"]["to"] == "analyst"


def test_invite_creation_is_audited(monkeypatch) -> None:
    members, orgs, invites = _repos()
    audit = FakeAuditRepository()
    client = _client(
        members=members, orgs=orgs, invites=invites, audit=audit, email=FakeEmailBackend(),
        user_id="user-admin", role=UserRole.admin, monkeypatch=monkeypatch,
    )

    client.post("/api/v1/workspace/invites", json={"email": "hire@example.test", "role": "developer"})

    assert audit.entries[0]["action"] == AuditAction.invite_created
    assert audit.entries[0]["metadata"]["email"] == "hire@example.test"


def test_a_failed_action_is_not_audited() -> None:
    members, orgs, invites = _repos()
    audit = FakeAuditRepository()
    # Removing the owner is rejected before any state change; nothing is audited.
    client = _client(
        members=members, orgs=orgs, invites=invites, audit=audit,
        user_id="user-admin", role=UserRole.admin,
    )

    response = client.delete("/api/v1/workspace/members/user-owner")

    assert response.status_code == 403
    assert audit.entries == []


def test_audit_log_is_readable_by_admin_and_org_scoped() -> None:
    members, orgs, invites = _repos()
    audit = FakeAuditRepository()

    async def _list_in_org(org_id, skip=0, limit=50):
        assert org_id == "org-1"
        return [
            SimpleNamespace(
                id="entry-1",
                action=AuditAction.member_removed,
                actor_user_id="user-admin",
                actor_email="user-admin@example.test",
                target_type="user",
                target_id="user-dev",
                metadata={"email": "user-dev@example.test"},
                created_at=datetime(2026, 7, 21, 9, 10, 17, tzinfo=timezone.utc),
            )
        ]

    audit.list_in_org = _list_in_org
    client = _client(members=members, orgs=orgs, invites=invites, audit=audit, role=UserRole.admin)

    response = client.get("/api/v1/workspace/audit-log")

    assert response.status_code == 200
    items = response.json()["data"]["items"]
    assert items[0]["action"] == "member_removed"
    assert items[0]["target_id"] == "user-dev"


def test_viewer_cannot_read_audit_log() -> None:
    members, orgs, invites = _repos()
    client = _client(members=members, orgs=orgs, invites=invites, role=UserRole.viewer)

    response = client.get("/api/v1/workspace/audit-log")

    assert response.status_code == 403
