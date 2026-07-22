import asyncio
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from app import cli
from shared.models.invite import InviteEmailStatus, InviteState
from shared.models.user import UserRole


def test_invite_owner_accepts_per_workspace_member_limit(monkeypatch) -> None:
    captured = {}

    async def invite_owner(email: str, org: str, member_limit: int) -> int:
        captured.update(email=email, org=org, member_limit=member_limit)
        return 0

    monkeypatch.setattr(cli, "_invite_owner", invite_owner)

    result = cli.main(
        [
            "invite-owner",
            "--email",
            "owner@example.test",
            "--org",
            "Acme",
            "--member-limit",
            "100",
        ]
    )

    assert result == 0
    assert captured == {
        "email": "owner@example.test",
        "org": "Acme",
        "member_limit": 100,
    }


def test_invite_owner_defaults_to_ten_members(monkeypatch) -> None:
    captured = {}

    async def invite_owner(email: str, org: str, member_limit: int) -> int:
        captured["member_limit"] = member_limit
        return 0

    monkeypatch.setattr(cli, "_invite_owner", invite_owner)

    assert cli.main(["invite-owner", "--email", "owner@example.test", "--org", "Acme"]) == 0
    assert captured["member_limit"] == 10


def test_invite_owner_smtp_failure_is_recorded_and_returns_error(monkeypatch, capsys) -> None:
    recorded = {}
    sent = {}
    invite = SimpleNamespace(id="invite-1")

    class Service:
        async def create_or_retry_owner_invite(self, **kwargs):
            _ = kwargs
            return "raw-token", invite, False

        async def record_email_delivery(self, target, **kwargs):
            assert target is invite
            recorded.update(kwargs)

    class FailingBackend:
        name = "smtp"

        def send(self, **kwargs):
            sent.update(kwargs)
            raise RuntimeError("smtp unavailable")

    async def no_op(*_args):
        return None

    monkeypatch.setattr(cli, "init_db", no_op)
    monkeypatch.setattr(cli, "close_db", no_op)
    monkeypatch.setattr(cli, "InviteService", Service)
    monkeypatch.setattr(cli, "get_email_backend", FailingBackend)
    monkeypatch.setattr(cli, "build_invite_link", lambda token: f"https://test/register?invite={token}")

    result = asyncio.run(cli._invite_owner("owner@example.test", "Acme", 10))

    captured = capsys.readouterr()
    assert result == 1
    assert recorded["status"] == InviteEmailStatus.failed
    assert "Set up the Acme workspace" in sent["body_html"]
    assert "https://test/register?invite=raw-token" in sent["body_html"]
    assert "SMTP did not accept" in captured.err
    assert "dispatched" not in captured.out


def test_set_member_limit_targets_one_existing_workspace(monkeypatch) -> None:
    captured = {}

    async def set_member_limit(org_id: str, limit: int) -> int:
        captured.update(org_id=org_id, limit=limit)
        return 0

    monkeypatch.setattr(cli, "_set_member_limit", set_member_limit)

    result = cli.main(["set-member-limit", "--org-id", "org-100", "--limit", "25"])

    assert result == 0
    assert captured == {"org_id": "org-100", "limit": 25}


@pytest.mark.parametrize("value", ["0", "10001", "not-a-number"])
def test_member_limit_rejects_invalid_values(value: str) -> None:
    with pytest.raises(SystemExit) as exc_info:
        cli.main(
            [
                "invite-owner",
                "--email",
                "owner@example.test",
                "--org",
                "Acme",
                "--member-limit",
                value,
            ]
        )

    assert exc_info.value.code == 2


def test_email_check_reports_smtp_acceptance(monkeypatch, capsys) -> None:
    settings = SimpleNamespace(
        email_smtp_host="smtp.example.test",
        email_smtp_port=587,
        email_smtp_starttls=True,
        email_smtp_user="configured-user",
        email_smtp_password="configured-password",
    )

    class Backend:
        from_address = "sender@example.test"

        def send(self, **kwargs):
            assert kwargs["to"] == "operator@example.test"
            return None

    monkeypatch.setattr(cli, "get_settings", lambda: settings)
    monkeypatch.setattr(cli, "get_email_backend", Backend)

    result = cli.main(["email-check", "--to", "operator@example.test"])

    output = capsys.readouterr().out
    assert result == 0
    assert "accepted the diagnostic message" in output
    assert "configured-password" not in output


def test_invite_status_dispatches_by_email(monkeypatch) -> None:
    captured = {}

    async def invite_status(email: str) -> int:
        captured["email"] = email
        return 0

    monkeypatch.setattr(cli, "_invite_status", invite_status)

    result = cli.main(["invite-status", "--email", "owner@example.test"])

    assert result == 0
    assert captured["email"] == "owner@example.test"


def test_invite_status_reports_delivery_and_owner_joined(monkeypatch, capsys) -> None:
    invite = SimpleNamespace(
        id="invite-1",
        email="owner@example.test",
        role=UserRole.owner,
        org_name="Acme",
        org_id=None,
        state=InviteState.accepted,
        email_delivery_status=InviteEmailStatus.smtp_accepted,
        email_delivery_backend="smtp",
        email_delivery_attempted_at=datetime(2026, 7, 21, tzinfo=timezone.utc),
        email_delivery_error=None,
        accepted_user_id="user-1",
    )

    class Query:
        def sort(self, *args):
            return self

        def limit(self, *args):
            return self

        async def to_list(self):
            return [invite]

    async def no_op(*_args):
        return None

    async def find_user(*args):
        return SimpleNamespace(id="user-1")

    class Field:
        def __eq__(self, other):
            _ = other
            return self

        def __neg__(self):
            return self

    fake_invite_model = SimpleNamespace(
        email=Field(),
        created_at=Field(),
        find=lambda *args: Query(),
    )
    fake_user_model = SimpleNamespace(email=Field(), find_one=find_user)

    monkeypatch.setattr(cli, "init_db", no_op)
    monkeypatch.setattr(cli, "close_db", no_op)
    monkeypatch.setattr(cli, "Invite", fake_invite_model)
    monkeypatch.setattr(cli, "User", fake_user_model)

    exit_code = asyncio.run(cli._invite_status("OWNER@example.test"))

    output = capsys.readouterr().out
    assert exit_code == 0
    assert "Email status: smtp_accepted" in output
    assert "Invite accepted / account joined: yes" in output
