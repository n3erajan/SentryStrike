import asyncio
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from app import cli
from shared.models.invite import InviteEmailStatus, InviteState
from shared.models.user import UserRole


def test_approve_access_request_accepts_per_workspace_member_limit(monkeypatch) -> None:
    captured = {}

    async def approve(request_id: str, member_limit: int) -> int:
        captured.update(request_id=request_id, member_limit=member_limit)
        return 0

    monkeypatch.setattr(cli, "_approve_access_request", approve)

    result = cli.main(
        [
            "approve",
            "request-1",
            "--member-limit",
            "100",
        ]
    )

    assert result == 0
    assert captured == {
        "request_id": "request-1",
        "member_limit": 100,
    }


def test_approve_access_request_defaults_to_ten_members(monkeypatch) -> None:
    captured = {}

    async def approve(request_id: str, member_limit: int) -> int:
        captured["request_id"] = request_id
        captured["member_limit"] = member_limit
        return 0

    monkeypatch.setattr(cli, "_approve_access_request", approve)

    assert cli.main(["approve", "request-1"]) == 0
    assert captured["request_id"] == "request-1"
    assert captured["member_limit"] == 10


def test_approve_access_request_smtp_failure_keeps_request(monkeypatch, capsys) -> None:
    recorded = {}
    sent = {}
    invite = SimpleNamespace(id="invite-1")
    access_request = SimpleNamespace(
        email="owner@example.test",
        organization_name="Acme",
        deleted=False,
    )

    async def delete_request():
        access_request.deleted = True

    access_request.delete = delete_request

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

    async def find_access_request(_request_id):
        return access_request

    monkeypatch.setattr(cli, "init_db", no_op)
    monkeypatch.setattr(cli, "close_db", no_op)
    monkeypatch.setattr(cli, "InviteService", Service)
    monkeypatch.setattr(cli, "get_email_backend", FailingBackend)
    monkeypatch.setattr(cli, "build_invite_link", lambda token: f"https://test/register?invite={token}")
    monkeypatch.setattr(cli, "_find_access_request", find_access_request)

    result = asyncio.run(cli._approve_access_request("request-1", 10))

    captured = capsys.readouterr()
    assert result == 1
    assert recorded["status"] == InviteEmailStatus.failed
    assert "Your access request was approved" in sent["body_html"]
    assert "https://test/register?invite=raw-token" in sent["body_html"]
    assert "SMTP did not accept" in captured.err
    assert "dispatched" not in captured.out
    assert access_request.deleted is False


def test_set_member_limit_targets_one_existing_workspace(monkeypatch) -> None:
    captured = {}

    async def set_member_limit(org_id: str, limit: int) -> int:
        captured.update(org_id=org_id, limit=limit)
        return 0

    monkeypatch.setattr(cli, "_set_member_limit", set_member_limit)

    result = cli.main(["set-limit", "org-100", "25"])

    assert result == 0
    assert captured == {"org_id": "org-100", "limit": 25}


@pytest.mark.parametrize("value", ["0", "10001", "not-a-number"])
def test_member_limit_rejects_invalid_values(value: str) -> None:
    with pytest.raises(SystemExit) as exc_info:
        cli.main(
            [
                "approve",
                "request-1",
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

    result = cli.main(["email", "operator@example.test"])

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

    result = cli.main(["status", "owner@example.test"])

    assert result == 0
    assert captured["email"] == "owner@example.test"


@pytest.mark.parametrize("command", ["invite", "invite-status"])
def test_invite_status_aliases_remain_supported(monkeypatch, command: str) -> None:
    captured = {}

    async def invite_status(email: str) -> int:
        captured["email"] = email
        return 0

    monkeypatch.setattr(cli, "_invite_status", invite_status)

    assert cli.main([command, "owner@example.test"]) == 0
    assert captured["email"] == "owner@example.test"


@pytest.mark.parametrize(
    ("alias", "canonical"),
    [
        ("list-access-requests", "list"),
        ("approve-access-request", "approve"),
        ("reject-access-request", "reject"),
        ("email-check", "email"),
        ("set-member-limit", "set-limit"),
        ("purge-retention", "purge"),
    ],
)
def test_legacy_command_aliases_are_canonicalized(alias: str, canonical: str) -> None:
    assert cli._canonicalize_command([alias, "value"]) == [canonical, "value"]


def test_main_help_has_banner_commands_and_examples(capsys) -> None:
    with pytest.raises(SystemExit) as exc_info:
        cli.main(["--help"])

    output = capsys.readouterr().out
    assert exc_info.value.code == 0
    assert cli._BANNER in output
    assert "Management console | vendor operations" in output
    assert "USAGE: python -m app.cli" in output
    assert "COMMANDS:" in output
    assert "EXAMPLES:" in output
    assert "approve" in output
    command_table = output.split("COMMANDS:", 1)[1].split("OPTIONS:", 1)[0]
    assert "list-access-requests" not in command_table


def test_command_help_documents_arguments_example_and_alias(capsys) -> None:
    with pytest.raises(SystemExit) as exc_info:
        cli.main(["approve", "--help"])

    output = capsys.readouterr().out
    assert exc_info.value.code == 0
    assert "REQUEST_ID" in output
    assert "--member-limit N" in output
    assert "EXAMPLE:" in output
    assert "approve-access-request" in output


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
