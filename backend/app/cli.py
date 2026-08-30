"""Management CLI for vendor-only operations.

Owner onboarding has no web UI: the vendor invites a business owner from a shell
inside the backend container. Access *is* container access, so there is no HTTP
surface to secure.

Usage (long-form aliases in parentheses still work)::

    python -m app.cli list [-l 50]                         (list-access-requests)
    python -m app.cli approve <request-id> [-l 100]        (approve-access-request)
    python -m app.cli reject <request-id>                  (reject-access-request)
    python -m app.cli status owner@acme.com                (invite, invite-status)
    python -m app.cli email operator@example.com           (email-check)
    python -m app.cli purge                                (purge-retention)
    python -m app.cli set-limit <organization-id> 25       (set-member-limit)

Creates a pending owner invite, prints the signup link, and emails it when a
real (SMTP) email backend is configured. The owner accepts by registering with
the invited email, which creates the workspace and their owner account together.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
import unicodedata
from datetime import datetime, timezone, tzinfo

from beanie import PydanticObjectId

from app.config import get_settings
from app.core.auth import normalize_email
from app.core.email import get_email_backend, render_workspace_invite_email
from app.core.invites import InviteError, InviteService, build_invite_link
from app.core.retention import RetentionService
from shared.database.connection import close_db, init_db
from shared.database.repositories.organization_repository import OrganizationRepository
from shared.models.access_request import AccessRequest
from shared.models.invite import Invite, InviteEmailStatus, InviteState
from shared.models.user import User


def _member_limit(value: str) -> int:
    try:
        limit = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("member limit must be an integer") from exc
    if not 1 <= limit <= 10000:
        raise argparse.ArgumentTypeError("member limit must be between 1 and 10000")
    return limit


def _access_request_list_limit(value: str) -> int:
    try:
        limit = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("limit must be an integer") from exc
    if not 1 <= limit <= 200:
        raise argparse.ArgumentTypeError("limit must be between 1 and 200")
    return limit


def _safe_table_cell(value: object, max_length: int) -> str:
    text = " ".join(str(value).split())
    text = "".join(
        char for char in text if not unicodedata.category(char).startswith("C")
    )
    if len(text) <= max_length:
        return text
    return f"{text[: max_length - 1]}…"


def _format_local_datetime(
    value: datetime,
    local_timezone: tzinfo | None = None,
) -> str:
    """Format a stored UTC timestamp in the operator's local timezone."""
    utc_value = value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)
    local_value = (
        utc_value.astimezone(local_timezone)
        if local_timezone is not None
        else utc_value.astimezone()
    )
    return local_value.strftime("%Y-%m-%d %H:%M %z")


async def _list_access_requests(limit: int) -> int:
    await init_db(get_settings())
    try:
        requests = (
            await AccessRequest.find()
            .sort(AccessRequest.created_at)
            .limit(limit)
            .to_list()
        )
        if not requests:
            print("No pending access requests.")
            return 0

        headers = ("REQUEST ID", "CREATED", "NAME", "EMAIL", "ORGANIZATION")
        rows = [
            (
                str(item.id),
                _format_local_datetime(item.created_at),
                _safe_table_cell(item.full_name, 24),
                _safe_table_cell(item.email, 36),
                _safe_table_cell(item.organization_name, 30),
            )
            for item in requests
        ]
        widths = [
            max(len(headers[index]), *(len(row[index]) for row in rows))
            for index in range(len(headers))
        ]
        print("  ".join(value.ljust(widths[index]) for index, value in enumerate(headers)))
        print("  ".join("-" * width for width in widths))
        for row in rows:
            print("  ".join(value.ljust(widths[index]) for index, value in enumerate(row)))
        return 0
    finally:
        await close_db()


async def _find_access_request(request_id: str) -> AccessRequest | None:
    try:
        object_id = PydanticObjectId(request_id)
    except Exception:
        return None
    return await AccessRequest.get(object_id)


async def _approve_access_request(request_id: str, member_limit: int) -> int:
    await init_db(get_settings())
    try:
        access_request = await _find_access_request(request_id)
        if access_request is None:
            print("Error: pending access request not found.", file=sys.stderr)
            return 1

        service = InviteService()
        try:
            token, invite, retried = await service.create_or_retry_owner_invite(
                email=access_request.email,
                org_name=access_request.organization_name,
                member_limit=member_limit,
                full_name=access_request.full_name,
            )
        except InviteError as exc:
            print(f"Error: {exc.message}", file=sys.stderr)
            return 1

        link = build_invite_link(token)
        subject, body_text, body_html = render_workspace_invite_email(
            org_name=access_request.organization_name,
            role="owner",
            link=link,
            token=token,
            owns_workspace=True,
        )

        action = "reused after failed delivery" if retried else "created"
        print(
            f"Owner invite {action} for {access_request.email} "
            f"(workspace: {access_request.organization_name!r}, "
            f"member limit: {member_limit})."
        )
        print(f"Invite id: {invite.id}")
        if link:
            print(f"Invite link: {link}")
        else:
            print("PUBLIC_HOSTNAME is not set; share this invite token directly:")
            print(f"  {token}")

        backend = get_email_backend()
        try:
            backend.send(
                to=access_request.email,
                subject=subject,
                body_text=body_text,
                body_html=body_html,
            )
        except Exception as exc:  # noqa: BLE001 - surface any delivery failure to the operator
            await service.record_email_delivery(
                invite,
                status=InviteEmailStatus.failed,
                backend=backend.name,
                error=f"{type(exc).__name__}: {exc}",
            )
            print(
                f"Error: SMTP did not accept the invitation ({type(exc).__name__}: {exc}). "
                "The invite link above is still valid.",
                file=sys.stderr,
            )
            return 1

        await service.record_email_delivery(
            invite,
            status=InviteEmailStatus.smtp_accepted,
            backend=backend.name,
        )
        print(
            f"SMTP server accepted the invitation for {access_request.email}. "
            "This confirms server handoff, not inbox delivery."
        )
        await access_request.delete()
        print(f"Access request {request_id} approved and removed.")
        return 0
    finally:
        await close_db()


async def _reject_access_request(request_id: str) -> int:
    await init_db(get_settings())
    try:
        access_request = await _find_access_request(request_id)
        if access_request is None:
            print("Error: pending access request not found.", file=sys.stderr)
            return 1
        await access_request.delete()
        print(f"Access request {request_id} rejected and removed.")
        return 0
    finally:
        await close_db()


def _email_check(to: str) -> int:
    """Show effective email configuration and send a real diagnostic message."""
    try:
        settings = get_settings()
        backend = get_email_backend()
    except Exception as exc:  # noqa: BLE001 - settings validation is operator-facing here
        print(f"Email configuration is invalid: {exc}", file=sys.stderr)
        return 1

    print("Email delivery: SMTP")

    print(f"SMTP endpoint: {settings.email_smtp_host}:{settings.email_smtp_port}")
    print(f"STARTTLS: {'enabled' if settings.email_smtp_starttls else 'disabled'}")
    print(f"SMTP username: {'configured' if settings.email_smtp_user else 'not configured'}")
    print(f"SMTP password: {'configured' if settings.email_smtp_password else 'not configured'}")
    print(f"From: {backend.from_address}")
    try:
        backend.send(
            to=to,
            subject="SentryStrike SMTP configuration check",
            body_text=(
                "This message confirms that the configured SMTP server accepted a "
                "diagnostic email from SentryStrike."
            ),
        )
    except Exception as exc:  # noqa: BLE001 - exact SMTP failure is useful to the operator
        print(f"SMTP check failed ({type(exc).__name__}: {exc}).", file=sys.stderr)
        return 1
    print(
        f"SMTP server accepted the diagnostic message for {to}. "
        "Check the inbox and spam folder to verify final delivery."
    )
    return 0


async def _invite_status(email: str) -> int:
    """Report the latest invitation's email handoff and account-acceptance state."""
    await init_db(get_settings())
    try:
        normalized = normalize_email(email)
        matches = (
            await Invite.find(Invite.email == normalized)
            .sort(-Invite.created_at)
            .limit(1)
            .to_list()
        )
        if not matches:
            print(f"No invitation found for {normalized}.", file=sys.stderr)
            return 1
        invite = matches[0]
        user = await User.find_one(User.email == normalized)
        joined = bool(
            invite.state == InviteState.accepted
            and invite.accepted_user_id
            and user is not None
            and str(user.id) == invite.accepted_user_id
        )

        print(f"Invite id: {invite.id}")
        print(f"Email: {invite.email}")
        print(f"Role: {invite.role.value}")
        print(f"Workspace: {invite.org_name or invite.org_id or 'not created yet'}")
        print(f"Invite state: {invite.state.value}")
        print(f"Email status: {invite.email_delivery_status.value}")
        print(f"Email backend: {invite.email_delivery_backend or 'not attempted'}")
        if invite.email_delivery_attempted_at:
            print(f"Email attempted at: {invite.email_delivery_attempted_at.isoformat()}")
        if invite.email_delivery_error:
            print(f"Email error: {invite.email_delivery_error}")
        print(f"Invite accepted / account joined: {'yes' if joined else 'no'}")
        if invite.accepted_user_id:
            print(f"Accepted user id: {invite.accepted_user_id}")
        return 0
    finally:
        await close_db()


async def _purge_retention() -> int:
    await init_db(get_settings())
    try:
        summary = await RetentionService().purge_once()
        total = sum(summary.values())
        print(f"Retention purge complete: {total} scan(s) deleted across {len(summary)} workspace(s).")
        for org_id, count in summary.items():
            if count:
                print(f"  {org_id}: {count} scan(s) deleted")
        return 0
    finally:
        await close_db()


async def _set_member_limit(org_id: str, limit: int) -> int:
    await init_db(get_settings())
    try:
        if not 1 <= limit <= 10000:
            print("Error: limit must be between 1 and 10000.", file=sys.stderr)
            return 1
        org = await OrganizationRepository().set_member_limit(org_id, limit)
        if org is None:
            print(
                "Error: workspace not found, or the limit is below its occupied seats.",
                file=sys.stderr,
            )
            return 1
        print(
            f"Workspace {org_id} member limit set to {org.member_limit} "
            f"({org.occupied_seats} occupied)."
        )
        return 0
    finally:
        await close_db()


_PROGRAM = "python -m app.cli"
_BANNER = r"""
  ____  _____ _   _ _____ ______   ______ _____ ____  ___ _  _______
 / ___|| ____| \ | |_   _|  _ \ \ / / ___|_   _|  _ \|_ _| |/ / ____|
 \___ \|  _| |  \| | | | | |_) \ V /\___ \ | | | |_) || || ' /|  _|
  ___) | |___| |\  | | | |  _ < | |  ___) || | |  _ < | || . \| |___
 |____/|_____|_| \_| |_| |_| \_\|_| |____/ |_| |_| \_\___|_|\_\_____|
""".strip("\n")

_COMMAND_ALIASES = {
    "list-access-requests": "list",
    "approve-access-request": "approve",
    "reject-access-request": "reject",
    "invite": "status",
    "invite-status": "status",
    "email-check": "email",
    "set-member-limit": "set-limit",
    "purge-retention": "purge",
}

_MAIN_EPILOG = """\
EXAMPLES:
  Review the oldest pending access requests:
    python -m app.cli list --limit 20

  Approve a request and create a workspace with 100 seats:
    python -m app.cli approve 665f0c2b3d4e5f60718293a4 --member-limit 100

  Inspect invitation delivery and account acceptance:
    python -m app.cli status owner@acme.com

  Verify the configured SMTP service:
    python -m app.cli email ops@example.com

Run 'python -m app.cli COMMAND --help' for command-specific arguments and examples.
Legacy long-form command aliases remain supported.\
"""


class _HelpFormatter(argparse.RawDescriptionHelpFormatter):
    """Keep management help readable and stable across terminal widths."""

    def __init__(self, prog: str) -> None:
        super().__init__(prog, max_help_position=30, width=100)

    def start_section(self, heading: str | None) -> None:
        super().start_section(heading.upper() if heading else heading)

    def _format_action(self, action):
        if isinstance(action, argparse._SubParsersAction):
            # The section already says COMMANDS; argparse's extra "COMMAND" row
            # adds no information and pushes the useful command names too far right.
            return self._join_parts(
                [self._format_action(item) for item in action._get_subactions()]
            )
        return super()._format_action(action)


class _ArgumentParser(argparse.ArgumentParser):
    """Argument parser with SentryStrike branding and actionable errors."""

    def format_help(self) -> str:
        help_text = super().format_help().replace("usage:", "USAGE:", 1)
        return f"{_BANNER}\n  Management console | vendor operations\n\n{help_text}"

    def format_usage(self) -> str:
        return super().format_usage().replace("usage:", "USAGE:", 1)

    def error(self, message: str) -> None:
        self.print_usage(sys.stderr)
        self.exit(
            2,
            f"\nERROR: {message}\n"
            f"Run '{self.prog} --help' for usage and examples.\n",
        )


def _command_aliases(command: str) -> tuple[str, ...]:
    return tuple(alias for alias, canonical in _COMMAND_ALIASES.items() if canonical == command)


def _add_command(
    sub,
    name: str,
    summary: str,
    description: str,
    example: str,
) -> argparse.ArgumentParser:
    """Register a subcommand with consistent help, examples, and documented aliases."""
    aliases = _command_aliases(name)
    alias_help = f"\n\nALIASES:\n  {', '.join(aliases)}" if aliases else ""
    return sub.add_parser(
        name,
        help=summary,
        description=description,
        epilog=f"EXAMPLE:\n  {example}{alias_help}",
        formatter_class=_HelpFormatter,
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = _ArgumentParser(
        prog=_PROGRAM,
        description=(
            "Vendor-only operations for access requests, workspace invitations, "
            "email diagnostics, member limits, and scan-data retention. Run this "
            "command inside the backend container."
        ),
        epilog=_MAIN_EPILOG,
        formatter_class=_HelpFormatter,
    )
    sub = parser.add_subparsers(
        title="commands",
        dest="command",
        metavar="COMMAND",
        required=True,
    )
    # Command discovery is the primary purpose of top-level help, so present it
    # before the single global help option.
    parser._action_groups.remove(sub.container)
    parser._action_groups.insert(1, sub.container)

    p = _add_command(
        sub, "list",
        "List pending workspace-access requests",
        "List pending public workspace-access requests, oldest first.",
        "python -m app.cli list -l 20",
    )
    p.add_argument(
        "-l", "--limit", type=_access_request_list_limit, default=50, metavar="N",
        help="maximum rows to show, 1–200 (default: 50)",
    )

    p = _add_command(
        sub, "approve",
        "Approve a request and email the owner a signup link",
        "Approve a pending access request: create a pending owner invite, print "
        "the signup link, and email it to the requester.",
        "python -m app.cli approve 665f0c2b3d4e5f60718293a4 -l 100",
    )
    p.add_argument("request_id", metavar="REQUEST_ID", help="pending access-request id (from `list`)")
    p.add_argument(
        "-l", "--member-limit", type=_member_limit, default=10, metavar="N",
        help="initial workspace member limit, 1–10000 (default: 10)",
    )

    p = _add_command(
        sub, "reject",
        "Reject and delete a pending access request",
        "Reject a pending access request and delete it. No email is sent.",
        "python -m app.cli reject 665f0c2b3d4e5f60718293a4",
    )
    p.add_argument("request_id", metavar="REQUEST_ID", help="pending access-request id (from `list`)")

    p = _add_command(
        sub, "status",
        "Show invite delivery / acceptance state for an email",
        "Show the latest invite's email-delivery and account-acceptance state "
        "for an invited email address.",
        "python -m app.cli status owner@acme.com",
    )
    p.add_argument("email", metavar="EMAIL", help="invited email address")

    p = _add_command(
        sub, "email",
        "Send an SMTP diagnostic and show email settings",
        "Show the effective email configuration and send a real diagnostic "
        "message to confirm SMTP handoff.",
        "python -m app.cli email ops@example.com",
    )
    p.add_argument("to", metavar="TO", help="recipient for the diagnostic email")

    p = _add_command(
        sub, "set-limit",
        "Set a workspace's member limit",
        "Set the vendor-controlled member limit for one existing workspace.",
        "python -m app.cli set-limit 665f1a0b2c3d4e5f60718293 25",
    )
    p.add_argument("org_id", metavar="ORG_ID", help="workspace organization id")
    p.add_argument("limit", type=_member_limit, metavar="LIMIT", help="new member limit, 1–10000")

    _add_command(
        sub, "purge",
        "Run one scan-data retention purge pass",
        "Run a single scan-data retention purge pass across all workspaces.",
        "python -m app.cli purge",
    )

    return parser


def _canonicalize_command(arguments: list[str]) -> list[str]:
    if not arguments:
        return arguments
    command = _COMMAND_ALIASES.get(arguments[0], arguments[0])
    return [command, *arguments[1:]]


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    arguments = list(sys.argv[1:] if argv is None else argv)
    args = parser.parse_args(_canonicalize_command(arguments))

    cmd = args.command

    if cmd == "list":
        return asyncio.run(_list_access_requests(args.limit))
    if cmd == "approve":
        return asyncio.run(_approve_access_request(args.request_id, args.member_limit))
    if cmd == "reject":
        return asyncio.run(_reject_access_request(args.request_id))
    if cmd == "email":
        return _email_check(args.to)
    if cmd == "status":
        return asyncio.run(_invite_status(args.email))
    if cmd == "purge":
        return asyncio.run(_purge_retention())
    if cmd == "set-limit":
        return asyncio.run(_set_member_limit(args.org_id, args.limit))
    parser.error(f"unknown command: {cmd}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
