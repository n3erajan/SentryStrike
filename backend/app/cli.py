"""Management CLI for vendor-only operations.

Owner onboarding has no web UI: the vendor invites a business owner from a shell
inside the backend container. Access *is* container access, so there is no HTTP
surface to secure.

Usage::

    python -m app.cli invite-owner --email owner@acme.com --org "Acme Corp" --member-limit 100
    python -m app.cli email-check --to operator@example.com
    python -m app.cli invite-status --email owner@acme.com
    python -m app.cli set-member-limit --org-id <organization-id> --limit 25

Creates a pending owner invite, prints the signup link, and emails it when a
real (SMTP) email backend is configured. The owner accepts by registering with
the invited email, which creates the workspace and their owner account together.
"""

from __future__ import annotations

import argparse
import asyncio
import sys

from app.config import get_settings
from app.core.auth import normalize_email
from app.core.email import get_email_backend, render_workspace_invite_email
from app.core.invites import InviteError, InviteService, build_invite_link
from app.core.retention import RetentionService
from shared.database.connection import close_db, init_db
from shared.database.repositories.organization_repository import OrganizationRepository
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


async def _invite_owner(email: str, org: str, member_limit: int) -> int:
    await init_db(get_settings())
    try:
        if not 1 <= member_limit <= 10000:
            print("Error: member-limit must be between 1 and 10000.", file=sys.stderr)
            return 1
        service = InviteService()
        try:
            token, invite, retried = await service.create_or_retry_owner_invite(
                email=email,
                org_name=org,
                member_limit=member_limit,
            )
        except InviteError as exc:
            print(f"Error: {exc.message}", file=sys.stderr)
            return 1

        link = build_invite_link(token)
        subject, body_text, body_html = render_workspace_invite_email(
            org_name=org,
            role="owner",
            link=link,
            token=token,
            owns_workspace=True,
        )

        # Always show the operator the link/token, then attempt delivery.
        action = "reused after failed delivery" if retried else "created"
        print(
            f"Owner invite {action} for {email} (workspace: {org!r}, "
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
                to=email,
                subject=subject,
                body_text=body_text,
                body_html=body_html,
            )
        except Exception as exc:  # noqa: BLE001 — surface any delivery failure to the operator
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
            f"SMTP server accepted the invitation for {email}. "
            "This confirms server handoff, not inbox delivery."
        )
        return 0
    finally:
        await close_db()


def _email_check(to: str) -> int:
    """Show effective email configuration and send a real diagnostic message."""
    try:
        settings = get_settings()
        backend = get_email_backend()
    except Exception as exc:  # noqa: BLE001 — settings validation is operator-facing here
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
    except Exception as exc:  # noqa: BLE001 — exact SMTP failure is useful to the operator
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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="app.cli", description="SentryStrike management CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    invite = sub.add_parser("invite-owner", help="Invite a business owner to create a new workspace")
    invite.add_argument("--email", required=True, help="Email address of the owner to invite")
    invite.add_argument("--org", required=True, help="Name of the workspace the owner will create")
    invite.add_argument(
        "--member-limit",
        type=_member_limit,
        default=10,
        help="Initial workspace member limit (1–10000), including the owner and pending invites (default: 10)",
    )

    email_check = sub.add_parser(
        "email-check", help="Show effective email settings and send an SMTP diagnostic"
    )
    email_check.add_argument("--to", required=True, help="Recipient for the diagnostic email")

    invite_status = sub.add_parser(
        "invite-status", help="Show email delivery and acceptance state for the latest invite"
    )
    invite_status.add_argument("--email", required=True, help="Invited email address")

    sub.add_parser("purge-retention", help="Run one scan-data retention purge pass across all workspaces")

    member_limit = sub.add_parser(
        "set-member-limit", help="Set the vendor-controlled member limit for a workspace"
    )
    member_limit.add_argument("--org-id", required=True, help="Workspace organization id")
    member_limit.add_argument(
        "--limit", required=True, type=_member_limit, help="Member limit (1–10000)"
    )

    args = parser.parse_args(argv)

    if args.command == "invite-owner":
        return asyncio.run(_invite_owner(args.email, args.org, args.member_limit))
    if args.command == "email-check":
        return _email_check(args.to)
    if args.command == "invite-status":
        return asyncio.run(_invite_status(args.email))
    if args.command == "purge-retention":
        return asyncio.run(_purge_retention())
    if args.command == "set-member-limit":
        return asyncio.run(_set_member_limit(args.org_id, args.limit))
    parser.error(f"unknown command: {args.command}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
