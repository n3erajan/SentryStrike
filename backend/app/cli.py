"""Management CLI for vendor-only operations.

Owner onboarding has no web UI: the vendor invites a business owner from a shell
inside the backend container. Access *is* container access, so there is no HTTP
surface to secure.

Usage::

    python -m app.cli invite-owner --email owner@acme.com --org "Acme Corp"

Creates a pending owner invite, prints the signup link, and emails it when a
real (SMTP) email backend is configured. The owner accepts by registering with
the invited email, which creates the workspace and their owner account together.
"""

from __future__ import annotations

import argparse
import asyncio
import sys

from app.core.email import get_email_backend
from app.core.invites import InviteError, InviteService, build_invite_link
from app.core.retention import RetentionService
from shared.database.connection import close_db, init_db
from shared.models.user import UserRole


def _render_invite_email(org_name: str, link: str | None, token: str) -> tuple[str, str]:
    """Return (subject, body) for the owner invitation email."""
    subject = f"You're invited to set up the {org_name} workspace on SentryStrike"
    where = link or f"your SentryStrike signup page with this invite token:\n\n    {token}"
    body = (
        f"Hello,\n\n"
        f"You've been invited to create and own the '{org_name}' workspace on "
        f"SentryStrike.\n\n"
        f"To accept, complete registration here:\n\n    {where}\n\n"
        f"This link is single-use and will expire. If you weren't expecting this, "
        f"you can ignore this email.\n"
    )
    return subject, body


async def _invite_owner(email: str, org: str) -> int:
    await init_db()
    try:
        service = InviteService()
        try:
            token, _invite = await service.create_invite(
                email=email,
                role=UserRole.owner,
                org_id=None,
                org_name=org,
                invited_by_user_id=None,
            )
        except InviteError as exc:
            print(f"Error: {exc.message}", file=sys.stderr)
            return 1

        link = build_invite_link(token)
        subject, body = _render_invite_email(org, link, token)

        # Always show the operator the link/token, then attempt delivery.
        print(f"Owner invite created for {email} (workspace: {org!r}).")
        if link:
            print(f"Invite link: {link}")
        else:
            print("PUBLIC_HOSTNAME is not set; share this invite token directly:")
            print(f"  {token}")

        try:
            get_email_backend().send(to=email, subject=subject, body_text=body)
            print(f"Invitation email dispatched to {email}.")
        except Exception as exc:  # noqa: BLE001 — surface any delivery failure to the operator
            print(f"Warning: could not send email ({exc}). The link above is still valid.", file=sys.stderr)
        return 0
    finally:
        await close_db()


async def _purge_retention() -> int:
    await init_db()
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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="app.cli", description="SentryStrike management CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    invite = sub.add_parser("invite-owner", help="Invite a business owner to create a new workspace")
    invite.add_argument("--email", required=True, help="Email address of the owner to invite")
    invite.add_argument("--org", required=True, help="Name of the workspace the owner will create")

    sub.add_parser("purge-retention", help="Run one scan-data retention purge pass across all workspaces")

    args = parser.parse_args(argv)

    if args.command == "invite-owner":
        return asyncio.run(_invite_owner(args.email, args.org))
    if args.command == "purge-retention":
        return asyncio.run(_purge_retention())
    parser.error(f"unknown command: {args.command}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
