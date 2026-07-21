"""Invitation lifecycle: issue, validate, accept, and cancel.

Registration is invite-only. An invite pins an email and a role at issue time;
the registrant can change neither. Only the SHA-256 hash of the token is stored
(mirroring ``UserSession``), so the raw token exists only in the emailed link.

Two tiers issue invites:

* **Vendor -> owner** (via the management CLI): ``org_id`` is None and
  ``org_name`` carries the workspace name. Accepting it creates the
  ``Organization`` and the owner ``User`` together.
* **Owner/Admin -> member**: ``org_id`` targets an existing workspace; accepting
  it creates a member ``User`` with the pinned role.
"""

from __future__ import annotations

import hashlib
import secrets
from datetime import timedelta

from app.config import get_settings
from app.core.auth import AuthError, as_utc_naive, hash_password, normalize_email, utc_now
from shared.config import get_infrastructure_settings
from shared.models.invite import Invite, InviteState
from shared.models.organization import Organization
from shared.models.user import User, UserRole


class InviteError(AuthError):
    """Base for invite failures."""

    status_code = 400
    message = "Invite error"


class InvalidInviteError(InviteError):
    """The token is unknown, already used, cancelled, or expired."""

    status_code = 400
    message = "This invite link is invalid or has expired."


class InviteEmailMismatchError(InviteError):
    """Registration email does not match the invited address."""

    status_code = 400
    message = "This invite was issued to a different email address."


class DuplicateUserError(InviteError):
    """An account with the invited email already exists."""

    status_code = 409
    message = "An account with this email already exists."


def _new_token() -> str:
    """Generate a cryptographically random, URL-safe invite token."""
    return secrets.token_urlsafe(48)


def hash_invite_token(token: str) -> str:
    """Return the SHA-256 hash of an invite token for server-side storage."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def build_invite_link(token: str) -> str | None:
    """Construct the public invite link, or None if no PUBLIC_HOSTNAME is set.

    e.g. ``https://sentry.example.com/signup?invite=<token>``. When the hostname
    is unset (local dev), returns None and callers surface the raw token instead.
    """
    base = get_infrastructure_settings().public_base_url
    if not base:
        return None
    path = get_settings().invite_signup_path
    if not path.startswith("/"):
        path = f"/{path}"
    return f"{base}{path}?invite={token}"


class InviteService:
    """Application logic for issuing, validating, accepting, and cancelling invites."""

    async def create_invite(
        self,
        *,
        email: str,
        role: UserRole,
        org_id: str | None,
        org_name: str | None,
        invited_by_user_id: str | None,
    ) -> tuple[str, Invite]:
        """Create a pending invite and return the raw token alongside the record.

        The raw token is returned only here (for the link) and never persisted.
        Refuses to invite an email that already has an account.
        """
        normalized = normalize_email(email)
        existing = await User.find_one(User.email == normalized)
        if existing is not None:
            raise DuplicateUserError()

        token = _new_token()
        settings = get_settings()
        invite = Invite(
            email=normalized,
            org_id=org_id,
            org_name=org_name,
            role=role,
            token_hash=hash_invite_token(token),
            state=InviteState.pending,
            expires_at=utc_now() + timedelta(hours=settings.invite_ttl_hours),
            invited_by_user_id=invited_by_user_id,
        )
        await invite.insert()
        return token, invite

    async def _resolve_pending(self, token: str | None) -> Invite:
        """Return the pending, unexpired invite for a token, or raise.

        An expired-but-still-pending invite is transitioned to ``expired`` so it
        cannot be retried and the state reflects reality.
        """
        if not token:
            raise InvalidInviteError()
        invite = await Invite.find_one(Invite.token_hash == hash_invite_token(token))
        if invite is None or invite.state != InviteState.pending:
            raise InvalidInviteError()
        expires_at = as_utc_naive(invite.expires_at)
        if expires_at is None or expires_at <= utc_now():
            invite.state = InviteState.expired
            await invite.save()
            raise InvalidInviteError()
        return invite

    async def preview(self, token: str | None) -> Invite:
        """Validate a token without consuming it (for the signup form to prefill)."""
        return await self._resolve_pending(token)

    async def accept(self, *, token: str | None, email: str, password: str) -> User:
        """Consume a pending invite, creating the org (owner) and/or the user.

        The submitted email must match the invited address exactly. The role is
        taken from the invite, never from the caller. On success the invite is
        marked ``accepted``.
        """
        invite = await self._resolve_pending(token)
        normalized = normalize_email(email)
        if normalized != invite.email:
            raise InviteEmailMismatchError()
        if await User.find_one(User.email == normalized) is not None:
            raise DuplicateUserError()

        if invite.role == UserRole.owner:
            user = await self._accept_owner(invite, normalized, password)
        else:
            user = await self._accept_member(invite, normalized, password)

        invite.state = InviteState.accepted
        await invite.save()
        return user

    async def _accept_owner(self, invite: Invite, email: str, password: str) -> User:
        """Create the workspace and its owner together from an owner invite."""
        org = Organization(name=invite.org_name or "Workspace", owner_user_id="")
        await org.insert()
        user = User(
            email=email,
            password_hash=hash_password(password),
            org_id=str(org.id),
            role=UserRole.owner,
        )
        await user.insert()
        # Backfill the owner id now that the user exists.
        org.owner_user_id = str(user.id)
        org.updated_at = utc_now()
        await org.save()
        return user

    async def _accept_member(self, invite: Invite, email: str, password: str) -> User:
        """Create a member user in the invite's existing organization."""
        if not invite.org_id:
            # A non-owner invite must target an existing org; a missing org_id is
            # a malformed invite that must never silently create a new workspace.
            raise InvalidInviteError()
        user = User(
            email=email,
            password_hash=hash_password(password),
            org_id=invite.org_id,
            role=invite.role,
        )
        await user.insert()
        return user

    async def cancel(self, invite: Invite) -> Invite:
        """Invalidate a pending invite so its token no longer accepts."""
        if invite.state == InviteState.pending:
            invite.state = InviteState.cancelled
            await invite.save()
        return invite
