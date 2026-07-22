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
from pymongo.errors import DuplicateKeyError

from app.config import get_settings
from app.core.auth import AuthError, as_utc_naive, hash_password, normalize_email, utc_now
from app.core.invite_rate_limit import (
    InviteRateLimitExceeded,
    InviteRateLimiterUnavailable,
    RedisInviteRateLimiter,
)
from shared.database.repositories.organization_repository import OrganizationRepository
from shared.models.invite import Invite, InviteEmailStatus, InviteState
from shared.models.organization import Organization
from shared.models.organization import DEFAULT_MEMBER_LIMIT
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


class DuplicatePendingInviteError(InviteError):
    status_code = 409
    message = "A pending invitation already exists for this email."


class WorkspaceMemberLimitError(InviteError):
    status_code = 409
    message = "This workspace has reached its member limit."


class InviteThrottleError(InviteError):
    status_code = 429
    message = "Too many invitation attempts. Please try again later."

    def __init__(self, retry_after: int) -> None:
        self.retry_after = retry_after


class InviteServiceUnavailableError(InviteError):
    status_code = 503
    message = "Invitation service is temporarily unavailable."


def _new_token() -> str:
    """Generate a cryptographically random, URL-safe invite token."""
    return secrets.token_urlsafe(48)


def hash_invite_token(token: str) -> str:
    """Return the SHA-256 hash of an invite token for server-side storage."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def build_invite_link(token: str) -> str | None:
    """Construct the public invite link, or None if no PUBLIC_HOSTNAME is set.

    e.g. ``https://sentry.example.com/register?invite=<token>``. When the hostname
    is unset (local dev), returns None and callers surface the raw token instead.
    """
    base = get_settings().public_base_url
    if not base:
        return None
    return f"{base}/register?invite={token}"


class InviteService:
    """Application logic for issuing, validating, accepting, and cancelling invites."""

    def __init__(self, rate_limiter: RedisInviteRateLimiter | None = None) -> None:
        self.rate_limiter = rate_limiter
        self.organizations = OrganizationRepository()

    async def close(self) -> None:
        if self.rate_limiter is not None:
            await self.rate_limiter.close()

    async def record_email_delivery(
        self,
        invite: Invite,
        *,
        status: InviteEmailStatus,
        backend: str,
        error: str | None = None,
    ) -> Invite:
        """Persist the latest known email handoff result for an invitation."""
        attempted_at = utc_now()
        safe_error = error[:1000] if error else None
        result = await Invite.get_motor_collection().update_one(
            {"_id": invite.id},
            {
                "$set": {
                    "email_delivery_status": status.value,
                    "email_delivery_backend": backend,
                    "email_delivery_attempted_at": attempted_at,
                    "email_delivery_error": safe_error,
                }
            },
        )
        if result.matched_count != 1:
            raise RuntimeError(f"Invite {invite.id} disappeared while recording email delivery")
        invite.email_delivery_status = status
        invite.email_delivery_backend = backend
        invite.email_delivery_attempted_at = attempted_at
        invite.email_delivery_error = safe_error
        return invite

    async def expire_pending_member_invites(self, org_id: str) -> None:
        """Expire stale member invites and release only seats this call transitions."""
        stale = await Invite.find(
            Invite.org_id == org_id,
            Invite.state == InviteState.pending,
            Invite.expires_at <= utc_now(),
        ).to_list()
        for invite in stale:
            result = await Invite.get_motor_collection().update_one(
                {"_id": invite.id, "state": InviteState.pending.value},
                {
                    "$set": {"state": InviteState.expired.value},
                    "$unset": {"pending_key": ""},
                },
            )
            if result.modified_count == 1:
                await self.organizations.release_member_seat(org_id)

    async def create_or_retry_owner_invite(
        self,
        *,
        email: str,
        org_name: str,
        member_limit: int,
    ) -> tuple[str, Invite, bool]:
        """Create an owner invite or rotate the token on its failed pending record."""
        normalized = normalize_email(email)
        if await User.find_one(User.email == normalized) is not None:
            raise DuplicateUserError()

        pending = await Invite.find_one(
            Invite.email == normalized,
            Invite.role == UserRole.owner,
            Invite.state == InviteState.pending,
        )
        if pending is not None:
            expires_at = as_utc_naive(pending.expires_at)
            if expires_at is None or expires_at <= utc_now():
                expired = await Invite.get_motor_collection().update_one(
                    {"_id": pending.id, "state": InviteState.pending.value},
                    {
                        "$set": {"state": InviteState.expired.value},
                        "$unset": {"pending_key": ""},
                    },
                )
                if expired.modified_count != 1:
                    raise DuplicatePendingInviteError()
            elif pending.email_delivery_status in {
                InviteEmailStatus.failed,
                InviteEmailStatus.not_attempted,
            }:
                token = _new_token()
                retry_expires_at = utc_now() + timedelta(hours=get_settings().invite_ttl_hours)
                try:
                    retried = await Invite.get_motor_collection().update_one(
                        {
                            "_id": pending.id,
                            "state": InviteState.pending.value,
                            "email_delivery_status": {
                                "$in": [
                                    InviteEmailStatus.failed.value,
                                    InviteEmailStatus.not_attempted.value,
                                ]
                            },
                        },
                        {
                            "$set": {
                                "org_name": org_name,
                                "member_limit": member_limit,
                                "token_hash": hash_invite_token(token),
                                "pending_key": f"owner:{normalized}",
                                "expires_at": retry_expires_at,
                                "email_delivery_status": InviteEmailStatus.not_attempted.value,
                                "email_delivery_backend": None,
                                "email_delivery_attempted_at": None,
                                "email_delivery_error": None,
                            }
                        },
                    )
                except DuplicateKeyError as exc:
                    raise DuplicatePendingInviteError() from exc
                if retried.modified_count != 1:
                    raise DuplicatePendingInviteError()
                pending.org_name = org_name
                pending.member_limit = member_limit
                pending.token_hash = hash_invite_token(token)
                pending.pending_key = f"owner:{normalized}"
                pending.expires_at = retry_expires_at
                pending.email_delivery_status = InviteEmailStatus.not_attempted
                pending.email_delivery_backend = None
                pending.email_delivery_attempted_at = None
                pending.email_delivery_error = None
                return token, pending, True
            else:
                raise DuplicatePendingInviteError()

        token, invite = await self.create_invite(
            email=normalized,
            role=UserRole.owner,
            org_id=None,
            org_name=org_name,
            invited_by_user_id=None,
            member_limit=member_limit,
        )
        return token, invite, False

    async def create_invite(
        self,
        *,
        email: str,
        role: UserRole,
        org_id: str | None,
        org_name: str | None,
        invited_by_user_id: str | None,
        member_limit: int | None = None,
    ) -> tuple[str, Invite]:
        """Create a pending invite and return the raw token alongside the record.

        The raw token is returned only here (for the link) and never persisted.
        Refuses to invite an email that already has an account.
        """
        normalized = normalize_email(email)
        if org_id is not None and self.rate_limiter is not None:
            try:
                await self.rate_limiter.check(
                    org_id=org_id,
                    actor_user_id=invited_by_user_id or "unknown",
                )
            except InviteRateLimitExceeded as exc:
                raise InviteThrottleError(exc.retry_after) from exc
            except InviteRateLimiterUnavailable as exc:
                raise InviteServiceUnavailableError() from exc
        existing = await User.find_one(User.email == normalized)
        if existing is not None:
            raise DuplicateUserError()

        seat_reserved = False
        if org_id is not None:
            await self.expire_pending_member_invites(org_id)
            duplicate = await Invite.find_one(
                Invite.org_id == org_id,
                Invite.email == normalized,
                Invite.state == InviteState.pending,
                Invite.expires_at > utc_now(),
            )
            if duplicate is not None:
                raise DuplicatePendingInviteError()
            seat_reserved = await self.organizations.reserve_member_seat(org_id)
            if not seat_reserved:
                raise WorkspaceMemberLimitError()

        token = _new_token()
        settings = get_settings()
        invite = Invite(
            email=normalized,
            org_id=org_id,
            org_name=org_name,
            member_limit=member_limit if role == UserRole.owner else None,
            role=role,
            token_hash=hash_invite_token(token),
            pending_key=(
                f"{org_id}:{normalized}"
                if org_id is not None
                else f"owner:{normalized}"
            ),
            state=InviteState.pending,
            expires_at=utc_now() + timedelta(hours=settings.invite_ttl_hours),
            invited_by_user_id=invited_by_user_id,
        )
        try:
            await invite.insert()
        except DuplicateKeyError as exc:
            if seat_reserved and org_id is not None:
                await self.organizations.release_member_seat(org_id)
            raise DuplicatePendingInviteError() from exc
        except Exception:
            if seat_reserved and org_id is not None:
                await self.organizations.release_member_seat(org_id)
            raise
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
            result = await Invite.get_motor_collection().update_one(
                {"_id": invite.id, "state": InviteState.pending.value},
                {
                    "$set": {"state": InviteState.expired.value},
                    "$unset": {"pending_key": ""},
                },
            )
            if result.modified_count == 1 and invite.org_id:
                await self.organizations.release_member_seat(invite.org_id)
            raise InvalidInviteError()
        return invite

    async def preview(self, token: str | None) -> Invite:
        """Validate a token without consuming it (for the signup form to prefill)."""
        return await self._resolve_pending(token)

    async def accept(
        self,
        *,
        token: str | None,
        full_name: str,
        email: str,
        password: str,
    ) -> User:
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

        claimed = await Invite.get_motor_collection().update_one(
            {"_id": invite.id, "state": InviteState.pending.value},
            {"$set": {"state": InviteState.accepting.value}},
        )
        if claimed.modified_count != 1:
            raise InvalidInviteError()

        user: User | None = None
        try:
            if invite.role == UserRole.owner:
                user = await self._accept_owner(invite, full_name, normalized, password)
            else:
                user = await self._accept_member(invite, full_name, normalized, password)

            accepted = await Invite.get_motor_collection().update_one(
                {"_id": invite.id, "state": InviteState.accepting.value},
                {
                    "$set": {
                        "state": InviteState.accepted.value,
                        "accepted_user_id": str(user.id),
                    },
                    "$unset": {"pending_key": ""},
                },
            )
            if accepted.modified_count != 1:
                raise InvalidInviteError()
            return user
        except Exception:
            if user is not None:
                org_id = user.org_id
                await user.delete()
                if invite.role == UserRole.owner:
                    org = await self.organizations.get_by_id(org_id)
                    if org is not None:
                        await org.delete()
            await Invite.get_motor_collection().update_one(
                {"_id": invite.id, "state": InviteState.accepting.value},
                {"$set": {"state": InviteState.pending.value}},
            )
            raise

    async def _accept_owner(
        self,
        invite: Invite,
        full_name: str,
        email: str,
        password: str,
    ) -> User:
        """Create the workspace and its owner together from an owner invite."""
        org = Organization(
            name=invite.org_name or "Workspace",
            owner_user_id="",
            member_limit=invite.member_limit or DEFAULT_MEMBER_LIMIT,
            occupied_seats=1,
        )
        await org.insert()
        user: User | None = None
        try:
            user = User(
                full_name=full_name,
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
        except Exception:
            if user is not None and user.id is not None:
                await user.delete()
            await org.delete()
            raise

    async def _accept_member(
        self,
        invite: Invite,
        full_name: str,
        email: str,
        password: str,
    ) -> User:
        """Create a member user in the invite's existing organization."""
        if not invite.org_id:
            # A non-owner invite must target an existing org; a missing org_id is
            # a malformed invite that must never silently create a new workspace.
            raise InvalidInviteError()
        if await self.organizations.get_by_id(invite.org_id) is None:
            raise InvalidInviteError()
        user = User(
            full_name=full_name,
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
            result = await Invite.get_motor_collection().update_one(
                {"_id": invite.id, "state": InviteState.pending.value},
                {
                    "$set": {"state": InviteState.cancelled.value},
                    "$unset": {"pending_key": ""},
                },
            )
            if result.modified_count == 1:
                invite.state = InviteState.cancelled
                if invite.org_id:
                    await self.organizations.release_member_seat(invite.org_id)
        return invite
