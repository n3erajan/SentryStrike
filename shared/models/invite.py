from datetime import datetime, timezone
from enum import Enum

from beanie import Document, Indexed
from pymongo import IndexModel
from pydantic import Field

from shared.models.user import UserRole


class InviteState(str, Enum):
    """Lifecycle state of an invitation from issue to a terminal state."""

    pending = "pending"
    accepting = "accepting"
    accepted = "accepted"
    cancelled = "cancelled"
    expired = "expired"


class InviteEmailStatus(str, Enum):
    """What the application knows about the latest invite-email attempt."""

    not_attempted = "not_attempted"
    smtp_accepted = "smtp_accepted"
    failed = "failed"


class Invite(Document):
    """An email-bound, role-pinned invitation to join a workspace.

    Registration is only reachable by consuming a pending invite. The invited
    email and role are fixed at issue time — the registrant cannot change either.
    Only the SHA-256 hash of the invite token is stored, mirroring
    ``UserSession``, so a database leak does not expose usable invite links.

    Two tiers issue invites:

    * **Vendor -> owner** (via the management CLI): ``org_id`` is None because the
      org does not exist yet; ``org_name`` carries the name the ``Organization``
      will take on acceptance. ``invited_by_user_id`` is None.
    * **Owner/Admin -> member**: ``org_id`` points at the existing workspace and
      ``invited_by_user_id`` records the issuer.
    """

    email: Indexed(str)
    org_id: str | None = None
    org_name: str | None = None
    # Vendor-selected initial limit for an owner invite. Member invites leave it unset.
    member_limit: int | None = Field(default=None, ge=1)
    role: UserRole
    token_hash: Indexed(str, unique=True)
    # Sparse unique reservation key prevents concurrent duplicate pending member
    # invites for the same workspace/email. It is removed at every terminal state.
    pending_key: str | None = None
    state: InviteState = InviteState.pending
    expires_at: datetime
    invited_by_user_id: str | None = None
    accepted_user_id: str | None = None
    email_delivery_status: InviteEmailStatus = InviteEmailStatus.not_attempted
    email_delivery_backend: str | None = None
    email_delivery_attempted_at: datetime | None = None
    email_delivery_error: str | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    class Settings:
        name = "invites"
        indexes = [
            "email",
            "token_hash",
            IndexModel([("pending_key", 1)], unique=True, sparse=True),
            [("created_at", -1)],
        ]
