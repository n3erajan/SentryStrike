from datetime import datetime, timezone
from enum import Enum

from beanie import Document, Indexed
from pydantic import Field

from shared.models.user import UserRole


class InviteState(str, Enum):
    """Lifecycle state of an invitation from issue to a terminal state."""

    pending = "pending"
    accepted = "accepted"
    cancelled = "cancelled"
    expired = "expired"


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
    role: UserRole
    token_hash: Indexed(str, unique=True)
    state: InviteState = InviteState.pending
    expires_at: datetime
    invited_by_user_id: str | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    class Settings:
        name = "invites"
        indexes = ["email", "token_hash", [("created_at", -1)]]
