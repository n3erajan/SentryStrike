from datetime import datetime, timezone
from enum import Enum

from beanie import Document, Indexed
from pydantic import Field


class UserRole(str, Enum):
    """A member's role within their organization.

    One user belongs to exactly one organization with exactly one role
    (removing a member deletes their account, so cross-org membership can
    never arise). The role gates *actions*, not visibility: every member can
    see all scans and findings in their org, but only some may launch scans,
    manage members, or configure the workspace.
    """

    owner = "owner"
    admin = "admin"
    analyst = "analyst"
    developer = "developer"
    viewer = "viewer"


class User(Document):
    """A registered account that belongs to one organization and can submit scans."""

    email: Indexed(str, unique=True)
    full_name: str
    password_hash: str
    org_id: Indexed(str)
    role: UserRole
    is_active: bool = True
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    class Settings:
        name = "users"
        indexes = ["email", "org_id", [("created_at", -1)]]


class UserSession(Document):
    """A server-side session token issued after successful authentication.

    Only the SHA-256 hash of the bearer token is stored, so a database leak
    does not expose usable credentials. Sessions support explicit revocation
    and track last-use for auditing.
    """

    user_id: Indexed(str)
    token_hash: Indexed(str, unique=True)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime
    revoked_at: datetime | None = None
    last_used_at: datetime | None = None

    class Settings:
        name = "user_sessions"
        indexes = ["user_id", "token_hash", [("expires_at", 1)]]
