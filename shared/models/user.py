from datetime import datetime, timezone

from beanie import Document, Indexed
from pydantic import Field


class User(Document):
    """A registered account that can own and launch scans."""

    email: Indexed(str, unique=True)
    password_hash: str
    is_active: bool = True
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    class Settings:
        name = "users"
        indexes = ["email", [("created_at", -1)]]


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
