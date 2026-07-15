from datetime import datetime, timezone

from beanie import Document, Indexed
from pydantic import Field


class User(Document):
    email: Indexed(str, unique=True)
    password_hash: str
    is_active: bool = True
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    class Settings:
        name = "users"
        indexes = ["email", [("created_at", -1)]]


class UserSession(Document):
    user_id: Indexed(str)
    token_hash: Indexed(str, unique=True)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime
    revoked_at: datetime | None = None
    last_used_at: datetime | None = None

    class Settings:
        name = "user_sessions"
        indexes = ["user_id", "token_hash", [("expires_at", 1)]]
