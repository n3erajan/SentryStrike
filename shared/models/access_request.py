from datetime import datetime, timezone

from beanie import Document
from pymongo import IndexModel
from pydantic import Field


class AccessRequest(Document):
    """A pending, vendor-reviewed request to create a workspace."""

    full_name: str = Field(min_length=2, max_length=120)
    email: str = Field(min_length=3, max_length=254)
    organization_name: str = Field(min_length=2, max_length=160)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime

    class Settings:
        name = "access_requests"
        indexes = [
            IndexModel([("email", 1)], unique=True),
            IndexModel([("created_at", -1)]),
            IndexModel([("expires_at", 1)], expireAfterSeconds=0),
        ]
