from datetime import datetime, timezone

from beanie import Document, Indexed
from pydantic import Field


class Application(Document):
    """A web application entity owned by an organization.

    Stores the target URL and default scan configuration for repeated assessments.
    """

    name: str
    target_url: Indexed(str)
    org_id: Indexed(str)
    default_scan_config: dict = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    class Settings:
        name = "applications"
        indexes = [
            "org_id",
            "target_url",
            [("org_id", 1), ("created_at", -1)],
        ]
