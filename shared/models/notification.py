from datetime import datetime, timezone
from enum import Enum

from beanie import Document, Indexed
from pydantic import Field


class NotificationType(str, Enum):
    scan_completed = "scan_completed"
    scan_failed = "scan_failed"
    scan_cancelled = "scan_cancelled"
    finding_assigned = "finding_assigned"
    finding_commented = "finding_commented"
    remediation_status_changed = "remediation_status_changed"
    reverification_completed = "reverification_completed"
    member_role_changed = "member_role_changed"


class Notification(Document):
    """Durable, tenant-scoped notification consumed through the pull API."""

    org_id: Indexed(str)
    recipient_user_id: Indexed(str)
    type: NotificationType
    title: str
    message: str
    resource_type: str | None = None
    resource_id: str | None = None
    metadata: dict = Field(default_factory=dict)
    dedupe_key: Indexed(str, unique=True)
    read_at: datetime | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    class Settings:
        name = "notifications"
        indexes = [
            "org_id",
            "recipient_user_id",
            "dedupe_key",
            [("org_id", 1), ("recipient_user_id", 1), ("created_at", -1)],
            [("org_id", 1), ("recipient_user_id", 1), ("read_at", 1)],
        ]
