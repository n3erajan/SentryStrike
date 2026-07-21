from datetime import datetime, timezone
from enum import Enum

from beanie import Document, Indexed
from pydantic import Field


class AuditAction(str, Enum):
    """The compliance-relevant actions recorded in the append-only audit log.

    Every entry names *who* did *what* to *which* target, within one org. The
    set is deliberately closed: adding an action here is a deliberate decision
    about what the workspace considers auditable.
    """

    invite_created = "invite_created"
    invite_cancelled = "invite_cancelled"
    member_removed = "member_removed"
    member_role_changed = "member_role_changed"
    scan_created = "scan_created"
    scan_cancelled = "scan_cancelled"
    finding_reverification_created = "finding_reverification_created"
    scan_purged = "scan_purged"


class AuditLogEntry(Document):
    """An append-only record of a compliance-relevant action within a workspace.

    Entries are never mutated or deleted by application code (they outlive the
    scans and members they reference — a removed member's id still appears here).
    Each is scoped to one ``org_id``; ``actor_*`` identifies who performed it
    (None for system actions like the retention purge), and ``metadata`` carries
    action-specific context (e.g. the old/new role, the purged scan's target).
    """

    org_id: Indexed(str)
    action: AuditAction
    actor_user_id: str | None = None
    actor_email: str | None = None
    target_type: str | None = None
    target_id: str | None = None
    metadata: dict = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    class Settings:
        name = "audit_log"
        indexes = ["org_id", [("created_at", -1)]]
