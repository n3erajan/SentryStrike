import logging

from shared.models.audit import AuditAction, AuditLogEntry

logger = logging.getLogger(__name__)


class AuditRepository:
    """Append-only persistence for the workspace audit log.

    Writes are best-effort: a failure to record an audit entry is logged but
    never propagated, so an audit-store hiccup can never break the primary
    action being audited (removing a member, launching a scan, etc.). Reads are
    always org-scoped.
    """

    async def record(
        self,
        *,
        org_id: str,
        action: AuditAction,
        actor_user_id: str | None = None,
        actor_email: str | None = None,
        target_type: str | None = None,
        target_id: str | None = None,
        metadata: dict | None = None,
    ) -> AuditLogEntry | None:
        """Append one audit entry, swallowing (and logging) any write failure."""
        try:
            entry = AuditLogEntry(
                org_id=org_id,
                action=action,
                actor_user_id=actor_user_id,
                actor_email=actor_email,
                target_type=target_type,
                target_id=target_id,
                metadata=metadata or {},
            )
            await entry.insert()
        except Exception:  # noqa: BLE001 — auditing must never break the audited action
            logger.exception("failed to record audit entry action=%s org=%s", action.value, org_id)
            return None
        return entry

    async def list_in_org(self, org_id: str, skip: int = 0, limit: int = 50) -> list[AuditLogEntry]:
        """List an org's audit entries, newest first."""
        return (
            await AuditLogEntry.find(AuditLogEntry.org_id == org_id)
            .sort(-AuditLogEntry.created_at)
            .skip(skip)
            .limit(limit)
            .to_list()
        )
