"""Per-org scan-data retention purge.

Each workspace keeps its scans for ``Organization.retention_days`` (never below
the ``MIN_RETENTION_DAYS`` compliance floor, enforced on write). This service
sweeps every org, deletes scans older than that window, and records one
``scan_purged`` audit entry per deleted scan so the deletion is itself
accountable. It is pure application logic — a caller (the periodic worker or the
management CLI) drives *when* it runs.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from shared.database.repositories.audit_repository import AuditRepository
from shared.database.repositories.organization_repository import OrganizationRepository
from shared.database.repositories.scan_repository import ScanRepository
from shared.models.audit import AuditAction

logger = logging.getLogger(__name__)


class RetentionService:
    """Deletes scans past each organization's retention window, with an audit trail."""

    def __init__(
        self,
        organization_repository: OrganizationRepository | None = None,
        scan_repository: ScanRepository | None = None,
        audit_repository: AuditRepository | None = None,
    ) -> None:
        self.orgs = organization_repository or OrganizationRepository()
        self.scans = scan_repository or ScanRepository()
        self.audit = audit_repository or AuditRepository()

    async def purge_once(self) -> dict[str, int]:
        """Run one purge pass over every org. Returns ``{org_id: scans_deleted}``.

        A failure purging one org is logged and skipped so it cannot stall the
        sweep for the others. Each deleted scan is audited before removal.
        """
        now = datetime.now(timezone.utc)
        summary: dict[str, int] = {}
        for org in await self.orgs.list_all():
            org_id = str(org.id)
            try:
                summary[org_id] = await self._purge_org(org_id, org.retention_days, now)
            except Exception:  # noqa: BLE001 — one org's failure must not stall the sweep
                logger.exception("retention purge failed for org %s", org_id)
                summary[org_id] = 0
        total = sum(summary.values())
        if total:
            logger.info("retention purge deleted %d scan(s) across %d org(s)", total, len(summary))
        return summary

    async def _purge_org(self, org_id: str, retention_days: int, now: datetime) -> int:
        """Purge one org's expired scans and return how many were deleted."""
        cutoff = now - timedelta(days=retention_days)
        expired = await self.scans.list_expired(org_id, cutoff)
        for scan in expired:
            await self.audit.record(
                org_id=org_id,
                action=AuditAction.scan_purged,
                target_type="scan",
                target_id=str(scan.id),
                metadata={
                    "target_url": getattr(scan, "target_url", None),
                    "created_at": getattr(scan, "created_at", None),
                    "retention_days": retention_days,
                },
            )
            await scan.delete()
        if expired:
            logger.info(
                "retention purge: org=%s deleted=%d cutoff=%s (retention_days=%d)",
                org_id, len(expired), cutoff.isoformat(), retention_days,
            )
        return len(expired)
