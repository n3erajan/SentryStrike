from __future__ import annotations

from datetime import datetime, timezone

from beanie import PydanticObjectId

from shared.models.scan import CrawlMode, Scan, ScanAuthRole, ScanPhase, ScanStatus


class ScanRepository:
    """Persistence layer for Scan documents.

    Centralizes all database access for scans so that both the API and the
    worker operate on the same query logic (workspace scoping, lifecycle
    timestamps, status transitions) rather than duplicating it per service.
    """

    async def create(
        self,
        target_url: str,
        *,
        org_id: str,
        submitted_by_user_id: str,
        submitted_by_full_name: str,
        submitted_by_email: str,
        authorization_confirmed: bool,
        crawl_mode: CrawlMode = CrawlMode.full,
        auth_roles_provided: list[ScanAuthRole] | None = None,
    ) -> Scan:
        now = datetime.now(timezone.utc)
        scan = Scan(
            target_url=target_url,
            org_id=org_id,
            submitted_by_user_id=submitted_by_user_id,
            submitted_by_full_name=submitted_by_full_name,
            submitted_by_email=submitted_by_email,
            crawl_mode=crawl_mode,
            status=ScanStatus.queued,
            authorization_confirmed=authorization_confirmed,
            authorization_confirmed_at=now if authorization_confirmed else None,
            auth_roles_provided=auth_roles_provided or [],
        )
        await scan.insert()
        return scan

    async def get_by_id(self, scan_id: str) -> Scan | None:
        """Fetch a scan by its string id, returning None for malformed ids."""
        try:
            oid = PydanticObjectId(scan_id)
        except Exception:
            return None
        return await Scan.get(oid)

    async def get_in_org(self, scan_id: str, org_id: str) -> Scan | None:
        """Fetch a scan only if it belongs to the given organization.

        Returns None when the scan does not exist or belongs to another org,
        so callers cannot distinguish between the two cases (a member of one
        workspace cannot probe for the existence of another workspace's scans).
        """
        try:
            oid = PydanticObjectId(scan_id)
        except Exception:
            return None
        return await Scan.find_one(Scan.id == oid, Scan.org_id == org_id)

    async def list(self, org_id: str, skip: int = 0, limit: int = 20) -> list[Scan]:
        """List scans for an organization (all members share one view), newest first.

        The organization id is mandatory: cross-tenant listing is not a valid
        repository operation.
        """
        return await Scan.find(Scan.org_id == org_id).sort(-Scan.created_at).skip(skip).limit(limit).to_list()

    async def list_expired(self, org_id: str, cutoff: datetime) -> list[Scan]:
        """List an org's scans created strictly before ``cutoff`` (retention purge).

        The comparison runs in MongoDB against the stored UTC ``created_at``; a
        timezone-aware ``cutoff`` is converted to UTC by the driver.
        """
        return await Scan.find(Scan.org_id == org_id, Scan.created_at < cutoff).to_list()

    async def attach_reverification_job(
        self,
        *,
        scan_id: str,
        org_id: str,
        vulnerability_id: str,
        job_id: str,
    ) -> bool:
        """Atomically attach a verification-history reference to one finding."""
        try:
            oid = PydanticObjectId(scan_id)
        except Exception:
            return False
        result = await Scan.get_motor_collection().update_one(
            {
                "_id": oid,
                "org_id": org_id,
                "vulnerabilities.id": vulnerability_id,
            },
            {
                "$addToSet": {
                    "vulnerabilities.$.reverification_job_ids": job_id,
                },
                "$set": {"updated_at": datetime.now(timezone.utc)},
            },
        )
        return result.modified_count == 1

    async def update_status(
        self,
        scan: Scan,
        status: ScanStatus,
        progress: int | None = None,
        current_phase: ScanPhase | None = None,
        phase_message: str | None = None,
        error_message: str | None = None,
    ) -> Scan:
        """Transition a scan to a new status and stamp lifecycle timestamps.

        ``started_at`` is recorded the first time a scan enters ``running``;
        ``completed_at`` is recorded on any terminal state (completed, failed,
        or cancelled). Optional fields are only overwritten when provided, so
        callers can update a single attribute without clobbering the rest.
        """
        scan.status = status
        if progress is not None:
            scan.progress = progress
        if current_phase is not None:
            scan.current_phase = current_phase
        if phase_message is not None:
            scan.phase_message = phase_message
        if status == ScanStatus.running and scan.started_at is None:
            scan.started_at = datetime.now(timezone.utc)
        if status in {ScanStatus.completed, ScanStatus.failed, ScanStatus.cancelled}:
            scan.completed_at = datetime.now(timezone.utc)
        if error_message:
            scan.error_message = error_message
        scan.updated_at = datetime.now(timezone.utc)
        await scan.save()
        return scan

    async def reconcile_if_orphaned(self, scan: Scan, queue) -> Scan:
        """Fail a scan whose worker has died, detected via a missing lease.

        A running scan is backed by a short-TTL Redis lease that its worker
        renews on a timer. If the worker crashes, the lease expires and the DB
        is left showing ``running`` forever — the UI then polls indefinitely and
        cancelling only sets a key no worker will read. This reconciles that
        lazily at read time: a ``running`` scan with a provably-absent lease is
        transitioned to ``failed`` with a clear message.

        Fail-safe against Redis outages: the scan is only failed when the lease
        is *positively confirmed absent* (Redis reachable, key missing). If the
        lease check raises (Redis unavailable), we cannot distinguish a dead
        worker from an unreachable Redis, so the scan is left untouched — a
        transient Redis blip must never mass-fail live scans.

        Only ``running`` scans are candidates. ``queued`` scans have no worker
        (and no lease) yet, and terminal scans are already resolved.
        """
        if scan.status != ScanStatus.running:
            return scan
        try:
            lease_alive = await queue.is_lease_alive(str(scan.id))
        except Exception:
            # Can't tell (Redis down / queue error) -> do not touch the scan.
            return scan
        if lease_alive:
            return scan
        return await self.update_status(
            scan,
            ScanStatus.failed,
            current_phase=ScanPhase.failed,
            phase_message="Scan worker stopped unexpectedly",
            error_message=(
                "Scan worker stopped unexpectedly; no active worker is "
                "processing this scan."
            ),
        )
