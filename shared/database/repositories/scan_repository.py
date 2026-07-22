from __future__ import annotations

from datetime import datetime, timezone

from beanie import PydanticObjectId

from shared.models.analysis_job import AnalysisStatus
from shared.models.scan import (
    CrawlMode,
    Scan,
    ScanAnalysisState,
    ScanAuthRole,
    ScanPhase,
    ScanStatus,
)
from shared.models.vulnerability import AiAnalysis


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

    async def attach_initial_analysis_job(
        self,
        *,
        scan_id: str,
        org_id: str,
        job_id: str,
        revision: int,
        queued_at: datetime,
    ) -> bool:
        """Attach revision 1 only while a completed scan has no analysis state."""
        try:
            oid = PydanticObjectId(scan_id)
        except Exception:
            return False
        now = datetime.now(timezone.utc)
        projection = ScanAnalysisState(
            status=AnalysisStatus.queued,
            current_job_id=job_id,
            revision=revision,
            progress=0,
            message="Analysis queued",
            queued_at=queued_at,
            updated_at=now,
        )
        result = await Scan.get_motor_collection().update_one(
            {
                "_id": oid,
                "org_id": org_id,
                "status": ScanStatus.completed.value,
                "$or": [
                    {"analysis": {"$exists": False}},
                    {"analysis": None},
                ],
            },
            {
                "$set": {
                    "analysis": projection.model_dump(mode="python"),
                    "updated_at": now,
                }
            },
        )
        return result.modified_count == 1

    async def attach_retry_analysis_job(
        self,
        *,
        scan_id: str,
        org_id: str,
        previous_job_id: str,
        previous_revision: int,
        job_id: str,
        revision: int,
        queued_at: datetime,
    ) -> bool:
        """CAS a specific failed current revision to one new queued revision."""
        try:
            oid = PydanticObjectId(scan_id)
        except Exception:
            return False
        now = datetime.now(timezone.utc)
        projection = ScanAnalysisState(
            status=AnalysisStatus.queued,
            current_job_id=job_id,
            revision=revision,
            progress=0,
            message="Analysis queued",
            queued_at=queued_at,
            updated_at=now,
        )
        result = await Scan.get_motor_collection().update_one(
            {
                "_id": oid,
                "org_id": org_id,
                "status": ScanStatus.completed.value,
                "analysis.current_job_id": previous_job_id,
                "analysis.revision": previous_revision,
                "analysis.status": AnalysisStatus.failed.value,
            },
            {
                "$set": {
                    "analysis": projection.model_dump(mode="python"),
                    "updated_at": now,
                }
            },
        )
        return result.modified_count == 1

    async def list_completed_without_analysis(self, limit: int = 100) -> list[Scan]:
        """Return completed scans whose post-completion job handoff was interrupted."""
        return await Scan.find(
            {
                "status": ScanStatus.completed.value,
                "$or": [
                    {"analysis": {"$exists": False}},
                    {"analysis": None},
                ],
            }
        ).limit(limit).to_list()

    async def set_finding_analysis(
        self,
        *,
        scan_id: str,
        org_id: str,
        finding_id: str,
        current_job_id: str,
        expected_revision: int,
        lease_owner: str,
        analysis: AiAnalysis,
    ) -> bool:
        """Replace only one finding's analyzer-owned projection."""
        try:
            oid = PydanticObjectId(scan_id)
        except Exception:
            return False
        result = await Scan.get_motor_collection().update_one(
            {
                "_id": oid,
                "org_id": org_id,
                "analysis.current_job_id": current_job_id,
                "analysis.revision": expected_revision,
                "analysis.lease_owner": lease_owner,
                "vulnerabilities.id": finding_id,
            },
            {
                "$set": {
                    "vulnerabilities.$[finding].ai_analysis": analysis.model_dump(
                        mode="python"
                    ),
                    "updated_at": datetime.now(timezone.utc),
                }
            },
            array_filters=[{"finding.id": finding_id}],
        )
        return result.modified_count == 1

    async def update_analysis_projection(
        self,
        *,
        scan_id: str,
        org_id: str,
        current_job_id: str,
        expected_revision: int,
        status: AnalysisStatus,
        progress: int,
        message: str,
        started_at: datetime | None = None,
        error_code: str | None = None,
        error_message: str | None = None,
        lease_owner: str | None = None,
        expected_lease_owner: str | None = None,
        clear_lease_owner: bool = False,
    ) -> bool:
        """Update current analysis state only when job and revision still match."""
        try:
            oid = PydanticObjectId(scan_id)
        except Exception:
            return False
        now = datetime.now(timezone.utc)
        fields = {
            "analysis.status": status.value,
            "analysis.progress": max(0, min(100, progress)),
            "analysis.message": message,
            "analysis.error_code": error_code,
            "analysis.error_message": error_message,
            "analysis.updated_at": now,
            "updated_at": now,
        }
        if started_at is not None:
            fields["analysis.started_at"] = started_at
        if lease_owner is not None:
            fields["analysis.lease_owner"] = lease_owner
        elif clear_lease_owner:
            fields["analysis.lease_owner"] = None
        query = {
            "_id": oid,
            "org_id": org_id,
            "analysis.current_job_id": current_job_id,
            "analysis.revision": expected_revision,
        }
        if expected_lease_owner is not None:
            query["analysis.lease_owner"] = expected_lease_owner
        result = await Scan.get_motor_collection().update_one(
            query,
            {"$set": fields},
        )
        return result.modified_count == 1

    async def complete_analysis_projection(
        self,
        *,
        scan_id: str,
        org_id: str,
        current_job_id: str,
        expected_revision: int,
        lease_owner: str,
        summary: str,
        model: str,
        prompt_version: str,
        generated_by: str,
        generated_at: datetime,
    ) -> bool:
        """Atomically publish report narrative and final readiness for one revision."""
        try:
            oid = PydanticObjectId(scan_id)
        except Exception:
            return False
        now = datetime.now(timezone.utc)
        result = await Scan.get_motor_collection().update_one(
            {
                "_id": oid,
                "org_id": org_id,
                "analysis.current_job_id": current_job_id,
                "analysis.revision": expected_revision,
                "analysis.lease_owner": lease_owner,
            },
            {
                "$set": {
                    "report_metadata.summary": summary,
                    "report_metadata.generated_at": generated_at,
                    "report_metadata.generated_by": generated_by,
                    "report_metadata.ai_model": model,
                    "report_metadata.prompt_version": prompt_version,
                    "analysis.status": AnalysisStatus.completed.value,
                    "analysis.progress": 100,
                    "analysis.message": "Analysis completed",
                    "analysis.model": model,
                    "analysis.prompt_version": prompt_version,
                    "analysis.error_code": None,
                    "analysis.error_message": None,
                    "analysis.completed_at": generated_at,
                    "analysis.lease_owner": None,
                    "analysis.updated_at": now,
                    "updated_at": now,
                }
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
