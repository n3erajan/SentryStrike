from datetime import datetime, timezone

from beanie import PydanticObjectId

from shared.models.reverification import (
    ReverificationEvidence,
    ReverificationJob,
    ReverificationOutcome,
    ReverificationStatus,
)
from shared.models.scan import ScanAuthRole
from shared.models.vulnerability import VerificationTarget


class ReverificationRepository:
    """Tenant-scoped persistence for focused finding verification jobs."""

    async def create(
        self,
        *,
        org_id: str,
        scan_id: str,
        vulnerability_id: str,
        requested_by_user_id: str,
        requested_by_email: str,
        target: VerificationTarget,
        auth_roles_provided: list[ScanAuthRole] | None = None,
    ) -> ReverificationJob:
        job = ReverificationJob(
            org_id=org_id,
            scan_id=scan_id,
            vulnerability_id=vulnerability_id,
            requested_by_user_id=requested_by_user_id,
            requested_by_email=requested_by_email,
            target=target.model_copy(deep=True),
            auth_roles_provided=auth_roles_provided or [],
        )
        await job.insert()
        return job

    async def get_by_id(self, job_id: str) -> ReverificationJob | None:
        try:
            oid = PydanticObjectId(job_id)
        except Exception:
            return None
        return await ReverificationJob.get(oid)

    async def get_in_org(self, job_id: str, org_id: str) -> ReverificationJob | None:
        try:
            oid = PydanticObjectId(job_id)
        except Exception:
            return None
        return await ReverificationJob.find_one(
            ReverificationJob.id == oid, ReverificationJob.org_id == org_id
        )

    async def list_for_finding(
        self, *, org_id: str, scan_id: str, vulnerability_id: str
    ) -> list[ReverificationJob]:
        return (
            await ReverificationJob.find(
                ReverificationJob.org_id == org_id,
                ReverificationJob.scan_id == scan_id,
                ReverificationJob.vulnerability_id == vulnerability_id,
            )
            .sort(-ReverificationJob.created_at)
            .to_list()
        )

    async def mark_running(self, job: ReverificationJob) -> ReverificationJob:
        job.status = ReverificationStatus.running
        job.started_at = datetime.now(timezone.utc)
        await job.save()
        return job

    async def complete(
        self,
        job: ReverificationJob,
        *,
        outcome: ReverificationOutcome,
        evidence: list[ReverificationEvidence],
    ) -> ReverificationJob:
        job.status = ReverificationStatus.completed
        job.outcome = outcome
        job.evidence = [item.model_copy(deep=True) for item in evidence]
        job.completed_at = datetime.now(timezone.utc)
        await job.save()
        return job

    async def fail(self, job: ReverificationJob, error_message: str) -> ReverificationJob:
        job.status = ReverificationStatus.failed
        job.error_message = error_message
        job.completed_at = datetime.now(timezone.utc)
        await job.save()
        return job
