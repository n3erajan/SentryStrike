from __future__ import annotations

from datetime import datetime, timedelta, timezone

from beanie import PydanticObjectId
from pymongo import ReturnDocument
from pymongo.errors import DuplicateKeyError

from shared.models.analysis_job import (
    AnalysisJob,
    AnalysisStatus,
    AnalysisTrigger,
)


class AnalysisJobRepository:
    """Durable lifecycle operations for revisioned scan-analysis jobs."""

    @staticmethod
    def _object_id(value: str) -> PydanticObjectId | None:
        try:
            return PydanticObjectId(value)
        except Exception:
            return None

    async def get_by_id(self, job_id: str) -> AnalysisJob | None:
        object_id = self._object_id(job_id)
        if object_id is None:
            return None
        return await AnalysisJob.get(object_id)

    async def get_in_org(self, job_id: str, org_id: str) -> AnalysisJob | None:
        object_id = self._object_id(job_id)
        if object_id is None:
            return None
        return await AnalysisJob.find_one(
            AnalysisJob.id == object_id,
            AnalysisJob.org_id == org_id,
        )

    async def get_for_revision(
        self, *, scan_id: str, org_id: str, revision: int
    ) -> AnalysisJob | None:
        return await AnalysisJob.find_one(
            AnalysisJob.scan_id == scan_id,
            AnalysisJob.org_id == org_id,
            AnalysisJob.revision == revision,
        )

    async def create_initial(
        self,
        *,
        scan_id: str,
        org_id: str,
        finding_count: int,
        max_attempts: int = 3,
    ) -> AnalysisJob:
        return await self._create_revision(
            scan_id=scan_id,
            org_id=org_id,
            revision=1,
            trigger=AnalysisTrigger.automatic,
            finding_count=finding_count,
            max_attempts=max_attempts,
        )

    async def create_manual_retry(
        self,
        *,
        scan_id: str,
        org_id: str,
        revision: int,
        finding_count: int,
        requested_by_user_id: str,
        requested_by_email: str,
        max_attempts: int = 3,
    ) -> AnalysisJob:
        return await self._create_revision(
            scan_id=scan_id,
            org_id=org_id,
            revision=revision,
            trigger=AnalysisTrigger.manual_retry,
            finding_count=finding_count,
            requested_by_user_id=requested_by_user_id,
            requested_by_email=requested_by_email,
            max_attempts=max_attempts,
        )

    async def _create_revision(
        self,
        *,
        scan_id: str,
        org_id: str,
        revision: int,
        trigger: AnalysisTrigger,
        finding_count: int,
        max_attempts: int,
        requested_by_user_id: str | None = None,
        requested_by_email: str | None = None,
    ) -> AnalysisJob:
        existing = await self.get_for_revision(
            scan_id=scan_id,
            org_id=org_id,
            revision=revision,
        )
        if existing is not None:
            return existing

        now = datetime.now(timezone.utc)
        job = AnalysisJob(
            scan_id=scan_id,
            org_id=org_id,
            revision=revision,
            trigger=trigger,
            requested_by_user_id=requested_by_user_id,
            requested_by_email=requested_by_email,
            finding_count=finding_count,
            max_attempts=max_attempts,
            created_at=now,
            queued_at=now,
            updated_at=now,
        )
        try:
            await job.insert()
            return job
        except DuplicateKeyError:
            # A concurrent scanner/reconciler won the unique (scan, revision)
            # insert. Return that durable winner rather than creating a duplicate.
            existing = await self.get_for_revision(
                scan_id=scan_id,
                org_id=org_id,
                revision=revision,
            )
            if existing is None:
                raise
            return existing

    async def claim_next(
        self,
        *,
        worker_id: str,
        lease_seconds: int,
        job_id: str | None = None,
        now: datetime | None = None,
    ) -> AnalysisJob | None:
        now = now or datetime.now(timezone.utc)
        query: dict = {
            "$expr": {"$lt": ["$attempt", "$max_attempts"]},
            "$or": [
                {
                    "status": AnalysisStatus.queued.value,
                    "$or": [
                        {"next_attempt_at": None},
                        {"next_attempt_at": {"$lte": now}},
                    ],
                },
                {
                    "status": AnalysisStatus.running.value,
                    "lease_expires_at": {"$lte": now},
                },
            ],
        }
        if job_id is not None:
            object_id = self._object_id(job_id)
            if object_id is None:
                return None
            query["_id"] = object_id

        lease_expires_at = now + timedelta(seconds=lease_seconds)
        document = await AnalysisJob.get_motor_collection().find_one_and_update(
            query,
            [
                {
                    "$set": {
                        "status": AnalysisStatus.running.value,
                        "attempt": {"$add": ["$attempt", 1]},
                        "lease_owner": worker_id,
                        "lease_expires_at": lease_expires_at,
                        "next_attempt_at": None,
                        "started_at": {"$ifNull": ["$started_at", now]},
                        "updated_at": now,
                        "message": "Analysis running",
                    }
                }
            ],
            sort=[("queued_at", 1)],
            return_document=ReturnDocument.AFTER,
        )
        if document is None:
            return None
        return AnalysisJob.model_validate(document)

    async def renew_lease(
        self,
        *,
        job_id: str,
        worker_id: str,
        lease_seconds: int,
        now: datetime | None = None,
    ) -> bool:
        object_id = self._object_id(job_id)
        if object_id is None:
            return False
        now = now or datetime.now(timezone.utc)
        result = await AnalysisJob.get_motor_collection().update_one(
            {
                "_id": object_id,
                "status": AnalysisStatus.running.value,
                "lease_owner": worker_id,
            },
            {
                "$set": {
                    "lease_expires_at": now + timedelta(seconds=lease_seconds),
                    "updated_at": now,
                }
            },
        )
        return result.modified_count == 1

    async def update_progress(
        self,
        *,
        job_id: str,
        worker_id: str,
        analyzed_finding_count: int,
        failed_finding_count: int,
        progress: int,
        message: str,
    ) -> bool:
        object_id = self._object_id(job_id)
        if object_id is None:
            return False
        result = await AnalysisJob.get_motor_collection().update_one(
            {
                "_id": object_id,
                "status": AnalysisStatus.running.value,
                "lease_owner": worker_id,
            },
            {
                "$set": {
                    "analyzed_finding_count": analyzed_finding_count,
                    "failed_finding_count": failed_finding_count,
                    "progress": max(0, min(100, progress)),
                    "message": message,
                    "updated_at": datetime.now(timezone.utc),
                }
            },
        )
        return result.modified_count == 1

    async def schedule_retry(
        self,
        *,
        job_id: str,
        worker_id: str,
        next_attempt_at: datetime,
        error_code: str,
        error_message: str,
    ) -> bool:
        object_id = self._object_id(job_id)
        if object_id is None:
            return False
        result = await AnalysisJob.get_motor_collection().update_one(
            {
                "_id": object_id,
                "status": AnalysisStatus.running.value,
                "lease_owner": worker_id,
                "$expr": {"$lt": ["$attempt", "$max_attempts"]},
            },
            {
                "$set": {
                    "status": AnalysisStatus.queued.value,
                    "next_attempt_at": next_attempt_at,
                    "lease_owner": None,
                    "lease_expires_at": None,
                    "error_code": error_code,
                    "error_message": error_message,
                    "message": "Analysis retry scheduled",
                    "updated_at": datetime.now(timezone.utc),
                }
            },
        )
        return result.modified_count == 1

    async def complete(
        self,
        *,
        job_id: str,
        worker_id: str,
        model: str,
        prompt_version: str,
        provider_request_ids: list[str],
        input_tokens: int | None,
        output_tokens: int | None,
    ) -> bool:
        return await self._mark_terminal(
            job_id=job_id,
            worker_id=worker_id,
            status=AnalysisStatus.completed,
            message="Analysis completed",
            extra={
                "progress": 100,
                "model": model,
                "prompt_version": prompt_version,
                "provider_request_ids": provider_request_ids,
                "input_tokens": input_tokens,
                "output_tokens": output_tokens,
                "error_code": None,
                "error_message": None,
            },
        )

    async def fail(
        self,
        *,
        job_id: str,
        worker_id: str,
        error_code: str,
        error_message: str,
    ) -> bool:
        return await self._mark_terminal(
            job_id=job_id,
            worker_id=worker_id,
            status=AnalysisStatus.failed,
            message="Analysis failed",
            extra={
                "error_code": error_code,
                "error_message": error_message,
            },
        )

    async def _mark_terminal(
        self,
        *,
        job_id: str,
        worker_id: str,
        status: AnalysisStatus,
        message: str,
        extra: dict,
    ) -> bool:
        object_id = self._object_id(job_id)
        if object_id is None:
            return False
        now = datetime.now(timezone.utc)
        result = await AnalysisJob.get_motor_collection().update_one(
            {
                "_id": object_id,
                "status": AnalysisStatus.running.value,
                "lease_owner": worker_id,
            },
            {
                "$set": {
                    "status": status.value,
                    "message": message,
                    "completed_at": now,
                    "updated_at": now,
                    "lease_owner": None,
                    "lease_expires_at": None,
                    **extra,
                }
            },
        )
        return result.modified_count == 1
