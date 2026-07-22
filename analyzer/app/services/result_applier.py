from datetime import datetime

from shared.database.repositories.scan_repository import ScanRepository
from shared.models.analysis_job import AnalysisJob, AnalysisStatus
from shared.models.vulnerability import AiAnalysis


class StaleAnalysisRevisionError(RuntimeError):
    """Raised when a worker no longer owns the scan's current analysis revision."""


class ResultApplier:
    def __init__(self, repository: ScanRepository) -> None:
        self.repository = repository

    async def mark_running(
        self, job: AnalysisJob, *, worker_id: str, started_at: datetime
    ) -> None:
        updated = await self.repository.update_analysis_projection(
            scan_id=job.scan_id,
            org_id=job.org_id,
            current_job_id=str(job.id),
            expected_revision=job.revision,
            status=AnalysisStatus.running,
            progress=0,
            message="Analysis running",
            started_at=started_at,
            lease_owner=worker_id,
        )
        if not updated:
            raise StaleAnalysisRevisionError("Analysis revision is no longer current")

    async def set_finding(
        self,
        job: AnalysisJob,
        *,
        worker_id: str,
        finding_id: str,
        analysis: AiAnalysis,
    ) -> None:
        updated = await self.repository.set_finding_analysis(
            scan_id=job.scan_id,
            org_id=job.org_id,
            finding_id=finding_id,
            current_job_id=str(job.id),
            expected_revision=job.revision,
            lease_owner=worker_id,
            analysis=analysis,
        )
        if not updated:
            raise StaleAnalysisRevisionError("Finding analysis publication was rejected")

    async def set_progress(
        self,
        job: AnalysisJob,
        *,
        worker_id: str,
        progress: int,
        message: str,
    ) -> None:
        updated = await self.repository.update_analysis_projection(
            scan_id=job.scan_id,
            org_id=job.org_id,
            current_job_id=str(job.id),
            expected_revision=job.revision,
            expected_lease_owner=worker_id,
            status=AnalysisStatus.running,
            progress=progress,
            message=message,
        )
        if not updated:
            raise StaleAnalysisRevisionError("Analysis progress publication was rejected")

    async def complete(
        self,
        job: AnalysisJob,
        *,
        worker_id: str,
        summary: str,
        model: str,
        prompt_version: str,
        generated_by: str,
        generated_at: datetime,
    ) -> None:
        updated = await self.repository.complete_analysis_projection(
            scan_id=job.scan_id,
            org_id=job.org_id,
            current_job_id=str(job.id),
            expected_revision=job.revision,
            lease_owner=worker_id,
            summary=summary,
            model=model,
            prompt_version=prompt_version,
            generated_by=generated_by,
            generated_at=generated_at,
        )
        if not updated:
            raise StaleAnalysisRevisionError("Final analysis publication was rejected")

    async def fail(
        self,
        job: AnalysisJob,
        *,
        worker_id: str,
        error_code: str,
        error_message: str,
    ) -> None:
        updated = await self.repository.update_analysis_projection(
            scan_id=job.scan_id,
            org_id=job.org_id,
            current_job_id=str(job.id),
            expected_revision=job.revision,
            expected_lease_owner=worker_id,
            status=AnalysisStatus.failed,
            progress=job.progress,
            message="Analysis failed",
            error_code=error_code,
            error_message=error_message,
            clear_lease_owner=True,
        )
        if not updated:
            raise StaleAnalysisRevisionError("Analysis failure publication was rejected")
