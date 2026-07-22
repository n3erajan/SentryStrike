from __future__ import annotations

import logging

from shared.analysis_queue import AnalysisQueue, AnalysisQueueError, AnalysisSignal
from shared.database.repositories.analysis_job_repository import AnalysisJobRepository
from shared.database.repositories.scan_repository import ScanRepository
from shared.models.analysis_job import AnalysisJob
from shared.models.scan import Scan, ScanStatus

logger = logging.getLogger(__name__)


async def ensure_initial_analysis_job(
    scan: Scan,
    *,
    scan_repository: ScanRepository,
    analysis_repository: AnalysisJobRepository,
    analysis_queue: AnalysisQueue,
) -> AnalysisJob | None:
    """Idempotently create, attach, and signal a completed scan's first revision."""
    if scan.status != ScanStatus.completed:
        return None

    job = await analysis_repository.create_initial(
        scan_id=str(scan.id),
        org_id=scan.org_id,
        finding_count=len(scan.vulnerabilities),
    )
    await scan_repository.attach_initial_analysis_job(
        scan_id=str(scan.id),
        org_id=scan.org_id,
        job_id=str(job.id),
        revision=job.revision,
        queued_at=job.queued_at,
    )
    try:
        await analysis_queue.enqueue(AnalysisSignal(analysis_job_id=str(job.id)))
    except AnalysisQueueError:
        # MongoDB is the source of truth. A worker's periodic claim poll will
        # recover this job without a Redis signal.
        logger.warning(
            "analysis job %s is durable but Redis signaling failed",
            job.id,
        )
    return job


async def reconcile_missing_analysis_jobs(
    *,
    scan_repository: ScanRepository,
    analysis_repository: AnalysisJobRepository,
    analysis_queue: AnalysisQueue,
    limit: int = 100,
) -> int:
    """Repair completed scans interrupted between completion and job attachment."""
    reconciled = 0
    scans = await scan_repository.list_completed_without_analysis(limit=limit)
    for scan in scans:
        try:
            await ensure_initial_analysis_job(
                scan,
                scan_repository=scan_repository,
                analysis_repository=analysis_repository,
                analysis_queue=analysis_queue,
            )
            reconciled += 1
        except Exception:
            logger.exception("failed to reconcile analysis for scan %s", scan.id)
    return reconciled
