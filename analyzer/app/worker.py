from __future__ import annotations

import asyncio
import logging
import random
import socket
import uuid
from datetime import datetime, timedelta, timezone

from pydantic import ValidationError

from app.clients.ai_client import AIClient, ProviderError
from app.config import get_settings
from app.prompts.report_analysis import REPORT_PROMPT_VERSION
from app.services.finding_analysis import FALLBACK_MODEL, FindingAnalysisService
from app.services.report_analysis import (
    FALLBACK_REPORT_PROMPT_VERSION,
    ReportAnalysisService,
)
from app.services.result_applier import ResultApplier, StaleAnalysisRevisionError
from shared.analysis_handoff import reconcile_missing_analysis_jobs
from shared.analysis_queue import AnalysisQueueError, RedisAnalysisQueue
from shared.database.connection import close_db, init_db
from shared.database.repositories.analysis_job_repository import AnalysisJobRepository
from shared.database.repositories.member_repository import MemberRepository
from shared.database.repositories.notification_repository import NotificationRepository
from shared.database.repositories.scan_repository import ScanRepository
from shared.models.analysis_job import AnalysisJob, AnalysisStatus
from shared.models.notification import NotificationType
from shared.models.scan import ScanStatus
from shared.utils.logger import configure_logging

logger = logging.getLogger(__name__)


def _retry_delay_seconds(attempt: int) -> float:
    base = (30, 120, 600)[min(max(attempt - 1, 0), 2)]
    return base * random.uniform(0.9, 1.1)


async def _lease_loop(
    repository: AnalysisJobRepository,
    *,
    job_id: str,
    worker_id: str,
) -> None:
    settings = get_settings()
    while True:
        await asyncio.sleep(settings.analysis_lease_renew_seconds)
        renewed = await repository.renew_lease(
            job_id=job_id,
            worker_id=worker_id,
            lease_seconds=settings.analysis_lease_seconds,
        )
        if not renewed:
            raise StaleAnalysisRevisionError("Analysis lease ownership was lost")


async def _record_failure(
    job: AnalysisJob,
    *,
    worker_id: str,
    error: ProviderError,
    job_repository: AnalysisJobRepository,
    scan_repository: ScanRepository,
) -> bool:
    applier = ResultApplier(scan_repository)
    if error.retryable and job.attempt < job.max_attempts:
        next_attempt_at = datetime.now(timezone.utc) + timedelta(
            seconds=_retry_delay_seconds(job.attempt)
        )
        scheduled = await job_repository.schedule_retry(
            job_id=str(job.id),
            worker_id=worker_id,
            next_attempt_at=next_attempt_at,
            error_code=error.code,
            error_message=str(error),
        )
        if scheduled:
            await scan_repository.update_analysis_projection(
                scan_id=job.scan_id,
                org_id=job.org_id,
                current_job_id=str(job.id),
                expected_revision=job.revision,
                expected_lease_owner=worker_id,
                status=AnalysisStatus.queued,
                progress=job.progress,
                message="Analysis retry scheduled",
                error_code=error.code,
                error_message=str(error),
                clear_lease_owner=True,
            )
            return False

    projection_failed = True
    try:
        await applier.fail(
            job,
            worker_id=worker_id,
            error_code=error.code,
            error_message=str(error),
        )
    except StaleAnalysisRevisionError:
        projection_failed = False
    job_failed = await job_repository.fail(
        job_id=str(job.id),
        worker_id=worker_id,
        error_code=error.code,
        error_message=str(error),
    )
    return projection_failed and job_failed


async def _notify_analysis_terminal(
    scan,
    job: AnalysisJob,
    *,
    completed: bool,
    member_repository: MemberRepository | None,
    notification_repository: NotificationRepository | None,
) -> None:
    if member_repository is None or notification_repository is None:
        return
    try:
        recipient = await member_repository.get_in_org(
            scan.submitted_by_user_id,
            job.org_id,
        )
        if recipient is None:
            return
        event = "completed" if completed else "failed"
        notification_type = (
            NotificationType.analysis_completed
            if completed
            else NotificationType.analysis_failed
        )
        await notification_repository.create(
            org_id=job.org_id,
            recipient_user_id=scan.submitted_by_user_id,
            type=notification_type,
            title="Analysis completed" if completed else "Analysis failed",
            message=(
                "The analyzed report and PDF are ready."
                if completed
                else "Deterministic findings remain available; an authorized triager can retry analysis."
            ),
            resource_type="scan",
            resource_id=job.scan_id,
            metadata={
                "scan_id": job.scan_id,
                "revision": job.revision,
                "status": event,
            },
            dedupe_key=(
                f"analysis:{job.org_id}:{job.scan_id}:{job.revision}:"
                f"{event}:{scan.submitted_by_user_id}"
            ),
        )
    except Exception:
        logger.exception("analysis notification failed for job %s", job.id)


async def process_analysis_job(
    job: AnalysisJob,
    *,
    worker_id: str,
    job_repository: AnalysisJobRepository,
    scan_repository: ScanRepository,
    finding_service: FindingAnalysisService,
    report_service: ReportAnalysisService,
    member_repository: MemberRepository | None = None,
    notification_repository: NotificationRepository | None = None,
) -> None:
    scan = await scan_repository.get_in_org(job.scan_id, job.org_id)
    if scan is None or scan.status != ScanStatus.completed:
        await job_repository.fail(
            job_id=str(job.id),
            worker_id=worker_id,
            error_code="scan_not_ready",
            error_message="The org-scoped completed scan could not be loaded",
        )
        return

    applier = ResultApplier(scan_repository)
    started_at = job.started_at or datetime.now(timezone.utc)
    try:
        await applier.mark_running(job, worker_id=worker_id, started_at=started_at)
    except StaleAnalysisRevisionError:
        await job_repository.fail(
            job_id=str(job.id),
            worker_id=worker_id,
            error_code="stale_analysis_revision",
            error_message="A newer analysis revision is current",
        )
        return

    lease_task = asyncio.create_task(
        _lease_loop(job_repository, job_id=str(job.id), worker_id=worker_id)
    )
    provider_request_ids: list[str] = []
    input_tokens = 0
    output_tokens = 0
    analyzed = 0
    failed = 0
    settings = get_settings()
    publication_model = settings.ai_model if settings.ai_analysis_enabled else FALLBACK_MODEL
    publication_source = "ai" if settings.ai_analysis_enabled else "analyzer_fallback"
    report_prompt_version = (
        REPORT_PROMPT_VERSION
        if settings.ai_analysis_enabled
        else FALLBACK_REPORT_PROMPT_VERSION
    )
    technology_stack = ", ".join(
        technology.name for technology in scan.technology_stack
    ) or "Unknown"

    try:
        for vulnerability in scan.vulnerabilities:
            analysis, provider_result = await finding_service.analyze(
                vulnerability,
                revision=job.revision,
                technology_stack=technology_stack,
            )
            analysis.analyzed_at = datetime.now(timezone.utc)
            await applier.set_finding(
                job,
                worker_id=worker_id,
                finding_id=vulnerability.id,
                analysis=analysis,
            )
            vulnerability.ai_analysis = analysis
            analyzed += 1
            if provider_result.request_id:
                provider_request_ids.append(provider_result.request_id)
            input_tokens += provider_result.input_tokens or 0
            output_tokens += provider_result.output_tokens or 0
            progress = round((analyzed / max(1, job.finding_count + 1)) * 95)
            message = f"Analyzed {analyzed} of {job.finding_count} findings"
            job.progress = progress
            await job_repository.update_progress(
                job_id=str(job.id),
                worker_id=worker_id,
                analyzed_finding_count=analyzed,
                failed_finding_count=failed,
                progress=progress,
                message=message,
            )
            await applier.set_progress(
                job,
                worker_id=worker_id,
                progress=progress,
                message=message,
            )

        summary, report_result = await report_service.analyze(scan)
        if report_result.request_id:
            provider_request_ids.append(report_result.request_id)
        input_tokens += report_result.input_tokens or 0
        output_tokens += report_result.output_tokens or 0
        generated_at = datetime.now(timezone.utc)
        await applier.complete(
            job,
            worker_id=worker_id,
            summary=summary,
            model=publication_model,
            prompt_version=report_prompt_version,
            generated_by=publication_source,
            generated_at=generated_at,
        )
        completed = await job_repository.complete(
            job_id=str(job.id),
            worker_id=worker_id,
            model=publication_model,
            prompt_version=report_prompt_version,
            provider_request_ids=provider_request_ids,
            input_tokens=input_tokens or None,
            output_tokens=output_tokens or None,
        )
        if not completed:
            raise StaleAnalysisRevisionError("Analysis job lease was lost at completion")
        await _notify_analysis_terminal(
            scan,
            job,
            completed=True,
            member_repository=member_repository,
            notification_repository=notification_repository,
        )
    except ValidationError as exc:
        failed += 1
        terminal = await _record_failure(
            job,
            worker_id=worker_id,
            error=ProviderError(
                "invalid_provider_schema",
                "The provider response did not match the required schema",
                retryable=True,
            ),
            job_repository=job_repository,
            scan_repository=scan_repository,
        )
        if terminal:
            await _notify_analysis_terminal(
                scan,
                job,
                completed=False,
                member_repository=member_repository,
                notification_repository=notification_repository,
            )
        logger.info("analysis job %s schema validation failed: %s", job.id, exc)
    except ProviderError as exc:
        terminal = await _record_failure(
            job,
            worker_id=worker_id,
            error=exc,
            job_repository=job_repository,
            scan_repository=scan_repository,
        )
        if terminal:
            await _notify_analysis_terminal(
                scan,
                job,
                completed=False,
                member_repository=member_repository,
                notification_repository=notification_repository,
            )
    except StaleAnalysisRevisionError:
        logger.warning("analysis job %s lost publication ownership", job.id)
    except Exception:
        logger.exception("analysis job %s failed unexpectedly", job.id)
        terminal = await _record_failure(
            job,
            worker_id=worker_id,
            error=ProviderError(
                "analysis_internal_error",
                "Analysis failed before completion",
                retryable=False,
            ),
            job_repository=job_repository,
            scan_repository=scan_repository,
        )
        if terminal:
            await _notify_analysis_terminal(
                scan,
                job,
                completed=False,
                member_repository=member_repository,
                notification_repository=notification_repository,
            )
    finally:
        lease_task.cancel()
        try:
            await lease_task
        except (asyncio.CancelledError, Exception):  # noqa: BLE001 - teardown
            pass


async def run_worker() -> None:
    settings = get_settings()
    configure_logging(log_level=settings.log_level)
    await init_db(settings)
    queue = RedisAnalysisQueue.from_settings(settings)
    job_repository = AnalysisJobRepository()
    scan_repository = ScanRepository()
    member_repository = MemberRepository()
    notification_repository = NotificationRepository()
    client = AIClient()
    finding_service = FindingAnalysisService(client)
    report_service = ReportAnalysisService(client)
    worker_id = f"{socket.gethostname()}-{uuid.uuid4().hex[:8]}"
    last_reconciliation = datetime.min.replace(tzinfo=timezone.utc)

    try:
        while True:
            now = datetime.now(timezone.utc)
            if (
                now - last_reconciliation
            ).total_seconds() >= settings.analysis_reconcile_interval_seconds:
                await reconcile_missing_analysis_jobs(
                    scan_repository=scan_repository,
                    analysis_repository=job_repository,
                    analysis_queue=queue,
                )
                last_reconciliation = now

            try:
                signal = await queue.dequeue(settings.analysis_poll_seconds)
            except AnalysisQueueError:
                logger.exception("analysis queue read failed; polling MongoDB")
                signal = None

            job = await job_repository.claim_next(
                worker_id=worker_id,
                lease_seconds=settings.analysis_lease_seconds,
                job_id=signal.analysis_job_id if signal else None,
            )
            if job is None and signal is not None:
                # Duplicate/stale signals are harmless; also poll for other due work.
                job = await job_repository.claim_next(
                    worker_id=worker_id,
                    lease_seconds=settings.analysis_lease_seconds,
                )
            if job is None:
                continue
            await process_analysis_job(
                job,
                worker_id=worker_id,
                job_repository=job_repository,
                scan_repository=scan_repository,
                finding_service=finding_service,
                report_service=report_service,
                member_repository=member_repository,
                notification_repository=notification_repository,
            )
    finally:
        await queue.close()
        await close_db()


def main() -> None:
    try:
        asyncio.run(run_worker())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
