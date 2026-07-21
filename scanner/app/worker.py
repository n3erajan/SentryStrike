from __future__ import annotations

import asyncio
import logging
import socket
import uuid

from app.core.scanner import ScanOrchestrator
from app.reverification import run_focused_reverification
from shared.database.connection import close_db, init_db
from shared.database.repositories.scan_repository import ScanRepository
from shared.database.repositories.notification_repository import NotificationRepository
from shared.database.repositories.reverification_repository import ReverificationRepository
from shared.models.notification import NotificationType
from shared.models.reverification import ReverificationStatus
from shared.models.scan import ScanPhase, ScanStatus
from shared.scan_queue import RedisScanQueue, ScanJob, ScanJobKind, ScanQueue, ScanQueueError
from shared.utils.logger import configure_logging

logger = logging.getLogger(__name__)

TERMINAL_SCAN_STATUSES = {
    ScanStatus.completed,
    ScanStatus.failed,
    ScanStatus.cancelled,
}


async def _notify_terminal_scan(scan) -> None:
    """Emit one idempotent terminal notification for the scan submitter."""
    mapping = {
        ScanStatus.completed: (NotificationType.scan_completed, "Scan completed", "completed"),
        ScanStatus.failed: (NotificationType.scan_failed, "Scan failed", "failed"),
        ScanStatus.cancelled: (NotificationType.scan_cancelled, "Scan cancelled", "was cancelled"),
    }
    details = mapping.get(scan.status)
    if details is None:
        return
    notification_type, title, verb = details
    target_url = scan.target_url
    message = f"The scan of {target_url} {verb}."
    await NotificationRepository().create(
        org_id=scan.org_id,
        recipient_user_id=scan.submitted_by_user_id,
        type=notification_type,
        title=title,
        message=message,
        resource_type="scan",
        resource_id=str(scan.id),
        metadata={"status": scan.status.value, "target_url": target_url},
        dedupe_key=f"scan-terminal:{scan.org_id}:{scan.id}:{scan.status.value}",
    )


def _make_cancellation_checker(queue: ScanQueue):
    """Build a fail-safe cancellation checker for the orchestrator.

    The cancel key is a *signal*, not scan data. If Redis is unreachable when
    the orchestrator polls it at a phase boundary, we must NOT abort the scan —
    "can't tell" is treated as "not cancelled" so the scan proceeds. A genuine
    cancellation still lands via the pub/sub watcher (task cancel) and, once
    Redis recovers, the next phase-boundary poll.
    """

    async def _is_cancelled(scan_id: str) -> bool:
        try:
            return await queue.is_cancelled(scan_id)
        except ScanQueueError:
            logger.warning(
                "cancel-key check failed for scan %s (Redis unavailable?); "
                "treating as not cancelled so the scan continues",
                scan_id,
            )
            return False

    return _is_cancelled


async def _best_effort_clear_cancel(queue: ScanQueue, scan_id: str) -> None:
    """Delete the cancel key, swallowing Redis errors.

    Clearing the signal must never break job flow: a stale cancel key expires
    on its own TTL, so a failed delete is logged and ignored.
    """
    try:
        await queue.clear_cancel(scan_id)
    except ScanQueueError:
        logger.warning("failed to clear cancellation key for scan %s", scan_id)


async def _lease_loop(queue: ScanQueue, scan_id: str, ttl_seconds: int) -> None:
    """Renew the per-scan lease while the scan runs.

    Refreshes at half the TTL so a single missed renewal does not expire the
    lease. Best-effort: a failed renewal is logged and retried, never fatal to
    the scan — the lease only drives dead-worker detection, not scan logic.
    """
    interval = max(1, ttl_seconds // 2)
    while True:
        try:
            await queue.renew_lease(scan_id)
        except ScanQueueError:
            logger.warning("lease renewal failed for scan %s", scan_id)
        await asyncio.sleep(interval)


async def _cancel_watcher(
    queue: ScanQueue,
    scan_id: str,
    scan_task: asyncio.Task,
) -> None:
    """Cancel ``scan_task`` the instant a cancellation for ``scan_id`` arrives.

    Subscribes to the cancel pub/sub channel for immediate (sub-second)
    delivery, then closes the subscribe/publish race with a single cancel-key
    read (a request published before the subscription went live). Entirely
    best-effort: if Redis is down the subscription simply never fires and
    cancellation falls back to the orchestrator's phase-boundary key polls.
    """
    # Close the race: a cancel may have been requested between the worker
    # claiming the job and this subscription becoming live.
    try:
        if await queue.is_cancelled(scan_id):
            scan_task.cancel()
            return
    except ScanQueueError:
        logger.debug("initial cancel-key read failed for scan %s", scan_id)

    try:
        async for cancelled_id in queue.watch_cancellations():
            if cancelled_id == scan_id:
                logger.info("cancellation received for scan %s; cancelling task", scan_id)
                scan_task.cancel()
                return
    except ScanQueueError:
        logger.warning(
            "cancel watcher for scan %s stopped (Redis unavailable?); "
            "falling back to phase-boundary cancellation checks",
            scan_id,
        )


async def process_scan_job(
    job: ScanJob,
    *,
    queue: ScanQueue,
    repository: ScanRepository,
    orchestrator: ScanOrchestrator,
) -> None:
    """Claim a scan job from the queue and run it through the orchestrator.

    Skips jobs whose scan document no longer exists or has already reached a
    terminal state. Cancelled jobs are marked and cleaned up without running.
    """
    scan = await repository.get_by_id(job.scan_id)
    if scan is None:
        await _best_effort_clear_cancel(queue, job.scan_id)
        logger.error("discarding scan job %s: scan document not found", job.scan_id)
        return

    if scan.status in TERMINAL_SCAN_STATUSES:
        await _best_effort_clear_cancel(queue, job.scan_id)
        logger.info(
            "discarding scan job %s: scan already %s",
            job.scan_id,
            scan.status.value,
        )
        return

    # Best-effort pre-run cancel check: if Redis is unreachable we cannot tell,
    # so we proceed with the scan rather than abort it (the signal is not scan
    # data). A genuine cancel still lands via the watcher / phase-boundary polls.
    try:
        already_cancelled = await queue.is_cancelled(job.scan_id)
    except ScanQueueError:
        logger.warning(
            "pre-run cancel check failed for scan %s (Redis unavailable?); "
            "proceeding with the scan",
            job.scan_id,
        )
        already_cancelled = False
    if already_cancelled:
        await repository.update_status(
            scan,
            ScanStatus.cancelled,
            progress=scan.progress,
            current_phase=ScanPhase.cancelled,
            phase_message="Scan cancelled by user",
        )
        await _notify_terminal_scan(scan)
        await _best_effort_clear_cancel(queue, job.scan_id)
        logger.info("discarding cancelled scan job %s", job.scan_id)
        return

    # Run the scan as a task so a cancellation can interrupt it at the next
    # await anywhere in the pipeline (mid-crawl, mid-detector, mid-AI), not only
    # at the orchestrator's phase boundaries. A concurrent watcher cancels the
    # task the moment a request is published; a lease loop proves this worker is
    # alive so a crash leaves the scan detectable as orphaned rather than stuck.
    lease_ttl = getattr(queue, "lease_ttl_seconds", 30)
    scan_task = asyncio.create_task(
        orchestrator.run_scan(
            job.scan_id,
            auth_accounts=job.auth_accounts,
            scan_config=job.scan_config,
        )
    )
    watcher_task = asyncio.create_task(_cancel_watcher(queue, job.scan_id, scan_task))
    lease_task = asyncio.create_task(_lease_loop(queue, job.scan_id, lease_ttl))
    try:
        await scan_task
        refreshed = await repository.get_by_id(job.scan_id)
        if refreshed is not None:
            await _notify_terminal_scan(refreshed)
    finally:
        watcher_task.cancel()
        lease_task.cancel()
        for background in (watcher_task, lease_task):
            try:
                await background
            except (asyncio.CancelledError, Exception):  # noqa: BLE001 - best-effort teardown
                pass
        # Best-effort cleanup: releasing the lease and cancel key must never
        # turn a finished scan into a failure if Redis is unavailable.
        try:
            await queue.clear_lease(job.scan_id)
        except ScanQueueError:
            logger.warning("failed to clear lease for scan %s", job.scan_id)
        await _best_effort_clear_cancel(queue, job.scan_id)


async def process_reverification_job(
    job: ScanJob,
    *,
    repository: ReverificationRepository,
) -> None:
    """Run one focused finding replay and persist its immutable evidence."""
    if not job.reverification_job_id:
        logger.error("discarding re-verification queue item without a job id")
        return
    verification = await repository.get_by_id(job.reverification_job_id)
    if verification is None:
        logger.error(
            "discarding re-verification job %s: record not found",
            job.reverification_job_id,
        )
        return
    if verification.status in {
        ReverificationStatus.completed,
        ReverificationStatus.failed,
    }:
        return

    await repository.mark_running(verification)
    try:
        outcome, evidence = await run_focused_reverification(
            verification.target, job.auth_accounts
        )
        await repository.complete(verification, outcome=outcome, evidence=evidence)
        message = (
            f"Re-verification finished with outcome: {outcome.value.replace('_', ' ')}."
        )
    except Exception as exc:
        logger.exception("re-verification job %s failed", verification.id)
        await repository.fail(verification, str(exc))
        message = "Re-verification failed before a result could be determined."

    await NotificationRepository().create(
        org_id=verification.org_id,
        recipient_user_id=verification.requested_by_user_id,
        type=NotificationType.reverification_completed,
        title="Finding re-verification completed",
        message=message,
        resource_type="reverification",
        resource_id=str(verification.id),
        metadata={
            "scan_id": verification.scan_id,
            "vulnerability_id": verification.vulnerability_id,
            "outcome": verification.outcome.value if verification.outcome else None,
        },
        dedupe_key=f"reverification-terminal:{verification.org_id}:{verification.id}",
    )


async def _heartbeat_loop(queue: RedisScanQueue, worker_id: str) -> None:
    """Periodically refresh the worker heartbeat key in Redis.

    Runs at half the TTL interval so a single missed beat does not
    immediately mark the worker as dead. The heartbeat allows the backend
    health endpoint to report the number of active workers.
    """
    interval = max(1, queue.heartbeat_ttl_seconds // 2)
    while True:
        try:
            await queue.set_heartbeat(worker_id)
        except ScanQueueError:
            logger.exception("heartbeat failed")
        await asyncio.sleep(interval)


async def run_worker() -> None:
    """Main worker loop: initialise services, then dequeue and process scan jobs forever."""
    configure_logging()
    await init_db()

    queue = RedisScanQueue.from_settings()
    worker_id = f"{socket.gethostname()}-{uuid.uuid4().hex[:8]}"
    heartbeat_task = asyncio.create_task(_heartbeat_loop(queue, worker_id))

    repository = ScanRepository()
    reverification_repository = ReverificationRepository()
    orchestrator = ScanOrchestrator(
        repository,
        cancellation_checker=_make_cancellation_checker(queue),
    )

    logger.info(
        "scanner worker %s waiting on queue %s",
        worker_id,
        queue.queue_name,
    )
    try:
        while True:
            try:
                job = await queue.dequeue()
            except ScanQueueError:
                logger.exception("scan queue read failed; retrying")
                await asyncio.sleep(1)
                continue

            try:
                if job.kind == ScanJobKind.finding_reverification:
                    await process_reverification_job(
                        job, repository=reverification_repository
                    )
                else:
                    await process_scan_job(
                        job,
                        queue=queue,
                        repository=repository,
                        orchestrator=orchestrator,
                    )
            except Exception:
                logger.exception("worker failed while handling scan %s", job.scan_id)
    finally:
        heartbeat_task.cancel()
        try:
            await queue.clear_heartbeat(worker_id)
        except ScanQueueError:
            logger.exception("failed to clear heartbeat for worker %s", worker_id)
        await queue.close()
        await close_db()


def main() -> None:
    try:
        asyncio.run(run_worker())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
