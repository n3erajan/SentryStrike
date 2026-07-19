from __future__ import annotations

import asyncio
import logging
import socket
import uuid

from app.core.scanner import ScanOrchestrator
from shared.database.connection import close_db, init_db
from shared.database.repositories.scan_repository import ScanRepository
from shared.models.scan import ScanPhase, ScanStatus
from shared.scan_queue import RedisScanQueue, ScanJob, ScanQueue, ScanQueueError
from shared.utils.logger import configure_logging

logger = logging.getLogger(__name__)

TERMINAL_SCAN_STATUSES = {
    ScanStatus.completed,
    ScanStatus.failed,
    ScanStatus.cancelled,
}


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
        await queue.clear_cancel(job.scan_id)
        logger.error("discarding scan job %s: scan document not found", job.scan_id)
        return

    if scan.status in TERMINAL_SCAN_STATUSES:
        await queue.clear_cancel(job.scan_id)
        logger.info(
            "discarding scan job %s: scan already %s",
            job.scan_id,
            scan.status.value,
        )
        return

    if await queue.is_cancelled(job.scan_id):
        await repository.update_status(
            scan,
            ScanStatus.cancelled,
            progress=scan.progress,
            current_phase=ScanPhase.cancelled,
            phase_message="Scan cancelled by user",
        )
        await queue.clear_cancel(job.scan_id)
        logger.info("discarding cancelled scan job %s", job.scan_id)
        return

    try:
        await orchestrator.run_scan(
            job.scan_id,
            auth_accounts=job.auth_accounts,
            scan_config=job.scan_config,
        )
    finally:
        try:
            await queue.clear_cancel(job.scan_id)
        except ScanQueueError:
            logger.exception("failed to clear cancellation key for scan %s", job.scan_id)


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
    orchestrator = ScanOrchestrator(
        repository,
        cancellation_checker=queue.is_cancelled,
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
