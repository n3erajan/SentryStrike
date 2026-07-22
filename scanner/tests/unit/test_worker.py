import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from app.worker import process_scan_job
from shared.models.scan import ScanAuthAccount, ScanAuthRole, ScanPhase, ScanStatus
from shared.scan_queue import ScanJob, ScanQueueError
from shared.schemas.scan_schema import ScanConfig


class FakeQueue:
    """In-memory stand-in for RedisScanQueue used by the worker tests.

    Records signal calls (cancel key clears, lease renew/clear) and drives the
    pub/sub cancel channel through an ``asyncio.Queue`` so a test can publish a
    cancellation while a scan task is running.
    """

    def __init__(self, *, cancelled: bool = False, lease_ttl_seconds: int = 30) -> None:
        self.lease_ttl_seconds = lease_ttl_seconds
        self._cancelled = cancelled
        self._cancel_channel: asyncio.Queue[str] = asyncio.Queue()
        self.is_cancelled_calls: list[str] = []
        self.cleared_cancel: list[str] = []
        self.cleared_lease: list[str] = []
        self.renew_calls: list[str] = []

    async def is_cancelled(self, scan_id: str) -> bool:
        self.is_cancelled_calls.append(scan_id)
        return self._cancelled

    async def clear_cancel(self, scan_id: str) -> None:
        self.cleared_cancel.append(scan_id)

    async def renew_lease(self, scan_id: str) -> None:
        self.renew_calls.append(scan_id)

    async def clear_lease(self, scan_id: str) -> None:
        self.cleared_lease.append(scan_id)

    async def watch_cancellations(self):
        while True:
            yield await self._cancel_channel.get()

    def publish_cancel(self, scan_id: str) -> None:
        self._cancel_channel.put_nowait(scan_id)


@pytest.mark.asyncio
async def test_cancelled_queued_job_is_discarded_and_marked_cancelled() -> None:
    scan = SimpleNamespace(status=ScanStatus.queued, progress=12)
    queue = FakeQueue(cancelled=True)
    repository = AsyncMock()
    repository.get_by_id.return_value = scan
    orchestrator = AsyncMock()

    await process_scan_job(
        ScanJob(scan_id="scan-cancelled"),
        queue=queue,
        repository=repository,
        orchestrator=orchestrator,
    )

    repository.update_status.assert_awaited_once_with(
        scan,
        ScanStatus.cancelled,
        progress=12,
        current_phase=ScanPhase.cancelled,
        phase_message="Scan cancelled by user",
    )
    assert queue.cleared_cancel == ["scan-cancelled"]
    orchestrator.run_scan.assert_not_awaited()


@pytest.mark.asyncio
async def test_missing_scan_job_is_discarded() -> None:
    queue = FakeQueue()
    repository = AsyncMock()
    repository.get_by_id.return_value = None
    orchestrator = AsyncMock()

    await process_scan_job(
        ScanJob(scan_id="scan-missing"),
        queue=queue,
        repository=repository,
        orchestrator=orchestrator,
    )

    assert queue.cleared_cancel == ["scan-missing"]
    assert queue.is_cancelled_calls == []
    orchestrator.run_scan.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "terminal_status",
    [ScanStatus.completed, ScanStatus.failed, ScanStatus.cancelled],
)
async def test_terminal_scan_job_is_discarded(terminal_status: ScanStatus) -> None:
    queue = FakeQueue()
    repository = AsyncMock()
    repository.get_by_id.return_value = SimpleNamespace(
        status=terminal_status,
        progress=100,
    )
    orchestrator = AsyncMock()

    await process_scan_job(
        ScanJob(scan_id="scan-terminal"),
        queue=queue,
        repository=repository,
        orchestrator=orchestrator,
    )

    assert queue.cleared_cancel == ["scan-terminal"]
    assert queue.is_cancelled_calls == []
    orchestrator.run_scan.assert_not_awaited()


@pytest.mark.asyncio
async def test_job_credentials_and_config_are_passed_to_orchestrator() -> None:
    account = ScanAuthAccount(
        role=ScanAuthRole.main,
        username="scanner@example.test",
        password="secret",
    )
    config = ScanConfig(crawl_depth=2)
    queue = FakeQueue()
    repository = AsyncMock()
    repository.get_by_id.return_value = SimpleNamespace(
        status=ScanStatus.queued,
        progress=0,
    )
    orchestrator = AsyncMock()

    await process_scan_job(
        ScanJob(
            scan_id="scan-ready",
            auth_accounts=[account],
            scan_config=config,
        ),
        queue=queue,
        repository=repository,
        orchestrator=orchestrator,
    )

    orchestrator.run_scan.assert_awaited_once_with(
        "scan-ready",
        auth_accounts=[account],
        scan_config=config,
    )
    # The scan ran, so its lease was renewed and both signals cleared afterward.
    assert queue.renew_calls == ["scan-ready"]
    assert queue.cleared_lease == ["scan-ready"]
    assert queue.cleared_cancel == ["scan-ready"]


@pytest.mark.asyncio
async def test_published_cancellation_cancels_running_scan_immediately() -> None:
    """A cancel published mid-scan cancels the task at its next await, without
    waiting for a phase boundary. The pipeline swallows CancelledError, so
    process_scan_job returns normally and clears the lease + cancel key."""
    started = asyncio.Event()
    outcome: dict[str, bool] = {}

    async def slow_run_scan(scan_id: str, **kwargs) -> None:
        started.set()
        try:
            await asyncio.sleep(30)  # simulate a long crawl/detector phase
        except asyncio.CancelledError:
            # Mirror the real pipeline, which catches CancelledError and
            # records the scan as cancelled rather than re-raising.
            outcome["cancelled"] = True
            return

    queue = FakeQueue()
    repository = AsyncMock()
    repository.get_by_id.return_value = SimpleNamespace(status=ScanStatus.queued, progress=0)
    orchestrator = SimpleNamespace(run_scan=slow_run_scan)

    proc = asyncio.create_task(
        process_scan_job(
            ScanJob(scan_id="scan-run"),
            queue=queue,
            repository=repository,
            orchestrator=orchestrator,
        )
    )
    await asyncio.wait_for(started.wait(), timeout=1)
    queue.publish_cancel("scan-run")
    await asyncio.wait_for(proc, timeout=2)

    assert outcome.get("cancelled") is True
    assert queue.cleared_lease == ["scan-run"]
    assert queue.cleared_cancel == ["scan-run"]


@pytest.mark.asyncio
async def test_scan_proceeds_when_cancel_signal_check_fails() -> None:
    """Redis is only a signalling layer: if the pre-run cancel check raises, the
    scan must still run rather than abort."""
    queue = FakeQueue()

    async def _raise(_scan_id: str) -> bool:
        raise ScanQueueError("redis down")

    queue.is_cancelled = _raise  # type: ignore[assignment]
    repository = AsyncMock()
    repository.get_by_id.return_value = SimpleNamespace(status=ScanStatus.queued, progress=0)
    orchestrator = AsyncMock()

    await process_scan_job(
        ScanJob(scan_id="scan-degraded"),
        queue=queue,
        repository=repository,
        orchestrator=orchestrator,
    )

    orchestrator.run_scan.assert_awaited_once()
