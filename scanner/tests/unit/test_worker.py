from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from app.worker import process_scan_job
from shared.models.scan import ScanAuthAccount, ScanAuthRole, ScanPhase, ScanStatus
from shared.scan_queue import ScanJob
from shared.schemas.scan_schema import ScanConfig


@pytest.mark.asyncio
async def test_cancelled_queued_job_is_discarded_and_marked_cancelled() -> None:
    scan = SimpleNamespace(status=ScanStatus.queued, progress=12)
    queue = AsyncMock()
    queue.is_cancelled.return_value = True
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
    queue.clear_cancel.assert_awaited_once_with("scan-cancelled")
    orchestrator.run_scan.assert_not_awaited()


@pytest.mark.asyncio
async def test_missing_scan_job_is_discarded() -> None:
    queue = AsyncMock()
    repository = AsyncMock()
    repository.get_by_id.return_value = None
    orchestrator = AsyncMock()

    await process_scan_job(
        ScanJob(scan_id="scan-missing"),
        queue=queue,
        repository=repository,
        orchestrator=orchestrator,
    )

    queue.clear_cancel.assert_awaited_once_with("scan-missing")
    queue.is_cancelled.assert_not_awaited()
    orchestrator.run_scan.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "terminal_status",
    [ScanStatus.completed, ScanStatus.failed, ScanStatus.cancelled],
)
async def test_terminal_scan_job_is_discarded(terminal_status: ScanStatus) -> None:
    queue = AsyncMock()
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

    queue.clear_cancel.assert_awaited_once_with("scan-terminal")
    queue.is_cancelled.assert_not_awaited()
    orchestrator.run_scan.assert_not_awaited()


@pytest.mark.asyncio
async def test_job_credentials_and_config_are_passed_to_orchestrator() -> None:
    account = ScanAuthAccount(
        role=ScanAuthRole.main,
        username="scanner@example.test",
        password="secret",
    )
    config = ScanConfig(crawl_depth=2)
    queue = AsyncMock()
    queue.is_cancelled.return_value = False
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
    queue.clear_cancel.assert_awaited_once_with("scan-ready")
