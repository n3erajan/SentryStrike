from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from shared.analysis_handoff import (
    ensure_initial_analysis_job,
    reconcile_missing_analysis_jobs,
)
from shared.analysis_queue import AnalysisQueueError
from shared.models.scan import ScanStatus


class FakeScanRepository:
    def __init__(self, scans=None) -> None:
        self.scans = list(scans or [])
        self.attachments = []

    async def attach_initial_analysis_job(self, **kwargs):
        self.attachments.append(kwargs)
        return True

    async def list_completed_without_analysis(self, limit=100):
        return self.scans[:limit]


class FakeAnalysisRepository:
    def __init__(self) -> None:
        self.created = []

    async def create_initial(self, **kwargs):
        self.created.append(kwargs)
        return SimpleNamespace(
            id="job-1",
            revision=1,
            queued_at=datetime(2026, 7, 21, tzinfo=timezone.utc),
        )


class FakeAnalysisQueue:
    def __init__(self, *, fail=False) -> None:
        self.fail = fail
        self.signals = []

    async def enqueue(self, signal):
        self.signals.append(signal)
        if self.fail:
            raise AnalysisQueueError("Redis unavailable")


def _scan(scan_id="scan-1"):
    return SimpleNamespace(
        id=scan_id,
        org_id="org-1",
        status=ScanStatus.completed,
        vulnerabilities=[SimpleNamespace(id="v-1")],
    )


@pytest.mark.asyncio
async def test_redis_signal_failure_keeps_durable_job_and_projection() -> None:
    scan_repository = FakeScanRepository()
    analysis_repository = FakeAnalysisRepository()
    queue = FakeAnalysisQueue(fail=True)

    job = await ensure_initial_analysis_job(
        _scan(),
        scan_repository=scan_repository,
        analysis_repository=analysis_repository,
        analysis_queue=queue,
    )

    assert job is not None
    assert analysis_repository.created[0]["finding_count"] == 1
    assert scan_repository.attachments[0]["job_id"] == "job-1"
    assert queue.signals[0].model_dump() == {"analysis_job_id": "job-1"}


@pytest.mark.asyncio
async def test_reconciliation_repairs_completed_scan_without_analysis() -> None:
    scan_repository = FakeScanRepository([_scan("scan-orphan")])
    analysis_repository = FakeAnalysisRepository()
    queue = FakeAnalysisQueue()

    reconciled = await reconcile_missing_analysis_jobs(
        scan_repository=scan_repository,
        analysis_repository=analysis_repository,
        analysis_queue=queue,
    )

    assert reconciled == 1
    assert analysis_repository.created == [
        {
            "scan_id": "scan-orphan",
            "org_id": "org-1",
            "finding_count": 1,
        }
    ]
    assert scan_repository.attachments[0]["scan_id"] == "scan-orphan"
