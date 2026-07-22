from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.dependencies import (
    get_analysis_job_repository,
    get_analysis_queue,
    get_audit_repository,
    get_current_user,
    get_scan_repository,
)
from app.api.routes import analysis
from shared.analysis_queue import AnalysisQueueError
from shared.models.analysis_job import AnalysisStatus
from shared.models.scan import ScanAnalysisState, ScanStatus
from shared.models.user import UserRole


class FakeScanRepository:
    def __init__(self, *, attach=True) -> None:
        self.attach = attach
        self.scan = SimpleNamespace(
            id="scan-1",
            org_id="org-1",
            status=ScanStatus.completed,
            analysis=ScanAnalysisState(
                status=AnalysisStatus.failed,
                current_job_id="job-1",
                revision=1,
                progress=50,
                message="Analysis failed",
            ),
            vulnerabilities=[SimpleNamespace(id="v-1")],
        )
        self.attachments = []

    async def get_in_org(self, scan_id, org_id):
        if scan_id != "scan-1" or org_id != "org-1":
            return None
        return self.scan

    async def attach_retry_analysis_job(self, **kwargs):
        self.attachments.append(kwargs)
        if self.attach:
            self.scan.analysis = ScanAnalysisState(
                status=AnalysisStatus.queued,
                current_job_id=kwargs["job_id"],
                revision=kwargs["revision"],
                message="Analysis queued",
            )
        return self.attach


class FakeAnalysisRepository:
    def __init__(self) -> None:
        self.created = []

    async def create_manual_retry(self, **kwargs):
        self.created.append(kwargs)
        return SimpleNamespace(
            id="job-2",
            queued_at=datetime(2026, 7, 21, tzinfo=timezone.utc),
        )


class FakeQueue:
    def __init__(self, *, fail: bool = False) -> None:
        self.signals = []
        self.fail = fail

    async def enqueue(self, signal):
        if self.fail:
            raise AnalysisQueueError("Redis unavailable")
        self.signals.append(signal)


class FakeAudit:
    def __init__(self) -> None:
        self.entries = []

    async def record(self, **kwargs):
        self.entries.append(kwargs)


def _client(
    role: UserRole,
    *,
    attach=True,
    org_id: str = "org-1",
    queue_fails: bool = False,
):
    app = FastAPI()
    app.include_router(analysis.router)
    scan_repository = FakeScanRepository(attach=attach)
    analysis_repository = FakeAnalysisRepository()
    queue = FakeQueue(fail=queue_fails)
    audit = FakeAudit()
    user = SimpleNamespace(
        id="user-1",
        org_id=org_id,
        email="user@example.test",
        role=role,
    )
    app.dependency_overrides[get_current_user] = lambda: user
    app.dependency_overrides[get_scan_repository] = lambda: scan_repository
    app.dependency_overrides[get_analysis_job_repository] = lambda: analysis_repository
    app.dependency_overrides[get_analysis_queue] = lambda: queue
    app.dependency_overrides[get_audit_repository] = lambda: audit
    return TestClient(app), scan_repository, analysis_repository, queue, audit


@pytest.mark.parametrize(
    "role",
    [UserRole.owner, UserRole.admin, UserRole.analyst],
)
def test_triager_can_create_new_failed_analysis_revision(role) -> None:
    client, scan_repository, analysis_repository, queue, audit = _client(role)

    response = client.post("/analysis/scans/scan-1/retry")

    assert response.status_code == 202
    data = response.json()["data"]
    assert data["job_id"] == "job-2"
    assert data["revision"] == 2
    assert data["status"] == "queued"
    assert analysis_repository.created[0]["requested_by_user_id"] == "user-1"
    assert scan_repository.attachments[0]["previous_revision"] == 1
    assert queue.signals[0].analysis_job_id == "job-2"
    assert audit.entries[0]["metadata"]["new_revision"] == 2


@pytest.mark.parametrize("role", [UserRole.developer, UserRole.viewer])
def test_non_triager_cannot_retry_analysis(role) -> None:
    client, *_ = _client(role)

    response = client.post("/analysis/scans/scan-1/retry")

    assert response.status_code == 403


def test_concurrent_retry_loser_receives_active_conflict() -> None:
    client, *_ = _client(UserRole.analyst, attach=False)

    response = client.post("/analysis/scans/scan-1/retry")

    assert response.status_code == 409
    assert response.json()["detail"]["code"] == "analysis_already_active"


@pytest.mark.parametrize(
    ("analysis_status", "expected_code"),
    [
        (AnalysisStatus.queued, "analysis_already_active"),
        (AnalysisStatus.running, "analysis_already_active"),
        (AnalysisStatus.completed, "analysis_already_completed"),
    ],
)
def test_active_or_completed_analysis_cannot_be_retried(
    analysis_status, expected_code
) -> None:
    client, scan_repository, analysis_repository, queue, audit = _client(
        UserRole.analyst
    )
    scan_repository.scan.analysis.status = analysis_status

    response = client.post("/analysis/scans/scan-1/retry")

    assert response.status_code == 409
    assert response.json()["detail"]["code"] == expected_code
    assert analysis_repository.created == []
    assert queue.signals == []
    assert audit.entries == []


def test_non_completed_scan_cannot_create_analysis_retry() -> None:
    client, scan_repository, analysis_repository, queue, audit = _client(
        UserRole.analyst
    )
    scan_repository.scan.status = ScanStatus.running

    response = client.post("/analysis/scans/scan-1/retry")

    assert response.status_code == 409
    assert response.json()["detail"]["code"] == "analysis_not_retryable"
    assert analysis_repository.created == []
    assert queue.signals == []
    assert audit.entries == []


def test_cross_org_retry_is_not_discoverable() -> None:
    client, *_ = _client(UserRole.analyst, org_id="org-2")

    response = client.post("/analysis/scans/scan-1/retry")

    assert response.status_code == 404


def test_retry_remains_durable_when_redis_signal_fails() -> None:
    client, scan_repository, analysis_repository, queue, audit = _client(
        UserRole.analyst,
        queue_fails=True,
    )

    response = client.post("/analysis/scans/scan-1/retry")

    assert response.status_code == 202
    assert response.json()["data"]["signal_delivered"] is False
    assert len(analysis_repository.created) == 1
    assert len(scan_repository.attachments) == 1
    assert queue.signals == []
    assert len(audit.entries) == 1
