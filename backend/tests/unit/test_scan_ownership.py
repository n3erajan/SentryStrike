from datetime import datetime, timezone
from types import SimpleNamespace

from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from app.api.dependencies import get_current_user, get_scan_repository
from app.api.routes import analysis, reports, scan
from shared.models.scan import CrawlMode, ReportMetadata, ScanPhase, ScanStatistics, ScanStatus
from shared.scan_queue import ScanQueueError


class FakeScanQueue:
    def __init__(
        self,
        *,
        enqueue_error: Exception | None = None,
        cancel_error: Exception | None = None,
        lease_alive: bool = True,
        lease_error: Exception | None = None,
    ) -> None:
        self.queued: list[str] = []
        self.cancelled: list[str] = []
        self.enqueue_error = enqueue_error
        self.cancel_error = cancel_error
        # Controls what reconcile_if_orphaned sees: True = a worker still holds
        # the lease, False = worker died, error = Redis unreachable.
        self.lease_alive = lease_alive
        self.lease_error = lease_error

    async def enqueue(self, job) -> None:
        if self.enqueue_error is not None:
            raise self.enqueue_error
        self.queued.append(job.scan_id)

    async def request_cancel(self, scan_id: str) -> None:
        if self.cancel_error is not None:
            raise self.cancel_error
        self.cancelled.append(scan_id)

    async def is_lease_alive(self, scan_id: str) -> bool:
        if self.lease_error is not None:
            raise self.lease_error
        return self.lease_alive


class FakeScan:
    def __init__(self, scan_id: str, owner_user_id: str, owner_email: str = "owner@example.test") -> None:
        self.id = scan_id
        self.target_url = "https://target.example"
        self.owner_user_id = owner_user_id
        self.owner_email = owner_email
        self.crawl_mode = CrawlMode.full
        self.status = ScanStatus.queued
        self.progress = 0
        self.current_phase = ScanPhase.queued
        self.phase_message = "Scan queued"
        self.authorization_confirmed = True
        self.authorization_confirmed_at = datetime(2026, 6, 8, 9, 10, 17, tzinfo=timezone.utc)
        self.started_at = None
        self.completed_at = None
        self.eta_seconds = None
        self.created_at = datetime(2026, 6, 8, 9, 10, 17, tzinfo=timezone.utc)
        self.updated_at = datetime(2026, 6, 8, 9, 10, 17, tzinfo=timezone.utc)
        self.statistics = ScanStatistics(total_urls_crawled=1, total_vulnerabilities=0)
        self.overall_risk_score = 0.0
        self.technology_stack = []
        self.vulnerabilities = []
        self.report_metadata = ReportMetadata(summary="Summary.")
        self.error_message = None
        self.saved = False
        self.deleted = False

    def model_dump(self, *_, **__) -> dict:
        return {
            "target_url": self.target_url,
            "owner_user_id": self.owner_user_id,
            "owner_email": self.owner_email,
            "crawl_mode": self.crawl_mode,
            "status": self.status,
            "progress": self.progress,
            "current_phase": self.current_phase,
            "phase_message": self.phase_message,
            "authorization_confirmed": self.authorization_confirmed,
            "authorization_confirmed_at": self.authorization_confirmed_at,
            "statistics": self.statistics.model_dump(mode="json"),
            "overall_risk_score": self.overall_risk_score,
            "technology_stack": [],
            "vulnerabilities": [],
            "report_metadata": self.report_metadata.model_dump(mode="json"),
        }

    async def save(self) -> None:
        self.saved = True

    async def delete(self) -> None:
        self.deleted = True


class FakeScanRepository:
    def __init__(self) -> None:
        self.scans = {
            "scan-owned": FakeScan("scan-owned", "user-1", "user1@example.test"),
            "scan-other": FakeScan("scan-other", "user-2", "user2@example.test"),
        }
        self.created_kwargs: dict | None = None

    async def create(self, target_url: str, **kwargs):
        self.created_kwargs = {"target_url": target_url, **kwargs}
        created = FakeScan("scan-new", kwargs["owner_user_id"], kwargs["owner_email"])
        created.target_url = target_url
        created.authorization_confirmed = kwargs["authorization_confirmed"]
        self.scans[str(created.id)] = created
        return created

    async def list(self, skip: int = 0, limit: int = 20, owner_user_id: str | None = None):
        items = [scan for scan in self.scans.values() if owner_user_id is None or scan.owner_user_id == owner_user_id]
        return items[skip: skip + limit]

    async def get_owned_by_id(self, scan_id: str, owner_user_id: str):
        item = self.scans.get(scan_id)
        if item is None or item.owner_user_id != owner_user_id:
            return None
        return item

    async def update_status(
        self,
        item: FakeScan,
        status: ScanStatus,
        progress: int | None = None,
        current_phase: ScanPhase | None = None,
        phase_message: str | None = None,
        error_message: str | None = None,
    ) -> FakeScan:
        item.status = status
        if progress is not None:
            item.progress = progress
        if current_phase is not None:
            item.current_phase = current_phase
        if phase_message is not None:
            item.phase_message = phase_message
        if error_message is not None:
            item.error_message = error_message
        return item

    async def reconcile_if_orphaned(self, scan: FakeScan, queue) -> FakeScan:
        """Mirror production: only fail a running scan when the lease is
        provably absent. If the lease check raises (Redis down) or the queue is
        missing, leave the scan untouched."""
        if scan.status != ScanStatus.running:
            return scan
        if queue is None:
            return scan
        try:
            lease_alive = await queue.is_lease_alive(str(scan.id))
        except Exception:
            return scan
        if lease_alive:
            return scan
        return await self.update_status(
            scan,
            ScanStatus.failed,
            current_phase=ScanPhase.failed,
            phase_message="Scan worker stopped unexpectedly",
            error_message="Scan worker stopped unexpectedly; no active worker is processing this scan.",
        )

def _client(repo: FakeScanRepository, user_id: str = "user-1") -> TestClient:
    app = FastAPI()
    app.include_router(scan.router, prefix="/api/v1", dependencies=[Depends(get_current_user)])
    app.include_router(analysis.router, prefix="/api/v1", dependencies=[Depends(get_current_user)])
    app.include_router(reports.router, prefix="/api/v1", dependencies=[Depends(get_current_user)])
    app.dependency_overrides[get_scan_repository] = lambda: repo
    app.dependency_overrides[get_current_user] = lambda: SimpleNamespace(id=user_id, email=f"{user_id}@example.test")
    return TestClient(app)


def test_create_scan_requires_authorization_confirmation() -> None:
    repo = FakeScanRepository()
    scan.set_scan_queue(FakeScanQueue())
    client = _client(repo)

    response = client.post("/api/v1/scans", json={"target_url": "https://target.example"})

    assert response.status_code == 422
    assert repo.created_kwargs is None


def test_create_scan_binds_owner_and_authorization_metadata() -> None:
    repo = FakeScanRepository()
    scan_queue = FakeScanQueue()
    scan.set_scan_queue(scan_queue)
    client = _client(repo)

    response = client.post(
        "/api/v1/scans",
        json={
            "target_url": "https://target.example",
            "authorization_confirmed": True,
        },
    )

    assert response.status_code == 202
    assert repo.created_kwargs["owner_user_id"] == "user-1"
    assert repo.created_kwargs["owner_email"] == "user-1@example.test"
    assert repo.created_kwargs["authorization_confirmed"] is True
    assert scan_queue.queued == ["scan-new"]


def test_create_scan_marks_scan_failed_when_queue_is_unavailable() -> None:
    repo = FakeScanRepository()
    scan.set_scan_queue(FakeScanQueue(enqueue_error=ScanQueueError("offline")))
    client = _client(repo)

    response = client.post(
        "/api/v1/scans",
        json={
            "target_url": "https://target.example",
            "authorization_confirmed": True,
        },
    )

    assert response.status_code == 503
    created = repo.scans["scan-new"]
    assert created.status == ScanStatus.failed
    assert created.current_phase == ScanPhase.failed
    assert created.phase_message == "Scan queue unavailable"
    assert created.error_message == "Scan queue unavailable"


def test_cancel_queued_scan_marks_it_cancelled_and_sets_queue_key() -> None:
    repo = FakeScanRepository()
    scan_queue = FakeScanQueue()
    scan.set_scan_queue(scan_queue)
    client = _client(repo)

    response = client.post("/api/v1/scans/scan-owned/cancel")

    assert response.status_code == 200
    assert response.json()["data"]["cancelled"] is True
    assert scan_queue.cancelled == ["scan-owned"]
    assert repo.scans["scan-owned"].status == ScanStatus.cancelled
    assert repo.scans["scan-owned"].current_phase == ScanPhase.cancelled


def test_cancel_scan_returns_service_unavailable_when_queue_is_offline() -> None:
    repo = FakeScanRepository()
    scan.set_scan_queue(FakeScanQueue(cancel_error=ScanQueueError("offline")))
    client = _client(repo)

    response = client.post("/api/v1/scans/scan-owned/cancel")

    assert response.status_code == 503
    assert repo.scans["scan-owned"].status == ScanStatus.queued


def test_list_scans_only_returns_current_users_scans() -> None:
    repo = FakeScanRepository()
    client = _client(repo, user_id="user-1")

    response = client.get("/api/v1/scans")

    assert response.status_code == 200
    items = response.json()["data"]["items"]
    assert [item["id"] for item in items] == ["scan-owned"]
    assert items[0]["owner_user_id"] == "user-1"
    assert items[0]["current_phase"] == "queued"
    assert items[0]["phase_message"] == "Scan queued"


def test_scan_status_returns_phase_and_message_for_polling() -> None:
    repo = FakeScanRepository()
    # A live worker still holds the lease, so reconciliation leaves it running.
    scan.set_scan_queue(FakeScanQueue(lease_alive=True))
    owned = repo.scans["scan-owned"]
    owned.status = ScanStatus.running
    owned.progress = 45
    owned.current_phase = ScanPhase.vulnerability_detection
    owned.phase_message = "Running active detectors"
    client = _client(repo, user_id="user-1")

    response = client.get("/api/v1/scans/scan-owned/status")

    assert response.status_code == 200
    data = response.json()["data"]
    assert data["progress"] == 45
    assert data["current_phase"] == "vulnerability_detection"
    assert data["phase_message"] == "Running active detectors"


def test_scan_detail_for_other_user_returns_not_found() -> None:
    repo = FakeScanRepository()
    client = _client(repo, user_id="user-1")

    response = client.get("/api/v1/scans/scan-other")

    assert response.status_code == 404


def test_analysis_for_other_users_scan_returns_not_found() -> None:
    repo = FakeScanRepository()
    client = _client(repo, user_id="user-1")

    response = client.get("/api/v1/analysis/scans/scan-other/vulnerabilities")

    assert response.status_code == 404


def test_report_for_other_users_scan_returns_not_found() -> None:
    repo = FakeScanRepository()
    client = _client(repo, user_id="user-1")

    response = client.get("/api/v1/reports/scan-other")

    assert response.status_code == 404


def test_report_payload_includes_owner_and_authorization_audit_fields() -> None:
    repo = FakeScanRepository()
    client = _client(repo, user_id="user-1")

    response = client.get("/api/v1/reports/scan-owned")

    assert response.status_code == 200
    data = response.json()["data"]
    assert data["owner_user_id"] == "user-1"
    assert data["owner_email"] == "user1@example.test"
    assert data["authorization"]["confirmed"] is True


def _running(repo: FakeScanRepository, scan_id: str = "scan-owned") -> FakeScan:
    """Put an owned scan into the running state for reconciliation tests."""
    scan = repo.scans[scan_id]
    scan.status = ScanStatus.running
    scan.progress = 40
    scan.current_phase = ScanPhase.vulnerability_detection
    return scan


def test_status_of_running_scan_with_dead_worker_is_reconciled_to_failed() -> None:
    repo = FakeScanRepository()
    _running(repo)
    # No live lease => the worker died; the read must flip it to failed.
    scan.set_scan_queue(FakeScanQueue(lease_alive=False))
    client = _client(repo, user_id="user-1")

    response = client.get("/api/v1/scans/scan-owned/status")

    assert response.status_code == 200
    data = response.json()["data"]
    assert data["status"] == "failed"
    assert data["current_phase"] == "failed"
    assert repo.scans["scan-owned"].status == ScanStatus.failed


def test_status_of_running_scan_with_live_lease_stays_running() -> None:
    repo = FakeScanRepository()
    _running(repo)
    scan.set_scan_queue(FakeScanQueue(lease_alive=True))
    client = _client(repo, user_id="user-1")

    response = client.get("/api/v1/scans/scan-owned/status")

    assert response.status_code == 200
    assert response.json()["data"]["status"] == "running"
    assert repo.scans["scan-owned"].status == ScanStatus.running


def test_running_scan_is_not_reconciled_when_redis_is_unavailable() -> None:
    repo = FakeScanRepository()
    _running(repo)
    # Lease check raises => cannot tell a dead worker from an unreachable Redis,
    # so the scan must be left untouched rather than falsely failed.
    scan.set_scan_queue(FakeScanQueue(lease_error=ScanQueueError("offline")))
    client = _client(repo, user_id="user-1")

    response = client.get("/api/v1/scans/scan-owned/status")

    assert response.status_code == 200
    assert response.json()["data"]["status"] == "running"
    assert repo.scans["scan-owned"].status == ScanStatus.running


def test_cancel_of_scan_with_dead_worker_resolves_to_failed_without_queue_key() -> None:
    repo = FakeScanRepository()
    _running(repo)
    fake_queue = FakeScanQueue(lease_alive=False)
    scan.set_scan_queue(fake_queue)
    client = _client(repo, user_id="user-1")

    response = client.post("/api/v1/scans/scan-owned/cancel")

    # A dead scan cancels into failed without setting a cancel key nobody reads.
    assert response.status_code == 200
    assert response.json()["data"]["cancelled"] is False
    assert repo.scans["scan-owned"].status == ScanStatus.failed
    assert fake_queue.cancelled == []
