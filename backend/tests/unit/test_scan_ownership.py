from datetime import datetime, timezone
from types import SimpleNamespace

from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from app.api.dependencies import get_current_user, get_scan_repository
from app.api.routes import analysis, reports, scan
from app.models.scan import CrawlMode, ReportMetadata, ScanStatistics, ScanStatus


class FakeOrchestrator:
    def __init__(self) -> None:
        self.queued: list[str] = []
        self.cancelled: list[str] = []

    async def queue_scan(self, scan_id: str) -> None:
        self.queued.append(scan_id)

    async def cancel_scan(self, scan_id: str) -> bool:
        self.cancelled.append(scan_id)
        return True


class FakeScan:
    def __init__(self, scan_id: str, owner_user_id: str, owner_email: str = "owner@example.test") -> None:
        self.id = scan_id
        self.target_url = "https://target.example"
        self.owner_user_id = owner_user_id
        self.owner_email = owner_email
        self.crawl_mode = CrawlMode.full
        self.status = ScanStatus.queued
        self.progress = 0
        self.authorization_confirmed = True
        self.authorization_text = "Ticket SEC-123"
        self.authorization_confirmed_at = datetime(2026, 6, 8, 9, 10, 17, tzinfo=timezone.utc)
        self.started_at = None
        self.completed_at = None
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
            "authorization_confirmed": self.authorization_confirmed,
            "authorization_text": self.authorization_text,
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
        created.authorization_text = kwargs["authorization_text"]
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

    async def delete_owned(self, scan_id: str, owner_user_id: str) -> bool:
        item = await self.get_owned_by_id(scan_id, owner_user_id)
        if item is None:
            return False
        await item.delete()
        return True


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
    scan.set_orchestrator(FakeOrchestrator())
    client = _client(repo)

    response = client.post("/api/v1/scans", json={"target_url": "https://target.example"})

    assert response.status_code == 422
    assert repo.created_kwargs is None


def test_create_scan_binds_owner_and_authorization_metadata() -> None:
    repo = FakeScanRepository()
    orchestrator = FakeOrchestrator()
    scan.set_orchestrator(orchestrator)
    client = _client(repo)

    response = client.post(
        "/api/v1/scans",
        json={
            "target_url": "https://target.example",
            "authorization_confirmed": True,
            "authorization_text": "Ticket SEC-123",
        },
    )

    assert response.status_code == 202
    assert repo.created_kwargs["owner_user_id"] == "user-1"
    assert repo.created_kwargs["owner_email"] == "user-1@example.test"
    assert repo.created_kwargs["authorization_confirmed"] is True
    assert repo.created_kwargs["authorization_text"] == "Ticket SEC-123"
    assert orchestrator.queued == ["scan-new"]


def test_list_scans_only_returns_current_users_scans() -> None:
    repo = FakeScanRepository()
    client = _client(repo, user_id="user-1")

    response = client.get("/api/v1/scans")

    assert response.status_code == 200
    items = response.json()["data"]["items"]
    assert [item["id"] for item in items] == ["scan-owned"]
    assert items[0]["owner_user_id"] == "user-1"


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
    assert data["authorization"]["text"] == "Ticket SEC-123"
