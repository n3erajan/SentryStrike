"""Unit tests for Application CRUD endpoints and org isolation."""

from datetime import datetime, timezone
from types import SimpleNamespace

from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from app.api.dependencies import (
    get_application_repository,
    get_current_user,
    get_scan_repository,
)
from app.api.routes import applications
from shared.models.user import UserRole


class FakeApplication:
    def __init__(
        self,
        app_id: str,
        name: str,
        target_url: str,
        org_id: str,
        default_scan_config: dict | None = None,
    ) -> None:
        self.id = app_id
        self.name = name
        self.target_url = target_url
        self.org_id = org_id
        self.default_scan_config = default_scan_config or {}
        self.created_at = datetime(2026, 7, 24, 12, 0, 0, tzinfo=timezone.utc)
        self.updated_at = datetime(2026, 7, 24, 12, 0, 0, tzinfo=timezone.utc)


class FakeApplicationRepository:
    def __init__(self) -> None:
        self.apps = {
            "app-1": FakeApplication("app-1", "App One", "https://app1.example.test", "org-1"),
            "app-2": FakeApplication("app-2", "App Two", "https://app2.example.test", "org-2"),
        }

    async def create(self, name: str, target_url: str, *, org_id: str, default_scan_config: dict | None = None):
        app_id = f"app-{len(self.apps) + 1}"
        app = FakeApplication(app_id, name, target_url, org_id, default_scan_config)
        self.apps[app_id] = app
        return app

    async def get_in_org(self, app_id: str, org_id: str):
        app = self.apps.get(app_id)
        if app is None or app.org_id != org_id:
            return None
        return app

    async def list_in_org(self, org_id: str, skip: int = 0, limit: int = 20):
        items = [a for a in self.apps.values() if a.org_id == org_id]
        return items[skip : skip + limit]

    async def count_in_org(self, org_id: str) -> int:
        return sum(app.org_id == org_id for app in self.apps.values())

    async def update_in_org(self, app_id: str, org_id: str, *, name=None, target_url=None, default_scan_config=None):
        app = await self.get_in_org(app_id, org_id)
        if app is None:
            return None
        if name is not None:
            app.name = name
        if target_url is not None:
            app.target_url = target_url
        if default_scan_config is not None:
            app.default_scan_config = default_scan_config
        return app

    async def delete_in_org(self, app_id: str, org_id: str) -> bool:
        app = await self.get_in_org(app_id, org_id)
        if app is None:
            return False
        self.apps.pop(app_id, None)
        return True


class FakeScanRepository:
    def __init__(self) -> None:
        self.requested_application_id: str | None = None
        self.scans = [
            SimpleNamespace(
                id="scan-1",
                org_id="org-1",
                target_url="https://app1.example.test",
                crawl_mode="full",
                status="completed",
                progress=100,
                current_phase="completed",
                phase_message="Scan completed",
                overall_risk_score=45.0,
                overall_risk_level="Medium",
                created_at=datetime(2026, 7, 24, 10, 0, 0, tzinfo=timezone.utc),
                completed_at=datetime(2026, 7, 24, 10, 30, 0, tzinfo=timezone.utc),
            )
        ]

    async def list_by_application(
        self,
        org_id: str,
        application_id: str,
        target_url: str,
        skip: int = 0,
        limit: int = 20,
    ):
        self.requested_application_id = application_id
        items = [s for s in self.scans if s.org_id == org_id and s.target_url == target_url]
        return items[skip : skip + limit]


def _client(
    app_repo: FakeApplicationRepository,
    scan_repo: FakeScanRepository,
    user_id: str = "user-1",
    org_id: str = "org-1",
    role: UserRole = UserRole.admin,
) -> TestClient:
    app = FastAPI()
    app.include_router(applications.router, prefix="/api/v1", dependencies=[Depends(get_current_user)])
    app.dependency_overrides[get_application_repository] = lambda: app_repo
    app.dependency_overrides[get_scan_repository] = lambda: scan_repo
    app.dependency_overrides[get_current_user] = lambda: SimpleNamespace(
        id=user_id, email=f"{user_id}@example.test", org_id=org_id, role=role
    )
    return TestClient(app)


def test_create_application() -> None:
    app_repo = FakeApplicationRepository()
    scan_repo = FakeScanRepository()
    client = _client(app_repo, scan_repo, role=UserRole.admin)

    resp = client.post(
        "/api/v1/applications",
        json={
            "name": "My App",
            "target_url": "https://myapp.example.test",
            "default_scan_config": {"crawl_depth": 5},
        },
    )

    assert resp.status_code == 201
    data = resp.json()["data"]
    assert data["name"] == "My App"
    assert data["target_url"] == "https://myapp.example.test/"
    assert data["default_scan_config"] == {"crawl_depth": 5}


def test_list_applications_org_scoped() -> None:
    app_repo = FakeApplicationRepository()
    app_repo.apps["app-3"] = FakeApplication(
        "app-3", "App Three", "https://app3.example.test", "org-1"
    )
    scan_repo = FakeScanRepository()
    client = _client(app_repo, scan_repo, org_id="org-1")

    resp = client.get("/api/v1/applications?limit=1")
    assert resp.status_code == 200
    data = resp.json()["data"]
    items = data["items"]
    assert len(items) == 1
    assert items[0]["id"] == "app-1"
    assert data["total"] == 2


def test_get_application_idor_prevention() -> None:
    app_repo = FakeApplicationRepository()
    scan_repo = FakeScanRepository()

    # User in org-1 tries to access app-2 (which belongs to org-2)
    client = _client(app_repo, scan_repo, org_id="org-1")
    resp = client.get("/api/v1/applications/app-2")

    assert resp.status_code == 404
    assert resp.json()["detail"] == "Application not found"


def test_update_application() -> None:
    app_repo = FakeApplicationRepository()
    scan_repo = FakeScanRepository()
    client = _client(app_repo, scan_repo, org_id="org-1", role=UserRole.admin)

    resp = client.put(
        "/api/v1/applications/app-1",
        json={"name": "Updated Name"},
    )
    assert resp.status_code == 200
    assert resp.json()["data"]["name"] == "Updated Name"


def test_delete_application() -> None:
    app_repo = FakeApplicationRepository()
    scan_repo = FakeScanRepository()
    client = _client(app_repo, scan_repo, org_id="org-1", role=UserRole.admin)

    resp = client.delete("/api/v1/applications/app-1")
    assert resp.status_code == 200
    assert resp.json()["data"]["deleted"] is True
    assert "app-1" not in app_repo.apps


def test_viewer_cannot_mutate_applications() -> None:
    app_repo = FakeApplicationRepository()
    scan_repo = FakeScanRepository()
    client = _client(app_repo, scan_repo, org_id="org-1", role=UserRole.viewer)

    post_resp = client.post("/api/v1/applications", json={"name": "App", "target_url": "https://test.com"})
    put_resp = client.put("/api/v1/applications/app-1", json={"name": "New"})
    del_resp = client.delete("/api/v1/applications/app-1")

    assert post_resp.status_code == 403
    assert put_resp.status_code == 403
    assert del_resp.status_code == 403


def test_list_application_scans() -> None:
    app_repo = FakeApplicationRepository()
    scan_repo = FakeScanRepository()
    client = _client(app_repo, scan_repo, org_id="org-1")

    resp = client.get("/api/v1/applications/app-1/scans")
    assert resp.status_code == 200
    items = resp.json()["data"]["items"]
    assert len(items) == 1
    assert items[0]["id"] == "scan-1"
    assert scan_repo.requested_application_id == "app-1"
