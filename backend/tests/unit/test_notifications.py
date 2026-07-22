from datetime import datetime, timezone
from types import SimpleNamespace

from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from app.api.dependencies import get_current_user, get_notification_repository
from app.api.routes import notifications
from shared.models.notification import NotificationType


class FakeNotification:
    def __init__(self, notification_id: str, org_id: str, user_id: str) -> None:
        self.id = notification_id
        self.org_id = org_id
        self.recipient_user_id = user_id
        self.type = NotificationType.scan_completed
        self.title = "Scan completed"
        self.message = "Done"
        self.resource_type = "scan"
        self.resource_id = "scan-1"
        self.metadata = {}
        self.dedupe_key = f"scan:{notification_id}"
        self.read_at = None
        self.created_at = datetime(2026, 7, 21, tzinfo=timezone.utc)

    def model_dump(self, mode="python"):
        _ = mode
        return {
            "org_id": self.org_id,
            "recipient_user_id": self.recipient_user_id,
            "type": self.type.value,
            "title": self.title,
            "message": self.message,
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "metadata": self.metadata,
            "dedupe_key": self.dedupe_key,
            "read_at": self.read_at,
            "created_at": self.created_at.isoformat(),
        }


class FakeNotificationRepository:
    def __init__(self) -> None:
        self.item = FakeNotification("notification-1", "org-1", "user-1")
        self.calls: list[tuple] = []

    async def list_for_user(self, **kwargs):
        self.calls.append(("list", kwargs))
        return [self.item]

    async def unread_count(self, **kwargs):
        self.calls.append(("count", kwargs))
        return 1

    async def mark_read(self, notification_id, **kwargs):
        self.calls.append(("read", {"notification_id": notification_id, **kwargs}))
        if notification_id != self.item.id:
            return None
        self.item.read_at = datetime.now(timezone.utc)
        return self.item

    async def mark_all_read(self, **kwargs):
        self.calls.append(("read_all", kwargs))
        return 3


def _client(repo: FakeNotificationRepository) -> TestClient:
    app = FastAPI()
    app.include_router(
        notifications.router, prefix="/api/v1", dependencies=[Depends(get_current_user)]
    )
    app.dependency_overrides[get_notification_repository] = lambda: repo
    app.dependency_overrides[get_current_user] = lambda: SimpleNamespace(
        id="user-1", org_id="org-1"
    )
    return TestClient(app)


def test_notification_list_and_count_are_user_and_org_scoped() -> None:
    repo = FakeNotificationRepository()
    client = _client(repo)

    listed = client.get("/api/v1/notifications", params={"unread_only": True})
    counted = client.get("/api/v1/notifications/unread-count")

    assert listed.status_code == 200
    assert listed.json()["data"]["items"][0]["id"] == "notification-1"
    assert counted.json()["data"]["count"] == 1
    for _, kwargs in repo.calls:
        assert kwargs["org_id"] == "org-1"
        assert kwargs["recipient_user_id"] == "user-1"


def test_mark_read_and_read_all_use_scoped_repository_operations() -> None:
    repo = FakeNotificationRepository()
    client = _client(repo)

    marked = client.patch("/api/v1/notifications/notification-1/read")
    all_marked = client.post("/api/v1/notifications/read-all")
    missing = client.patch("/api/v1/notifications/missing/read")

    assert marked.status_code == 200
    assert marked.json()["data"]["read_at"] is not None
    assert all_marked.json()["data"]["updated"] == 3
    assert missing.status_code == 404
