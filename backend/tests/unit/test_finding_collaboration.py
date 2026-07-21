"""Finding-collaboration authorization and workflow tests (Phase 4).

Findings are embedded in their scan document; assigning, commenting, and
advancing a fix mutate the finding in place and persist via ``scan.save()``.
The invariants under test: every mutation is org-scoped (a foreign scan or
finding is a 404), an assignee must be a same-org member, viewers are read-only,
and the terminal remediation states (verified / won't-fix) are triager-only so a
developer cannot sign off their own fix.
"""

from datetime import datetime, timezone
from types import SimpleNamespace

from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from app.api.dependencies import (
    get_current_user,
    get_member_repository,
    get_notification_repository,
    get_scan_repository,
)
from app.api.routes import analysis
from shared.models.user import UserRole
from shared.models.vulnerability import (
    LocationInfo,
    OwaspCategory,
    RemediationStatus,
    SeverityLevel,
    Vulnerability,
)


def _finding(vuln_id: str) -> Vulnerability:
    return Vulnerability(
        id=vuln_id,
        category=OwaspCategory.a05,
        vuln_type="Reflected XSS",
        severity=SeverityLevel.high,
        location=LocationInfo(url="https://target.example/search", parameter="q"),
    )


class FakeScan:
    def __init__(self, scan_id: str, org_id: str) -> None:
        self.id = scan_id
        self.org_id = org_id
        self.vulnerabilities = [_finding("vuln-1")]
        self.saved = False

    async def save(self) -> None:
        self.saved = True


class FakeScanRepository:
    def __init__(self) -> None:
        self.scans = {
            "scan-1": FakeScan("scan-1", "org-1"),
            "scan-other": FakeScan("scan-other", "org-2"),
        }

    async def get_in_org(self, scan_id: str, org_id: str):
        scan = self.scans.get(scan_id)
        if scan is None or scan.org_id != org_id:
            return None
        return scan


class FakeMember:
    def __init__(self, user_id: str, org_id: str) -> None:
        self.id = user_id
        self.org_id = org_id
        self.email = f"{user_id}@example.test"


class FakeMemberRepository:
    def __init__(self) -> None:
        self.members = {
            "user-dev": FakeMember("user-dev", "org-1"),
            "user-other": FakeMember("user-other", "org-2"),
        }

    async def get_in_org(self, user_id: str, org_id: str):
        member = self.members.get(user_id)
        if member is None or member.org_id != org_id:
            return None
        return member


class FakeNotificationRepository:
    def __init__(self) -> None:
        self.entries: list[dict] = []

    async def create(self, **kwargs):
        self.entries.append(kwargs)
        return SimpleNamespace(**kwargs)


def _client(
    repo: FakeScanRepository,
    members: FakeMemberRepository,
    *,
    user_id: str = "user-analyst",
    org_id: str = "org-1",
    role: UserRole = UserRole.analyst,
) -> TestClient:
    app = FastAPI()
    app.include_router(analysis.router, prefix="/api/v1", dependencies=[Depends(get_current_user)])
    app.dependency_overrides[get_scan_repository] = lambda: repo
    app.dependency_overrides[get_member_repository] = lambda: members
    app.dependency_overrides[get_notification_repository] = lambda: FakeNotificationRepository()
    app.dependency_overrides[get_current_user] = lambda: SimpleNamespace(
        id=user_id, email=f"{user_id}@example.test", org_id=org_id, role=role
    )
    return TestClient(app)


def _repos():
    return FakeScanRepository(), FakeMemberRepository()


# ---------------------------------------------------------------------------
# Assignment
# ---------------------------------------------------------------------------


def test_triager_can_assign_finding_to_same_org_member() -> None:
    repo, members = _repos()
    client = _client(repo, members, role=UserRole.analyst)

    response = client.put(
        "/api/v1/analysis/scans/scan-1/vulnerabilities/vuln-1/assignment",
        json={"assignee_user_id": "user-dev"},
    )

    assert response.status_code == 200
    data = response.json()["data"]
    assert data["assignee_user_id"] == "user-dev"
    assert data["assignee_email"] == "user-dev@example.test"
    assert repo.scans["scan-1"].vulnerabilities[0].assignee_user_id == "user-dev"


def test_assign_can_be_cleared_with_null() -> None:
    repo, members = _repos()
    repo.scans["scan-1"].vulnerabilities[0].assignee_user_id = "user-dev"
    client = _client(repo, members, role=UserRole.admin)

    response = client.put(
        "/api/v1/analysis/scans/scan-1/vulnerabilities/vuln-1/assignment",
        json={"assignee_user_id": None},
    )

    assert response.status_code == 200
    assert response.json()["data"]["assignee_user_id"] is None
    assert repo.scans["scan-1"].vulnerabilities[0].assignee_user_id is None


def test_cannot_assign_to_member_of_another_org() -> None:
    repo, members = _repos()
    client = _client(repo, members, role=UserRole.analyst)

    response = client.put(
        "/api/v1/analysis/scans/scan-1/vulnerabilities/vuln-1/assignment",
        json={"assignee_user_id": "user-other"},
    )

    assert response.status_code == 404


def test_developer_cannot_assign_findings() -> None:
    repo, members = _repos()
    client = _client(repo, members, user_id="user-dev", role=UserRole.developer)

    response = client.put(
        "/api/v1/analysis/scans/scan-1/vulnerabilities/vuln-1/assignment",
        json={"assignee_user_id": "user-dev"},
    )

    assert response.status_code == 403


def test_assign_on_foreign_org_scan_is_not_found() -> None:
    repo, members = _repos()
    client = _client(repo, members, role=UserRole.analyst)

    response = client.put(
        "/api/v1/analysis/scans/scan-other/vulnerabilities/vuln-1/assignment",
        json={"assignee_user_id": "user-dev"},
    )

    assert response.status_code == 404


# ---------------------------------------------------------------------------
# Comments
# ---------------------------------------------------------------------------


def test_contributor_can_comment() -> None:
    repo, members = _repos()
    client = _client(repo, members, user_id="user-dev", role=UserRole.developer)

    response = client.post(
        "/api/v1/analysis/scans/scan-1/vulnerabilities/vuln-1/comments",
        json={"body": "Reproduced on staging; patching the sink."},
    )

    assert response.status_code == 201
    data = response.json()["data"]
    assert data["author_user_id"] == "user-dev"
    assert data["body"] == "Reproduced on staging; patching the sink."
    assert len(repo.scans["scan-1"].vulnerabilities[0].comments) == 1


def test_viewer_cannot_comment() -> None:
    repo, members = _repos()
    client = _client(repo, members, role=UserRole.viewer)

    response = client.post(
        "/api/v1/analysis/scans/scan-1/vulnerabilities/vuln-1/comments",
        json={"body": "looks bad"},
    )

    assert response.status_code == 403


def test_empty_comment_is_rejected() -> None:
    repo, members = _repos()
    client = _client(repo, members, role=UserRole.analyst)

    response = client.post(
        "/api/v1/analysis/scans/scan-1/vulnerabilities/vuln-1/comments",
        json={"body": ""},
    )

    assert response.status_code == 422


def test_comment_on_missing_finding_is_not_found() -> None:
    repo, members = _repos()
    client = _client(repo, members, role=UserRole.analyst)

    response = client.post(
        "/api/v1/analysis/scans/scan-1/vulnerabilities/nope/comments",
        json={"body": "hello"},
    )

    assert response.status_code == 404


# ---------------------------------------------------------------------------
# Remediation workflow
# ---------------------------------------------------------------------------


def test_developer_can_advance_to_pending_verification() -> None:
    repo, members = _repos()
    client = _client(repo, members, user_id="user-dev", role=UserRole.developer)

    response = client.put(
        "/api/v1/analysis/scans/scan-1/vulnerabilities/vuln-1/remediation",
        json={"remediation_status": "fixed_pending_verification"},
    )

    assert response.status_code == 200
    assert repo.scans["scan-1"].vulnerabilities[0].remediation_status == RemediationStatus.fixed_pending_verification


def test_developer_cannot_confirm_verified_fixed() -> None:
    repo, members = _repos()
    client = _client(repo, members, user_id="user-dev", role=UserRole.developer)

    response = client.put(
        "/api/v1/analysis/scans/scan-1/vulnerabilities/vuln-1/remediation",
        json={"remediation_status": "verified_fixed"},
    )

    assert response.status_code == 403
    assert repo.scans["scan-1"].vulnerabilities[0].remediation_status == RemediationStatus.open


def test_developer_cannot_waive_a_finding() -> None:
    repo, members = _repos()
    client = _client(repo, members, user_id="user-dev", role=UserRole.developer)

    response = client.put(
        "/api/v1/analysis/scans/scan-1/vulnerabilities/vuln-1/remediation",
        json={"remediation_status": "wont_fix"},
    )

    assert response.status_code == 403


def test_analyst_can_confirm_verified_fixed() -> None:
    repo, members = _repos()
    client = _client(repo, members, role=UserRole.analyst)

    response = client.put(
        "/api/v1/analysis/scans/scan-1/vulnerabilities/vuln-1/remediation",
        json={"remediation_status": "verified_fixed"},
    )

    assert response.status_code == 200
    assert repo.scans["scan-1"].vulnerabilities[0].remediation_status == RemediationStatus.verified_fixed


def test_viewer_cannot_update_remediation() -> None:
    repo, members = _repos()
    client = _client(repo, members, role=UserRole.viewer)

    response = client.put(
        "/api/v1/analysis/scans/scan-1/vulnerabilities/vuln-1/remediation",
        json={"remediation_status": "in_progress"},
    )

    assert response.status_code == 403
