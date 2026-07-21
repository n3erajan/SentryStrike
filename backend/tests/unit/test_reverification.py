from datetime import datetime, timezone
from types import SimpleNamespace

from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from app.api.dependencies import (
    get_audit_repository,
    get_current_user,
    get_reverification_repository,
    get_scan_repository,
)
from app.api.routes import analysis, scan as scan_routes
from shared.models.reverification import ReverificationStatus
from shared.models.user import UserRole
from shared.models.vulnerability import (
    AuthContext,
    LocationInfo,
    OwaspCategory,
    SeverityLevel,
    VerificationTarget,
    Vulnerability,
)
from shared.scan_queue import ScanJobKind


class FakeScan:
    def __init__(self, org_id: str = "org-1") -> None:
        self.id = "scan-1"
        self.org_id = org_id
        self.vulnerabilities = [
            Vulnerability(
                id="vuln-1",
                category=OwaspCategory.a05,
                vuln_type="Reflected XSS",
                severity=SeverityLevel.high,
                location=LocationInfo(
                    url="https://target.example/search",
                    parameter="q",
                    parameter_location="query",
                ),
                verification_target=VerificationTarget(
                    detector_id="xss_detector",
                    url="https://target.example/search",
                    method="GET",
                    parameter="q",
                    parameter_location="query",
                    payload="<script>alert(1)</script>",
                    proof_type="reflection",
                    auth_context=AuthContext.unauthenticated,
                ),
            )
        ]
        self.saved = False

    async def save(self) -> None:
        self.saved = True


class FakeScanRepository:
    def __init__(self) -> None:
        self.scan = FakeScan()

    async def get_in_org(self, scan_id: str, org_id: str):
        if scan_id != "scan-1" or org_id != self.scan.org_id:
            return None
        return self.scan

    async def attach_reverification_job(
        self, *, scan_id: str, org_id: str, vulnerability_id: str, job_id: str
    ) -> bool:
        if scan_id != "scan-1" or org_id != self.scan.org_id or vulnerability_id != "vuln-1":
            return False
        self.scan.vulnerabilities[0].reverification_job_ids.append(job_id)
        self.scan.saved = True
        return True


class FakeJob:
    def __init__(self, target: VerificationTarget) -> None:
        self.id = "reverify-1"
        self.org_id = "org-1"
        self.scan_id = "scan-1"
        self.vulnerability_id = "vuln-1"
        self.requested_by_user_id = "user-analyst"
        self.requested_by_email = "analyst@example.test"
        self.target = target
        self.auth_roles_provided = []
        self.status = ReverificationStatus.queued
        self.outcome = None
        self.evidence = []
        self.error_message = None
        self.created_at = datetime(2026, 7, 21, tzinfo=timezone.utc)
        self.started_at = None
        self.completed_at = None

    def model_dump(self, mode="python"):
        _ = mode
        return {
            "org_id": self.org_id,
            "scan_id": self.scan_id,
            "vulnerability_id": self.vulnerability_id,
            "requested_by_user_id": self.requested_by_user_id,
            "requested_by_email": self.requested_by_email,
            "target": self.target.model_dump(mode="json"),
            "auth_roles_provided": self.auth_roles_provided,
            "status": self.status.value,
            "outcome": self.outcome,
            "evidence": self.evidence,
            "error_message": self.error_message,
            "created_at": self.created_at.isoformat(),
            "started_at": self.started_at,
            "completed_at": self.completed_at,
        }


class FakeReverificationRepository:
    def __init__(self) -> None:
        self.job: FakeJob | None = None
        self.created: dict | None = None

    async def create(self, **kwargs):
        self.created = kwargs
        self.job = FakeJob(kwargs["target"])
        self.job.auth_roles_provided = kwargs["auth_roles_provided"]
        return self.job

    async def fail(self, job, error_message):
        job.status = ReverificationStatus.failed
        job.error_message = error_message
        return job

    async def list_for_finding(self, **kwargs):
        _ = kwargs
        return [self.job] if self.job else []

    async def get_in_org(self, job_id: str, org_id: str):
        if self.job and job_id == self.job.id and org_id == self.job.org_id:
            return self.job
        return None


class FakeQueue:
    def __init__(self) -> None:
        self.jobs = []

    async def enqueue(self, job) -> None:
        self.jobs.append(job)


class FakeAuditRepository:
    def __init__(self) -> None:
        self.entries = []

    async def record(self, **kwargs) -> None:
        self.entries.append(kwargs)


def _client(role: UserRole = UserRole.analyst):
    scans = FakeScanRepository()
    reverifications = FakeReverificationRepository()
    queue = FakeQueue()
    scan_routes.set_scan_queue(queue)
    app = FastAPI()
    app.include_router(
        analysis.router, prefix="/api/v1", dependencies=[Depends(get_current_user)]
    )
    app.dependency_overrides[get_scan_repository] = lambda: scans
    app.dependency_overrides[get_reverification_repository] = lambda: reverifications
    app.dependency_overrides[get_audit_repository] = lambda: FakeAuditRepository()
    app.dependency_overrides[get_current_user] = lambda: SimpleNamespace(
        id="user-analyst",
        email="analyst@example.test",
        org_id="org-1",
        role=role,
    )
    return TestClient(app), scans, reverifications, queue


def test_triager_queues_focused_reverification_without_persisting_credentials() -> None:
    client, scans, reverifications, queue = _client()

    response = client.post(
        "/api/v1/analysis/scans/scan-1/vulnerabilities/vuln-1/reverify",
        json={"credentials": {"main": {"cookie": "session=secret"}}},
    )

    assert response.status_code == 202
    assert queue.jobs[0].kind == ScanJobKind.finding_reverification
    assert queue.jobs[0].auth_accounts[0].cookie == "session=secret"
    assert reverifications.created["auth_roles_provided"][0].value == "main"
    assert "credentials" not in response.text
    assert scans.scan.vulnerabilities[0].reverification_job_ids == ["reverify-1"]
    assert scans.scan.saved is True


def test_reverification_history_is_readable_but_viewers_cannot_launch_jobs() -> None:
    client, _, reverifications, _ = _client()
    target = VerificationTarget(
        detector_id="xss_detector", url="https://target.example", payload="x"
    )
    reverifications.job = FakeJob(target)

    listed = client.get(
        "/api/v1/analysis/scans/scan-1/vulnerabilities/vuln-1/reverifications"
    )
    detail = client.get(
        "/api/v1/analysis/scans/scan-1/vulnerabilities/vuln-1/"
        "reverifications/reverify-1"
    )
    viewer, _, _, _ = _client(UserRole.viewer)
    denied = viewer.post(
        "/api/v1/analysis/scans/scan-1/vulnerabilities/vuln-1/reverify", json={}
    )

    assert listed.status_code == 200
    assert detail.status_code == 200
    assert denied.status_code == 403
