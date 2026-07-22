from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from app.clients.ai_client import ProviderError, ProviderResult
from app.services.result_applier import ResultApplier, StaleAnalysisRevisionError
from app.worker import _notify_analysis_terminal, process_analysis_job
from shared.models.analysis_job import AnalysisStatus
from shared.models.notification import NotificationType
from shared.models.scan import ReportMetadata, ScanStatistics, ScanStatus
from shared.models.vulnerability import (
    AiAnalysis,
    AiAnalysisStatus,
    Evidence,
    LocationInfo,
    OwaspCategory,
    SeverityLevel,
    Vulnerability,
)


def _scan():
    finding = Vulnerability(
        id="v-1",
        category=OwaspCategory.a05,
        vuln_type="SQL Injection",
        severity=SeverityLevel.high,
        cvss_score=8.8,
        location=LocationInfo(url="https://target.test/items"),
        evidence=Evidence(evidence_grade="A", proof_type="error_echo"),
    )
    return SimpleNamespace(
        status=ScanStatus.completed,
        target_url="https://target.test",
        vulnerabilities=[finding],
        technology_stack=[],
        statistics=ScanStatistics(total_vulnerabilities=1),
        overall_risk_score=88.0,
        overall_risk_level="High",
        report_metadata=ReportMetadata(),
        submitted_by_user_id="user-1",
    )


def _job():
    return SimpleNamespace(
        id="job-1",
        scan_id="scan-1",
        org_id="org-1",
        revision=1,
        attempt=1,
        max_attempts=3,
        finding_count=1,
        progress=0,
        started_at=datetime.now(timezone.utc),
    )


class FakeScanRepository:
    def __init__(self, scan) -> None:
        self.scan = scan
        self.projection_updates = []
        self.finding_updates = []
        self.completions = []

    async def get_in_org(self, scan_id, org_id):
        assert (scan_id, org_id) == ("scan-1", "org-1")
        return self.scan

    async def update_analysis_projection(self, **kwargs):
        self.projection_updates.append(kwargs)
        return True

    async def set_finding_analysis(self, **kwargs):
        self.finding_updates.append(kwargs)
        return True

    async def complete_analysis_projection(self, **kwargs):
        self.completions.append(kwargs)
        return True


class FakeJobRepository:
    def __init__(self, *, fail_result: bool = True) -> None:
        self.progress = []
        self.completed = []
        self.retries = []
        self.failures = []
        self.fail_result = fail_result

    async def renew_lease(self, **kwargs):
        return True

    async def update_progress(self, **kwargs):
        self.progress.append(kwargs)
        return True

    async def complete(self, **kwargs):
        self.completed.append(kwargs)
        return True

    async def schedule_retry(self, **kwargs):
        self.retries.append(kwargs)
        return True

    async def fail(self, **kwargs):
        self.failures.append(kwargs)
        return self.fail_result


class SuccessfulFindingService:
    async def analyze(self, vulnerability, **kwargs):
        return (
            AiAnalysis(
                revision=kwargs["revision"],
                description="SQL injection permits query manipulation.",
                remediation="Use parameterized queries.",
                ai_analysis_status=AiAnalysisStatus.success,
            ),
            ProviderResult(
                data={}, request_id="finding-request", input_tokens=10, output_tokens=5
            ),
        )


class SuccessfulReportService:
    async def analyze(self, scan):
        return (
            "One high-severity SQL injection finding requires remediation.",
            ProviderResult(
                data={}, request_id="report-request", input_tokens=6, output_tokens=3
            ),
        )


@pytest.mark.asyncio
async def test_worker_publishes_only_ai_projection_and_completes_job(monkeypatch) -> None:
    scan = _scan()
    original_cvss = scan.vulnerabilities[0].cvss_score
    scan_repository = FakeScanRepository(scan)
    job_repository = FakeJobRepository()
    monkeypatch.setattr(
        "app.worker.get_settings",
        lambda: SimpleNamespace(
            ai_analysis_enabled=True,
            ai_model="model-1",
            analysis_lease_renew_seconds=60,
            analysis_lease_seconds=300,
        ),
    )

    await process_analysis_job(
        _job(),
        worker_id="worker-1",
        job_repository=job_repository,
        scan_repository=scan_repository,
        finding_service=SuccessfulFindingService(),
        report_service=SuccessfulReportService(),
    )

    assert scan.vulnerabilities[0].cvss_score == original_cvss
    assert scan_repository.finding_updates[0]["lease_owner"] == "worker-1"
    assert scan_repository.finding_updates[0]["analysis"].revision == 1
    assert scan_repository.completions[0]["expected_revision"] == 1
    assert scan_repository.completions[0]["generated_by"] == "ai"
    assert job_repository.completed[0]["provider_request_ids"] == [
        "finding-request",
        "report-request",
    ]
    assert job_repository.failures == []


@pytest.mark.asyncio
async def test_disabled_model_publishes_fallback_completion_metadata(monkeypatch) -> None:
    scan_repository = FakeScanRepository(_scan())
    job_repository = FakeJobRepository()
    monkeypatch.setattr(
        "app.worker.get_settings",
        lambda: SimpleNamespace(
            ai_analysis_enabled=False,
            ai_model="unused-model",
            analysis_lease_renew_seconds=60,
            analysis_lease_seconds=300,
        ),
    )

    await process_analysis_job(
        _job(),
        worker_id="worker-1",
        job_repository=job_repository,
        scan_repository=scan_repository,
        finding_service=SuccessfulFindingService(),
        report_service=SuccessfulReportService(),
    )

    completion = scan_repository.completions[0]
    assert completion["generated_by"] == "analyzer_fallback"
    assert completion["model"] == "deterministic-fallback"
    assert completion["prompt_version"] == "report-fallback-v1"
    assert job_repository.completed[0]["model"] == "deterministic-fallback"


class RetryableFailureService:
    async def analyze(self, vulnerability, **kwargs):
        raise ProviderError(
            "provider_unavailable",
            "Provider unavailable",
            retryable=True,
        )


@pytest.mark.asyncio
async def test_retryable_provider_failure_schedules_same_revision(monkeypatch) -> None:
    scan_repository = FakeScanRepository(_scan())
    job_repository = FakeJobRepository()
    monkeypatch.setattr(
        "app.worker.get_settings",
        lambda: SimpleNamespace(
            ai_analysis_enabled=True,
            ai_model="model-1",
            analysis_lease_renew_seconds=60,
            analysis_lease_seconds=300,
        ),
    )
    monkeypatch.setattr("app.worker._retry_delay_seconds", lambda attempt: 30)

    await process_analysis_job(
        _job(),
        worker_id="worker-1",
        job_repository=job_repository,
        scan_repository=scan_repository,
        finding_service=RetryableFailureService(),
        report_service=SuccessfulReportService(),
    )

    assert len(job_repository.retries) == 1
    assert job_repository.retries[0]["job_id"] == "job-1"
    assert job_repository.failures == []
    assert scan_repository.projection_updates[-1]["status"].value == "queued"
    assert scan_repository.projection_updates[-1]["expected_revision"] == 1


class TerminalReportFailureService:
    async def analyze(self, scan):
        raise ProviderError(
            "provider_authentication_failed",
            "Provider authentication failed",
            retryable=False,
        )


@pytest.mark.asyncio
async def test_report_failure_marks_revision_failed_and_notifies(monkeypatch) -> None:
    scan_repository = FakeScanRepository(_scan())
    job_repository = FakeJobRepository()
    notifications = FakeNotificationRepository()
    monkeypatch.setattr(
        "app.worker.get_settings",
        lambda: SimpleNamespace(
            ai_analysis_enabled=True,
            ai_model="model-1",
            analysis_lease_renew_seconds=60,
            analysis_lease_seconds=300,
        ),
    )

    await process_analysis_job(
        _job(),
        worker_id="worker-1",
        job_repository=job_repository,
        scan_repository=scan_repository,
        finding_service=SuccessfulFindingService(),
        report_service=TerminalReportFailureService(),
        member_repository=FakeMemberRepository(),
        notification_repository=notifications,
    )

    assert len(scan_repository.finding_updates) == 1
    assert scan_repository.projection_updates[-1]["status"] == AnalysisStatus.failed
    assert len(job_repository.failures) == 1
    assert notifications.created[0]["type"] == NotificationType.analysis_failed


@pytest.mark.asyncio
async def test_lost_job_lease_does_not_emit_terminal_notification(monkeypatch) -> None:
    scan_repository = FakeScanRepository(_scan())
    job_repository = FakeJobRepository(fail_result=False)
    notifications = FakeNotificationRepository()
    monkeypatch.setattr(
        "app.worker.get_settings",
        lambda: SimpleNamespace(
            ai_analysis_enabled=True,
            ai_model="model-1",
            analysis_lease_renew_seconds=60,
            analysis_lease_seconds=300,
        ),
    )

    await process_analysis_job(
        _job(),
        worker_id="expired-worker",
        job_repository=job_repository,
        scan_repository=scan_repository,
        finding_service=SuccessfulFindingService(),
        report_service=TerminalReportFailureService(),
        member_repository=FakeMemberRepository(),
        notification_repository=notifications,
    )

    assert len(job_repository.failures) == 1
    assert notifications.created == []


@pytest.mark.asyncio
async def test_stale_lease_owner_cannot_publish_finding_analysis() -> None:
    scan_repository = FakeScanRepository(_scan())

    async def reject_stale_owner(**kwargs):
        scan_repository.finding_updates.append(kwargs)
        return False

    scan_repository.set_finding_analysis = reject_stale_owner
    applier = ResultApplier(scan_repository)

    with pytest.raises(StaleAnalysisRevisionError):
        await applier.set_finding(
            _job(),
            worker_id="expired-worker",
            finding_id="v-1",
            analysis=AiAnalysis(
                revision=1,
                remediation="Use parameterized queries.",
                ai_analysis_status=AiAnalysisStatus.success,
            ),
        )

    assert scan_repository.finding_updates[0]["lease_owner"] == "expired-worker"


class FakeMemberRepository:
    async def get_in_org(self, user_id, org_id):
        assert (user_id, org_id) == ("user-1", "org-1")
        return SimpleNamespace(id=user_id)


class FakeNotificationRepository:
    def __init__(self) -> None:
        self.created = []

    async def create(self, **kwargs):
        self.created.append(kwargs)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("completed", "notification_type", "event"),
    [
        (True, NotificationType.analysis_completed, "completed"),
        (False, NotificationType.analysis_failed, "failed"),
    ],
)
async def test_terminal_notification_uses_revision_recipient_dedupe_key(
    completed, notification_type, event
) -> None:
    notifications = FakeNotificationRepository()

    await _notify_analysis_terminal(
        _scan(),
        _job(),
        completed=completed,
        member_repository=FakeMemberRepository(),
        notification_repository=notifications,
    )

    created = notifications.created[0]
    assert created["type"] == notification_type
    assert created["dedupe_key"] == (
        f"analysis:org-1:scan-1:1:{event}:user-1"
    )
    assert created["metadata"] == {
        "scan_id": "scan-1",
        "revision": 1,
        "status": event,
    }
