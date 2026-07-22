from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
from beanie import PydanticObjectId

from shared.database.repositories.scan_repository import ScanRepository
from shared.models.scan import Scan, ScanPhase, ScanStatus
from shared.models.vulnerability import AiAnalysis, AiAnalysisStatus


class FakeScan:
    def __init__(self) -> None:
        self.status = ScanStatus.queued
        self.progress = 0
        self.current_phase = ScanPhase.queued
        self.phase_message = "Scan queued"
        self.started_at = None
        self.completed_at = None
        self.error_message = None
        self.updated_at = datetime.now(timezone.utc)
        self.saved = False

    async def save(self) -> None:
        self.saved = True


@pytest.mark.asyncio
async def test_update_status_persists_phase_and_message() -> None:
    scan = FakeScan()

    updated = await ScanRepository().update_status(
        scan,
        ScanStatus.running,
        progress=45,
        current_phase=ScanPhase.vulnerability_detection,
        phase_message="Running active detectors",
    )

    assert updated.status == ScanStatus.running
    assert updated.progress == 45
    assert updated.current_phase == ScanPhase.vulnerability_detection
    assert updated.phase_message == "Running active detectors"
    assert updated.started_at is not None
    assert updated.saved is True


@pytest.mark.asyncio
async def test_attach_reverification_job_is_atomic_and_org_scoped(monkeypatch) -> None:
    calls = []

    class Collection:
        async def update_one(self, query, update):
            calls.append((query, update))
            return SimpleNamespace(modified_count=1)

    monkeypatch.setattr(
        Scan, "get_motor_collection", classmethod(lambda cls: Collection())
    )
    scan_id = str(PydanticObjectId())

    attached = await ScanRepository().attach_reverification_job(
        scan_id=scan_id,
        org_id="org-1",
        vulnerability_id="vuln-1",
        job_id="job-1",
    )

    assert attached is True
    query, update = calls[0]
    assert query["org_id"] == "org-1"
    assert query["vulnerabilities.id"] == "vuln-1"
    assert update["$addToSet"] == {
        "vulnerabilities.$.reverification_job_ids": "job-1"
    }


@pytest.mark.asyncio
async def test_attach_initial_analysis_is_completed_org_scoped_and_absent_only(
    monkeypatch,
) -> None:
    calls = []

    class Collection:
        async def update_one(self, query, update):
            calls.append((query, update))
            return SimpleNamespace(modified_count=1)

    monkeypatch.setattr(
        Scan, "get_motor_collection", classmethod(lambda cls: Collection())
    )
    scan_id = str(PydanticObjectId())
    queued_at = datetime(2026, 7, 21, tzinfo=timezone.utc)

    attached = await ScanRepository().attach_initial_analysis_job(
        scan_id=scan_id,
        org_id="org-1",
        job_id="job-1",
        revision=1,
        queued_at=queued_at,
    )

    assert attached is True
    query, update = calls[0]
    assert query["org_id"] == "org-1"
    assert query["status"] == ScanStatus.completed.value
    assert query["$or"] == [
        {"analysis": {"$exists": False}},
        {"analysis": None},
    ]
    assert update["$set"]["analysis"]["current_job_id"] == "job-1"
    assert update["$set"]["analysis"]["revision"] == 1


@pytest.mark.asyncio
async def test_finding_analysis_update_is_revision_guarded_and_ai_only(monkeypatch) -> None:
    calls = []

    class Collection:
        async def update_one(self, query, update, **kwargs):
            calls.append((query, update, kwargs))
            return SimpleNamespace(modified_count=1)

    monkeypatch.setattr(
        Scan, "get_motor_collection", classmethod(lambda cls: Collection())
    )
    scan_id = str(PydanticObjectId())

    updated = await ScanRepository().set_finding_analysis(
        scan_id=scan_id,
        org_id="org-1",
        finding_id="vuln-1",
        current_job_id="job-2",
        expected_revision=2,
        lease_owner="worker-2",
        analysis=AiAnalysis(
            revision=2,
            remediation="Use parameterized queries.",
            ai_analysis_status=AiAnalysisStatus.success,
        ),
    )

    assert updated is True
    query, update, kwargs = calls[0]
    assert query["org_id"] == "org-1"
    assert query["analysis.current_job_id"] == "job-2"
    assert query["analysis.revision"] == 2
    assert query["analysis.lease_owner"] == "worker-2"
    assert kwargs["array_filters"] == [{"finding.id": "vuln-1"}]
    assert set(update["$set"]) == {
        "vulnerabilities.$[finding].ai_analysis",
        "updated_at",
    }
    serialized = str(update)
    assert "assignee_user_id" not in serialized
    assert "comments" not in serialized
    assert "remediation_status" not in serialized


@pytest.mark.asyncio
async def test_report_publication_and_readiness_are_one_revision_guarded_update(
    monkeypatch,
) -> None:
    calls = []

    class Collection:
        async def update_one(self, query, update):
            calls.append((query, update))
            return SimpleNamespace(modified_count=1)

    monkeypatch.setattr(
        Scan, "get_motor_collection", classmethod(lambda cls: Collection())
    )
    scan_id = str(PydanticObjectId())
    generated_at = datetime(2026, 7, 21, tzinfo=timezone.utc)

    completed = await ScanRepository().complete_analysis_projection(
        scan_id=scan_id,
        org_id="org-1",
        current_job_id="job-2",
        expected_revision=2,
        lease_owner="worker-2",
        summary="Executive summary",
        model="model-1",
        prompt_version="report-v1",
        generated_by="ai",
        generated_at=generated_at,
    )

    assert completed is True
    query, update = calls[0]
    assert query["analysis.current_job_id"] == "job-2"
    assert query["analysis.revision"] == 2
    assert query["analysis.lease_owner"] == "worker-2"
    fields = update["$set"]
    assert fields["report_metadata.summary"] == "Executive summary"
    assert fields["analysis.status"] == "completed"
    assert fields["analysis.completed_at"] == generated_at
