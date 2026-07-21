from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
from beanie import PydanticObjectId

from shared.database.repositories.scan_repository import ScanRepository
from shared.models.scan import Scan, ScanPhase, ScanStatus


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
