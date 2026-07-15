from datetime import datetime, timezone

import pytest

from shared.database.repositories.scan_repository import ScanRepository
from shared.models.scan import ScanPhase, ScanStatus


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
