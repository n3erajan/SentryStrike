from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from beanie import PydanticObjectId
from pymongo.errors import DuplicateKeyError

import shared.database.repositories.analysis_job_repository as repository_module
from shared.database.repositories.analysis_job_repository import AnalysisJobRepository
from shared.models.analysis_job import AnalysisJob, AnalysisStatus


@pytest.mark.asyncio
async def test_initial_job_creation_is_idempotent_when_revision_exists(monkeypatch) -> None:
    existing = SimpleNamespace(scan_id="scan-1", org_id="org-1", revision=1)
    repository = AnalysisJobRepository()
    lookup = AsyncMock(return_value=existing)
    monkeypatch.setattr(repository, "get_for_revision", lookup)

    result = await repository.create_initial(
        scan_id="scan-1",
        org_id="org-1",
        finding_count=4,
    )

    assert result is existing
    lookup.assert_awaited_once_with(scan_id="scan-1", org_id="org-1", revision=1)


@pytest.mark.asyncio
async def test_concurrent_initial_insert_returns_unique_index_winner(monkeypatch) -> None:
    winner = SimpleNamespace(scan_id="scan-1", org_id="org-1", revision=1)
    repository = AnalysisJobRepository()
    monkeypatch.setattr(
        repository,
        "get_for_revision",
        AsyncMock(side_effect=[None, winner]),
    )

    class LosingJob:
        def __init__(self, **kwargs):
            self.__dict__.update(kwargs)

        async def insert(self):
            raise DuplicateKeyError("duplicate scan/revision")

    monkeypatch.setattr(repository_module, "AnalysisJob", LosingJob)

    result = await repository.create_initial(
        scan_id="scan-1",
        org_id="org-1",
        finding_count=4,
    )

    assert result is winner


@pytest.mark.asyncio
async def test_claim_is_atomic_and_accepts_only_due_or_stale_jobs(monkeypatch) -> None:
    calls = []
    now = datetime(2026, 7, 21, 12, 0, tzinfo=timezone.utc)

    class Collection:
        async def find_one_and_update(self, query, update, **kwargs):
            calls.append((query, update, kwargs))
            return {"claimed": True}

    monkeypatch.setattr(
        AnalysisJob,
        "get_motor_collection",
        classmethod(lambda cls: Collection()),
    )
    monkeypatch.setattr(
        AnalysisJob,
        "model_validate",
        classmethod(lambda cls, document: document),
    )
    job_id = str(PydanticObjectId())

    claimed = await AnalysisJobRepository().claim_next(
        worker_id="worker-1",
        lease_seconds=300,
        job_id=job_id,
        now=now,
    )

    assert claimed == {"claimed": True}
    query, update, kwargs = calls[0]
    assert query["_id"] == PydanticObjectId(job_id)
    assert query["$expr"] == {"$lt": ["$attempt", "$max_attempts"]}
    assert query["$or"][0]["status"] == AnalysisStatus.queued.value
    assert query["$or"][1] == {
        "status": AnalysisStatus.running.value,
        "lease_expires_at": {"$lte": now},
    }
    assert update[0]["$set"]["lease_owner"] == "worker-1"
    assert update[0]["$set"]["attempt"] == {"$add": ["$attempt", 1]}
    assert kwargs["return_document"] is not None


@pytest.mark.asyncio
async def test_lease_renewal_requires_current_owner(monkeypatch) -> None:
    calls = []

    class Collection:
        async def update_one(self, query, update):
            calls.append((query, update))
            return SimpleNamespace(modified_count=1)

    monkeypatch.setattr(
        AnalysisJob,
        "get_motor_collection",
        classmethod(lambda cls: Collection()),
    )
    job_id = str(PydanticObjectId())

    renewed = await AnalysisJobRepository().renew_lease(
        job_id=job_id,
        worker_id="worker-1",
        lease_seconds=300,
    )

    assert renewed is True
    query, _ = calls[0]
    assert query == {
        "_id": PydanticObjectId(job_id),
        "status": AnalysisStatus.running.value,
        "lease_owner": "worker-1",
    }


@pytest.mark.asyncio
async def test_retry_requires_attempt_capacity_and_releases_lease(monkeypatch) -> None:
    calls = []

    class Collection:
        async def update_one(self, query, update):
            calls.append((query, update))
            return SimpleNamespace(modified_count=1)

    monkeypatch.setattr(
        AnalysisJob,
        "get_motor_collection",
        classmethod(lambda cls: Collection()),
    )
    job_id = str(PydanticObjectId())
    next_attempt = datetime(2026, 7, 21, 12, 2, tzinfo=timezone.utc)

    scheduled = await AnalysisJobRepository().schedule_retry(
        job_id=job_id,
        worker_id="worker-1",
        next_attempt_at=next_attempt,
        error_code="provider_timeout",
        error_message="Provider timed out",
    )

    assert scheduled is True
    query, update = calls[0]
    assert query["$expr"] == {"$lt": ["$attempt", "$max_attempts"]}
    assert update["$set"]["status"] == AnalysisStatus.queued.value
    assert update["$set"]["lease_owner"] is None
    assert update["$set"]["lease_expires_at"] is None

