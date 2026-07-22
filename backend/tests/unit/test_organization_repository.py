from types import SimpleNamespace

import pytest
from beanie import PydanticObjectId

from shared.database.repositories.organization_repository import OrganizationRepository
from shared.models.organization import Organization


class FakeCollection:
    def __init__(self, *, modified_count: int, matched_count: int = 1) -> None:
        self.result = SimpleNamespace(
            modified_count=modified_count, matched_count=matched_count
        )
        self.calls = []

    async def update_one(self, query, update):
        self.calls.append((query, update))
        return self.result


@pytest.mark.asyncio
async def test_reserve_member_seat_is_atomic_and_reports_full_workspace(
    monkeypatch,
) -> None:
    collection = FakeCollection(modified_count=0)
    monkeypatch.setattr(
        Organization,
        "get_motor_collection",
        classmethod(lambda cls: collection),
    )

    reserved = await OrganizationRepository().reserve_member_seat(
        str(PydanticObjectId())
    )

    assert reserved is False
    query, update = collection.calls[0]
    assert query["$expr"] == {"$lt": ["$occupied_seats", "$member_limit"]}
    assert update["$inc"] == {"occupied_seats": 1}


@pytest.mark.asyncio
async def test_release_member_seat_never_decrements_owner_seat(monkeypatch) -> None:
    collection = FakeCollection(modified_count=1)
    monkeypatch.setattr(
        Organization,
        "get_motor_collection",
        classmethod(lambda cls: collection),
    )

    released = await OrganizationRepository().release_member_seat(
        str(PydanticObjectId())
    )

    assert released is True
    query, update = collection.calls[0]
    assert query["occupied_seats"] == {"$gt": 1}
    assert update["$inc"] == {"occupied_seats": -1}


@pytest.mark.asyncio
async def test_member_limit_cannot_be_lowered_below_occupied_seats(
    monkeypatch,
) -> None:
    collection = FakeCollection(modified_count=0, matched_count=0)
    monkeypatch.setattr(
        Organization,
        "get_motor_collection",
        classmethod(lambda cls: collection),
    )

    updated = await OrganizationRepository().set_member_limit(
        str(PydanticObjectId()), 2
    )

    assert updated is None
    query, _ = collection.calls[0]
    assert query["occupied_seats"] == {"$lte": 2}
