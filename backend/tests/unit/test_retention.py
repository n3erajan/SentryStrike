"""Retention-purge unit tests (Phase 5).

The ``RetentionService`` sweeps every org, deletes scans older than that org's
retention window, and audits each deletion. These tests drive it with in-memory
fakes: the cutoff must respect each org's own ``retention_days``, deletions must
be audited, and one org's failure must not stall the sweep of the others.
"""

from datetime import datetime, timedelta, timezone

import pytest

from app.core.retention import RetentionService
from shared.models.audit import AuditAction

NOW = datetime(2026, 7, 21, 12, 0, 0, tzinfo=timezone.utc)


class FakeScan:
    def __init__(self, scan_id: str, created_at: datetime, target_url: str = "https://t.example") -> None:
        self.id = scan_id
        self.created_at = created_at
        self.target_url = target_url
        self.deleted = False

    async def delete(self) -> None:
        self.deleted = True


class FakeOrg:
    def __init__(self, org_id: str, retention_days: int) -> None:
        self.id = org_id
        self.retention_days = retention_days


class FakeOrganizationRepository:
    def __init__(self, orgs) -> None:
        self._orgs = orgs

    async def list_all(self):
        return self._orgs


class FakeScanRepository:
    def __init__(self, scans_by_org) -> None:
        # {org_id: [FakeScan, ...]}
        self.scans_by_org = scans_by_org
        self.expired_queries: list[tuple[str, datetime]] = []

    async def list_expired(self, org_id: str, cutoff: datetime):
        self.expired_queries.append((org_id, cutoff))
        return [s for s in self.scans_by_org.get(org_id, []) if s.created_at < cutoff]


class FakeAuditRepository:
    def __init__(self) -> None:
        self.entries: list[dict] = []

    async def record(self, **kwargs):
        self.entries.append(kwargs)
        return None


def _service(orgs, scans_by_org, audit=None):
    return RetentionService(
        organization_repository=FakeOrganizationRepository(orgs),
        scan_repository=FakeScanRepository(scans_by_org),
        audit_repository=audit or FakeAuditRepository(),
    )


@pytest.mark.asyncio
async def test_purge_deletes_only_scans_older_than_org_retention() -> None:
    orgs = [FakeOrg("org-1", retention_days=30)]
    old = FakeScan("old", NOW - timedelta(days=45))
    fresh = FakeScan("fresh", NOW - timedelta(days=10))
    svc = _service(orgs, {"org-1": [old, fresh]})

    summary = await svc.purge_once()

    assert summary == {"org-1": 1}
    assert old.deleted is True
    assert fresh.deleted is False


@pytest.mark.asyncio
async def test_purge_uses_each_orgs_own_retention_window() -> None:
    orgs = [FakeOrg("org-short", retention_days=30), FakeOrg("org-long", retention_days=365)]
    scan_short = FakeScan("s", NOW - timedelta(days=60))
    scan_long = FakeScan("l", NOW - timedelta(days=60))
    repo = FakeScanRepository({"org-short": [scan_short], "org-long": [scan_long]})
    svc = RetentionService(
        organization_repository=FakeOrganizationRepository(orgs),
        scan_repository=repo,
        audit_repository=FakeAuditRepository(),
    )

    summary = await svc.purge_once()

    # 60 days old: past the 30-day window, within the 365-day window.
    assert summary == {"org-short": 1, "org-long": 0}
    assert scan_short.deleted is True
    assert scan_long.deleted is False


@pytest.mark.asyncio
async def test_each_purged_scan_is_audited() -> None:
    orgs = [FakeOrg("org-1", retention_days=30)]
    old = FakeScan("old", NOW - timedelta(days=45), target_url="https://victim.example")
    audit = FakeAuditRepository()
    svc = _service(orgs, {"org-1": [old]}, audit=audit)

    await svc.purge_once()

    assert len(audit.entries) == 1
    entry = audit.entries[0]
    assert entry["action"] == AuditAction.scan_purged
    assert entry["org_id"] == "org-1"
    assert entry["target_id"] == "old"
    assert entry["metadata"]["target_url"] == "https://victim.example"


@pytest.mark.asyncio
async def test_scan_is_audited_before_it_is_deleted() -> None:
    # The audit entry must be written while the scan still exists, so a crash
    # mid-purge never loses the record of an already-deleted scan.
    orgs = [FakeOrg("org-1", retention_days=30)]
    old = FakeScan("old", NOW - timedelta(days=45))

    seen_deleted_flag: list[bool] = []

    class OrderCheckingAudit(FakeAuditRepository):
        async def record(self, **kwargs):
            seen_deleted_flag.append(old.deleted)
            return await super().record(**kwargs)

    svc = _service(orgs, {"org-1": [old]}, audit=OrderCheckingAudit())

    await svc.purge_once()

    assert seen_deleted_flag == [False]
    assert old.deleted is True


@pytest.mark.asyncio
async def test_one_orgs_failure_does_not_stall_the_sweep() -> None:
    orgs = [FakeOrg("org-bad", retention_days=30), FakeOrg("org-good", retention_days=30)]
    good_scan = FakeScan("g", NOW - timedelta(days=45))

    class ExplodingScanRepo(FakeScanRepository):
        async def list_expired(self, org_id: str, cutoff: datetime):
            if org_id == "org-bad":
                raise RuntimeError("db blip")
            return await super().list_expired(org_id, cutoff)

    svc = RetentionService(
        organization_repository=FakeOrganizationRepository(orgs),
        scan_repository=ExplodingScanRepo({"org-good": [good_scan]}),
        audit_repository=FakeAuditRepository(),
    )

    summary = await svc.purge_once()

    assert summary == {"org-bad": 0, "org-good": 1}
    assert good_scan.deleted is True


@pytest.mark.asyncio
async def test_purge_with_no_expired_scans_is_a_noop() -> None:
    orgs = [FakeOrg("org-1", retention_days=30)]
    fresh = FakeScan("fresh", NOW - timedelta(days=1))
    audit = FakeAuditRepository()
    svc = _service(orgs, {"org-1": [fresh]}, audit=audit)

    summary = await svc.purge_once()

    assert summary == {"org-1": 0}
    assert fresh.deleted is False
    assert audit.entries == []
