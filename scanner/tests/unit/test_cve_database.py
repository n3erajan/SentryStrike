import pytest

from app.integrations import cve_database
from app.integrations.cve_database import CveDatabaseService
from shared.models.vulnerability import TechnologyComponent


class FakeField:
    def __eq__(self, other):
        return ("eq", other)


class FakeCveRecord:
    cve_id = FakeField()
    inserted: list[str] = []

    def __init__(self, **kwargs):
        self.kwargs = kwargs

    @classmethod
    async def find_one(cls, _query):
        return None

    async def insert(self):
        self.inserted.append(self.kwargs["cve_id"])


class FakeNvdClient:
    def __init__(self):
        self.calls: list[tuple[str, str | None]] = []

    async def lookup_cves(self, component_name: str, version: str | None = None):
        self.calls.append((component_name, version))
        return [{"cve_id": f"CVE-TEST-{len(self.calls)}", "summary": "test", "severity_score": 7.5}]


@pytest.mark.asyncio
async def test_enrich_components_checks_every_detected_technology(monkeypatch) -> None:
    monkeypatch.setattr(cve_database, "CveRecord", FakeCveRecord)
    FakeCveRecord.inserted = []
    service = CveDatabaseService()
    fake_nvd = FakeNvdClient()
    service.nvd_client = fake_nvd
    components = [
        TechnologyComponent(name="nginx", version="1.18", category="server"),
        TechnologyComponent(name="PHP", version="8.1", category="framework"),
        TechnologyComponent(name="jQuery", version="3.6.0", category="library"),
    ]

    enriched = await service.enrich_components(components)

    assert fake_nvd.calls == [
        ("nginx", "1.18"),
        ("PHP", "8.1"),
        ("jQuery", "3.6.0"),
    ]
    assert [component.cves for component in enriched] == [
        ["CVE-TEST-1"],
        ["CVE-TEST-2"],
        ["CVE-TEST-3"],
    ]
    assert FakeCveRecord.inserted == ["CVE-TEST-1", "CVE-TEST-2", "CVE-TEST-3"]
