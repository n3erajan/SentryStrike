"""Routing of components to the vulnerability source that actually covers them.

No single database covers a whole web stack. The orchestrator picks per component
and records which source answered - or that none could:

* ecosystem package (Express, Django, Laravel, jQuery) -> OSV.dev
* WordPress plugin / theme -> Wordfence Intelligence
* server, language, CMS core (Nginx, PHP, WordPress) -> NVD by CPE
* anything unidentifiable -> ``not_assessed``, never an empty "clean" list

The last case is the important one. In the report that prompted this rewrite,
version-less PHP and MySQL entries - inferred from WordPress's ``implies`` list,
never independently observed - were queried by name and came back carrying CVEs
for TYPO3, NoneCms and Selesta Visual Access Manager.
"""

import pytest

from app.integrations import cve_database
from app.integrations.cve_database import CveDatabaseService
from app.integrations.vuln_lookup import VulnLookup
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


class FakeSource:
    """Records the calls it received and returns a canned lookup."""

    def __init__(self, result: VulnLookup | None = None, source: str = "fake") -> None:
        self.calls: list[tuple] = []
        self.result = result
        self.source_name = source

    def _answer(self) -> VulnLookup:
        return self.result if self.result is not None else VulnLookup.assessed(self.source_name, [])


class FakeOsv(FakeSource):
    async def lookup(self, name, version, ecosystem, package):
        self.calls.append((name, version, ecosystem, package))
        return self._answer()


class FakeNvd(FakeSource):
    async def lookup(self, name, version, cpe):
        self.calls.append((name, version, cpe))
        return self._answer()


class FakeWordfence(FakeSource):
    enabled = True

    async def lookup(self, name, version, software_type, slug):
        self.calls.append((name, version, software_type, slug))
        return self._answer()


class FakeThreatIntel:
    def __init__(self, kev: list[str] | None = None, epss: dict[str, float] | None = None) -> None:
        self.kev = kev or []
        self.epss = epss or {}

    async def known_exploited(self, cve_ids):
        return [c for c in cve_ids if c in self.kev]

    async def exploit_probability(self, cve_ids):
        return {c: v for c, v in self.epss.items() if c in cve_ids}


def _service(
    *, osv=None, nvd=None, wordfence=None, intel=None, monkeypatch=None
) -> CveDatabaseService:
    monkeypatch.setattr(cve_database, "CveRecord", FakeCveRecord)
    FakeCveRecord.inserted = []
    service = CveDatabaseService()
    service.osv_client = osv or FakeOsv()
    service.nvd_client = nvd or FakeNvd()
    service.wordfence_client = wordfence or FakeWordfence()
    service.threat_intel = intel or FakeThreatIntel()
    return service


def _cve(cve_id: str, score: float | None = 7.5) -> dict:
    return {"cve_id": cve_id, "summary": "s", "severity_score": score}


# --------------------------------------------------------------------------- #
# Routing
# --------------------------------------------------------------------------- #

@pytest.mark.asyncio
async def test_ecosystem_packages_route_to_osv(monkeypatch) -> None:
    osv = FakeOsv(VulnLookup.assessed("osv", [_cve("CVE-2024-43796", 5.0)]))
    nvd = FakeNvd()
    service = _service(osv=osv, nvd=nvd, monkeypatch=monkeypatch)

    [component] = await service.enrich_components(
        [TechnologyComponent(name="Express", version="4.18.2", category="framework")]
    )

    assert osv.calls == [("Express", "4.18.2", "npm", "express")]
    assert nvd.calls == []
    assert component.cves == ["CVE-2024-43796"]
    assert component.cve_assessment == "assessed"
    assert component.cve_source == "osv"


@pytest.mark.asyncio
async def test_servers_and_languages_route_to_nvd_by_cpe(monkeypatch) -> None:
    osv = FakeOsv()
    nvd = FakeNvd(VulnLookup.assessed("nvd-cpe", [_cve("CVE-2023-44487")]))
    service = _service(osv=osv, nvd=nvd, monkeypatch=monkeypatch)

    [component] = await service.enrich_components(
        [TechnologyComponent(name="Nginx", version="1.24.0", category="server")]
    )

    assert osv.calls == []
    assert nvd.calls == [("Nginx", "1.24.0", "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*")]
    assert component.cve_source == "nvd-cpe"
    assert component.cves == ["CVE-2023-44487"]


@pytest.mark.asyncio
async def test_wordpress_core_routes_to_nvd_not_wordfence(monkeypatch) -> None:
    """Core is CPE-indexed; only plugins and themes need the Wordfence feed."""
    nvd = FakeNvd(VulnLookup.assessed("nvd-cpe", []))
    wordfence = FakeWordfence()
    service = _service(nvd=nvd, wordfence=wordfence, monkeypatch=monkeypatch)

    [component] = await service.enrich_components(
        [TechnologyComponent(name="WordPress", version="7.1", category="cms")]
    )

    assert nvd.calls == [("WordPress", "7.1", "cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*:*")]
    assert wordfence.calls == []
    assert component.cve_assessment == "assessed"
    assert component.cves == []


@pytest.mark.asyncio
async def test_wordpress_plugins_route_to_wordfence(monkeypatch) -> None:
    wordfence = FakeWordfence(VulnLookup.assessed("wordfence", [_cve("CVE-2024-9999", 9.8)]))
    nvd = FakeNvd()
    service = _service(nvd=nvd, wordfence=wordfence, monkeypatch=monkeypatch)
    component = TechnologyComponent(
        name="Smart Slider 3", version="3.5.1", category="wordpress plugins", slug="smart-slider-3"
    )

    [enriched] = await service.enrich_components([component])

    assert wordfence.calls == [("Smart Slider 3", "3.5.1", "plugin", "smart-slider-3")]
    assert nvd.calls == []
    assert enriched.cve_source == "wordfence"


@pytest.mark.asyncio
async def test_wordpress_themes_route_to_wordfence_as_themes(monkeypatch) -> None:
    wordfence = FakeWordfence()
    service = _service(wordfence=wordfence, monkeypatch=monkeypatch)
    component = TechnologyComponent(
        name="Astra", version="4.1.0", category="wordpress themes", slug="astra"
    )

    await service.enrich_components([component])

    assert wordfence.calls == [("Astra", "4.1.0", "theme", "astra")]


# --------------------------------------------------------------------------- #
# Refusals
# --------------------------------------------------------------------------- #

@pytest.mark.asyncio
async def test_version_less_components_are_never_queried(monkeypatch) -> None:
    """PHP and MySQL arrive version-less via WordPress's ``implies`` list."""
    osv, nvd = FakeOsv(), FakeNvd()
    service = _service(osv=osv, nvd=nvd, monkeypatch=monkeypatch)

    enriched = await service.enrich_components([
        TechnologyComponent(name="PHP", version=None, category="language"),
        TechnologyComponent(name="MySQL", version=None, category="database"),
    ])

    assert osv.calls == []
    assert nvd.calls == []
    for component in enriched:
        assert component.cve_assessment == "not_assessed"
        assert component.cves == []
        assert "version" in (component.cve_assessment_reason or "").lower()


@pytest.mark.asyncio
async def test_blank_version_string_counts_as_no_version(monkeypatch) -> None:
    nvd = FakeNvd()
    service = _service(nvd=nvd, monkeypatch=monkeypatch)

    [component] = await service.enrich_components(
        [TechnologyComponent(name="Nginx", version="   ", category="server")]
    )

    assert nvd.calls == []
    assert component.cve_assessment == "not_assessed"


@pytest.mark.asyncio
async def test_unidentifiable_components_are_not_assessed(monkeypatch) -> None:
    """"HTTP/3" has no CPE and no package; it previously drew H2O's CVE-2021-43848."""
    osv, nvd = FakeOsv(), FakeNvd()
    service = _service(osv=osv, nvd=nvd, monkeypatch=monkeypatch)

    [component] = await service.enrich_components(
        [TechnologyComponent(name="HTTP/3", version="3", category="miscellaneous")]
    )

    assert osv.calls == []
    assert nvd.calls == []
    assert component.cve_assessment == "not_assessed"
    assert component.cves == []


@pytest.mark.asyncio
async def test_plugin_without_a_slug_is_not_assessed(monkeypatch) -> None:
    """The Wordfence client owns this precondition and refuses before any request."""
    wordfence = FakeWordfence(
        VulnLookup.not_assessed("no plugin/theme slug resolved for Some Plugin")
    )
    service = _service(wordfence=wordfence, monkeypatch=monkeypatch)
    component = TechnologyComponent(
        name="Some Plugin", version="1.0.0", category="wordpress plugins"
    )

    [enriched] = await service.enrich_components([component])

    assert wordfence.calls == [("Some Plugin", "1.0.0", "plugin", None)]
    assert enriched.cve_assessment == "not_assessed"
    assert enriched.cves == []
    assert "slug" in (enriched.cve_assessment_reason or "").lower()


# --------------------------------------------------------------------------- #
# Failure propagation
# --------------------------------------------------------------------------- #

@pytest.mark.asyncio
async def test_source_failure_is_recorded_as_failed_not_clean(monkeypatch) -> None:
    nvd = FakeNvd(VulnLookup.failed("nvd-cpe", "NVD returned HTTP 429 for f5:nginx"))
    service = _service(nvd=nvd, monkeypatch=monkeypatch)

    [component] = await service.enrich_components(
        [TechnologyComponent(name="Nginx", version="1.24.0", category="server")]
    )

    assert component.cve_assessment == "failed"
    assert component.cves == []
    assert "429" in (component.cve_assessment_reason or "")


@pytest.mark.asyncio
async def test_unexpected_exception_is_recorded_as_failed(monkeypatch) -> None:
    class Exploding:
        async def lookup(self, *args):
            raise RuntimeError("kaboom")

    service = _service(nvd=Exploding(), monkeypatch=monkeypatch)

    [component] = await service.enrich_components(
        [TechnologyComponent(name="Nginx", version="1.24.0", category="server")]
    )

    assert component.cve_assessment == "failed"
    assert "kaboom" in (component.cve_assessment_reason or "")


# --------------------------------------------------------------------------- #
# Threat-intel overlay
# --------------------------------------------------------------------------- #

@pytest.mark.asyncio
async def test_kev_membership_and_epss_are_attached(monkeypatch) -> None:
    nvd = FakeNvd(VulnLookup.assessed("nvd-cpe", [
        _cve("CVE-2021-44228", 10.0), _cve("CVE-2024-0001", 5.0)
    ]))
    intel = FakeThreatIntel(
        kev=["CVE-2021-44228"], epss={"CVE-2021-44228": 0.97, "CVE-2024-0001": 0.01}
    )
    service = _service(nvd=nvd, intel=intel, monkeypatch=monkeypatch)

    [component] = await service.enrich_components(
        [TechnologyComponent(name="Nginx", version="1.24.0", category="server")]
    )

    assert component.cve_kev == ["CVE-2021-44228"]
    assert component.cve_epss == {"CVE-2021-44228": 0.97, "CVE-2024-0001": 0.01}


@pytest.mark.asyncio
async def test_overlay_is_skipped_when_there_are_no_cves(monkeypatch) -> None:
    class ExplodingIntel:
        async def known_exploited(self, cve_ids):
            raise AssertionError("must not be called with no CVEs")

        async def exploit_probability(self, cve_ids):
            raise AssertionError("must not be called with no CVEs")

    service = _service(intel=ExplodingIntel(), monkeypatch=monkeypatch)

    [component] = await service.enrich_components(
        [TechnologyComponent(name="Nginx", version="1.24.0", category="server")]
    )

    assert component.cve_kev == []


@pytest.mark.asyncio
async def test_overlay_failure_does_not_fail_the_assessment(monkeypatch) -> None:
    class BrokenIntel:
        async def known_exploited(self, cve_ids):
            raise RuntimeError("kev down")

        async def exploit_probability(self, cve_ids):
            raise RuntimeError("epss down")

    nvd = FakeNvd(VulnLookup.assessed("nvd-cpe", [_cve("CVE-2023-44487")]))
    service = _service(nvd=nvd, intel=BrokenIntel(), monkeypatch=monkeypatch)

    [component] = await service.enrich_components(
        [TechnologyComponent(name="Nginx", version="1.24.0", category="server")]
    )

    assert component.cve_assessment == "assessed"
    assert component.cves == ["CVE-2023-44487"]
    assert component.cve_kev == []


# --------------------------------------------------------------------------- #
# Persistence
# --------------------------------------------------------------------------- #

@pytest.mark.asyncio
async def test_discovered_cves_are_cached_with_their_source(monkeypatch) -> None:
    nvd = FakeNvd(VulnLookup.assessed("nvd-cpe", [_cve("CVE-2023-44487")]))
    service = _service(nvd=nvd, monkeypatch=monkeypatch)

    await service.enrich_components(
        [TechnologyComponent(name="Nginx", version="1.24.0", category="server")]
    )

    assert FakeCveRecord.inserted == ["CVE-2023-44487"]


@pytest.mark.asyncio
async def test_scores_only_include_cves_that_have_one(monkeypatch) -> None:
    nvd = FakeNvd(VulnLookup.assessed("nvd-cpe", [
        _cve("CVE-2024-0001", 7.5), _cve("CVE-2024-0002", None)
    ]))
    service = _service(nvd=nvd, monkeypatch=monkeypatch)

    [component] = await service.enrich_components(
        [TechnologyComponent(name="Nginx", version="1.24.0", category="server")]
    )

    assert component.cves == ["CVE-2024-0001", "CVE-2024-0002"]
    assert component.cve_scores == {"CVE-2024-0001": 7.5}
