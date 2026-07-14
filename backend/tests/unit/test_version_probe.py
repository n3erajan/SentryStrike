"""Tests for the generic manifest / header version probe (Phase 1).

Locks in the requirement that *actual* component versions a target reveals
(package manifests, lockfiles, version-bearing headers) are captured so the
supply-chain version gate can emit true A03 findings — for ANY stack, never a
target-specific path. Also covers the scanner merge semantics (back-fill
versions onto existing components, add versioned new ones, CVE-enrich only what
newly resolved).
"""

from __future__ import annotations

from types import SimpleNamespace

from app.integrations import version_probe as vp
from app.integrations.wappalyzer_engine import TechComponent
from app.core.scanner import ScanOrchestrator
from app.models.vulnerability import TechnologyComponent


def _by_name(comps):
    return {c.name: c.version for c in comps}


# --------------------------------------------------------------------------- #
# Manifest parsers (pure, no HTTP)
# --------------------------------------------------------------------------- #

def test_parse_package_json_deps_and_engines():
    body = """
    {
      "name": "demo", "version": "1.0.0",
      "engines": {"node": ">=18.16.0"},
      "dependencies": {"express": "^4.18.2", "sequelize": "~6.28.0"},
      "devDependencies": {"typeorm": "0.3.17"}
    }
    """
    got = _by_name(vp.parse_manifest("/package.json", body))
    assert got.get("Node.js") == "18.16.0"
    assert got.get("Express") == "4.18.2"
    assert got.get("Sequelize") == "6.28.0"
    assert got.get("TypeORM") == "0.3.17"


def test_parse_package_lock_exact_versions():
    body = """
    {
      "name": "demo", "lockfileVersion": 3,
      "packages": {
        "": {"name": "demo", "version": "1.0.0"},
        "node_modules/express": {"version": "4.18.2"},
        "node_modules/mongoose": {"version": "7.6.3"}
      }
    }
    """
    got = _by_name(vp.parse_manifest("/package-lock.json", body))
    assert got.get("Express") == "4.18.2"
    assert got.get("Mongoose") == "7.6.3"


def test_parse_composer_json_and_lock():
    cj = '{"require": {"php": "^8.1", "laravel/framework": "10.2.0"}}'
    got = _by_name(vp.parse_manifest("/composer.json", cj))
    assert got.get("PHP") == "8.1"
    assert got.get("Laravel") == "10.2.0"

    cl = '{"packages": [{"name": "symfony/symfony", "version": "v6.3.1"}]}'
    got2 = _by_name(vp.parse_manifest("/composer.lock", cl))
    assert got2.get("Symfony") == "6.3.1"


def test_parse_requirements_txt():
    body = "Django==4.2.1\nFlask>=2.3\nsome-unmapped-pkg==9.9.9\n# comment\n"
    got = _by_name(vp.parse_manifest("/requirements.txt", body))
    assert got.get("Django") == "4.2.1"
    assert got.get("Flask") == "2.3"
    assert "some-unmapped-pkg" not in got


def test_parse_gemfile_lock():
    body = "GEM\n  specs:\n    rails (7.0.4)\n    rack (2.2.7)\n"
    got = _by_name(vp.parse_manifest("/Gemfile.lock", body))
    assert got.get("Ruby on Rails") == "7.0.4"
    assert got.get("Rack") == "2.2.7"


def test_parse_manifest_never_raises_on_garbage():
    assert vp.parse_manifest("/package.json", "{not json") == []
    assert vp.parse_manifest("/composer.json", "") == []
    assert vp.parse_manifest("/unknown.file", "whatever") == []


# --------------------------------------------------------------------------- #
# Header version extraction
# --------------------------------------------------------------------------- #

def test_extract_header_versions():
    headers = {
        "server": "nginx/1.18.0",
        "x-powered-by": "PHP/8.1.2",
        "x-aspnet-version": "4.0.30319",
    }
    got = _by_name(vp.extract_header_versions(headers))
    assert got.get("Nginx") == "1.18.0"
    assert got.get("PHP") == "8.1.2"
    assert got.get("Microsoft ASP.NET") == "4.0.30319"


def test_extract_header_versions_bare_name_no_version():
    # A bare "Express" X-Powered-By carries no version -> nothing emitted (no
    # false version), leaving detection to other surfaces.
    assert vp.extract_header_versions({"x-powered-by": "Express"}) == []


# --------------------------------------------------------------------------- #
# probe_versions: ecosystem selection + bounded HTTP via a fake client
# --------------------------------------------------------------------------- #

class _FakeResp:
    def __init__(self, status_code, text):
        self.status_code = status_code
        self.text = text


class _FakeClient:
    """Serves one manifest, 404s everything else, and counts requests."""

    def __init__(self, served: dict[str, str]):
        self.served = served
        self.requested: list[str] = []

    async def get(self, url, *a, **k):
        self.requested.append(url)
        for path, body in self.served.items():
            if url.endswith(path):
                return _FakeResp(200, body)
        return _FakeResp(404, "")


async def test_probe_versions_maps_node_manifest():
    client = _FakeClient({"/package.json": '{"dependencies": {"express": "^4.18.2"}}'})
    got = _by_name(await vp.probe_versions("http://t.example/", client, ["Angular", "Node.js"]))
    assert got.get("Express") == "4.18.2"


async def test_probe_versions_skips_irrelevant_ecosystems():
    # No Node/PHP/Python/Ruby marker -> no manifest requests at all (near-zero cost).
    client = _FakeClient({"/package.json": '{"dependencies": {"express": "^4.18.2"}}'})
    got = await vp.probe_versions("http://t.example/", client, ["Nginx"])
    assert got == []
    assert client.requested == []


async def test_probe_versions_is_bounded():
    client = _FakeClient({})  # everything 404s
    await vp.probe_versions("http://t.example/", client, ["Node.js", "PHP", "Python", "Ruby"])
    assert len(client.requested) <= 8


# --------------------------------------------------------------------------- #
# Scanner merge semantics (mirror of the error-enrichment merge)
# --------------------------------------------------------------------------- #

class _FakeCve:
    def __init__(self):
        self.enriched_names: list[str] = []

    async def enrich_components(self, comps):
        self.enriched_names = [c.name for c in comps]
        return comps


async def test_manifest_merge_backfills_version_and_enriches(monkeypatch):
    orch = ScanOrchestrator.__new__(ScanOrchestrator)
    orch.cve_service = _FakeCve()

    scan = SimpleNamespace(
        target_url="http://t.example/",
        technology_stack=[
            TechnologyComponent(name="Express", version=None, category="framework"),
        ],
    )
    # Crawl exposes a version-bearing Server header; the manifest probe adds a
    # brand-new versioned component.
    crawl_result = SimpleNamespace(
        requests=[SimpleNamespace(response_headers={"Server": "nginx/1.18.0"})]
    )

    async def _fake_probe(root_url, client, names, **kw):
        return [TechComponent(name="Express", version="4.18.2", category="framework", confidence=100)]

    monkeypatch.setattr(vp, "probe_versions", _fake_probe)

    await orch._enrich_tech_from_manifests(scan, crawl_result)

    by_name = {c.name: c.version for c in scan.technology_stack}
    # Existing Express got its version back-filled from the manifest.
    assert by_name.get("Express") == "4.18.2"
    # Nginx (new, versioned, from header) was added.
    assert by_name.get("Nginx") == "1.18.0"
    # Both the version-resolved existing component and the new one were CVE-enriched.
    assert "Express" in orch.cve_service.enriched_names
    assert "Nginx" in orch.cve_service.enriched_names


async def test_manifest_merge_noop_when_nothing_resolves(monkeypatch):
    orch = ScanOrchestrator.__new__(ScanOrchestrator)
    orch.cve_service = _FakeCve()
    scan = SimpleNamespace(target_url="http://t.example/", technology_stack=[])
    crawl_result = SimpleNamespace(requests=[])

    async def _fake_probe(root_url, client, names, **kw):
        return []

    monkeypatch.setattr(vp, "probe_versions", _fake_probe)
    await orch._enrich_tech_from_manifests(scan, crawl_result)
    assert scan.technology_stack == []
    assert orch.cve_service.enriched_names == []
