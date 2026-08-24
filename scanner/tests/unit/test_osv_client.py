"""OSV.dev lookups for ecosystem packages.

NVD's CPE index covers servers, languages and CMS cores, but library releases
late and incompletely. OSV.dev aggregates GitHub Security Advisories, PyPA,
RustSec and friends, resolves version ranges natively per ecosystem, and needs no
API key - it answers ``express@4.18.2`` with CVE-2024-43796 and CVE-2024-29041,
both of which NVD's keyword search returned nothing for.
"""

import httpx
import pytest

from app.integrations.osv_client import OsvClient


def _vuln(
    osv_id: str,
    *,
    aliases: list[str] | None = None,
    vector: str | None = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
    summary: str = "test advisory",
    withdrawn: str | None = None,
    label: str | None = "HIGH",
) -> dict:
    entry: dict = {
        "id": osv_id,
        "aliases": aliases if aliases is not None else [],
        "summary": summary,
        "references": [{"url": "https://example.test/advisory"}],
        "database_specific": {"severity": label} if label else {},
    }
    if vector:
        entry["severity"] = [{"type": "CVSS_V3", "score": vector}]
    if withdrawn:
        entry["withdrawn"] = withdrawn
    return entry


def _client(handler) -> OsvClient:
    return OsvClient(transport=httpx.MockTransport(handler))


# --------------------------------------------------------------------------- #
# Refusals
# --------------------------------------------------------------------------- #

@pytest.mark.asyncio
async def test_missing_version_is_not_assessed_and_sends_no_request() -> None:
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(200, json={})

    result = await _client(handler).lookup("Express", None, "npm", "express")

    assert result.status == "not_assessed"
    assert "version" in (result.reason or "").lower()
    assert calls == []


# --------------------------------------------------------------------------- #
# Query construction + parsing
# --------------------------------------------------------------------------- #

@pytest.mark.asyncio
async def test_lookup_posts_package_ecosystem_and_version() -> None:
    import json

    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"vulns": []})

    await _client(handler).lookup("Express", "4.18.2", "npm", "express")

    assert len(seen) == 1
    assert json.loads(seen[0].content) == {
        "package": {"name": "express", "ecosystem": "npm"},
        "version": "4.18.2",
    }


@pytest.mark.asyncio
async def test_cve_alias_is_preferred_over_the_osv_id() -> None:
    """Reports and the CVE cache are keyed on CVE IDs, not GHSA IDs."""
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"vulns": [
            _vuln("GHSA-qw6h-vgh9-j6wx", aliases=["CVE-2024-43796"]),
        ]})

    result = await _client(handler).lookup("Express", "4.18.2", "npm", "express")

    assert result.status == "assessed"
    assert result.source == "osv"
    assert [c["cve_id"] for c in result.cves] == ["CVE-2024-43796"]
    assert result.cves[0]["osv_id"] == "GHSA-qw6h-vgh9-j6wx"


@pytest.mark.asyncio
async def test_advisories_without_a_cve_alias_keep_their_osv_id() -> None:
    """A GHSA with no CVE assigned is still a real vulnerability."""
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"vulns": [_vuln("GHSA-only-1234", aliases=[])]})

    result = await _client(handler).lookup("Express", "4.18.2", "npm", "express")

    assert [c["cve_id"] for c in result.cves] == ["GHSA-only-1234"]


@pytest.mark.asyncio
async def test_first_cve_alias_wins_when_several_are_listed() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"vulns": [
            _vuln("GHSA-x", aliases=["GHSA-mirror", "CVE-2024-1111", "CVE-2024-2222"]),
        ]})

    result = await _client(handler).lookup("Express", "4.18.2", "npm", "express")

    assert [c["cve_id"] for c in result.cves] == ["CVE-2024-1111"]


@pytest.mark.asyncio
async def test_cvss_vector_is_converted_to_a_base_score() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"vulns": [
            _vuln("GHSA-a", aliases=["CVE-2023-44487"],
                  vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"),
        ]})

    result = await _client(handler).lookup("Express", "4.18.2", "npm", "express")

    assert result.cves[0]["severity_score"] == 7.5


@pytest.mark.asyncio
async def test_qualitative_label_is_carried_when_no_score_can_be_computed() -> None:
    """A CVSS v4-only advisory has no computable v3 score; the label still informs."""
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"vulns": [
            {
                "id": "GHSA-v4-only",
                "aliases": ["CVE-2025-0001"],
                "summary": "v4 only",
                "severity": [{"type": "CVSS_V4", "score": "CVSS:4.0/AV:N/AC:L/AT:P/PR:N"}],
                "database_specific": {"severity": "CRITICAL"},
            }
        ]})

    result = await _client(handler).lookup("Express", "4.18.2", "npm", "express")

    assert result.cves[0]["severity_score"] is None
    assert result.cves[0]["severity_label"] == "CRITICAL"


@pytest.mark.asyncio
async def test_withdrawn_advisories_are_skipped() -> None:
    """A withdrawn advisory was retracted; reporting it is a false positive."""
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"vulns": [
            _vuln("GHSA-live", aliases=["CVE-2024-0001"]),
            _vuln("GHSA-dead", aliases=["CVE-2024-0002"], withdrawn="2024-06-01T00:00:00Z"),
        ]})

    result = await _client(handler).lookup("Express", "4.18.2", "npm", "express")

    assert [c["cve_id"] for c in result.cves] == ["CVE-2024-0001"]


@pytest.mark.asyncio
async def test_no_vulnerabilities_is_an_assessed_clean_result() -> None:
    """Distinct from not_assessed: OSV covers this package and says it is clean."""
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={})

    result = await _client(handler).lookup("Express", "4.19.2", "npm", "express")

    assert result.status == "assessed"
    assert result.cves == []


# --------------------------------------------------------------------------- #
# Failure handling
# --------------------------------------------------------------------------- #

@pytest.mark.asyncio
async def test_http_error_yields_failed_status() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="boom")

    result = await _client(handler).lookup("Express", "4.18.2", "npm", "express")

    assert result.status == "failed"
    assert "500" in (result.reason or "")


@pytest.mark.asyncio
async def test_failed_lookups_are_not_cached() -> None:
    attempts = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        attempts["n"] += 1
        if attempts["n"] == 1:
            return httpx.Response(503, text="unavailable")
        return httpx.Response(200, json={"vulns": [_vuln("GHSA-a", aliases=["CVE-2024-0001"])]})

    client = _client(handler)
    first = await client.lookup("Express", "4.18.2", "npm", "express")
    second = await client.lookup("Express", "4.18.2", "npm", "express")

    assert first.status == "failed"
    assert [c["cve_id"] for c in second.cves] == ["CVE-2024-0001"]


@pytest.mark.asyncio
async def test_successful_lookups_are_cached() -> None:
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(200, json={"vulns": []})

    client = _client(handler)
    await client.lookup("Express", "4.18.2", "npm", "express")
    await client.lookup("Express", "4.18.2", "npm", "express")

    assert calls["n"] == 1
