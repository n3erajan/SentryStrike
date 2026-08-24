"""Exploitation-in-the-wild overlays: CISA KEV and EPSS.

Neither changes *which* CVEs apply - that is settled by CPE/OSV matching. They
change which ones matter. The old client truncated at ``resultsPerPage=5`` with no
ordering, so the five oldest CVE IDs won; with these overlays a component's
findings can be ranked by whether they are actually being exploited.
"""

import httpx
import pytest

from app.integrations.threat_intel import ThreatIntel


def _kev(*cve_ids: str) -> dict:
    return {
        "count": len(cve_ids),
        "vulnerabilities": [
            {"cveID": c, "vendorProject": "Test", "product": "Thing", "knownRansomwareCampaignUse": "Known"}
            for c in cve_ids
        ],
    }


def _epss(**scores: float) -> dict:
    return {
        "data": [
            {"cve": c, "epss": str(v), "percentile": "0.9"} for c, v in scores.items()
        ]
    }


def _intel(handler) -> ThreatIntel:
    return ThreatIntel(transport=httpx.MockTransport(handler))


# --------------------------------------------------------------------------- #
# KEV
# --------------------------------------------------------------------------- #

@pytest.mark.asyncio
async def test_known_exploited_cves_are_flagged() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if "cisa.gov" in str(request.url):
            return httpx.Response(200, json=_kev("CVE-2021-44228", "CVE-2026-60137"))
        return httpx.Response(200, json=_epss())

    intel = _intel(handler)
    flagged = await intel.known_exploited(["CVE-2021-44228", "CVE-2024-0001"])

    assert flagged == ["CVE-2021-44228"]


@pytest.mark.asyncio
async def test_kev_catalog_is_fetched_once_and_reused() -> None:
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(200, json=_kev("CVE-2021-44228"))

    intel = _intel(handler)
    await intel.known_exploited(["CVE-2021-44228"])
    await intel.known_exploited(["CVE-2024-0001"])

    assert calls["n"] == 1


@pytest.mark.asyncio
async def test_kev_failure_degrades_to_no_flags_rather_than_raising() -> None:
    """The overlay is advisory; losing it must not fail the whole enrichment."""
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, text="unavailable")

    flagged = await _intel(handler).known_exploited(["CVE-2021-44228"])

    assert flagged == []


@pytest.mark.asyncio
async def test_empty_cve_list_makes_no_request() -> None:
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(200, json=_kev())

    assert await _intel(handler).known_exploited([]) == []
    assert calls == []


# --------------------------------------------------------------------------- #
# EPSS
# --------------------------------------------------------------------------- #

@pytest.mark.asyncio
async def test_epss_scores_are_returned_per_cve() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=_epss(**{"CVE-2019-10692": 0.78699, "CVE-2007-2627": 0.02327}))

    scores = await _intel(handler).exploit_probability(["CVE-2019-10692", "CVE-2007-2627"])

    assert scores == {"CVE-2019-10692": 0.78699, "CVE-2007-2627": 0.02327}


@pytest.mark.asyncio
async def test_epss_requests_cves_in_batches() -> None:
    """The EPSS API caps the ``cve`` parameter length, so long lists are chunked."""
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.params["cve"])
        return httpx.Response(200, json=_epss())

    intel = _intel(handler)
    intel.epss_batch_size = 2
    await intel.exploit_probability(["CVE-1", "CVE-2", "CVE-3", "CVE-4", "CVE-5"])

    assert seen == ["CVE-1,CVE-2", "CVE-3,CVE-4", "CVE-5"]


@pytest.mark.asyncio
async def test_epss_failure_degrades_to_empty_scores() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("dns")

    assert await _intel(handler).exploit_probability(["CVE-1"]) == {}


@pytest.mark.asyncio
async def test_unscored_cves_are_absent_rather_than_zero() -> None:
    """EPSS has no score for very new or rejected CVEs; 0.0 would imply "safe"."""
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=_epss(**{"CVE-1": 0.5}))

    scores = await _intel(handler).exploit_probability(["CVE-1", "CVE-2"])

    assert scores == {"CVE-1": 0.5}
    assert "CVE-2" not in scores
