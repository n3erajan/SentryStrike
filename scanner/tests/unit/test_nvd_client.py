"""NVD lookups built on CPE applicability rather than description keywords.

The old client sent ``keywordSearch="<name> <version>"`` with
``resultsPerPage=5``. That is a full-text search over CVE prose, so it produced
noise for loosely-versioned components (WordPress "7.1" matched five plugin CVEs
whose descriptions read "before 7.1.03 for WordPress") and silence for precisely
versioned ones (Express 4.18.2, Nginx 1.24.0 and Node.js 18.16.0 all returned
zero results). These tests pin the replacement.
"""

import httpx
import pytest

from app.integrations.nvd_client import NvdClient


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def _cve(cve_id: str, *, score: float | None = 7.5, configurations: list | None = None,
         summary: str = "test summary", metric: str = "cvssMetricV31") -> dict:
    metrics = {}
    if score is not None:
        metrics[metric] = [{"cvssData": {"baseScore": score}}]
    return {
        "cve": {
            "id": cve_id,
            "descriptions": [{"lang": "en", "value": summary}],
            "metrics": metrics,
            "configurations": configurations if configurations is not None else [],
            "published": "2024-01-01T00:00:00.000",
        }
    }


def _nginx_config(start: str = "1.9.5", end: str = "1.25.2") -> list:
    return [
        {
            "nodes": [
                {
                    "cpeMatch": [
                        {
                            "criteria": "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*",
                            "versionStartIncluding": start,
                            "versionEndIncluding": end,
                            "vulnerable": True,
                        }
                    ]
                }
            ]
        }
    ]


def _client(handler, **kwargs) -> NvdClient:
    client = NvdClient(transport=httpx.MockTransport(handler), **kwargs)
    client.rate_limiter.min_interval = 0.0
    return client


NGINX_CPE = "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*"


# --------------------------------------------------------------------------- #
# Refusals: no version, no CPE -> no query at all
# --------------------------------------------------------------------------- #

@pytest.mark.asyncio
async def test_missing_version_is_not_assessed_and_sends_no_request() -> None:
    """An unversioned component cannot be CVE-matched, so it must not be queried.

    The old client happily sent ``keywordSearch="PHP"`` for a version-less PHP
    entry, got 12,324 results back and attached the first five - which described
    TYPO3, Selesta Visual Access Manager and NoneCms.
    """
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(200, json={"totalResults": 0, "vulnerabilities": []})

    result = await _client(handler).lookup("PHP", None, NGINX_CPE)

    assert result.status == "not_assessed"
    assert "version" in (result.reason or "").lower()
    assert result.cves == []
    assert calls == []


@pytest.mark.asyncio
async def test_missing_cpe_is_not_assessed_and_sends_no_request() -> None:
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(200, json={"totalResults": 0, "vulnerabilities": []})

    result = await _client(handler).lookup("jQuery Migrate", "3.4.1", None)

    assert result.status == "not_assessed"
    assert "cpe" in (result.reason or "").lower()
    assert calls == []


# --------------------------------------------------------------------------- #
# Query construction
# --------------------------------------------------------------------------- #

@pytest.mark.asyncio
async def test_lookup_queries_by_cpe_and_never_by_keyword() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={
            "totalResults": 1,
            "vulnerabilities": [_cve("CVE-2023-44487", configurations=_nginx_config())],
        })

    result = await _client(handler).lookup("Nginx", "1.24.0", NGINX_CPE)

    assert len(seen) == 1
    params = seen[0].url.params
    assert params["virtualMatchString"] == "cpe:2.3:a:f5:nginx:1.24.0"
    assert "keywordSearch" not in params
    assert result.status == "assessed"
    assert result.source == "nvd-cpe"
    assert [c["cve_id"] for c in result.cves] == ["CVE-2023-44487"]


@pytest.mark.asyncio
async def test_api_key_is_sent_as_header_when_configured(monkeypatch) -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"totalResults": 0, "vulnerabilities": []})

    client = _client(handler)
    # ``get_settings`` is lru_cached, so this object is shared process-wide;
    # monkeypatch restores it rather than leaking a key into later tests.
    monkeypatch.setattr(client.settings, "nvd_api_key", "secret-key")
    await client.lookup("Nginx", "1.24.0", NGINX_CPE)

    assert seen[0].headers["apiKey"] == "secret-key"


# --------------------------------------------------------------------------- #
# Client-side applicability verification
# --------------------------------------------------------------------------- #

@pytest.mark.asyncio
async def test_cves_outside_the_detected_version_range_are_dropped() -> None:
    """NVD's own filtering is trusted but re-checked; a stray result is dropped."""
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={
            "totalResults": 2,
            "vulnerabilities": [
                _cve("CVE-2023-44487", configurations=_nginx_config("1.9.5", "1.25.2")),
                # Range ends well before 1.24.0 - must not be reported.
                _cve("CVE-2019-9511", configurations=_nginx_config("1.9.5", "1.16.0")),
            ],
        })

    result = await _client(handler).lookup("Nginx", "1.24.0", NGINX_CPE)

    assert [c["cve_id"] for c in result.cves] == ["CVE-2023-44487"]


@pytest.mark.asyncio
async def test_unbounded_legacy_cpe_entries_are_dropped() -> None:
    """CVE-2007-2627 matches WordPress 7.1 only because its CPE has no bounds."""
    unbounded = [{"nodes": [{"cpeMatch": [
        {"criteria": "cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*:*", "vulnerable": True}
    ]}]}]

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={
            "totalResults": 1,
            "vulnerabilities": [_cve("CVE-2007-2627", configurations=unbounded)],
        })

    result = await _client(handler).lookup(
        "WordPress", "7.1", "cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*:*"
    )

    assert result.status == "assessed"
    assert result.cves == []


@pytest.mark.asyncio
async def test_cve_with_no_configurations_is_dropped() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={
            "totalResults": 1,
            "vulnerabilities": [_cve("CVE-2024-0001", configurations=[])],
        })

    result = await _client(handler).lookup("Nginx", "1.24.0", NGINX_CPE)

    assert result.cves == []


# --------------------------------------------------------------------------- #
# Pagination + parsing
# --------------------------------------------------------------------------- #

@pytest.mark.asyncio
async def test_all_pages_are_fetched_instead_of_truncating_at_five() -> None:
    """``resultsPerPage=5`` silently discarded the rest; paging keeps them."""
    def handler(request: httpx.Request) -> httpx.Response:
        start = int(request.url.params.get("startIndex", 0))
        page_size = int(request.url.params["resultsPerPage"])
        all_ids = [f"CVE-2024-{i:04d}" for i in range(7)]
        page = all_ids[start : start + page_size]
        return httpx.Response(200, json={
            "totalResults": len(all_ids),
            "vulnerabilities": [_cve(i, configurations=_nginx_config()) for i in page],
        })

    client = _client(handler)
    client.page_size = 3
    result = await client.lookup("Nginx", "1.24.0", NGINX_CPE)

    assert len(result.cves) == 7


@pytest.mark.asyncio
async def test_cvss_v40_and_v30_scores_are_read_when_v31_is_absent() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={
            "totalResults": 2,
            "vulnerabilities": [
                _cve("CVE-2024-0002", score=9.1, metric="cvssMetricV40",
                     configurations=_nginx_config()),
                _cve("CVE-2024-0003", score=5.3, metric="cvssMetricV30",
                     configurations=_nginx_config()),
            ],
        })

    result = await _client(handler).lookup("Nginx", "1.24.0", NGINX_CPE)

    assert {c["cve_id"]: c["severity_score"] for c in result.cves} == {
        "CVE-2024-0002": 9.1,
        "CVE-2024-0003": 5.3,
    }


# --------------------------------------------------------------------------- #
# Failure is reported, not silently rendered as "clean"
# --------------------------------------------------------------------------- #

@pytest.mark.asyncio
async def test_http_error_yields_failed_status_not_an_empty_clean_result() -> None:
    """A 403/429 must never be indistinguishable from "no vulnerabilities"."""
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, text="rate limited")

    result = await _client(handler).lookup("Nginx", "1.24.0", NGINX_CPE)

    assert result.status == "failed"
    assert result.cves == []
    assert "403" in (result.reason or "")


@pytest.mark.asyncio
async def test_transport_error_yields_failed_status() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("dns failure")

    result = await _client(handler).lookup("Nginx", "1.24.0", NGINX_CPE)

    assert result.status == "failed"


@pytest.mark.asyncio
async def test_failed_lookups_are_not_cached() -> None:
    """Caching a rate-limit blip would suppress the component for a full TTL."""
    attempts = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        attempts["n"] += 1
        if attempts["n"] == 1:
            return httpx.Response(429, text="too many requests")
        return httpx.Response(200, json={
            "totalResults": 1,
            "vulnerabilities": [_cve("CVE-2023-44487", configurations=_nginx_config())],
        })

    client = _client(handler)
    first = await client.lookup("Nginx", "1.24.0", NGINX_CPE)
    second = await client.lookup("Nginx", "1.24.0", NGINX_CPE)

    assert first.status == "failed"
    assert second.status == "assessed"
    assert [c["cve_id"] for c in second.cves] == ["CVE-2023-44487"]


@pytest.mark.asyncio
async def test_successful_lookups_are_cached() -> None:
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(200, json={"totalResults": 0, "vulnerabilities": []})

    client = _client(handler)
    await client.lookup("Nginx", "1.24.0", NGINX_CPE)
    await client.lookup("Nginx", "1.24.0", NGINX_CPE)

    assert calls["n"] == 1


# --------------------------------------------------------------------------- #
# Rate limiting
# --------------------------------------------------------------------------- #

def test_rate_limit_window_reflects_whether_an_api_key_is_present(monkeypatch) -> None:
    """NVD allows 5 requests/30s unkeyed and 50/30s with a key."""
    client = NvdClient()
    monkeypatch.setattr(client.settings, "nvd_api_key", None)
    assert client._request_budget() == 5

    monkeypatch.setattr(client.settings, "nvd_api_key", "k")
    assert client._request_budget() == 50


@pytest.mark.asyncio
async def test_rate_limiter_spaces_out_calls_beyond_the_budget() -> None:
    import time

    from app.integrations.nvd_client import _RateLimiter

    limiter = _RateLimiter(max_calls=2, window_seconds=0.3)
    start = time.monotonic()
    for _ in range(3):
        await limiter.acquire()
    elapsed = time.monotonic() - start

    assert elapsed >= 0.25
