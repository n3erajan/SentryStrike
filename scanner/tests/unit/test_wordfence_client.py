"""Wordfence Intelligence v3 lookups for WordPress plugins and themes.

WordPress core is well covered by NVD's CPE index; its plugin and theme ecosystem
is not. That gap is what produced the original false positives - NVD's keyword
search surfaced CVEs for the wp-google-maps and wp-live-chat-support *plugins*
while the scanner was asking about WordPress *core*.

Feed shape and auth are per Wordfence's published v3 documentation: the whole feed
is returned as a UUID-keyed object with no query parameters, authenticated with
``Authorization: Bearer <key>``. Version ranges use explicit
``from_version``/``to_version`` bounds with inclusive flags, where ``*`` means
unbounded - unlike NVD, an unbounded end here is a deliberate editorial statement
("all versions up to X are affected"), not missing data.
"""

import httpx
import pytest

from app.integrations.wordfence_client import WordfenceClient


def _record(
    *,
    cve: str = "CVE-2024-1234",
    slug: str = "example",
    sw_type: str = "plugin",
    from_version: str = "1.0.0",
    from_inclusive: bool = True,
    to_version: str = "1.2.3",
    to_inclusive: bool = True,
    score: float | None = 6.5,
    informational: bool = False,
    title: str = "Example Vulnerability",
) -> dict:
    return {
        "id": "848ccbdc-c6f1-480f-a272-cd459e706713",
        "title": title,
        "software": [
            {
                "type": sw_type,
                "name": "Example Plugin",
                "slug": slug,
                "affected_versions": {
                    f"{from_version} - {to_version}": {
                        "from_version": from_version,
                        "from_inclusive": from_inclusive,
                        "to_version": to_version,
                        "to_inclusive": to_inclusive,
                    }
                },
                "patched": True,
                "patched_versions": ["1.2.4"],
                "remediation": "Update to version 1.2.4, or a newer patched version",
            }
        ],
        "informational": informational,
        "description": "An example vulnerability",
        "references": ["https://www.wordfence.com/threat-intel/vulnerabilities/example"],
        "cvss": {"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N", "score": score,
                 "rating": "Medium"},
        "cve": cve,
        "published": "2024-01-09 00:00:00",
    }


def _feed(*records: dict) -> dict:
    return {r["id"] + str(i): r for i, r in enumerate(records)}


def _client(handler, key: str | None = "test-key", monkeypatch=None) -> WordfenceClient:
    client = WordfenceClient(transport=httpx.MockTransport(handler))
    object.__setattr__(client, "_api_key_override", key)
    return client


# --------------------------------------------------------------------------- #
# Disabled without a key
# --------------------------------------------------------------------------- #

@pytest.mark.asyncio
async def test_without_an_api_key_the_component_is_not_assessed() -> None:
    """No key means no coverage - which must be said, not silently shown as clean."""
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(200, json={})

    result = await _client(handler, key=None).lookup("Smart Slider 3", "3.5.1", "plugin", "smart-slider-3")

    assert result.status == "not_assessed"
    assert "wordfence" in (result.reason or "").lower()
    assert calls == []


@pytest.mark.asyncio
async def test_missing_version_is_not_assessed() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=_feed(_record()))

    result = await _client(handler).lookup("Example Plugin", None, "plugin", "example")

    assert result.status == "not_assessed"
    assert "version" in (result.reason or "").lower()


@pytest.mark.asyncio
async def test_missing_slug_is_not_assessed() -> None:
    """A display name is not a slug; guessing one queries the wrong plugin."""
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=_feed(_record()))

    result = await _client(handler).lookup("Example Plugin", "1.1.0", "plugin", None)

    assert result.status == "not_assessed"
    assert "slug" in (result.reason or "").lower()


# --------------------------------------------------------------------------- #
# Auth + matching
# --------------------------------------------------------------------------- #

@pytest.mark.asyncio
async def test_api_key_is_sent_as_a_bearer_token() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json=_feed(_record()))

    await _client(handler).lookup("Example Plugin", "1.1.0", "plugin", "example")

    assert seen[0].headers["authorization"] == "Bearer test-key"


@pytest.mark.asyncio
async def test_version_inside_an_inclusive_range_is_reported() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=_feed(_record(from_version="1.0.0", to_version="1.2.3")))

    result = await _client(handler).lookup("Example Plugin", "1.1.0", "plugin", "example")

    assert result.status == "assessed"
    assert result.source == "wordfence"
    assert [c["cve_id"] for c in result.cves] == ["CVE-2024-1234"]
    assert result.cves[0]["severity_score"] == 6.5


@pytest.mark.asyncio
async def test_version_above_the_range_is_not_reported() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=_feed(_record(from_version="1.0.0", to_version="1.2.3")))

    result = await _client(handler).lookup("Example Plugin", "1.2.4", "plugin", "example")

    assert result.status == "assessed"
    assert result.cves == []


@pytest.mark.asyncio
async def test_exclusive_bounds_exclude_the_boundary_version() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=_feed(
            _record(from_version="1.0.0", to_version="1.2.3", to_inclusive=False)
        ))

    client = _client(handler)
    assert (await client.lookup("Example Plugin", "1.2.3", "plugin", "example")).cves == []
    client._feed = None  # force a refetch rather than reusing the cached index
    assert (await client.lookup("Example Plugin", "1.2.2", "plugin", "example")).cve_ids == [
        "CVE-2024-1234"
    ]


@pytest.mark.asyncio
async def test_wildcard_bounds_are_treated_as_unbounded() -> None:
    """``*`` is an editorial "all versions below/above", not missing data."""
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=_feed(_record(from_version="*", to_version="1.2.3")))

    result = await _client(handler).lookup("Example Plugin", "0.1.0", "plugin", "example")

    assert [c["cve_id"] for c in result.cves] == ["CVE-2024-1234"]


@pytest.mark.asyncio
async def test_records_for_a_different_slug_are_ignored() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=_feed(_record(slug="other-plugin")))

    result = await _client(handler).lookup("Example Plugin", "1.1.0", "plugin", "example")

    assert result.cves == []


@pytest.mark.asyncio
async def test_records_for_a_different_software_type_are_ignored() -> None:
    """A theme and a plugin can share a slug."""
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=_feed(_record(slug="example", sw_type="theme")))

    result = await _client(handler).lookup("Example Plugin", "1.1.0", "plugin", "example")

    assert result.cves == []


@pytest.mark.asyncio
async def test_informational_records_are_excluded() -> None:
    """Informational entries document behaviour, not an exploitable flaw."""
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=_feed(_record(informational=True)))

    result = await _client(handler).lookup("Example Plugin", "1.1.0", "plugin", "example")

    assert result.cves == []


@pytest.mark.asyncio
async def test_records_without_a_cve_keep_their_wordfence_id() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=_feed(_record(cve="")))

    result = await _client(handler).lookup("Example Plugin", "1.1.0", "plugin", "example")

    assert result.cves[0]["cve_id"] == "WORDFENCE-848ccbdc-c6f1-480f-a272-cd459e706713"


# --------------------------------------------------------------------------- #
# Feed caching + failures
# --------------------------------------------------------------------------- #

@pytest.mark.asyncio
async def test_the_whole_feed_is_downloaded_once_for_many_components() -> None:
    """The endpoint takes no parameters, so it is fetched once and indexed."""
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(200, json=_feed(_record(slug="a"), _record(slug="b")))

    client = _client(handler)
    await client.lookup("A", "1.1.0", "plugin", "a")
    await client.lookup("B", "1.1.0", "plugin", "b")

    assert calls["n"] == 1


@pytest.mark.asyncio
async def test_http_error_yields_failed_status() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, text="too many requests")

    result = await _client(handler).lookup("Example Plugin", "1.1.0", "plugin", "example")

    assert result.status == "failed"
    assert "429" in (result.reason or "")
