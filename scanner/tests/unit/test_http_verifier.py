import asyncio

import pytest
import httpx

from app.core.verification.verification_framework import HttpVerifier, URLParameterBuilder
from app.utils import scan_throttle
from app.utils.scan_http import create_scan_client


@pytest.mark.asyncio
async def test_send_request_preserves_url_query_when_params_empty():
    """GET URLs built by URLParameterBuilder embed the query string in the URL."""
    verifier = HttpVerifier(timeout_seconds=5.0)
    captured_urls: list[str] = []

    async def mock_request(**kwargs):
        captured_urls.append(kwargs["url"])

        class FakeResponse:
            status_code = 200
            reason_phrase = "OK"
            headers = {}
            text = "ok"

            @property
            def url(self):
                return kwargs["url"]

        return FakeResponse()

    client = await verifier.get_client()
    client.request = mock_request  # type: ignore[method-assign]

    built_url, params, data = URLParameterBuilder.inject_parameter(
        "http://example.com/sqli/?id=1&Submit=Submit",
        "id",
        "1' AND '1'='1",
        "GET",
        form_inputs=None,
    )
    assert params == {}

    await verifier.send_request(built_url, "GET", params, data, test_phase="boolean_true")

    assert len(captured_urls) == 1
    assert "id=" in captured_urls[0]
    assert "Submit=Submit" in captured_urls[0]

    await verifier.close()


@pytest.mark.asyncio
async def test_scan_client_does_not_follow_external_redirects():
    seen_urls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_urls.append(str(request.url))
        return httpx.Response(
            302,
            headers={"Location": "https://github.com/juice-shop/juice-shop"},
            request=request,
        )

    async with create_scan_client(
        follow_redirects=True,
        transport=httpx.MockTransport(handler),
    ) as client:
        response = await client.get("http://target.test/redirect?to=https://github.com/juice-shop/juice-shop")

    assert response.status_code == 302
    assert seen_urls == [
        "http://target.test/redirect?to=https://github.com/juice-shop/juice-shop"
    ]


@pytest.mark.asyncio
async def test_scan_client_follows_same_origin_redirects():
    seen_urls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_urls.append(str(request.url))
        if request.url.path == "/start":
            return httpx.Response(302, headers={"Location": "/next"}, request=request)
        return httpx.Response(200, text="ok", request=request)

    async with create_scan_client(
        follow_redirects=True,
        transport=httpx.MockTransport(handler),
    ) as client:
        response = await client.get("http://target.test/start")

    assert response.status_code == 200
    assert seen_urls == ["http://target.test/start", "http://target.test/next"]


@pytest.mark.asyncio
async def test_send_request_does_not_double_acquire_scan_semaphore(monkeypatch):
    """Regression: HttpVerifier.send_request must not re-acquire the global scan
    semaphore that the scan client (create_scan_client) already holds per request.

    The scan client wraps every request in get_scan_http_semaphore() via
    throttled_request. If send_request acquires it a second time, the
    non-reentrant asyncio.Semaphore is double-acquired: the outer hold takes a
    slot and the inner acquire waits for a slot that can never free -> deadlock.
    With a size-1 semaphore, a single request self-deadlocks, which is a
    deterministic reproduction of the scan-wide hang.
    """
    monkeypatch.setattr(scan_throttle, "_scan_http_semaphore", asyncio.Semaphore(1))

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="ok", request=request)

    verifier = HttpVerifier(timeout_seconds=5.0)
    verifier._client = create_scan_client(transport=httpx.MockTransport(handler))

    try:
        response = await asyncio.wait_for(
            verifier.send_request("http://target.test/probe", "GET", test_phase="probe"),
            timeout=3.0,
        )
    except asyncio.TimeoutError:
        pytest.fail("send_request deadlocked: scan semaphore was acquired twice")

    assert response.status_code == 200
    await verifier.close()


class _BarrierTransport(httpx.AsyncBaseTransport):
    """Async transport that holds every request until ``parties`` have arrived.

    This forces all in-flight requests to be simultaneously past the semaphore
    and inside the transport before any completes. It deterministically exposes a
    double-acquire: if send_request grabs a second slot, the requests never reach
    the transport at all (they block on the inner acquire), the barrier never
    releases, and the scan deadlocks.
    """

    def __init__(self, parties: int) -> None:
        self._parties = parties
        self._arrived = 0
        self._event = asyncio.Event()

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self._arrived += 1
        if self._arrived >= self._parties:
            self._event.set()
        await self._event.wait()
        return httpx.Response(200, text="ok", request=request)


@pytest.mark.asyncio
async def test_concurrent_send_requests_saturate_slots_without_deadlock(monkeypatch):
    """Regression: with semaphore size == request count, every request must be
    able to hold a slot and reach the network at once. Under the old
    double-acquire each request would hold an *outer* slot and then block forever
    on the *inner* acquire, so none would reach the transport -> deadlock.
    """
    parties = 3
    monkeypatch.setattr(scan_throttle, "_scan_http_semaphore", asyncio.Semaphore(parties))

    verifier = HttpVerifier(timeout_seconds=5.0)
    verifier._client = create_scan_client(transport=_BarrierTransport(parties))

    try:
        results = await asyncio.wait_for(
            asyncio.gather(
                *[
                    verifier.send_request(f"http://target.test/probe/{i}", "GET")
                    for i in range(parties)
                ]
            ),
            timeout=5.0,
        )
    except asyncio.TimeoutError:
        pytest.fail("concurrent send_request calls deadlocked on the scan semaphore")

    assert [r.status_code for r in results] == [200] * parties
    await verifier.close()


@pytest.mark.asyncio
async def test_explicit_cookie_header_replaces_client_cookie_jar():
    observed_cookie_headers: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        observed_cookie_headers.append(request.headers.get("cookie", ""))
        return httpx.Response(200, text="ok", request=request)

    verifier = HttpVerifier(
        timeout_seconds=5.0,
        cookies={"security": "high", "session": "stale"},
    )
    verifier._client = create_scan_client(
        cookies=verifier.cookies,
        transport=httpx.MockTransport(handler),
    )

    response = await verifier.send_request(
        "http://target.test/app/probe",
        headers={"Cookie": "session=fresh; security=low"},
        cookies={"session": "fresh", "security": "low"},
    )

    assert observed_cookie_headers == ["session=fresh; security=low"]
    assert response.request_snippet is not None
    assert response.request_snippet.count("Cookie:") == 1
    assert "security=high" not in response.request_snippet
    await verifier.close()

