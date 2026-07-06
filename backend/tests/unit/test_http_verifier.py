import pytest
import httpx

from app.core.verification.verification_framework import HttpVerifier, URLParameterBuilder
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

