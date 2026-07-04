import pytest

from app.core.verification.verification_framework import HttpVerifier, URLParameterBuilder


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


