from types import SimpleNamespace
from unittest.mock import patch

import httpx
import pytest

from app.core.crawler.models import ApiEndpoint, ParameterCandidate, ParameterLocation, RequestObservation
from app.core.detectors.file_upload import FileUploadDetector
from app.core.detectors.open_redirect import OpenRedirectDetector
from app.core.detectors.ssrf_detector import SSRFDetector
from app.core.verification.oast import OastClient
from app.core.verification.response_analyzer import ResponseData
from app.core.verification.verification_framework import HttpVerifier


class FakeOast(OastClient):
    def __init__(self) -> None:
        super().__init__("https://oast.test", None)
        self.interaction_id = "ssrf-test-id"

    def new_callback_url(self, purpose: str = "ssrf") -> tuple[str, str]:
        return "https://oast.test/ssrf-test-id", self.interaction_id

    async def poll(self, interaction_id: str):
        return [SimpleNamespace(interaction_id=interaction_id, raw={"id": interaction_id})]


@pytest.mark.asyncio
async def test_ssrf_detector_reports_blind_oast_callback_for_json_body_target():
    detector = SSRFDetector()
    parameter = ParameterCandidate(
        name="url",
        location=ParameterLocation.json_body,
        url="https://example.test/api/fetch",
        method="POST",
        baseline_value="https://example.test/image.png",
        parent_path="url",
    )
    request_bodies: list[object] = []

    async def send_request(self, url, method="GET", params=None, data=None, **kwargs):
        request_bodies.append(kwargs.get("json_body"))
        return ResponseData(
            200,
            {"content-type": "application/json"},
            '{"ok":true}',
            5.0,
            request_snippet=f"{method} {url}",
            response_snippet="HTTP/1.1 200 OK",
        )

    with patch.object(HttpVerifier, "send_request", send_request):
        findings = await detector.detect(
            urls=[],
            forms=[],
            parameters=[parameter],
            api_endpoints=[],
            oast_client=FakeOast(),
        )

    assert any(body == {"url": "https://oast.test/ssrf-test-id"} for body in request_bodies)
    assert any(f.vuln_type == "Blind Server-Side Request Forgery (SSRF)" for f in findings)


@pytest.mark.asyncio
async def test_ssrf_inband_fallback_reports_probable_when_oast_unset():
    """No OAST configured + internal target behaves differently from the external
    control → a PROBABLE (unverified) in-band finding."""
    detector = SSRFDetector()
    parameter = ParameterCandidate(
        name="url",
        location=ParameterLocation.json_body,
        url="https://example.test/api/fetch",
        method="POST",
        baseline_value="https://example.test/image.png",
        parent_path="url",
    )

    async def send_request(self, url, method="GET", params=None, data=None, **kwargs):
        payload = kwargs.get("payload") or ""
        # Internal targets hang (slow); external control is fast. Body content
        # never matches the reflection signatures, so only the in-band path fires.
        if "127.0.0.1" in payload or "169.254.169.254" in payload:
            return ResponseData(200, {}, "blocked", 3000.0, request_snippet=f"{method} {url}", response_snippet="RESP")
        return ResponseData(200, {}, "external ok", 100.0, request_snippet=f"{method} {url}", response_snippet="RESP")

    with patch.object(HttpVerifier, "send_request", send_request):
        findings = await detector.detect(
            urls=[],
            forms=[],
            parameters=[parameter],
            api_endpoints=[],
            # no oast_client → OastClient built from (unset) settings, disabled
        )

    probable = [f for f in findings if f.vuln_type == "Server-Side Request Forgery (SSRF) - Probable"]
    assert probable, "expected a probable in-band SSRF finding"
    assert probable[0].verified is False
    assert probable[0].detection_method == "ssrf_inband_differential"


@pytest.mark.asyncio
async def test_ssrf_inband_fallback_silent_when_no_differential():
    """Internal and external targets behave identically → no in-band finding."""
    detector = SSRFDetector()
    parameter = ParameterCandidate(
        name="url",
        location=ParameterLocation.json_body,
        url="https://example.test/api/fetch",
        method="POST",
        baseline_value="https://example.test/image.png",
        parent_path="url",
    )

    async def send_request(self, url, method="GET", params=None, data=None, **kwargs):
        # Uniform response regardless of target: a well-behaved app.
        return ResponseData(200, {}, "same body", 100.0, request_snippet=f"{method} {url}", response_snippet="RESP")

    with patch.object(HttpVerifier, "send_request", send_request):
        findings = await detector.detect(
            urls=[],
            forms=[],
            parameters=[parameter],
            api_endpoints=[],
        )

    assert findings == []


def test_ssrf_inband_differential_evaluator_truth_cases():
    detector = SSRFDetector()
    delta = 1500.0
    # Consistent status divergence.
    assert detector._inband_differential(
        [(200, 10, 100.0), (200, 10, 110.0)],
        [(500, 5, 120.0), (500, 5, 130.0)],
        delta,
    )
    # Consistent large timing delta.
    assert detector._inband_differential(
        [(200, 10, 100.0), (200, 10, 100.0)],
        [(200, 10, 2000.0), (200, 10, 2000.0)],
        delta,
    )
    # Indistinguishable → None.
    assert detector._inband_differential(
        [(200, 10, 100.0), (200, 10, 105.0)],
        [(200, 10, 110.0), (200, 10, 108.0)],
        delta,
    ) is None


@pytest.mark.asyncio
async def test_open_redirect_detector_verifies_external_location_header():
    detector = OpenRedirectDetector()
    observed_urls: list[str] = []

    async def send_request(self, url, method="GET", params=None, data=None, **kwargs):
        observed_urls.append(url)
        return ResponseData(
            302,
            {"Location": "https://sentrystrike.invalid/open-redirect"},
            "",
            5.0,
            request_snippet=f"{method} {url}",
            response_snippet="HTTP/1.1 302 Found\nLocation: https://sentrystrike.invalid/open-redirect",
        )

    with patch.object(HttpVerifier, "send_request", send_request):
        findings = await detector.detect(urls=["https://example.test/login?next=/dashboard"], forms=[])

    assert observed_urls
    assert any(f.vuln_type == "Open Redirect" for f in findings)


@pytest.mark.asyncio
async def test_open_redirect_detector_reports_observed_external_redirect_without_following():
    detector = OpenRedirectDetector()
    observed_urls: list[str] = []

    async def send_request(self, url, method="GET", params=None, data=None, **kwargs):
        observed_urls.append(url)
        return ResponseData(
            302,
            {"Location": "https://github.com/juice-shop/juice-shop"},
            "",
            5.0,
            request_snippet=f"{method} {url}",
            response_snippet="HTTP/1.1 302 Found\nLocation: https://github.com/juice-shop/juice-shop",
        )

    with patch.object(HttpVerifier, "send_request", send_request):
        findings = await detector.detect(
            urls=["http://target.test/redirect?to=https://github.com/juice-shop/juice-shop"],
            forms=[],
        )

    assert len(observed_urls) == 1
    assert observed_urls[0].startswith("http://target.test/redirect?to=")
    assert "github.com" in observed_urls[0]
    assert any(
        f.vuln_type == "Open Redirect"
        and f.detection_method == "observed_external_location_redirect"
        for f in findings
    )


@pytest.mark.asyncio
async def test_open_redirect_detector_ignores_same_origin_location_header():
    detector = OpenRedirectDetector()

    async def send_request(self, url, method="GET", params=None, data=None, **kwargs):
        return ResponseData(302, {"Location": "https://example.test/dashboard"}, "", 5.0)

    with patch.object(HttpVerifier, "send_request", send_request):
        findings = await detector.detect(urls=["https://example.test/login?next=/dashboard"], forms=[])

    assert findings == []


@pytest.mark.asyncio
async def test_file_upload_detector_replays_browser_observed_multipart_request(monkeypatch):
    detector = FileUploadDetector()
    request = RequestObservation(
        url="https://example.test/api/upload",
        method="POST",
        request_headers={"content-type": "multipart/form-data; boundary=abc", "authorization": "Bearer token"},
        post_data='--abc\r\nContent-Disposition: form-data; name="avatar"; filename="old.png"\r\n\r\nx'
        '\r\n--abc\r\nContent-Disposition: form-data; name="userId"\r\n\r\n1\r\n--abc--',
    )
    uploads: list[dict] = []

    class FakeClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return None

        async def request(self, **kwargs):
            uploads.append(kwargs)
            return httpx.Response(
                201,
                json={"url": "/uploads/sentry_test.txt"},
                request=httpx.Request(kwargs["method"], kwargs["url"]),
            )

        async def get(self, url):
            return httpx.Response(200, text="SENTRY_UPLOAD_TEST_CANARY", request=httpx.Request("GET", url))

    monkeypatch.setattr("app.core.detectors.file_upload.create_scan_client", lambda **kwargs: FakeClient())

    findings = await detector.detect(urls=[], forms=[], requests=[request])

    assert uploads
    assert uploads[0]["files"]["avatar"][0] == "sentry_test.php"
    assert uploads[0]["data"]["userId"] == "sentry_test_val"
    assert uploads[0]["headers"] == {"authorization": "Bearer token"}
    assert any(f.vuln_type == "Unrestricted File Upload" for f in findings)


@pytest.mark.asyncio
async def test_file_upload_detector_passes_auth_headers_to_scan_client(monkeypatch):
    detector = FileUploadDetector()
    captured_client_kwargs: dict[str, object] = {}

    form = SimpleNamespace(
        page_url="https://example.test/profile",
        action="/api/profile/upload",
        method="POST",
        inputs=[SimpleNamespace(name="avatar", input_type="file")],
    )

    class FakeClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return None

        async def request(self, **kwargs):
            return httpx.Response(
                401,
                text="unauthorized",
                request=httpx.Request(kwargs["method"], kwargs["url"]),
            )

    def fake_create_scan_client(**kwargs):
        captured_client_kwargs.update(kwargs)
        return FakeClient()

    monkeypatch.setattr("app.core.detectors.file_upload.create_scan_client", fake_create_scan_client)

    await detector.detect(
        urls=[],
        forms=[form],
        auth_headers={"Authorization": "Bearer upload-token"},
    )

    assert captured_client_kwargs["headers"]["Authorization"] == "Bearer upload-token"
    assert captured_client_kwargs["headers"]["User-Agent"] == "SentryStrikeScanner/1.0"


def test_file_upload_static_formdata_candidate_extraction():
    detector = FileUploadDetector()
    candidates = detector._api_upload_candidates(
        {
            "root_url": "https://example.test/",
            "assets": [
                """
                const fd = new FormData();
                fd.append('document', file);
                fd.append('folder', 'profile');
                fetch('/api/files/upload', { method: 'POST', body: fd });
                """,
            ],
        }
    )

    assert len(candidates) == 1
    assert candidates[0].url == "https://example.test/api/files/upload"
    assert candidates[0].file_field == "document"
    assert candidates[0].data == {"folder": "sentry_test_val"}


def test_file_upload_candidate_extraction_from_api_endpoint():
    detector = FileUploadDetector()
    endpoint = ApiEndpoint(
        url="https://example.test/api/profile/upload",
        method="POST",
        content_type="multipart/form-data",
        request_body={"avatar": "sample.txt", "userId": 1},
        headers={"authorization": "Bearer token", "content-type": "multipart/form-data"},
    )

    candidates = detector._api_upload_candidates({"api_endpoints": [endpoint]})

    assert len(candidates) == 1
    assert candidates[0].url == "https://example.test/api/profile/upload"
    assert candidates[0].file_field == "avatar"
    assert candidates[0].data == {"userId": "1"}
    assert candidates[0].headers == {"authorization": "Bearer token"}
    assert candidates[0].source == "attack_surface_api_form_body"


def test_oast_client_extracts_interactions_from_common_payload_shapes():
    client = OastClient("https://oast.test", "https://oast.test/poll")

    assert client._extract_interactions({"interactions": [{"id": "a"}]}) == [{"id": "a"}]
    assert client._extract_interactions({"events": ["event-a"]}) == ["event-a"]
    assert client._extract_interactions("plain-event") == ["plain-event"]
