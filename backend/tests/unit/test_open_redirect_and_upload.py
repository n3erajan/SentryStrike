from types import SimpleNamespace
from unittest.mock import patch

import httpx
import pytest

from app.core.crawler.models import ApiEndpoint, ParameterCandidate, ParameterLocation, RequestObservation
from app.core.detectors.file_upload import FileUploadDetector
from app.core.detectors.open_redirect import OpenRedirectDetector
from app.core.verification.response_analyzer import ResponseData
from app.core.verification.verification_framework import HttpVerifier


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


def test_open_redirect_effective_host_normalises_bypass_families():
    detector = OpenRedirectDetector()
    marker = "sentrystrike.invalid"
    # Direct, protocol-relative, backslash scheme-confusion, path-relative
    # backslash, and userinfo-confusion all resolve to the marker host.
    assert detector._effective_redirect_host("https://sentrystrike.invalid/x") == marker
    assert detector._effective_redirect_host("//sentrystrike.invalid/x") == marker
    assert detector._effective_redirect_host("https:\\\\sentrystrike.invalid\\x") == marker
    assert detector._effective_redirect_host("/\\sentrystrike.invalid/x") == marker
    assert detector._effective_redirect_host("https://allowed.test@sentrystrike.invalid/x") == marker
    # Same-origin / relative Locations do not resolve to the marker.
    assert detector._effective_redirect_host("/dashboard") == ""
    assert detector._effective_redirect_host("https://example.test/x") == "example.test"


def test_open_redirect_payloads_include_allowlist_bypass_from_target_origin():
    detector = OpenRedirectDetector()
    from app.core.detectors.attack_surface import AttackTarget
    from app.core.crawler.models import ParameterLocation

    target = AttackTarget(
        url="https://app.example.test/redirect?to=/home",
        parameter="to",
        method="GET",
        value="/home",
        location=ParameterLocation.query,
    )
    payloads = detector._candidate_payloads(target)
    # Static families are all present.
    assert "https://sentrystrike.invalid/open-redirect" in payloads
    assert "//sentrystrike.invalid/open-redirect" in payloads
    # A data-driven userinfo bypass keeps the app's own host as an allowed
    # substring but resolves to the marker host.
    assert any(
        p.startswith("https://app.example.test@sentrystrike.invalid") for p in payloads
    )
    # No duplicate payloads.
    assert len(payloads) == len(set(payloads))


@pytest.mark.asyncio
async def test_open_redirect_detector_confirms_userinfo_confusion_bypass():
    """A server that reflects the payload into Location, keeping the allowed host
    as userinfo but redirecting to the marker host, is flagged."""
    detector = OpenRedirectDetector()
    seen_payloads: list[str] = []

    async def send_request(self, url, method="GET", params=None, data=None, **kwargs):
        payload = kwargs.get("payload") or ""
        seen_payloads.append(payload)
        # Only the userinfo-confusion payload "succeeds": the app echoes it into
        # Location verbatim (allowed host present, real host is the marker).
        if "@sentrystrike.invalid" in payload:
            return ResponseData(
                302,
                {"Location": payload},
                "",
                5.0,
                request_snippet=f"{method} {url}",
                response_snippet=f"HTTP/1.1 302 Found\nLocation: {payload}",
            )
        # Every other payload is safely rejected (same-origin bounce).
        return ResponseData(302, {"Location": "/home"}, "", 5.0)

    with patch.object(HttpVerifier, "send_request", send_request):
        findings = await detector.detect(
            urls=["https://app.example.test/redirect?to=/home"],
            forms=[],
        )

    assert any(f.vuln_type == "Open Redirect" for f in findings)
    assert any("@sentrystrike.invalid" in p for p in seen_payloads)


def test_open_redirect_browser_job_selection_and_injection():
    detector = OpenRedirectDetector()
    routes = [
        SimpleNamespace(url="http://h/#/redirect?to=x"),   # hash-route redirect sink
        SimpleNamespace(url="http://h/#/search?q=1"),        # not a redirect param
        SimpleNamespace(url="http://h/page?next=/a"),        # ordinary query redirect param
    ]
    jobs = detector._select_browser_redirect_jobs(routes, 10)
    assert ("http://h/#/redirect?to=x", "to") in jobs
    assert ("http://h/page?next=/a", "next") in jobs
    assert all(param != "q" for _, param in jobs)
    # Injection targets the correct query (fragment vs search).
    frag = detector._inject_redirect_param("http://h/#/redirect?to=x", "to", "https://sentrystrike.invalid/x")
    assert "sentrystrike.invalid" in frag and frag.split("#", 1)[1].startswith("/redirect?to=")


@pytest.mark.asyncio
async def test_open_redirect_browser_sweep_confirms_client_side_redirect(monkeypatch):
    """A hash-route redirect that navigates the browser to the marker host is
    flagged even though there is no HTTP 302 and no HTTP candidate."""
    import app.core.detectors.open_redirect as ormod

    detector = OpenRedirectDetector()
    routes = [SimpleNamespace(url="http://h/#/redirect?to=x")]

    class _FakeContext:
        async def close(self):
            pass

    class _FakeBrowser:
        async def new_context(self, **kwargs):
            return _FakeContext()

    class _FakeChromium:
        async def launch(self, **kwargs):
            return _FakeBrowser()

    class _FakeP:
        chromium = _FakeChromium()

        async def stop(self):
            pass

    class _FakePlaywrightCM:
        async def start(self):
            return _FakeP()

    monkeypatch.setattr(ormod, "async_playwright", lambda: _FakePlaywrightCM())
    monkeypatch.setattr(ormod, "PLAYWRIGHT_AVAILABLE", True)

    probed: list[str] = []

    async def fake_ctx(self, browser, route_url, session_cookies, storage_state):
        return _FakeContext()

    async def fake_nav(self, context, probe_url):
        probed.append(probe_url)
        return "sentrystrike.invalid" in probe_url

    monkeypatch.setattr(OpenRedirectDetector, "_new_browser_context", fake_ctx)
    monkeypatch.setattr(OpenRedirectDetector, "_navigate_and_detect_external", fake_nav)

    findings = await detector.detect(urls=[], forms=[], routes=routes, browser_available=True)

    assert probed and "sentrystrike.invalid" in probed[0]
    assert len(findings) == 1
    assert findings[0].detection_method == "browser_client_side_redirect"
    assert findings[0].parameter == "to"
    assert findings[0].verified is True


@pytest.mark.asyncio
async def test_open_redirect_browser_sweep_skipped_without_browser():
    detector = OpenRedirectDetector()
    routes = [SimpleNamespace(url="http://h/#/redirect?to=x")]
    findings = await detector.detect(urls=[], forms=[], routes=routes, browser_available=False)
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


@pytest.mark.asyncio
async def test_file_upload_detector_does_not_verify_plain_200_without_file_evidence(monkeypatch):
    detector = FileUploadDetector()
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
                200,
                text='{"ok":true}',
                request=httpx.Request(kwargs["method"], kwargs["url"]),
            )

        async def get(self, url):
            return httpx.Response(404, text="missing", request=httpx.Request("GET", url))

    monkeypatch.setattr("app.core.detectors.file_upload.create_scan_client", lambda **kwargs: FakeClient())

    findings = await detector.detect(urls=[], forms=[form])

    assert findings == []


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


@pytest.mark.asyncio
async def test_file_upload_detector_confirms_svg_image_bypass(monkeypatch):
    """An SVG accepted as an image and retrievable is flagged (stored-XSS-capable)."""
    detector = FileUploadDetector()
    form = SimpleNamespace(
        page_url="https://example.test/profile",
        action="/api/profile/avatar",
        method="POST",
        inputs=[SimpleNamespace(name="avatar", input_type="file")],
    )

    class FakeClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return None

        async def request(self, **kwargs):
            filename = kwargs["files"]["avatar"][0]
            # Only the SVG upload is accepted and echoed back; dangerous/txt
            # uploads are rejected so no other subcheck fires.
            if filename.endswith(".svg"):
                return httpx.Response(
                    201,
                    json={"url": f"/uploads/{filename}"},
                    request=httpx.Request(kwargs["method"], kwargs["url"]),
                )
            return httpx.Response(
                400, text="invalid file type",
                request=httpx.Request(kwargs["method"], kwargs["url"]),
            )

        async def get(self, url):
            # The stored SVG is retrievable with its canary intact.
            if url.endswith(".svg"):
                return httpx.Response(
                    200,
                    text="<svg><text>SENTRY_UPLOAD_TEST_CANARY</text></svg>",
                    request=httpx.Request("GET", url),
                )
            return httpx.Response(404, text="missing", request=httpx.Request("GET", url))

    monkeypatch.setattr("app.core.detectors.file_upload.create_scan_client", lambda **kwargs: FakeClient())

    findings = await detector.detect(urls=[], forms=[form])

    svg_findings = [f for f in findings if f.detection_method == "svg_image_upload_persistence"]
    assert svg_findings
    assert svg_findings[0].verified is True
    assert svg_findings[0].payload == "sentry_test.svg"


@pytest.mark.asyncio
async def test_file_upload_detector_reports_xml_entity_expansion(monkeypatch):
    """A parser endpoint that expands and reflects an internal XML entity is flagged."""
    detector = FileUploadDetector()
    form = SimpleNamespace(
        page_url="https://example.test/admin",
        action="/api/import/xml",
        method="POST",
        inputs=[SimpleNamespace(name="document", input_type="file")],
    )

    class FakeClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return None

        async def request(self, **kwargs):
            filename = kwargs["files"]["document"][0]
            # Dangerous/txt/svg uploads are rejected; the XML entity doc is parsed
            # and its expanded entity value is reflected in the response.
            if filename == "sentry_entity.xml":
                return httpx.Response(
                    200,
                    text="Parsed: SENTRY_XXE_ENTITY_CANARY",
                    request=httpx.Request(kwargs["method"], kwargs["url"]),
                )
            if filename == "sentry_control.xml":
                return httpx.Response(
                    200, text="Parsed: SENTRY_XML_CONTROL",
                    request=httpx.Request(kwargs["method"], kwargs["url"]),
                )
            return httpx.Response(
                400, text="invalid",
                request=httpx.Request(kwargs["method"], kwargs["url"]),
            )

        async def get(self, url):
            return httpx.Response(404, text="missing", request=httpx.Request("GET", url))

    monkeypatch.setattr("app.core.detectors.file_upload.create_scan_client", lambda **kwargs: FakeClient())

    findings = await detector.detect(urls=[], forms=[form])

    xxe = [f for f in findings if f.detection_method == "xml_entity_expansion_reflected"]
    assert xxe
    assert xxe[0].verified is True
    assert xxe[0].vuln_type == "XML Entity Expansion"


@pytest.mark.asyncio
async def test_file_upload_xml_probe_skipped_for_plain_image_form(monkeypatch):
    """The bounded XML entity probe must not fire on a plain avatar/image form."""
    detector = FileUploadDetector()
    form = SimpleNamespace(
        page_url="https://example.test/profile",
        action="/api/profile/avatar",
        method="POST",
        inputs=[SimpleNamespace(name="avatar", input_type="file")],
    )
    uploaded_names: list[str] = []

    class FakeClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return None

        async def request(self, **kwargs):
            uploaded_names.append(kwargs["files"]["avatar"][0])
            return httpx.Response(
                400, text="invalid",
                request=httpx.Request(kwargs["method"], kwargs["url"]),
            )

        async def get(self, url):
            return httpx.Response(404, text="missing", request=httpx.Request("GET", url))

    monkeypatch.setattr("app.core.detectors.file_upload.create_scan_client", lambda **kwargs: FakeClient())

    await detector.detect(urls=[], forms=[form])

    # No XML control/entity documents were uploaded to the image endpoint.
    assert "sentry_entity.xml" not in uploaded_names
    assert "sentry_control.xml" not in uploaded_names
