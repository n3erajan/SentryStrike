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
async def test_open_redirect_detector_ignores_constrained_allowlisted_redirect():
    """An app that always redirects to a fixed allowlisted host (and never to an
    attacker-controlled target) is NOT an open redirect. The destination is not
    attacker-controllable, so no payload reaches the marker host and nothing is
    reported — this is the false positive we must not raise."""
    detector = OpenRedirectDetector()
    observed_urls: list[str] = []

    async def send_request(self, url, method="GET", params=None, data=None, **kwargs):
        observed_urls.append(url)
        # Whatever the input, the app only ever redirects to its own allowlisted
        # host — never to the scanner marker. Not attacker-controllable.
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

    assert observed_urls  # payloads were attempted
    assert findings == []  # but none reached the marker → no open redirect reported


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


def test_open_redirect_payloads_bypass_from_observed_allowlisted_value():
    """When the discovered param value is a URL the app already emitted (hence an
    allowlisted target), craft a marker-resolving payload that embeds that exact
    value as a substring, defeating naive ``includes``/``endsWith`` allowlists.
    The allowed substring is taken from the target's own value, never hardcoded."""
    detector = OpenRedirectDetector()
    from app.core.detectors.attack_surface import AttackTarget
    from app.core.crawler.models import ParameterLocation
    from urllib.parse import urlparse

    observed = "https://github.com/juice-shop/juice-shop"
    target = AttackTarget(
        url=f"https://app.example.test/redirect?to={observed}",
        parameter="to",
        method="GET",
        value=observed,
        location=ParameterLocation.query,
    )
    payloads = detector._candidate_payloads(target)
    # At least one payload resolves (as a browser resolves authority) to the
    # marker host AND retains the observed allowlisted value as a substring.
    hits = [
        p for p in payloads
        if detector._effective_redirect_host(p) == detector._MARKER_HOST
        and observed in p
    ]
    assert hits, payloads
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


def _xxe_doc_reads_passwd(files: dict) -> bool:
    """True when the multipart upload carries our external-entity /etc/passwd XML."""
    for _field, spec in (files or {}).items():
        _name, content, _ctype = spec
        body = content.decode("utf-8", "ignore") if isinstance(content, (bytes, bytearray)) else str(content)
        if 'SYSTEM "file:///etc/passwd"' in body:
            return True
    return False


@pytest.mark.asyncio
async def test_file_upload_detector_reports_reflected_xxe_external_entity(monkeypatch):
    """A parser that resolves an external file:// entity and reflects the file's
    content is reported as verified XXE (arbitrary file disclosure)."""
    detector = FileUploadDetector()
    form = SimpleNamespace(
        page_url="https://example.test/complain",
        action="/file-upload",
        method="POST",
        inputs=[SimpleNamespace(name="file", input_type="file")],
    )

    class FakeClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return None

        async def request(self, **kwargs):
            if _xxe_doc_reads_passwd(kwargs.get("files")):
                # Server resolved the external entity and reflected /etc/passwd.
                return httpx.Response(
                    410,
                    text="Error: deprecated: <product>root:x:0:0:root:/root:/bin/bash</product>",
                    request=httpx.Request(kwargs["method"], kwargs["url"]),
                )
            return httpx.Response(204, request=httpx.Request(kwargs["method"], kwargs["url"]))

        async def get(self, url):
            return httpx.Response(404, request=httpx.Request("GET", url))

    monkeypatch.setattr("app.core.detectors.file_upload.create_scan_client", lambda **kwargs: FakeClient())

    findings = await detector.detect(urls=[], forms=[form])

    xxe = [f for f in findings if f.vuln_type == "XML External Entity (XXE) Injection"]
    assert len(xxe) == 1
    assert xxe[0].verified is True
    assert xxe[0].detection_method == "xxe_external_entity_file_read"
    assert xxe[0].detection_evidence["file_disclosed"] is True


@pytest.mark.asyncio
async def test_file_upload_xxe_probe_zero_fp_when_entity_not_resolved(monkeypatch):
    """A server that echoes the raw XML but does NOT resolve entities (the entity
    reference is reflected literally, no file content) yields no XXE finding."""
    detector = FileUploadDetector()
    form = SimpleNamespace(
        page_url="https://example.test/complain",
        action="/file-upload",
        method="POST",
        inputs=[SimpleNamespace(name="file", input_type="file")],
    )

    class FakeClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return None

        async def request(self, **kwargs):
            files = kwargs.get("files") or {}
            # Echo the uploaded document back verbatim (entity NOT expanded).
            body = ""
            for _field, spec in files.items():
                content = spec[1]
                body = content.decode("utf-8", "ignore") if isinstance(content, (bytes, bytearray)) else str(content)
            return httpx.Response(200, text=body, request=httpx.Request(kwargs["method"], kwargs["url"]))

        async def get(self, url):
            return httpx.Response(404, request=httpx.Request("GET", url))

    monkeypatch.setattr("app.core.detectors.file_upload.create_scan_client", lambda **kwargs: FakeClient())

    findings = await detector.detect(urls=[], forms=[form])

    assert not [f for f in findings if f.vuln_type == "XML External Entity (XXE) Injection"]


# ---------------------------------------------------------------------------
# Test 8: file-type allowlist bypass via accept/reject differential (no
# retrieval needed). Regression for the miss where a discard-on-upload endpoint
# (accepts any type, never serves it back) exposed no allowlist yet was never
# flagged because every other upload test requires retrieval/execution.
# ---------------------------------------------------------------------------
def _upload_form():
    return SimpleNamespace(
        page_url="https://example.test/complaint",
        action="/file-upload",
        method="POST",
        inputs=[SimpleNamespace(name="file", input_type="file")],
    )


def _typecheck_client(*, html_status, oversize_status, benign_status=204):
    """FakeClient whose response depends on the uploaded file's type/size."""
    class FakeClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return None

        async def request(self, **kwargs):
            _field, (filename, content, ctype) = next(iter(kwargs["files"].items()))
            url = kwargs["url"]
            if len(content) > 256 * 1024:
                return httpx.Response(oversize_status, text="File too large", request=httpx.Request("POST", url))
            if ctype == "text/html" or filename.endswith(".html"):
                return httpx.Response(html_status, text="", request=httpx.Request("POST", url))
            return httpx.Response(benign_status, text="", request=httpx.Request("POST", url))

        async def get(self, url):
            return httpx.Response(404, text="missing", request=httpx.Request("GET", url))

    return FakeClient


@pytest.mark.asyncio
async def test_upload_type_allowlist_bypass_flagged_when_size_checked_but_type_not(monkeypatch):
    detector = FileUploadDetector()
    # Accepts html (204) same as benign, but rejects oversize (500) → validates
    # size, not type → missing type validation.
    client = _typecheck_client(html_status=204, oversize_status=500)
    monkeypatch.setattr("app.core.detectors.file_upload.create_scan_client", lambda **kw: client())
    findings = await detector.detect(urls=[], forms=[_upload_form()])
    hits = [f for f in findings if f.detection_method == "upload_type_allowlist_bypass_differential"]
    assert hits, [f.vuln_type for f in findings]
    assert hits[0].severity.value.lower() in ("medium", "medium".upper())


@pytest.mark.asyncio
async def test_upload_type_validation_not_flagged_when_dangerous_type_rejected(monkeypatch):
    detector = FileUploadDetector()
    # Rejects html (415) → has a type allowlist → NOT vulnerable.
    client = _typecheck_client(html_status=415, oversize_status=500)
    monkeypatch.setattr("app.core.detectors.file_upload.create_scan_client", lambda **kw: client())
    findings = await detector.detect(urls=[], forms=[_upload_form()])
    assert not any(f.detection_method == "upload_type_allowlist_bypass_differential" for f in findings)


@pytest.mark.asyncio
async def test_upload_type_validation_not_flagged_when_endpoint_accepts_everything(monkeypatch):
    detector = FileUploadDetector()
    # Accepts EVERYTHING incl. oversize (200) → indistinguishable from a stub that
    # never validates; zero-FP gate requires a real reject signal → NO finding.
    client = _typecheck_client(html_status=200, oversize_status=200, benign_status=200)
    monkeypatch.setattr("app.core.detectors.file_upload.create_scan_client", lambda **kw: client())
    findings = await detector.detect(urls=[], forms=[_upload_form()])
    assert not any(f.detection_method == "upload_type_allowlist_bypass_differential" for f in findings)


@pytest.mark.asyncio
async def test_file_upload_skips_get_candidate_no_type_validation_fp(monkeypatch):
    """A GET endpoint is never a file-upload sink. A GET data endpoint ignores the
    multipart body (identical 2xx for any file type) and its framework rejects an
    oversized body with a generic 413 — which would otherwise trip the accept/reject
    differential (Test 8) and manufacture a 'Missing File Type Validation' FP.
    The detector must drop the GET candidate before testing it."""
    detector = FileUploadDetector()
    get_form = SimpleNamespace(
        page_url="http://localhost:3000/rest/memories/",
        action="http://localhost:3000/rest/memories/",
        method="GET",
        inputs=[SimpleNamespace(name="image", input_type="file")],
    )
    requests_sent: list[dict] = []

    class FakeClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return None

        async def request(self, **kwargs):
            requests_sent.append(kwargs)
            # Body-ignoring data endpoint: small files -> 200 identical; oversized
            # body -> generic 413. This is exactly what tripped the old FP.
            content = kwargs["files"]["image"][1]
            status = 413 if len(content) > 100_000 else 200
            return httpx.Response(
                status,
                text="{}" if status == 200 else "Payload Too Large",
                request=httpx.Request(kwargs["method"], kwargs["url"]),
            )

    monkeypatch.setattr("app.core.detectors.file_upload.create_scan_client", lambda **kwargs: FakeClient())

    findings = await detector.detect(urls=[], forms=[get_form])

    assert requests_sent == []  # candidate dropped: no request ever sent
    assert not any(f.vuln_type == "Missing File Type Validation" for f in findings)


@pytest.mark.asyncio
async def test_file_upload_flags_type_validation_on_post_sink(monkeypatch):
    """Guard against over-correction: a real POST upload sink that accepts any type
    (identical status) but rejects oversized bodies must STILL be flagged."""
    detector = FileUploadDetector()
    post_form = SimpleNamespace(
        page_url="http://localhost:3000/file-upload",
        action="http://localhost:3000/file-upload",
        method="POST",
        inputs=[SimpleNamespace(name="file", input_type="file")],
    )

    class FakeClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return None

        async def get(self, url):
            return httpx.Response(404, text="missing", request=httpx.Request("GET", url))

        async def request(self, **kwargs):
            content = kwargs["files"]["file"][1]
            status = 413 if len(content) > 100_000 else 204
            return httpx.Response(
                status,
                text="" if status == 204 else "Payload Too Large",
                request=httpx.Request(kwargs["method"], kwargs["url"]),
            )

    monkeypatch.setattr("app.core.detectors.file_upload.create_scan_client", lambda **kwargs: FakeClient())

    findings = await detector.detect(urls=[], forms=[post_form])

    assert any(f.vuln_type == "Missing File Type Validation" for f in findings)
