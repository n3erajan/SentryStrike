import asyncio
import json
import pytest
from unittest.mock import AsyncMock, patch
from urllib.parse import parse_qsl, urlparse

from app.core.crawler.models import ApiEndpoint, RequestObservation
from app.core.detectors.access_control import AccessControlDetector
from app.core.detectors.auth_detector import AuthenticationFailuresDetector
from app.core.detectors.crypto_failures import CryptoFailuresDetector
from app.core.detectors.file_inclusion import FileInclusionDetector
from app.core.detectors.security_headers import SecurityHeadersDetector
from app.core.detectors.sql_injection import SQLInjectionDetector
from app.core.detectors.xss_detector import XSSDetector
from app.core.verification.response_analyzer import ResponseData
from app.core.verification.verification_framework import HttpVerifier
from app.core.payload_profile import build_payload_profile
from app.models.vulnerability import OwaspCategory, SeverityLevel, TechnologyComponent


class DummyInput:
    def __init__(self, name: str, input_type: str = "text", value: str = "") -> None:
        self.name = name
        self.input_type = input_type
        self.value = value


class DummyForm:
    def __init__(self, action: str, method: str, inputs: list[DummyInput]) -> None:
        self.action = action
        self.method = method
        self.inputs = inputs


@pytest.fixture(autouse=True)
def mock_http_verifier():
    """Dynamically mock HttpVerifier.send_request to simulate vulnerable endpoints."""
    async def dynamic_send_request(self, url, method="GET", params=None, data=None, **kwargs):
        # Extract payload to reflect it
        payload_val = ""
        if params:
            payload_val = str(next(iter(params.values()))) if params else ""
        elif data:
            payload_val = str(next(iter(data.values()))) if data else ""
        else:
            query_values = parse_qsl(urlparse(url).query, keep_blank_values=True)
            payload_val = str(query_values[0][1]) if query_values else ""

        if kwargs.get("test_phase") in ("idor_unauth_base", "idor_unauth_own", "idor_unauth_mod"):
            return ResponseData(
                status_code=401,
                headers={"Content-Type": "text/plain"},
                body="Unauthorized",
                response_time_ms=5.0,
                request_snippet=f"{method} {url} HTTP/1.1",
                response_snippet="HTTP/1.1 401 Unauthorized\n\nUnauthorized"
            )

        if kwargs.get("test_phase") == "idor_authed_own":
            body = "Account portal for Alice Smith. Balance 100. Internal account id 1."
            return ResponseData(
                status_code=200,
                headers={"Content-Type": "text/html", "Server": "Apache/2.4.0"},
                body=body,
                response_time_ms=5.0,
                request_snippet=f"{method} {url} HTTP/1.1",
                response_snippet="HTTP/1.1 200 OK\nServer: Apache/2.4.0\n\n" + body
            )

        if kwargs.get("test_phase") == "idor_authed_mod":
            body = "Account portal for Bob Jones. Balance 900. Internal account id 2."
            return ResponseData(
                status_code=200,
                headers={"Content-Type": "text/html", "Server": "Apache/2.4.0"},
                body=body,
                response_time_ms=5.0,
                request_snippet=f"{method} {url} HTTP/1.1",
                response_snippet="HTTP/1.1 200 OK\nServer: Apache/2.4.0\n\n" + body
            )

        # Construct body with reflection and error patterns
        body = f"Mock Page Content. Reflection: {payload_val}. "
        # Include SQL error syntax if a quote is injected
        if "'" in payload_val or "extractvalue" in payload_val:
            body += "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version"
        
        return ResponseData(
            status_code=200,
            headers={"Content-Type": "text/html", "Server": "Apache/2.4.0"},
            body=body,
            response_time_ms=5.0,
            request_snippet=f"{method} {url} HTTP/1.1",
            response_snippet="HTTP/1.1 200 OK\nServer: Apache/2.4.0\n\n" + body
        )

    with patch.object(HttpVerifier, "send_request", dynamic_send_request):
        yield


@pytest.mark.asyncio
async def test_access_control_detector_flags_admin_and_idor() -> None:
    detector = AccessControlDetector()
    urls = ["https://example.com/admin", "https://example.com/account?id=1"]
    forms = [DummyForm("https://example.com/update", "POST", [DummyInput("user_id")])]
    
    findings = await detector.detect(urls=urls, forms=forms)
    assert any("Forced Browsing" in f.vuln_type for f in findings)
    assert any("IDOR" in f.vuln_type or "Insecure Direct Object Reference" in f.vuln_type for f in findings)


@pytest.mark.asyncio
async def test_access_control_tests_json_body_idor_targets() -> None:
    detector = AccessControlDetector()
    endpoint = ApiEndpoint(
        url="https://example.com/api/profile",
        method="POST",
        request_body={"userId": 1, "include": "summary"},
        headers={"Content-Type": "application/json"},
    )
    calls: list[tuple[str, object]] = []

    async def send_request(self, url, method="GET", params=None, data=None, **kwargs):
        calls.append((kwargs.get("test_phase", ""), kwargs.get("json_body")))
        body = kwargs.get("json_body") or {}
        user_id = str(body.get("userId", ""))
        if kwargs.get("test_phase") in {"idor_unauth_own", "idor_unauth_mod"}:
            return ResponseData(401, {"content-type": "application/json"}, '{"error":"unauthorized"}', 1.0)
        if kwargs.get("test_phase") == "idor_authed_own":
            return ResponseData(
                200,
                {"content-type": "application/json"},
                json.dumps({"userId": user_id, "email": "alice@example.com", "balance": 100}),
                1.0,
                request_snippet=f"{method} {url}",
                response_snippet="HTTP/1.1 200 OK",
            )
        if kwargs.get("test_phase") == "idor_authed_mod":
            return ResponseData(
                200,
                {"content-type": "application/json"},
                json.dumps({"userId": user_id, "email": "bob@example.com", "balance": 900}),
                1.0,
                request_snippet=f"{method} {url}",
                response_snippet="HTTP/1.1 200 OK",
            )
        return ResponseData(403, {"content-type": "application/json"}, '{"error":"forbidden"}', 1.0)

    with patch.object(HttpVerifier, "send_request", send_request):
        findings = await detector.detect(
            urls=[],
            forms=[],
            api_endpoints=[endpoint],
            session_cookies={"sid": "low"},
        )

    assert any(f.vuln_type == "Insecure Direct Object Reference (IDOR)" for f in findings)
    assert any(phase == "idor_authed_mod" and body == {"userId": "2", "include": "summary"} for phase, body in calls)


@pytest.mark.asyncio
async def test_access_control_tests_path_template_idor_targets() -> None:
    detector = AccessControlDetector()
    endpoint = ApiEndpoint(url="https://example.com/api/users/{userId}", method="GET")
    requested_urls: list[tuple[str, str]] = []

    async def send_request(self, url, method="GET", params=None, data=None, **kwargs):
        phase = kwargs.get("test_phase", "")
        requested_urls.append((phase, url))
        if phase in {"idor_unauth_own", "idor_unauth_mod"}:
            return ResponseData(401, {"content-type": "application/json"}, '{"error":"unauthorized"}', 1.0)
        if phase == "idor_authed_own":
            return ResponseData(200, {"content-type": "application/json"}, '{"userId":1,"email":"alice@example.com"}', 1.0)
        if phase == "idor_authed_mod":
            return ResponseData(200, {"content-type": "application/json"}, '{"userId":2,"email":"bob@example.com"}', 1.0)
        return ResponseData(403, {"content-type": "application/json"}, '{"error":"forbidden"}', 1.0)

    with patch.object(HttpVerifier, "send_request", send_request):
        findings = await detector.detect(
            urls=[],
            forms=[],
            api_endpoints=[endpoint],
            session_cookies={"sid": "low"},
        )

    assert any(f.vuln_type == "Insecure Direct Object Reference (IDOR)" for f in findings)
    assert ("idor_authed_mod", "https://example.com/api/users/2") in requested_urls


@pytest.mark.asyncio
async def test_access_control_matrix_flags_sensitive_unauthenticated_api_exposure() -> None:
    detector = AccessControlDetector()
    request = RequestObservation(
        url="https://example.com/api/profile",
        method="GET",
        request_headers={"authorization": "Bearer browser-token"},
    )
    seen_headers: list[dict | None] = []

    async def send_request(self, url, method="GET", params=None, data=None, **kwargs):
        seen_headers.append(kwargs.get("headers"))
        phase = kwargs.get("test_phase", "")
        if phase == "auth_matrix_unauth":
            return ResponseData(
                200,
                {"content-type": "application/json"},
                '{"userId":1,"email":"alice@example.com","role":"user"}',
                1.0,
                request_snippet=f"{method} {url}",
                response_snippet="HTTP/1.1 200 OK",
            )
        if phase == "auth_matrix_low":
            return ResponseData(
                200,
                {"content-type": "application/json"},
                '{"userId":1,"email":"alice@example.com","role":"user"}',
                1.0,
            )
        return ResponseData(404, {"content-type": "application/json"}, '{"error":"not found"}', 1.0)

    with patch.object(HttpVerifier, "send_request", send_request):
        findings = await detector.detect(
            urls=[],
            forms=[],
            requests=[request],
            auth_headers={"Authorization": "Bearer low-user"},
        )

    assert any(f.vuln_type == "Unauthenticated API Data Exposure" for f in findings)
    assert all(not headers or "authorization" not in {key.lower() for key in headers} for headers in seen_headers)


@pytest.mark.asyncio
async def test_access_control_matrix_does_not_flag_public_catalog_ids_without_sensitive_fields() -> None:
    detector = AccessControlDetector()
    request = RequestObservation(url="https://example.com/api/products", method="GET")

    async def send_request(self, url, method="GET", params=None, data=None, **kwargs):
        return ResponseData(
            200,
            {"content-type": "application/json"},
            '[{"id":1,"name":"apple"},{"id":2,"name":"banana"}]',
            1.0,
        )

    with patch.object(HttpVerifier, "send_request", send_request):
        findings = await detector.detect(urls=[], forms=[], requests=[request])

    assert not any(f.vuln_type == "Unauthenticated API Data Exposure" for f in findings)


@pytest.mark.asyncio
async def test_crypto_detector_flags_http() -> None:
    detector = CryptoFailuresDetector()
    urls = ["http://example.com/login"]
    findings = await detector.detect(urls=urls, forms=[])
    assert any(f.vuln_type == "Insecure Transport" for f in findings)


@pytest.mark.asyncio
async def test_security_headers_detector_reports_once_for_site() -> None:
    detector = SecurityHeadersDetector()
    urls = ["http://example.com/page1", "http://example.com/page2"]

    class DummyResponse:
        headers = {
            "server": "Apache/2.4.0",
        }

    class DummyClient:
        def __init__(self, *args, **kwargs) -> None:
            pass

        async def __aenter__(self) -> "DummyClient":
            return self

        async def __aexit__(self, exc_type, exc, tb) -> None:
            return None

        async def get(self, url: str) -> DummyResponse:
            return DummyResponse()

    import app.core.detectors.security_headers as security_headers_module

    def dummy_scan_client(**kwargs) -> DummyClient:
        return DummyClient()

    original_factory = security_headers_module.create_scan_client
    security_headers_module.create_scan_client = dummy_scan_client  # type: ignore[assignment]
    try:
        findings = await detector.detect(urls=urls, forms=[], root_url="http://example.com/")
    finally:
        security_headers_module.create_scan_client = original_factory  # type: ignore[assignment]

    header_findings = [finding for finding in findings if finding.vuln_type == "Missing Security Header"]
    assert len(header_findings) >= 4


@pytest.mark.asyncio
async def test_sql_detector_flags_query_params() -> None:
    detector = SQLInjectionDetector()
    urls = ["https://example.com/search?q=test", "https://example.com/item?id=1"]
    forms = [DummyForm("https://example.com/login", "POST", [DummyInput("username"), DummyInput("password")])]
    
    findings = await detector.detect(urls=urls, forms=forms)
    assert any("SQL Injection" in f.vuln_type for f in findings)


@pytest.mark.asyncio
async def test_xss_detector_flags_forms_and_query_params() -> None:
    detector = XSSDetector()
    urls = ["https://example.com/search?query=test"]
    forms = [DummyForm("https://example.com/comment", "POST", [DummyInput("comment"), DummyInput("title")])]

    with patch("app.core.verification.xss_verifier.PLAYWRIGHT_AVAILABLE", False):
        findings = await detector.detect(urls=urls, forms=forms)
    assert any("XSS" in f.vuln_type or "Cross-Site Scripting" in f.vuln_type for f in findings)


@pytest.mark.asyncio
async def test_auth_detector_flags_login_and_reset_forms() -> None:
    # Set scan mode to aggressive/heuristic to include observational findings,
    # or rely on active findings.
    from app.config import get_settings
    settings = get_settings()
    original_mode = settings.scan_mode
    settings.scan_mode = "heuristic"
    
    try:
        detector = AuthenticationFailuresDetector()
        urls = ["https://example.com/reset-password"]
        forms = [DummyForm("https://example.com/login", "POST", [DummyInput("username"), DummyInput("password")])]
        
        findings = await detector.detect(urls=urls, forms=forms)
        assert any("Brute-Force" in f.vuln_type or "Brute Force" in f.vuln_type for f in findings)
        assert any("CSRF" in f.vuln_type for f in findings)
    finally:
        settings.scan_mode = original_mode


def test_file_inclusion_classifies_direct_traversal_as_a01() -> None:
    category, vuln_type, method = FileInclusionDetector._file_read_finding_type("../../../../etc/passwd")

    assert category == OwaspCategory.a01
    assert vuln_type == "Path Traversal / Arbitrary File Read"
    assert method == "path_traversal_file_read"


def test_file_inclusion_keeps_wrappers_as_lfi() -> None:
    category, vuln_type, method = FileInclusionDetector._file_read_finding_type(
        "php://filter/convert.base64-encode/resource=index.php"
    )

    assert category == OwaspCategory.a05
    assert vuln_type == "Local File Inclusion (LFI)"
    assert method == "file_retrieval"


def test_file_inclusion_payloads_are_tuned_for_windows_iis() -> None:
    profile = build_payload_profile([
        TechnologyComponent(name="Microsoft-IIS", version="10.0", category="server"),
        TechnologyComponent(name="ASP.NET", version=None, category="framework"),
    ])

    payloads = FileInclusionDetector._select_lfi_payloads(profile)
    payload_values = [payload for payload, _, _ in payloads]

    assert any("windows" in payload.lower() for payload in payload_values)
    assert not any("/etc/passwd" in payload.lower() for payload in payload_values)
    assert not any(payload.lower().startswith("php://") for payload in payload_values)


def test_file_inclusion_payloads_keep_php_wrappers_for_php_stack() -> None:
    profile = build_payload_profile([
        TechnologyComponent(name="PHP", version="8.2", category="framework"),
        TechnologyComponent(name="Apache", version="2.4", category="server"),
    ])

    payloads = FileInclusionDetector._select_lfi_payloads(profile)
    payload_values = [payload for payload, _, _ in payloads]

    assert any("/etc/passwd" in payload.lower() for payload in payload_values)
    assert any(payload.lower().startswith("php://") for payload in payload_values)
