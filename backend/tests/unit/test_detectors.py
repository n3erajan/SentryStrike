import asyncio
import pytest
from unittest.mock import AsyncMock, patch

from app.core.detectors.access_control import AccessControlDetector
from app.core.detectors.auth_detector import AuthenticationFailuresDetector
from app.core.detectors.crypto_failures import CryptoFailuresDetector
from app.core.detectors.file_inclusion import FileInclusionDetector
from app.core.detectors.security_headers import SecurityHeadersDetector
from app.core.detectors.sql_injection import SQLInjectionDetector
from app.core.detectors.xss_detector import XSSDetector
from app.core.verification.response_analyzer import ResponseData
from app.core.verification.verification_framework import HttpVerifier
from app.models.vulnerability import OwaspCategory, SeverityLevel


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

        if kwargs.get("test_phase") in ("idor_unauth_base", "idor_unauth_mod"):
            return ResponseData(
                status_code=401,
                headers={"Content-Type": "text/plain"},
                body="Unauthorized",
                response_time_ms=5.0,
                request_snippet=f"{method} {url} HTTP/1.1",
                response_snippet="HTTP/1.1 401 Unauthorized\n\nUnauthorized"
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
