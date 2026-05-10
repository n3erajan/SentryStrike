import pytest

from app.core.detectors.access_control import AccessControlDetector
from app.core.detectors.auth_detector import AuthenticationFailuresDetector
from app.core.detectors.crypto_failures import CryptoFailuresDetector
from app.core.detectors.security_headers import SecurityHeadersDetector
from app.core.detectors.sql_injection import SQLInjectionDetector
from app.core.detectors.xss_detector import XSSDetector


class DummyInput:
    def __init__(self, name: str, input_type: str = "text") -> None:
        self.name = name
        self.input_type = input_type


class DummyForm:
    def __init__(self, action: str, method: str, inputs: list[DummyInput]) -> None:
        self.action = action
        self.method = method
        self.inputs = inputs


@pytest.mark.asyncio
async def test_access_control_detector_flags_admin_and_idor() -> None:
    detector = AccessControlDetector()
    urls = ["https://example.com/admin", "https://example.com/account?id=1"]
    findings = await detector.detect(urls=urls, forms=[DummyForm("https://example.com/update", "POST", [DummyInput("user_id")])])
    assert any(f.vuln_type == "Potential Forced Browsing" for f in findings)
    assert any(f.vuln_type == "Potential IDOR" for f in findings)


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

    original_client = security_headers_module.httpx.AsyncClient
    security_headers_module.httpx.AsyncClient = DummyClient  # type: ignore[assignment]
    try:
        findings = await detector.detect(urls=urls, forms=[], root_url="http://example.com/")
    finally:
        security_headers_module.httpx.AsyncClient = original_client  # type: ignore[assignment]

    header_findings = [finding for finding in findings if finding.vuln_type == "Missing Security Header"]
    assert len(header_findings) == 4


@pytest.mark.asyncio
async def test_sql_detector_flags_query_params() -> None:
    detector = SQLInjectionDetector()
    urls = ["https://example.com/search?q=test", "https://example.com/item?id=1' OR 1=1--"]
    forms = [DummyForm("https://example.com/login", "POST", [DummyInput("username"), DummyInput("password")])]
    findings = await detector.detect(urls=urls, forms=forms)
    assert sum(1 for finding in findings if finding.vuln_type == "Potential SQL Injection") >= 2


@pytest.mark.asyncio
async def test_xss_detector_flags_forms_and_query_params() -> None:
    detector = XSSDetector()
    urls = ["https://example.com/search?query=<script>alert(1)</script>"]
    forms = [DummyForm("https://example.com/comment", "POST", [DummyInput("comment"), DummyInput("title")])]
    findings = await detector.detect(urls=urls, forms=forms)
    assert any("XSS" in f.vuln_type for f in findings)


@pytest.mark.asyncio
async def test_auth_detector_flags_login_and_reset_forms() -> None:
    detector = AuthenticationFailuresDetector()
    urls = ["https://example.com/reset-password"]
    forms = [DummyForm("https://example.com/login", "POST", [DummyInput("username"), DummyInput("password"), DummyInput("otp")])]
    findings = await detector.detect(urls=urls, forms=forms)
    assert any(f.vuln_type == "Login Endpoint Requires Brute Force Protection Verification" for f in findings)
    assert any(f.vuln_type == "Multi-Factor Authentication Flow Detected" for f in findings)
    assert any(f.vuln_type == "Weak Password Reset Flow" for f in findings)
