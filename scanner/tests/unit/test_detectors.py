import asyncio
import json
import pytest
from unittest.mock import AsyncMock, patch
from urllib.parse import parse_qsl, urlparse

from app.core.crawler.models import ApiEndpoint, ParameterCandidate, ParameterLocation, RequestObservation
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
from shared.models.vulnerability import OwaspCategory, SeverityLevel, TechnologyComponent


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
    # A genuine unauthenticated exposure: the anonymous response carries secret
    # material (a token). Such data must never be world-readable regardless of
    # whether authenticated identities receive the same body, so the
    # public-endpoint suppression does NOT apply — the secret path fires.
    detector = AccessControlDetector()
    request = RequestObservation(
        url="https://example.com/api/profile",
        method="GET",
        request_headers={"authorization": "Bearer browser-token"},
    )
    seen_headers: list[dict | None] = []
    secret_body = (
        '{"userId":1,"email":"alice@example.com","role":"user",'
        '"apiToken":"sk_live_9f8e7d6c5b4a3210"}'
    )

    async def send_request(self, url, method="GET", params=None, data=None, **kwargs):
        seen_headers.append(kwargs.get("headers"))
        phase = kwargs.get("test_phase", "")
        if phase == "auth_matrix_unauth":
            return ResponseData(
                200,
                {"content-type": "application/json"},
                secret_body,
                1.0,
                request_snippet=f"{method} {url}",
                response_snippet="HTTP/1.1 200 OK",
            )
        if phase == "auth_matrix_low":
            return ResponseData(
                200,
                {"content-type": "application/json"},
                secret_body,
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
async def test_access_control_matrix_does_not_flag_public_endpoint_identical_across_auth_states() -> None:
    # Regression guard for the dominant real-world false positive: a public
    # endpoint (e.g. an app-configuration route) that returns a byte-identical
    # response to anonymous, low-privilege and second-user requests. Identity
    # does not change the result, so there is no authorization boundary being
    # bypassed — even though the body contains a field name that trips the broad
    # "sensitive" heuristic (``privacyContactEmail``). It must NOT be flagged.
    detector = AccessControlDetector()
    request = RequestObservation(
        url="https://example.com/rest/admin/application-configuration",
        method="GET",
    )
    public_config = (
        '{"config":{"application":{"name":"Shop",'
        '"privacyContactEmail":"donotreply@shop.example","altcoinName":"Coin"}}}'
    )

    async def send_request(self, url, method="GET", params=None, data=None, **kwargs):
        # Same public body regardless of which auth state (unauth/low/second) asks.
        return ResponseData(200, {"content-type": "application/json"}, public_config, 1.0)

    with patch.object(HttpVerifier, "send_request", send_request):
        findings = await detector.detect(
            urls=[],
            forms=[],
            requests=[request],
            auth_headers={"Authorization": "Bearer low-user"},
            second_user_headers={"Authorization": "Bearer second-user"},
        )

    assert not any(f.vuln_type == "Unauthenticated API Data Exposure" for f in findings)


@pytest.mark.asyncio
async def test_access_control_reports_mass_assignment_privilege_field() -> None:
    detector = AccessControlDetector()
    request = RequestObservation(
        url="https://example.com/api/users",
        method="POST",
        request_headers={"content-type": "application/json"},
        post_data='{"email":"alice@example.com","password":"pw12345"}',
        request_content_type="application/json",
        replayable=True,
    )
    seen_bodies: list[object] = []

    async def send_request(self, url, method="GET", params=None, data=None, **kwargs):
        body = kwargs.get("json_body")
        phase = kwargs.get("test_phase", "")
        seen_bodies.append(body)
        if phase == "mass_assignment_baseline":
            return ResponseData(
                201,
                {"content-type": "application/json"},
                '{"id":1,"email":"alice@example.com"}',
                1.0,
                request_snippet=f"{method} {url}",
                response_snippet="HTTP/1.1 201 Created",
            )
        if phase == "mass_assignment_probe" and isinstance(body, dict) and body.get("role") == "admin":
            return ResponseData(
                201,
                {"content-type": "application/json"},
                '{"id":1,"email":"alice@example.com","role":"admin"}',
                1.0,
                request_snippet=f"{method} {url}",
                response_snippet="HTTP/1.1 201 Created\n\n{\"role\":\"admin\"}",
            )
        return ResponseData(400, {"content-type": "application/json"}, '{"error":"bad request"}', 1.0)

    with patch.object(HttpVerifier, "send_request", send_request):
        findings = await detector.detect(
            urls=[],
            forms=[],
            requests=[request],
            auth_headers={"Authorization": "Bearer low-user"},
        )

    assert any(body and body.get("role") == "admin" for body in seen_bodies if isinstance(body, dict))
    assert any(f.vuln_type == "Mass Assignment / Privilege Field Injection" for f in findings)


@pytest.mark.asyncio
async def test_mass_assignment_survives_unique_create_collision() -> None:
    """A replayed registration whose captured email is already taken must still
    be detected: the detector freshens the unique identity field so the create
    succeeds instead of aborting on the duplicate-email 400."""
    detector = AccessControlDetector()
    original_email = "taken@example.com"
    request = RequestObservation(
        url="https://example.com/api/Users",
        method="POST",
        request_headers={"content-type": "application/json"},
        post_data='{"email":"' + original_email + '","password":"pw12345","passwordRepeat":"pw12345"}',
        request_content_type="application/json",
        replayable=True,
    )
    seen_emails: list[object] = []

    async def send_request(self, url, method="GET", params=None, data=None, **kwargs):
        body = kwargs.get("json_body")
        phase = kwargs.get("test_phase", "")
        email = body.get("email") if isinstance(body, dict) else None
        seen_emails.append(email)
        # The app enforces email uniqueness: any replay of the captured email
        # (already registered) is rejected, exactly like Juice Shop.
        if email == original_email:
            return ResponseData(
                400,
                {"content-type": "application/json"},
                '{"message":"Validation error","errors":[{"field":"email","message":"email must be unique"}]}',
                1.0,
            )
        if phase == "mass_assignment_baseline":
            return ResponseData(
                201, {"content-type": "application/json"},
                '{"id":9,"email":"' + str(email) + '","role":"customer"}', 1.0,
                request_snippet=f"{method} {url}", response_snippet="HTTP/1.1 201 Created",
            )
        if phase == "mass_assignment_probe" and isinstance(body, dict) and body.get("role") == "admin":
            return ResponseData(
                201, {"content-type": "application/json"},
                '{"id":9,"email":"' + str(email) + '","role":"admin"}', 1.0,
                request_snippet=f"{method} {url}",
                response_snippet="HTTP/1.1 201 Created\n\n{\"role\":\"admin\"}",
            )
        return ResponseData(400, {"content-type": "application/json"}, '{"error":"bad request"}', 1.0)

    with patch.object(HttpVerifier, "send_request", send_request):
        findings = await detector.detect(
            urls=[], forms=[], requests=[request],
            auth_headers={"Authorization": "Bearer low-user"},
        )

    # Mass-assignment replays used freshened unique identities (not the taken
    # email), so the create succeeded and the probe ran — proving the finding is
    # produced only because the duplicate-email collision was avoided. (Other
    # access-control checks share the patched sender and may replay the observed
    # body verbatim; the freshened create is what unlocks this finding.)
    assert any(isinstance(e, str) and e.startswith("ss_ma_") for e in seen_emails)
    assert any(f.vuln_type == "Mass Assignment / Privilege Field Injection" for f in findings)


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


def test_evaluate_cors_classifies_permissive_policies() -> None:
    detector = SecurityHeadersDetector()
    probe = detector._CORS_PROBE_ORIGIN
    probe_lower = probe.lower()

    # Reflected arbitrary origin + credentials -> high (fully exploitable).
    assert detector._evaluate_cors(
        {"access-control-allow-origin": probe_lower, "access-control-allow-credentials": "true"}, probe
    )[0] == "high"
    # Reflected arbitrary origin, no credentials -> medium.
    assert detector._evaluate_cors(
        {"access-control-allow-origin": probe_lower}, probe
    )[0] == "medium"
    # Wildcard + credentials -> medium.
    assert detector._evaluate_cors(
        {"access-control-allow-origin": "*", "access-control-allow-credentials": "true"}, probe
    )[0] == "medium"
    # Wildcard alone -> low (the Juice Shop shape).
    assert detector._evaluate_cors({"access-control-allow-origin": "*"}, probe)[0] == "low"
    # null origin -> medium.
    assert detector._evaluate_cors({"access-control-allow-origin": "null"}, probe)[0] == "medium"

    # Correctly-scoped policies are NOT flagged (zero-FP).
    assert detector._evaluate_cors({}, probe) is None  # no ACAO header
    assert detector._evaluate_cors(
        {"access-control-allow-origin": "https://app.example.com"}, probe
    ) is None  # echoes a specific allowed origin, not the arbitrary probe


@pytest.mark.asyncio
async def test_security_headers_detector_reports_cors_wildcard() -> None:
    detector = SecurityHeadersDetector()

    class DummyResponse:
        def __init__(self, headers: dict) -> None:
            self.headers = headers

    class DummyClient:
        def __init__(self, *args, **kwargs) -> None:
            pass

        async def __aenter__(self) -> "DummyClient":
            return self

        async def __aexit__(self, exc_type, exc, tb) -> None:
            return None

        async def get(self, url: str, headers: dict | None = None) -> DummyResponse:
            # The CORS probe carries an Origin header; the target answers with a
            # static wildcard ACAO regardless of the request origin.
            return DummyResponse({"access-control-allow-origin": "*"})

    import app.core.detectors.security_headers as security_headers_module

    original_factory = security_headers_module.create_scan_client
    security_headers_module.create_scan_client = lambda **kwargs: DummyClient()  # type: ignore[assignment]
    try:
        findings = await detector.detect(urls=["http://example.com/"], forms=[], root_url="http://example.com/")
    finally:
        security_headers_module.create_scan_client = original_factory  # type: ignore[assignment]

    cors = [f for f in findings if f.vuln_type == "CORS Misconfiguration"]
    assert len(cors) == 1
    assert cors[0].severity == SeverityLevel.low
    assert cors[0].verified is True
    assert cors[0].category == OwaspCategory.a02


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


# --- Poison-null-byte extension-filter bypass (directory-served files) --------

def test_looks_like_directory_listing() -> None:
    assert FileInclusionDetector._looks_like_directory_listing(
        "<html><head><title>listing directory /ftp</title></head><body>...</body></html>"
    )
    assert FileInclusionDetector._looks_like_directory_listing(
        '<a href="../">..</a><a href="a.md">a</a><a href="b.bak">b</a>'
        '<a href="c.pyc">c</a><a href="d.yml">d</a><a href="e.gg">e</a>'
    )
    # A normal application page is not a directory listing.
    assert not FileInclusionDetector._looks_like_directory_listing(
        "<html><body><h1>Welcome</h1><a href='/login'>Login</a></body></html>"
    )


class _FakeResp:
    def __init__(self, status_code: int, body: str) -> None:
        self.status_code = status_code
        self.body = body
        self.request_snippet = "GET"
        self.response_snippet = body[:120]


class _FakeVerifier:
    """Serves canned (status, body) by exact URL; everything else is 404."""

    def __init__(self, routes: dict[str, tuple[int, str]]) -> None:
        self._routes = routes

    def set_request_context(self, **_kw) -> None:
        pass

    async def send_request(self, url, method, params, data, test_phase=None, payload=None, **_kw):
        status, body = self._routes.get(url, (404, "Cannot GET"))
        return _FakeResp(status, body)

    async def close(self) -> None:
        pass


_FTP_LISTING = (
    "<html><head><title>listing directory /ftp</title></head><body>"
    '<a href="../">..</a>'
    '<a href="legal.md">legal.md</a>'
    '<a href="package.json.bak">package.json.bak</a>'
    "</body></html>"
)


@pytest.mark.asyncio
async def test_null_byte_bypass_detects_forbidden_file_read() -> None:
    """A file forbidden directly (403) but readable via ``%2500.<allowed-ext>``
    is reported as a poison-null-byte arbitrary file read."""
    routes = {
        "http://h/ftp/": (200, _FTP_LISTING),
        "http://h/ftp/legal.md": (200, "# Legal document, readable and allowed."),
        "http://h/ftp/package.json.bak": (403, "Error: Only .md and .pdf files are allowed!"),
        "http://h/ftp/package.json.bak%2500.md": (200, '{"name":"app","secret":"leaked-backup"}'),
        # control (non-existent sibling) is not in routes -> defaults to 404.
    }
    det = FileInclusionDetector()
    findings = await det._detect_null_byte_filter_bypass(
        ["http://h/ftp/legal.md"], _FakeVerifier(routes), asyncio.Semaphore(4), ""
    )
    assert len(findings) == 1
    f = findings[0]
    assert f.url == "http://h/ftp/package.json.bak"
    assert f.detection_method == "poison_null_byte_extension_bypass"
    assert f.payload == "http://h/ftp/package.json.bak%2500.md"
    assert f.verified is True
    assert f.category == OwaspCategory.a05


@pytest.mark.asyncio
async def test_null_byte_bypass_ignores_catch_all_soft_200() -> None:
    """When a non-existent-file control returns the SAME 200 body as the injected
    request, the 200 is a catch-all/SPA shell, not a real read -> no finding."""
    shell = "<html><body><app-root></app-root></body></html>"
    routes = {
        "http://h/ftp/": (200, _FTP_LISTING),
        "http://h/ftp/legal.md": (200, "# Legal document."),
        "http://h/ftp/package.json.bak": (403, "Error: Only .md and .pdf files are allowed!"),
        # Both the injected AND the control return the identical shell.
        "http://h/ftp/package.json.bak%2500.md": (200, shell),
        "http://h/ftp/sentry_nx_probe_md%2500.md": (200, shell),
    }
    det = FileInclusionDetector()
    findings = await det._detect_null_byte_filter_bypass(
        ["http://h/ftp/legal.md"], _FakeVerifier(routes), asyncio.Semaphore(4), ""
    )
    assert findings == []


@pytest.mark.asyncio
async def test_ssrf_detector_verifies_blind_via_oast_client():
    from app.core.detectors.ssrf_detector import SSRFDetector
    from shared.verification.oast import OastClient, OastInteraction

    # A fake OAST client: enabled, returns an interaction only on the 3rd poll
    # (simulates a fire-and-forget callback landing after a short delay).
    class FakeOast(OastClient):
        def __init__(self):
            super().__init__("https://scanner.test/oast", "https://scanner.test/oast/poll")
            self._polls = 0

        async def poll(self, interaction_id):
            self._polls += 1
            if self._polls >= 3:
                return [OastInteraction(interaction_id=interaction_id, raw="hit")]
            return []

    detector = SSRFDetector()

    async def send_request(self, url, method="GET", params=None, data=None, **kwargs):
        # Blind sink: constant 302, no reflection, regardless of payload.
        return ResponseData(
            302, {"content-type": "text/html"}, "", 1.0,
            request_snippet=f"{method} {url}", response_snippet="HTTP/1.1 302 Found",
        )

    param = ParameterCandidate(
        name="imageUrl",
        location=ParameterLocation.json_body,
        url="https://example.com/profile/image/url",
        method="POST",
        baseline_value="http://example.com/a.png",
    )
    with patch.object(HttpVerifier, "send_request", send_request):
        findings = await detector.detect(
            urls=["https://example.com/profile/image/url"],
            forms=[],
            parameters=[param],
            oast_client=FakeOast(),
        )
    oast_findings = [
        finding
        for finding in findings
        if "Blind Server-Side Request Forgery" in finding.vuln_type
    ]
    assert oast_findings and oast_findings[0].verified
    assert oast_findings[0].category == OwaspCategory.a01
    assert "OAST collaborator" in oast_findings[0].verification_response_snippet
    assert oast_findings[0].detection_evidence["interaction_count"] == 1
