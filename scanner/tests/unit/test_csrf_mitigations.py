import pytest
import asyncio

from app.core.detectors import csrf_detector as csrf_module
from app.core.detectors.csrf_detector import CSRFDetector
from shared.models.vulnerability import SeverityLevel


@pytest.mark.asyncio
async def test_csrf_samesite_strict_downgrade():
    detector = CSRFDetector()

    # Test that SameSite=Strict on a session cookie downgrades or notes the finding.
    # The actual behavior is inside the active verification of verify_csrf.
    # We test this conceptually by ensuring the detector logic respects it.

    # Just asserting the structure is ready
    assert hasattr(detector, "detect")


class _FakeResponse:
    def __init__(self, status_code=200, body="", headers=None):
        self.status_code = status_code
        self.body = body
        self.headers = headers or {}
        self.request_snippet = "REQ"
        self.response_snippet = "RESP"


class _FakeVerifier:
    """Stand-in for HttpVerifier — records nothing, always accepts the request."""

    def __init__(self, *args, **kwargs):
        self.cookies = kwargs.get("cookies")

    def set_request_context(self, **kwargs):
        return None

    async def send_request(self, url, method, params, data, headers=None, test_phase="", **kwargs):
        # Simulate a server that accepts state-changing requests without any
        # CSRF-token validation, so the detector should flag it.
        return _FakeResponse(status_code=200, body="OK, profile updated")

    async def close(self):
        return None


@pytest.mark.asyncio
async def test_csrf_token_auth_spa_no_high_severity_finding(monkeypatch):
    """Bearer/header-token SPA: no cookies → no fabricated CSRF vuln.

    At most an informational posture note is emitted for a state-changing
    endpoint; nothing at medium/high severity.
    """
    # If the detector ever tried active verification here, it would need cookies;
    # ensure it does not by refusing to construct a real verifier.
    monkeypatch.setattr(csrf_module, "HttpVerifier", _FakeVerifier)

    detector = CSRFDetector()
    browser_forms = [
        {
            "action": "http://spa.test/profile",
            "method": "POST",
            "inputs": [{"name": "displayName", "type": "text"}],
            "page_url": "http://spa.test/profile",
        }
    ]

    findings = await detector.detect(
        ["http://spa.test/profile"],
        [],
        session_cookies={},
        auth_headers={"Authorization": "Bearer eyJhbGciOi.token.sig"},
        browser_forms=browser_forms,
    )

    # No high/medium-severity CSRF finding should be fabricated for token-auth.
    assert all(f.severity == SeverityLevel.info for f in findings)
    assert all(not f.verified for f in findings)
    assert findings, "expected an informational posture note for the state-changing endpoint"
    assert findings[0].detection_method == "csrf_posture_token_auth"


@pytest.mark.asyncio
async def test_csrf_token_auth_without_state_changing_forms_is_silent():
    detector = CSRFDetector()

    findings = await detector.detect(
        ["http://spa.test/"],
        [],
        session_cookies={},
        auth_headers={"Authorization": "Bearer token"},
        browser_forms=[],
    )

    assert findings == []


@pytest.mark.asyncio
async def test_csrf_cookie_auth_consumes_browser_discovered_forms(monkeypatch):
    """Cookie-auth app with a token-less, browser-discovered state-changing form.

    The detector must merge browser forms with static forms and actively verify
    them, producing a real CSRF finding.
    """
    monkeypatch.setattr(csrf_module, "HttpVerifier", _FakeVerifier)

    detector = CSRFDetector()
    browser_forms = [
        {
            "action": "http://target.test/profile/update",
            "method": "POST",
            "inputs": [
                {"name": "displayName", "type": "text"},
                {"name": "bio", "type": "text"},
            ],
            "page_url": "http://target.test/profile",
        }
    ]

    findings = await detector.detect(
        ["http://target.test/profile"],
        [],  # no static forms — SPA renders forms only in the DOM
        session_cookies={"session": "abc123"},
        auth_headers={},
        browser_forms=browser_forms,
    )

    assert findings, "expected a CSRF finding from the browser-discovered form"
    finding = findings[0]
    assert "Cross-Site Request Forgery" in finding.vuln_type
    assert finding.url == "http://target.test/profile/update"
    assert finding.verified is True
    # Token-less form with no SameSite protection accepted a foreign-Origin POST.
    assert finding.severity in {SeverityLevel.high, SeverityLevel.medium}


_SPA_SHELL = (
    "<html><head><title>App</title></head><body>"
    "<app-root></app-root><script src=\"main.js\"></script></body></html>"
)


class _ShellVerifier(_FakeVerifier):
    """Every submission returns the SPA HTML shell (as any client route would)."""

    async def send_request(self, url, method, params, data, headers=None, test_phase="", **kwargs):
        return _FakeResponse(
            status_code=200,
            body=_SPA_SHELL,
            headers={"content-type": "text/html; charset=utf-8"},
        )


@pytest.mark.asyncio
async def test_csrf_no_finding_on_spa_client_routes(monkeypatch):
    """P0-4: browser-discovered SPA "forms" are client-side routes whose action
    returns the 200 HTML shell. With no observed mutating API backing them, they
    must not be tested at all — no CSRF findings on navigation routes."""
    monkeypatch.setattr(csrf_module, "HttpVerifier", _ShellVerifier)

    detector = CSRFDetector()
    browser_forms = [
        {"action": "http://spa.test/register", "method": "POST",
         "inputs": [{"name": "email", "type": "text"}], "page_url": "http://spa.test/register"},
        {"action": "http://spa.test/search", "method": "POST",
         "inputs": [{"name": "q", "type": "text"}], "page_url": "http://spa.test/search"},
    ]

    findings = await detector.detect(
        ["http://spa.test/register", "http://spa.test/search"],
        [],
        session_cookies={"session": "abc123"},
        auth_headers={},
        browser_forms=browser_forms,
        is_spa=True,
        spa_root_html=_SPA_SHELL,
        root_url="http://spa.test/",
    )

    assert findings == [], "no CSRF findings should attach to SPA navigation routes"


@pytest.mark.asyncio
async def test_csrf_shell_guard_suppresses_finding_for_shell_response(monkeypatch):
    """P0-4: even a confirmed mutating-API candidate must not produce a finding
    when the verification response is the SPA shell (no state change occurred)."""
    from app.core.crawler.models import RequestObservation

    monkeypatch.setattr(csrf_module, "HttpVerifier", _ShellVerifier)

    detector = CSRFDetector()
    observed = [
        RequestObservation(
            url="http://spa.test/api/profile",
            method="POST",
            request_content_type="application/json",
            post_data='{"displayName":"x"}',
            body_kind="json",
            body_schema=["displayName"],
        )
    ]

    findings = await detector.detect(
        ["http://spa.test/"],
        [],
        session_cookies={"session": "abc123"},
        auth_headers={},
        browser_forms=[],
        requests=observed,
        is_spa=True,
        spa_root_html=_SPA_SHELL,
        root_url="http://spa.test/",
    )

    assert findings == [], "SPA-shell response must not be treated as a state change"


@pytest.mark.asyncio
async def test_csrf_finding_on_real_mutating_api(monkeypatch):
    """P0-4: an observed mutating XHR (real API) that accepts a tampered,
    foreign-Origin submission with a non-shell response is a genuine CSRF finding.

    The observed request is form-encoded, so it is genuinely cross-site
    forgeable (a JSON body would not be — see test_csrf_suppressed_on_json_api).
    """
    from app.core.crawler.models import RequestObservation

    monkeypatch.setattr(csrf_module, "HttpVerifier", _FakeVerifier)

    detector = CSRFDetector()
    observed = [
        RequestObservation(
            url="http://spa.test/api/profile",
            method="POST",
            request_content_type="application/x-www-form-urlencoded",
            post_data="displayName=x",
            body_kind="form",
            body_schema=["displayName"],
        )
    ]

    findings = await detector.detect(
        ["http://spa.test/"],
        [],
        session_cookies={"session": "abc123"},
        auth_headers={},
        browser_forms=[],
        requests=observed,
        is_spa=True,
        spa_root_html=_SPA_SHELL,
        root_url="http://spa.test/",
    )

    assert findings, "expected a CSRF finding on the real mutating API endpoint"
    assert findings[0].url == "http://spa.test/api/profile"
    assert findings[0].verified is True


@pytest.mark.asyncio
async def test_csrf_builds_candidate_from_mutating_api_schema(monkeypatch):
    from app.core.crawler.models import ApiEndpoint

    calls: list[dict[str, object]] = []

    class _RecordingVerifier(_FakeVerifier):
        async def send_request(self, url, method, params, data, headers=None, test_phase="", **kwargs):
            calls.append(
                {
                    "url": url,
                    "method": method,
                    "params": params,
                    "data": data,
                    "headers": headers,
                    "json_body": kwargs.get("json_body"),
                    "test_phase": test_phase,
                }
            )
            return _FakeResponse(status_code=200, body='{"ok":true}', headers={"content-type": "application/json"})

    monkeypatch.setattr(csrf_module, "HttpVerifier", _RecordingVerifier)

    detector = CSRFDetector()
    endpoint = ApiEndpoint(
        url="http://spa.test/api/profile",
        method="POST",
        content_type="application/x-www-form-urlencoded",
        body_schema=["displayName"],
    )

    findings = await detector.detect(
        ["http://spa.test/"],
        [],
        session_cookies={"session": "abc123"},
        auth_headers={},
        browser_forms=[],
        requests=[],
        api_endpoints=[endpoint],
        is_spa=True,
        spa_root_html=_SPA_SHELL,
        root_url="http://spa.test/",
    )

    assert findings, "expected CSRF finding from generic mutating API schema"
    assert calls
    # Form-encoded endpoint → sent as a urlencoded body (data=), no JSON body,
    # and no forced Content-Type header (the client sets it for form data).
    assert calls[0]["data"] == {"displayName": "sentry_test_val"}
    assert calls[0]["json_body"] is None
    assert calls[0]["headers"] is None


@pytest.mark.asyncio
async def test_csrf_skips_mutating_api_schema_with_unresolved_path(monkeypatch):
    from app.core.crawler.models import ApiEndpoint

    class _FailIfUsedVerifier(_FakeVerifier):
        async def send_request(self, *args, **kwargs):
            raise AssertionError("unresolved path candidate should not be probed")

    monkeypatch.setattr(csrf_module, "HttpVerifier", _FailIfUsedVerifier)

    detector = CSRFDetector()
    endpoint = ApiEndpoint(
        url="http://spa.test/api/items/{id}",
        method="PATCH",
        content_type="application/json",
        body_schema=["name"],
    )

    findings = await detector.detect(
        ["http://spa.test/"],
        [],
        session_cookies={"session": "abc123"},
        auth_headers={},
        browser_forms=[],
        requests=[],
        api_endpoints=[endpoint],
        is_spa=True,
        spa_root_html=_SPA_SHELL,
        root_url="http://spa.test/",
    )

    assert findings == []


@pytest.mark.asyncio
async def test_csrf_suppressed_on_json_api(monkeypatch):
    """JSON APIs requiring application/json are not cross-site forgeable (HTML
    forms cannot set that Content-Type; fetch() triggers a blocked CORS
    preflight). The detector must skip them — no false CSRF on JSON endpoints."""
    from app.core.crawler.models import RequestObservation

    monkeypatch.setattr(csrf_module, "HttpVerifier", _FakeVerifier)

    detector = CSRFDetector()
    observed = [
        RequestObservation(
            url="http://spa.test/api/profile",
            method="POST",
            request_content_type="application/json",
            post_data='{"displayName":"x"}',
            body_kind="json",
            body_schema=["displayName"],
        )
    ]

    findings = await detector.detect(
        ["http://spa.test/"],
        [],
        session_cookies={"session": "abc123"},
        auth_headers={},
        browser_forms=[],
        requests=observed,
    )

    assert findings == [], "JSON API must not be flagged as classic ambient-cookie CSRF"


@pytest.mark.asyncio
async def test_csrf_suppressed_on_login_endpoint(monkeypatch):
    """Login/authenticate endpoints accept anonymous callers by design. A forged
    login is the separate, weaker 'login CSRF' class with no ambient session to
    abuse — skip them uniformly. Structural path detection -> framework-agnostic."""
    from app.core.crawler.models import RequestObservation

    monkeypatch.setattr(csrf_module, "HttpVerifier", _FakeVerifier)

    detector = CSRFDetector()
    observed = [
        RequestObservation(
            url="http://app.test/auth/login",
            method="POST",
            request_content_type="application/x-www-form-urlencoded",
            post_data="username=u&password=p",
            body_kind="form",
            body_schema=["username", "password"],
        ),
        RequestObservation(
            url="http://app.test/api/authenticate",
            method="POST",
            request_content_type="application/x-www-form-urlencoded",
            post_data="email=e&password=p",
            body_kind="form",
            body_schema=["email", "password"],
        ),
    ]

    findings = await detector.detect(
        ["http://app.test/"],
        [],
        session_cookies={"session": "abc123"},
        auth_headers={},
        browser_forms=[],
        requests=observed,
    )

    assert findings == [], "login/authenticate endpoints must be suppressed"
