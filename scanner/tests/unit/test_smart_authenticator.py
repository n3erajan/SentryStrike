import pytest
import httpx

from app.core.crawler.auth_manager import (
    AuthResult,
    AuthVerificationState,
    SmartAuthenticator,
    redact_secret,
)
from app.core.crawler.models import ApiEndpoint


def test_auth_result_carries_full_storage_state():
    """AuthResult exposes an optional storage_state blob captured whole
    from the Playwright context (opaque; never key-inspected)."""
    blob = {
        "cookies": [{"name": "sid", "value": "abc"}],
        "origins": [
            {"origin": "http://spa.test", "localStorage": [{"name": "jwt", "value": "t"}]}
        ],
    }
    result = AuthResult(authenticated=True, storage_state=blob)
    assert result.storage_state == blob
    # Default stays None so cookie/static-auth paths are unaffected.
    assert AuthResult().storage_state is None


class _FakeSessionPage:
    """Minimal page stub exposing sessionStorage + origin via evaluate()."""

    def __init__(self, session: dict, origin: str = "http://spa.test"):
        self._session = session
        self._origin = origin

    async def evaluate(self, script):
        import json as _json

        if "sessionStorage" in script:
            return _json.dumps(self._session)
        if "location.origin" in script:
            return self._origin
        return None


@pytest.mark.asyncio
async def test_merge_session_storage_attaches_to_matching_origin():
    """Playwright storage_state drops sessionStorage; the merge re-attaches it to
    the matching origin so the crawler can re-seed session-scoped ids (cart id,
    CSRF token) that button-triggered mutations need."""
    from app.core.crawler.auth_manager import _merge_session_storage

    blob = {
        "cookies": [{"name": "sid", "value": "abc"}],
        "origins": [
            {"origin": "http://spa.test", "localStorage": [{"name": "jwt", "value": "t"}]}
        ],
    }
    page = _FakeSessionPage({"bid": "6", "csrf": "xyz"})
    merged = await _merge_session_storage(blob, page)
    origin = next(o for o in merged["origins"] if o["origin"] == "http://spa.test")
    names = {e["name"]: e["value"] for e in origin["sessionStorage"]}
    assert names == {"bid": "6", "csrf": "xyz"}
    # localStorage on the same origin is preserved (merge, not replace).
    assert origin["localStorage"] == [{"name": "jwt", "value": "t"}]


@pytest.mark.asyncio
async def test_merge_session_storage_noop_when_empty_or_invalid():
    from app.core.crawler.auth_manager import _merge_session_storage

    # Empty sessionStorage leaves the blob unchanged (no empty origin added).
    blob = {"origins": [{"origin": "http://spa.test", "localStorage": []}]}
    page = _FakeSessionPage({})
    merged = await _merge_session_storage(blob, page)
    assert all("sessionStorage" not in o for o in merged["origins"])
    # A non-dict storage_state (capture failed) is returned untouched.
    assert await _merge_session_storage(None, page) is None


class MockSettings:
    def __init__(self):
        self.authentication_cookie = None
        self.authentication_username = "testuser"
        self.authentication_password = "testpassword"
        self.authentication_failure_text = None
        self.authentication_failure_regex = None
        self.authentication_success_text = None
        self.authentication_success_regex = None
        self.authentication_success_url = None
        self.authentication_validation_url = None


def test_classify_field_name_and_attrs():
    auth = SmartAuthenticator(MockSettings())

    # Test username classification
    assert auth._classify_field_name_and_attrs("email") == "username"
    assert auth._classify_field_name_and_attrs("user_name") == "username"
    assert auth._classify_field_name_and_attrs("loginId") == "username"
    assert auth._classify_field_name_and_attrs("custom", inp_type="email") == "username"
    assert auth._classify_field_name_and_attrs("custom", autocomplete="username") == "username"

    # Test password classification
    assert auth._classify_field_name_and_attrs("password") == "password"
    assert auth._classify_field_name_and_attrs("pass") == "password"
    assert auth._classify_field_name_and_attrs("passwd") == "password"
    assert auth._classify_field_name_and_attrs("custom", inp_type="password") == "password"
    assert auth._classify_field_name_and_attrs("custom", autocomplete="current-password") == "password"

    # Test unknown classification
    assert auth._classify_field_name_and_attrs("remember_me") is None


def test_extract_js_body_params():
    auth = SmartAuthenticator(MockSettings())

    # Angular HttpClient pattern
    js_content_1 = 'this.http.post(this.hostServer+"/rest/user/login", {email: t.email, password: t.password})'
    params = auth._extract_js_body_params(js_content_1, "/rest/user/login")
    assert "email" in params
    assert "password" in params

    # React fetch / stringify pattern
    js_content_2 = 'fetch("/api/auth/login", {method:"POST", body:JSON.stringify({username:e, password:n})})'
    params = auth._extract_js_body_params(js_content_2, "/api/auth/login")
    assert "username" in params
    assert "password" in params

    # Angular FormBuilder pattern
    js_content_3 = 'this.loginForm = this.fb.group({ email: ["", Validators.required], password: [""] })'
    params = auth._extract_js_body_params(js_content_3, "email")
    assert "email" in params
    assert "password" in params


def test_map_credentials_to_params():
    auth = SmartAuthenticator(MockSettings())

    # Clear keys
    payload = auth._map_credentials_to_params(["email", "password"], "admin@domain.com", "pass123")
    assert payload == {"email": "admin@domain.com", "password": "pass123"}

    # Fallback keys
    payload = auth._map_credentials_to_params(["someUser", "somePass"], "admin", "pass")
    assert payload == {"someUser": "admin", "somePass": "pass"}


def test_rank_auth_endpoints_prefers_real_api_login_over_spa_route():
    auth = SmartAuthenticator(MockSettings())
    script = (
        'path:"login";'
        'this.http.post(this.hostServer+"/rest/user/login", {email: t.email, password: t.password})'
    )
    endpoints = [
        ApiEndpoint(url="http://localhost:3000/login", method="POST", evidence="/login"),
        ApiEndpoint(url="http://localhost:3000/rest/user/login", method="POST", evidence="/rest/user/login"),
    ]

    ranked = auth._rank_auth_endpoints(endpoints, {"main.js": script})

    assert ranked[0].url == "http://localhost:3000/rest/user/login"


def test_redact_secret_keeps_debug_shape_without_exposing_token():
    token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.payload.signature"

    redacted = redact_secret(token)

    assert redacted.startswith("eyJ0eX")
    assert redacted.endswith(f" len={len(token)}")
    assert "payload" not in redacted


@pytest.mark.asyncio
async def test_verify_auth_with_cookies():
    auth = SmartAuthenticator(MockSettings())
    client = httpx.AsyncClient()

    # No cookies -> not authenticated
    result = await auth._verify_auth(client)
    assert not result.authenticated

    # With cookies alone -> usable but unverified, not proof of login.
    client.cookies.set("sessionid", "xyz123")
    result = await auth._verify_auth(client)
    assert result.authenticated
    assert result.state == AuthVerificationState.authenticated_unverified
    assert result.cookies == {"sessionid": "xyz123"}


@pytest.mark.asyncio
async def test_verify_auth_with_post_login_marker_is_verified():
    auth = SmartAuthenticator(MockSettings())
    client = httpx.AsyncClient()
    client.cookies.set("sessionid", "xyz123")
    mock_resp = httpx.Response(
        200,
        text="<html><a href='/logout'>Logout</a><h1>Dashboard</h1></html>",
        request=httpx.Request("POST", "http://example.com/login"),
    )

    result = await auth._verify_auth(client, response=mock_resp)

    assert result.authenticated
    assert result.state == AuthVerificationState.authenticated_verified


@pytest.mark.asyncio
async def test_verify_auth_with_json_token():
    auth = SmartAuthenticator(MockSettings())
    client = httpx.AsyncClient()

    # Mock response containing a token
    mock_resp = httpx.Response(
        200,
        json={"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOjF9"},
        request=httpx.Request("POST", "http://example.com/login")
    )

    result = await auth._verify_auth(client, response=mock_resp)
    assert result.authenticated
    assert result.state == AuthVerificationState.authenticated_verified
    assert result.bearer_token == "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOjF9"
