import pytest
import httpx

from app.core.crawler.auth_manager import (
    AuthVerificationState,
    SmartAuthenticator,
    redact_secret,
)
from app.core.crawler.models import ApiEndpoint


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
