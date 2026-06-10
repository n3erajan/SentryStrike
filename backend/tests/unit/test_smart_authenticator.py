import pytest
import httpx
from types import SimpleNamespace
from bs4 import BeautifulSoup

from app.core.crawler.auth_manager import SmartAuthenticator, AuthStrategy, AuthResult, AuthReplayState


class MockSettings:
    def __init__(self):
        self.authentication_cookie = None
        self.authentication_username = "testuser"
        self.authentication_password = "testpassword"


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


@pytest.mark.asyncio
async def test_verify_auth_with_cookies():
    auth = SmartAuthenticator(MockSettings())
    client = httpx.AsyncClient()

    # No cookies -> not authenticated
    result = await auth._verify_auth(client)
    assert not result.authenticated

    # With cookies -> authenticated
    client.cookies.set("sessionid", "xyz123")
    result = await auth._verify_auth(client)
    assert result.authenticated
    assert result.cookies == {"sessionid": "xyz123"}


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
    assert result.bearer_token == "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOjF9"
