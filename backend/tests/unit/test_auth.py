from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from app.api.dependencies import (
    get_auth_service,
    get_current_user,
    get_session_token,
    get_turnstile_verifier,
)
from app.api.routes import auth, scan
from app.core.auth import (
    InvalidSessionError,
    as_utc_naive,
    hash_password,
    utc_now,
    verify_password,
)
from app.core.turnstile import CaptchaInvalidError


class FakeAuthService:
    def __init__(self) -> None:
        self.revoked_token: str | None = None
        self.authenticate_calls: list[tuple[str, str]] = []
        self.authenticate_session_calls: list[str | None] = []
        self.invalid_session = False
        self.user = SimpleNamespace(
            id="user-1",
            full_name="Niuradaj Adhadh",
            email="user@example.test",
            org_id="org-1",
            role=SimpleNamespace(value="owner"),
            created_at=datetime(2026, 6, 8, 9, 10, 17, tzinfo=timezone.utc),
        )
        now = datetime.now(timezone.utc)
        self.session = SimpleNamespace(created_at=now, expires_at=now + timedelta(hours=24))

    async def authenticate(self, email: str, password: str):
        self.authenticate_calls.append((email, password))
        return self.user

    async def create_session(self, user):
        _ = user
        return "test-token", self.session

    async def authenticate_session(self, token: str | None):
        self.authenticate_session_calls.append(token)
        if self.invalid_session:
            raise InvalidSessionError()
        return self.user, self.session

    async def revoke_session(self, token: str | None) -> bool:
        self.revoked_token = token
        return True


class FakeTurnstileVerifier:
    def __init__(self, error: Exception | None = None) -> None:
        self.calls: list[dict] = []
        self.error = error

    async def verify(self, **kwargs) -> None:
        self.calls.append(kwargs)
        if self.error:
            raise self.error


def _auth_app(
    service: FakeAuthService,
    turnstile: FakeTurnstileVerifier | None = None,
) -> TestClient:
    app = FastAPI()
    app.include_router(auth.router, prefix="/api/v1")
    app.dependency_overrides[get_auth_service] = lambda: service
    app.dependency_overrides[get_turnstile_verifier] = lambda: (
        turnstile or FakeTurnstileVerifier()
    )
    return TestClient(app)


def test_password_hash_roundtrip_and_rejects_wrong_password() -> None:
    encoded = hash_password("correct horse battery staple")

    assert verify_password("correct horse battery staple", encoded) is True
    assert verify_password("wrong password", encoded) is False
    assert "correct horse battery staple" not in encoded


def test_auth_datetime_helpers_compare_database_naive_values() -> None:
    naive_expires_at = datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(hours=1)
    aware_expires_at = datetime.now(timezone.utc) + timedelta(hours=1)

    assert as_utc_naive(naive_expires_at).tzinfo is None
    assert as_utc_naive(aware_expires_at).tzinfo is None
    assert as_utc_naive(naive_expires_at) > utc_now()
    assert as_utc_naive(aware_expires_at) > utc_now()


def test_login_returns_token_and_http_only_cookie() -> None:
    turnstile = FakeTurnstileVerifier()
    client = _auth_app(FakeAuthService(), turnstile)

    response = client.post(
        "/api/v1/auth/login",
        json={
            "email": "USER@example.test",
            "password": "password123",
            "turnstile_token": "verified-token",
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["data"]["access_token"] == "test-token"
    assert body["data"]["token_type"] == "bearer"
    assert body["data"]["user"]["full_name"] == "Niuradaj Adhadh"
    assert body["data"]["user"]["email"] == "user@example.test"
    assert "sentrystrike_session=test-token" in response.headers["set-cookie"]
    assert "HttpOnly" in response.headers["set-cookie"]
    assert turnstile.calls == [
        {
            "token": "verified-token",
            "client_ip": "testclient",
            "expected_action": "login",
        }
    ]


def test_login_rejects_invalid_captcha_before_checking_credentials() -> None:
    service = FakeAuthService()
    turnstile = FakeTurnstileVerifier(
        CaptchaInvalidError("Complete the security check and try again.")
    )
    client = _auth_app(service, turnstile)

    response = client.post(
        "/api/v1/auth/login",
        json={
            "email": "user@example.test",
            "password": "password123",
            "turnstile_token": "invalid-token",
        },
    )

    assert response.status_code == 400
    assert "security check" in response.json()["detail"]
    assert service.authenticate_calls == []


def test_logout_requires_current_user_and_revokes_current_token() -> None:
    service = FakeAuthService()
    app = FastAPI()
    app.include_router(auth.router, prefix="/api/v1")
    app.dependency_overrides[get_auth_service] = lambda: service
    app.dependency_overrides[get_current_user] = lambda: service.user
    client = TestClient(app)

    response = client.post("/api/v1/auth/logout", headers={"Authorization": "Bearer token-from-header"})

    assert response.status_code == 200
    assert response.json()["data"]["logged_out"] is True
    assert service.revoked_token == "token-from-header"


def test_session_probe_returns_null_without_credentials() -> None:
    service = FakeAuthService()
    client = _auth_app(service)

    response = client.get("/api/v1/auth/session")

    assert response.status_code == 200
    assert response.json()["data"] is None
    assert service.authenticate_session_calls == []


def test_session_probe_returns_current_user_for_valid_cookie() -> None:
    service = FakeAuthService()
    client = _auth_app(service)

    response = client.get(
        "/api/v1/auth/session",
        headers={"Cookie": "sentrystrike_session=valid-token"},
    )

    assert response.status_code == 200
    assert response.json()["data"]["id"] == "user-1"
    assert service.authenticate_session_calls == ["valid-token"]


def test_session_probe_clears_invalid_cookie_without_a_401() -> None:
    service = FakeAuthService()
    service.invalid_session = True
    client = _auth_app(service)

    response = client.get(
        "/api/v1/auth/session",
        headers={"Cookie": "sentrystrike_session=expired-token"},
    )

    assert response.status_code == 200
    assert response.json()["data"] is None
    assert service.authenticate_session_calls == ["expired-token"]
    assert "sentrystrike_session=" in response.headers["set-cookie"]
    assert "Max-Age=0" in response.headers["set-cookie"]


def test_session_token_prefers_bearer_token_over_cookie() -> None:
    app = FastAPI()

    @app.get("/token")
    async def token(value: str | None = Depends(get_session_token)):
        return {"token": value}

    client = TestClient(app)

    response = client.get(
        "/token",
        headers={"Authorization": "Bearer header-token", "Cookie": "sentrystrike_session=cookie-token"},
    )

    assert response.json()["token"] == "header-token"


def test_session_token_survives_malformed_sibling_cookie() -> None:
    """A stale/foreign cookie with an unparseable value (unquoted JSON, spaces)
    left on the same host by another app must not stop us reading the valid
    session cookie. ``http.cookies.SimpleCookie`` discards the ENTIRE jar on such
    input - losing the session token and 401-ing every request even straight
    after a successful login (the observed 'dashboard blink then logout'). The
    lenient Starlette parser skips only the offending pair."""
    app = FastAPI()

    @app.get("/token")
    async def token(value: str | None = Depends(get_session_token)):
        return {"token": value}

    client = TestClient(app)

    for hostile in ('pref={"theme":"dark"}', "old=a b c"):
        response = client.get(
            "/token",
            headers={"Cookie": f"{hostile}; sentrystrike_session=valid-token"},
        )
        assert response.json()["token"] == "valid-token", f"token lost beside sibling: {hostile}"


def test_protected_router_requires_authentication() -> None:
    app = FastAPI()
    app.include_router(scan.router, prefix="/api/v1", dependencies=[Depends(get_current_user)])
    client = TestClient(app)

    response = client.get("/api/v1/scans")

    assert response.status_code == 401
