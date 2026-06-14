from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from app.api.dependencies import get_auth_service, get_current_user, get_session_token
from app.api.routes import auth, scan
from app.config import get_settings
from app.core.auth import AuthService, RegistrationClosedError, hash_password, verify_password


class FakeAuthService:
    def __init__(self) -> None:
        self.revoked_token: str | None = None
        self.user = SimpleNamespace(
            id="user-1",
            email="user@example.test",
            created_at=datetime(2026, 6, 8, 9, 10, 17, tzinfo=timezone.utc),
        )
        now = datetime.now(timezone.utc)
        self.session = SimpleNamespace(created_at=now, expires_at=now + timedelta(hours=24))

    async def register(self, email: str, password: str):
        _ = (email, password)
        return self.user

    async def authenticate(self, email: str, password: str):
        _ = (email, password)
        return self.user

    async def create_session(self, user):
        _ = user
        return "test-token", self.session

    async def revoke_session(self, token: str | None) -> bool:
        self.revoked_token = token
        return True


class RegistrationClosedService(FakeAuthService):
    async def register(self, email: str, password: str):
        _ = (email, password)
        raise RegistrationClosedError()


def _auth_app(service: FakeAuthService) -> TestClient:
    app = FastAPI()
    app.include_router(auth.router, prefix="/api/v1")
    app.dependency_overrides[get_auth_service] = lambda: service
    return TestClient(app)


def test_password_hash_roundtrip_and_rejects_wrong_password() -> None:
    encoded = hash_password("correct horse battery staple")

    assert verify_password("correct horse battery staple", encoded) is True
    assert verify_password("wrong password", encoded) is False
    assert "correct horse battery staple" not in encoded


def test_register_returns_closed_message_when_registration_disabled() -> None:
    client = _auth_app(RegistrationClosedService())

    response = client.post(
        "/api/v1/auth/register",
        json={"email": "user@example.test", "password": "password123"},
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "Sorry, we currently don't take new users registration."


@pytest.mark.asyncio
async def test_auth_service_registration_is_closed_by_env(monkeypatch) -> None:
    monkeypatch.setenv("ALLOW_REGISTRATION", "false")
    get_settings.cache_clear()

    with pytest.raises(RegistrationClosedError):
        await AuthService().register("user@example.test", "password123")

    get_settings.cache_clear()


def test_login_returns_token_and_http_only_cookie() -> None:
    client = _auth_app(FakeAuthService())

    response = client.post(
        "/api/v1/auth/login",
        json={"email": "USER@example.test", "password": "password123"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["data"]["access_token"] == "test-token"
    assert body["data"]["token_type"] == "bearer"
    assert body["data"]["user"]["email"] == "user@example.test"
    assert "sentrystrike_session=test-token" in response.headers["set-cookie"]
    assert "HttpOnly" in response.headers["set-cookie"]


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


def test_protected_router_requires_authentication() -> None:
    app = FastAPI()
    app.include_router(scan.router, prefix="/api/v1", dependencies=[Depends(get_current_user)])
    client = TestClient(app)

    response = client.get("/api/v1/scans")

    assert response.status_code == 401
