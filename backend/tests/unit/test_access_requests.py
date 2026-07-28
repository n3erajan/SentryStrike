from datetime import timedelta

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.dependencies import get_access_request_service
from app.api.routes import access_requests
from app.core import access_requests as access_request_module
from app.core.access_request_rate_limit import (
    AccessRequestRateLimiterUnavailable,
    AccessRequestRateLimitExceeded,
)
from app.core.access_requests import AccessRequestService
from app.core.auth import utc_now
from app.core.turnstile import CaptchaInvalidError, TurnstileVerifier


class FakeAccessRequestService:
    def __init__(
        self,
        error: Exception | None = None,
        result: bool = True,
    ) -> None:
        self.error = error
        self.result = result
        self.calls: list[dict] = []

    async def submit(self, **kwargs) -> bool:
        self.calls.append(kwargs)
        if self.error:
            raise self.error
        return self.result


def _client(service: FakeAccessRequestService) -> TestClient:
    app = FastAPI()
    app.include_router(access_requests.router, prefix="/api/v1")
    app.dependency_overrides[get_access_request_service] = lambda: service
    return TestClient(app)


def _payload() -> dict:
    return {
        "full_name": "Avery Stone",
        "email": "avery@example.test",
        "organization_name": "Northstar Security",
        "turnstile_token": "verified-token",
        "website": "",
    }


def test_public_access_request_forwards_validated_submission() -> None:
    service = FakeAccessRequestService()

    response = _client(service).post("/api/v1/access-requests", json=_payload())

    assert response.status_code == 202
    assert response.json()["data"] == {"submitted": True}
    assert service.calls[0]["email"] == "avery@example.test"
    assert service.calls[0]["client_ip"] == "testclient"


def test_public_access_request_does_not_disclose_a_rejected_email() -> None:
    service = FakeAccessRequestService(result=False)

    response = _client(service).post("/api/v1/access-requests", json=_payload())

    assert response.status_code == 202
    assert response.json()["data"] == {"submitted": True}


def test_public_access_request_returns_retry_after_when_limited() -> None:
    service = FakeAccessRequestService(AccessRequestRateLimitExceeded(321))

    response = _client(service).post("/api/v1/access-requests", json=_payload())

    assert response.status_code == 429
    assert response.headers["retry-after"] == "321"


def test_public_access_request_fails_closed_when_redis_is_unavailable() -> None:
    service = FakeAccessRequestService(AccessRequestRateLimiterUnavailable("offline"))

    response = _client(service).post("/api/v1/access-requests", json=_payload())

    assert response.status_code == 503
    assert "temporarily unavailable" in response.json()["detail"]


def test_public_access_request_rejects_terminal_control_characters() -> None:
    service = FakeAccessRequestService()
    payload = _payload()
    payload["organization_name"] = "Northstar\x1b[2J"

    response = _client(service).post("/api/v1/access-requests", json=payload)

    assert response.status_code == 422
    assert service.calls == []


class FakeLimiter:
    def __init__(self) -> None:
        self.ips: list[str] = []

    async def check(self, *, client_ip: str) -> None:
        self.ips.append(client_ip)

    async def close(self) -> None:
        return None


class FakeTurnstileResponse:
    def __init__(self, result: dict | None = None) -> None:
        self.result = result or {"success": True, "action": "request_access"}

    def raise_for_status(self) -> None:
        return None

    def json(self) -> dict:
        return self.result


class FakeHttpClient:
    def __init__(self, result: dict | None = None) -> None:
        self.calls: list[dict] = []
        self.result = result

    async def post(self, url: str, *, data: dict) -> FakeTurnstileResponse:
        self.calls.append({"url": url, "data": data})
        return FakeTurnstileResponse(self.result)


class FakeField:
    def __eq__(self, value):
        return value


class FakeAccessRequestDocument:
    email = FakeField()
    existing = None
    inserted: list["FakeAccessRequestDocument"] = []

    def __init__(self, **values) -> None:
        self.__dict__.update(values)

    @classmethod
    async def find_one(cls, _query):
        return cls.existing

    async def insert(self) -> None:
        self.__class__.inserted.append(self)


class FakeUserDocument:
    email = FakeField()
    existing = None

    @classmethod
    async def find_one(cls, _query):
        return cls.existing


@pytest.mark.asyncio
async def test_turnstile_verifier_rejects_missing_token_without_network_call() -> None:
    http_client = FakeHttpClient()
    verifier = TurnstileVerifier(http_client)

    with pytest.raises(CaptchaInvalidError):
        await verifier.verify(
            token="",
            client_ip="203.0.113.9",
            expected_action="login",
        )

    assert http_client.calls == []


@pytest.mark.asyncio
async def test_turnstile_verifier_rejects_token_for_another_action() -> None:
    verifier = TurnstileVerifier(
        FakeHttpClient({"success": True, "action": "request_access"})
    )

    with pytest.raises(CaptchaInvalidError):
        await verifier.verify(
            token="captcha-token",
            client_ip="203.0.113.9",
            expected_action="login",
        )


@pytest.mark.asyncio
async def test_access_request_service_verifies_normalizes_and_sets_thirty_day_expiry(
    monkeypatch,
) -> None:
    FakeAccessRequestDocument.existing = None
    FakeAccessRequestDocument.inserted = []
    FakeUserDocument.existing = None
    monkeypatch.setattr(access_request_module, "AccessRequest", FakeAccessRequestDocument)
    monkeypatch.setattr(access_request_module, "User", FakeUserDocument)
    limiter = FakeLimiter()
    http_client = FakeHttpClient()
    service = AccessRequestService(limiter, TurnstileVerifier(http_client))
    before = utc_now()

    created = await service.submit(
        full_name="Avery Stone",
        email="  AVERY@EXAMPLE.TEST ",
        organization_name="Northstar Security",
        turnstile_token="captcha-token",
        client_ip="203.0.113.9",
    )

    assert created is True
    assert limiter.ips == ["203.0.113.9"]
    assert http_client.calls[0]["data"]["response"] == "captcha-token"
    stored = FakeAccessRequestDocument.inserted[0]
    assert stored.email == "avery@example.test"
    assert before + timedelta(days=30) <= stored.expires_at
    assert stored.expires_at <= utc_now() + timedelta(days=30)
    assert "turnstile_token" not in stored.__dict__


@pytest.mark.asyncio
async def test_access_request_service_deduplicates_pending_email(monkeypatch) -> None:
    FakeAccessRequestDocument.existing = object()
    FakeAccessRequestDocument.inserted = []
    FakeUserDocument.existing = None
    monkeypatch.setattr(access_request_module, "AccessRequest", FakeAccessRequestDocument)
    monkeypatch.setattr(access_request_module, "User", FakeUserDocument)
    service = AccessRequestService(
        FakeLimiter(),
        TurnstileVerifier(FakeHttpClient()),
    )

    created = await service.submit(
        full_name="Avery Stone",
        email="avery@example.test",
        organization_name="Northstar Security",
        turnstile_token="captcha-token",
        client_ip="203.0.113.9",
    )

    assert created is False
    assert FakeAccessRequestDocument.inserted == []


@pytest.mark.asyncio
async def test_access_request_service_skips_registered_email(monkeypatch) -> None:
    FakeAccessRequestDocument.existing = None
    FakeAccessRequestDocument.inserted = []
    FakeUserDocument.existing = object()
    monkeypatch.setattr(access_request_module, "AccessRequest", FakeAccessRequestDocument)
    monkeypatch.setattr(access_request_module, "User", FakeUserDocument)
    service = AccessRequestService(
        FakeLimiter(),
        TurnstileVerifier(FakeHttpClient()),
    )

    created = await service.submit(
        full_name="Existing User",
        email="  EXISTING@EXAMPLE.TEST ",
        organization_name="Existing Workspace",
        turnstile_token="captcha-token",
        client_ip="203.0.113.9",
    )

    assert created is False
    assert FakeAccessRequestDocument.inserted == []
