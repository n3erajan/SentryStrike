from fastapi import HTTPException
from fastapi.testclient import TestClient

from app.main import create_app


def _client() -> TestClient:
    app = create_app()

    @app.get("/_test/not-found")
    async def not_found():
        raise HTTPException(status_code=404, detail="Application not found")

    @app.get("/_test/crash")
    async def crash():
        raise RuntimeError("redis password=secret at /app/worker.py:44")

    return TestClient(app, raise_server_exceptions=False)


def test_validation_errors_are_structured_and_professional():
    response = _client().post(
        "/api/v1/auth/login",
        json={"email": "not-an-email"},
    )

    assert response.status_code == 422
    body = response.json()
    assert body["message"] == "Check the highlighted fields and try again."
    assert body["error_code"] == "VALIDATION_ERROR"
    assert body["field_errors"] == [
        {"field": "email", "message": "Enter a valid email address."},
        {"field": "password", "message": "This field is required."},
    ]
    assert body["request_id"] == response.headers["X-Request-ID"]


def test_http_errors_keep_detail_and_add_the_standard_contract():
    response = _client().get("/_test/not-found")

    assert response.status_code == 404
    body = response.json()
    assert body["detail"] == "Application not found"
    assert body["message"] == "Application not found"
    assert body["error_code"] == "HTTP_404"
    assert body["request_id"] == response.headers["X-Request-ID"]


def test_unhandled_errors_never_expose_exception_details():
    response = _client().get("/_test/crash")

    assert response.status_code == 500
    body = response.json()
    assert body["message"] == "We couldn't complete your request. Please try again."
    assert body["error_code"] == "INTERNAL_ERROR"
    assert body["request_id"] == response.headers["X-Request-ID"]
    assert "redis" not in response.text.lower()
    assert "secret" not in response.text.lower()
