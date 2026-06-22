import pytest

from app.core.crawler.browser_engine import BrowserDiscoveryEngine
from app.core.crawler.models import RequestObservation


def test_browser_targets_visit_same_origin_routes_only():
    engine = BrowserDiscoveryEngine(max_interactions=3)

    targets = engine._browser_targets(
        "http://example.com/",
        [
            "http://example.com/admin",
            "http://evil.example/api",
            "/products",
            "/orders",
            "/ignored",
        ],
    )

    assert targets == [
        "http://example.com/",
        "http://example.com/admin",
        "http://example.com/products",
        "http://example.com/orders",
    ]


def test_browser_request_dedupe_uses_url_template_and_body_schema():
    engine = BrowserDiscoveryEngine()
    first = RequestObservation(
        url="http://example.com/api/users/1",
        method="POST",
        request_headers={"content-type": "application/json"},
        post_data='{"name":"alice","profile":{"id":1}}',
    )
    second = RequestObservation(
        url="http://example.com/api/users/2",
        method="POST",
        request_headers={"content-type": "application/json"},
        post_data='{"name":"bob","profile":{"id":2}}',
        response_status=200,
    )

    deduped = engine._dedupe_observations([first, second])

    assert len(deduped) == 1
    assert deduped[0].url == "http://example.com/api/users/2"
    assert engine._body_schema(second.post_data) == {"name", "profile", "profile.id"}


def test_browser_observation_key_preserves_same_url_different_bodies():
    assert BrowserDiscoveryEngine._observation_key(
        "http://example.com/api/login",
        "POST",
        '{"email":"a@example.com"}',
    ) != BrowserDiscoveryEngine._observation_key(
        "http://example.com/api/login",
        "POST",
        '{"email":"b@example.com"}',
    )


@pytest.mark.asyncio
async def test_browser_field_values_use_configured_credentials():
    class Field:
        def __init__(self, attrs):
            self.attrs = attrs

        async def get_attribute(self, name):
            return self.attrs.get(name)

    engine = BrowserDiscoveryEngine()
    original_username = engine.settings.authentication_username
    original_password = engine.settings.authentication_password

    try:
        engine.settings.authentication_username = "alice@example.test"
        engine.settings.authentication_password = "CorrectHorseBatteryStaple"

        assert await engine._value_for_field(Field({"name": "email", "type": "email"})) == "alice@example.test"
        assert await engine._value_for_field(Field({"name": "password", "type": "password"})) == "CorrectHorseBatteryStaple"
    finally:
        engine.settings.authentication_username = original_username
        engine.settings.authentication_password = original_password
