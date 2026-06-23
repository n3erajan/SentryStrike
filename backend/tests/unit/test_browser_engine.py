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


def test_browser_json_observation_metadata_preserves_body_and_replay_headers():
    engine = BrowserDiscoveryEngine()
    raw_body = '{"email":"alice@example.test","profile":{"name":"Alice"}}'
    headers = engine._normalize_request_headers(
        {
            "Content-Type": "application/json",
            "Authorization": "Bearer token",
            "X-CSRF-Token": "abc",
            "Content-Length": "55",
            "Sec-Fetch-Site": "same-origin",
        }
    )
    body_kind, body_schema, multipart_fields = engine._request_body_metadata(raw_body, headers["content-type"])

    assert headers == {
        "content-type": "application/json",
        "authorization": "Bearer token",
        "x-csrf-token": "abc",
    }
    assert raw_body == '{"email":"alice@example.test","profile":{"name":"Alice"}}'
    assert body_kind == "json"
    assert body_schema == ["email", "profile", "profile.name"]
    assert multipart_fields == []
    assert engine._is_replayable("POST", raw_body, headers["content-type"], body_schema, multipart_fields)


def test_browser_form_observation_metadata_extracts_fields():
    engine = BrowserDiscoveryEngine()
    body = "email=alice%40example.test&password=Secret123%21&csrf=abc"

    body_kind, body_schema, multipart_fields = engine._request_body_metadata(
        body,
        "application/x-www-form-urlencoded; charset=UTF-8",
    )

    assert body_kind == "form"
    assert body_schema == ["csrf", "email", "password"]
    assert multipart_fields == [
        {"name": "csrf", "type": "text"},
        {"name": "email", "type": "text"},
        {"name": "password", "type": "text"},
    ]
    assert engine._is_replayable("POST", body, "application/x-www-form-urlencoded", body_schema, multipart_fields)


def test_browser_multipart_observation_metadata_extracts_file_fields():
    engine = BrowserDiscoveryEngine()
    body = (
        '--abc\r\nContent-Disposition: form-data; name="avatar"; filename="old.png"\r\n\r\nx'
        '\r\n--abc\r\nContent-Disposition: form-data; name="userId"\r\n\r\n1\r\n--abc--'
    )

    body_kind, body_schema, multipart_fields = engine._request_body_metadata(
        body,
        "multipart/form-data; boundary=abc",
    )

    assert body_kind == "multipart"
    assert body_schema == ["avatar", "userId"]
    assert multipart_fields == [
        {"name": "avatar", "type": "file", "filename": "old.png"},
        {"name": "userId", "type": "text", "filename": None},
    ]
    assert engine._is_replayable("POST", body, "multipart/form-data; boundary=abc", body_schema, multipart_fields)


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


@pytest.mark.asyncio
async def test_workflow_explorer_exercises_multi_step_spa_and_file_inputs():
    class FakeElement:
        def __init__(self, page, attrs=None, text=""):
            self.page = page
            self.attrs = attrs or {}
            self.text = text

        async def is_visible(self):
            return True

        async def get_attribute(self, name):
            return self.attrs.get(name)

        async def inner_text(self, timeout=None):
            return self.text

        async def fill(self, value, timeout=None):
            self.page.filled[self.attrs.get("name", "field")] = value

        async def press(self, key, timeout=None):
            self.page.pressed.append(key)

        async def click(self, timeout=None):
            self.page.clicked.append(self.text or self.attrs.get("value", ""))
            self.page.step += 1
            self.page.url = f"http://example.test/#step-{self.page.step}"

        async def set_input_files(self, files, timeout=None):
            self.page.files = files

    class FakeLocator:
        def __init__(self, elements):
            self.elements = elements

        async def count(self):
            return len(self.elements)

        def nth(self, index):
            return self.elements[index]

        def locator(self, selector):
            return FakeLocator([])

    class FakePage:
        def __init__(self):
            self.url = "http://example.test/"
            self.step = 0
            self.clicked = []
            self.filled = {}
            self.pressed = []
            self.files = None

        def locator(self, selector):
            if selector == "form":
                return FakeLocator([FakeElement(self)])
            if selector == "input[type=file]":
                return FakeLocator([FakeElement(self, {"name": "avatar", "type": "file"})])
            if selector == "select":
                return FakeLocator([])
            if "input:not" in selector:
                return FakeLocator([FakeElement(self, {"name": "email", "type": "email"})])
            if selector.startswith("button"):
                return FakeLocator([])
            if "a[href]" in selector:
                if self.step == 0:
                    return FakeLocator([FakeElement(self, {"type": "button", "id": "next"}, "Next")])
                if self.step == 1:
                    return FakeLocator([FakeElement(self, {"type": "submit", "id": "submit"}, "Submit")])
            return FakeLocator([])

        async def evaluate(self, script):
            return f"step={self.step};email={'email' in self.filled};files={self.files is not None}"

        async def wait_for_load_state(self, state, timeout=None):
            return None

        async def wait_for_timeout(self, timeout):
            return None

    engine = BrowserDiscoveryEngine(max_interactions=5)
    original_username = engine.settings.authentication_username
    engine.settings.authentication_username = None
    page = FakePage()

    try:
        stats = await engine._exercise_page(page)
    finally:
        engine.settings.authentication_username = original_username

    assert page.clicked == ["Next", "Submit"]
    assert page.filled["email"] == "scanner@example.com"
    assert page.files["name"] == "sentry-upload.txt"
    assert stats["states"] >= 2
    assert stats["forms"] == 1
    assert stats["file_inputs"] == 1
