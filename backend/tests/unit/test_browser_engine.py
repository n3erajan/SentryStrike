import asyncio
import sys
import types

import pytest

from app.core.crawler.browser_engine import BrowserDiscoveryEngine
from app.core.crawler.models import CrawlState, RequestObservation


# --- Fake Playwright scaffolding for streaming/truncation tests -------------


class _FakeRequest:
    def __init__(self, url, method="POST", resource_type="xhr", post_data=None, headers=None):
        self.url = url
        self.method = method
        self.resource_type = resource_type
        self.post_data = post_data
        self._headers = headers or {"content-type": "application/json"}
        self.redirected_from = None

    async def all_headers(self):
        return dict(self._headers)


class _FakeResponse:
    def __init__(self, request, status=200, text="{}"):
        self.request = request
        self.status = status
        self.headers = {"content-type": "application/json"}
        self._text = text

    async def text(self):
        return self._text


class _FakeLocator:
    def __init__(self, elements=None):
        self._elements = elements or []

    async def count(self):
        return len(self._elements)

    def nth(self, index):
        return self._elements[index]

    def locator(self, selector):
        return _FakeLocator([])


class _FakePage:
    """Fires one XHR per navigation, and sleeps so a deadline can truncate."""

    def __init__(self, goto_sleep=0.1):
        self.url = "http://spa.test/"
        self._handlers = {}
        self.goto_sleep = goto_sleep
        self.goto_calls = []

    def on(self, event, handler):
        self._handlers[event] = handler

    async def goto(self, url, wait_until=None, timeout=None):
        self.goto_calls.append(url)
        self.url = url
        await asyncio.sleep(self.goto_sleep)
        request = _FakeRequest(
            url.rstrip("/") + "/xhr",
            method="POST",
            resource_type="xhr",
            post_data='{"a":1}',
        )
        await self._handlers["request"](request)
        await self._handlers["response"](_FakeResponse(request))

    def locator(self, selector):
        return _FakeLocator([])

    async def evaluate(self, script):
        return ""

    async def wait_for_load_state(self, state, timeout=None):
        return None

    async def wait_for_timeout(self, timeout):
        return None


class _FakeContext:
    def __init__(self, page):
        self._page = page

    async def add_cookies(self, cookies):
        return None

    async def set_extra_http_headers(self, headers):
        return None

    async def new_page(self):
        return self._page

    async def close(self):
        return None


class _FakeBrowser:
    def __init__(self, page):
        self._page = page

    async def new_context(self):
        return _FakeContext(self._page)

    async def close(self):
        return None


class _FakeChromium:
    def __init__(self, page):
        self._page = page

    async def launch(self, headless=True):
        return _FakeBrowser(self._page)


class _FakePlaywright:
    def __init__(self, page):
        self.chromium = _FakeChromium(page)


class _FakePlaywrightCM:
    def __init__(self, page):
        self._page = page

    async def __aenter__(self):
        return _FakePlaywright(self._page)

    async def __aexit__(self, *exc):
        return False


def _install_fake_playwright(monkeypatch, page):
    module = types.ModuleType("playwright.async_api")
    module.async_playwright = lambda: _FakePlaywrightCM(page)
    monkeypatch.setitem(sys.modules, "playwright.async_api", module)


@pytest.mark.asyncio
async def test_crawl_into_streams_partial_results_and_survives_deadline(monkeypatch):
    page = _FakePage(goto_sleep=0.1)
    _install_fake_playwright(monkeypatch, page)

    engine = BrowserDiscoveryEngine(max_interactions=2)
    state = CrawlState()
    loop = asyncio.get_running_loop()
    # Budget only allows a couple of navigations before truncation.
    deadline = loop.time() + 0.15

    routes = [f"/route-{i}" for i in range(10)]
    await engine.crawl_into(state, "http://spa.test/", routes=routes, deadline=deadline)

    # Partial: some but not all routes were visited.
    assert 0 < len(page.goto_calls) < len(routes) + 1
    # Streamed observations survived the truncation.
    assert len(state.requests) == len(page.goto_calls)
    # Availability reflects reality; error explains the truncation.
    assert state.browser_available is True
    assert state.browser_error is not None
    assert "truncat" in state.browser_error.lower()
    # Endpoints/params were derived from the partial observations.
    assert state.api_endpoints
    assert state.parameters


@pytest.mark.asyncio
async def test_crawl_into_reports_unavailable_when_launch_fails(monkeypatch):
    class _FailingChromium:
        async def launch(self, headless=True):
            raise RuntimeError("browser binary missing")

    class _FailingPlaywright:
        def __init__(self):
            self.chromium = _FailingChromium()

    class _FailingCM:
        async def __aenter__(self):
            return _FailingPlaywright()

        async def __aexit__(self, *exc):
            return False

    module = types.ModuleType("playwright.async_api")
    module.async_playwright = lambda: _FailingCM()
    monkeypatch.setitem(sys.modules, "playwright.async_api", module)

    engine = BrowserDiscoveryEngine()
    state = CrawlState()
    await engine.crawl_into(state, "http://spa.test/")

    # Launch failure must not regress: availability False with a recorded error.
    assert state.browser_available is False
    assert state.browser_error


@pytest.mark.asyncio
async def test_crawl_wrapper_returns_populated_state(monkeypatch):
    page = _FakePage(goto_sleep=0.0)
    _install_fake_playwright(monkeypatch, page)

    engine = BrowserDiscoveryEngine(max_interactions=1)
    state = await engine.crawl("http://spa.test/", routes=["/a"])

    assert isinstance(state, CrawlState)
    assert state.browser_available is True
    assert state.requests


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
