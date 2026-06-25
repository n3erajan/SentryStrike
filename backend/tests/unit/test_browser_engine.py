import asyncio
import inspect
import sys
import types

import pytest

from app.core.crawler.browser_engine import (
    BrowserDiscoveryEngine,
    _BOUNDED_FAILED,
)
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
        self._handlers.setdefault(event, []).append(handler)

    async def _fire(self, event, arg):
        for handler in self._handlers.get(event, []):
            result = handler(arg)
            if inspect.isawaitable(result):
                await result

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
        await self._fire("request", request)
        await self._fire("response", _FakeResponse(request))
        await self._fire("requestfinished", request)

    def locator(self, selector):
        return _FakeLocator([])

    async def evaluate(self, script, *args):
        # Non-SPA fake: programmatic routing "fails" so every route uses goto.
        if "pushState" in script or "location.hash" in script:
            raise RuntimeError("no SPA router")
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
    page = _FakePage(goto_sleep=0.2)
    _install_fake_playwright(monkeypatch, page)

    # High max_interactions so all routes are queued (not capped); each route
    # does a real goto (goto_sleep) so the deadline clearly truncates the queue.
    engine = BrowserDiscoveryEngine(max_interactions=20)
    state = CrawlState()
    loop = asyncio.get_running_loop()
    # Budget only allows a few navigations before truncation.
    deadline = loop.time() + 0.9

    routes = [f"/route-{i}" for i in range(10)]
    await engine.crawl_into(state, "http://spa.test/", routes=routes, deadline=deadline)

    # Partial: some but not all routes were visited.
    assert 0 < len(page.goto_calls) < len(routes) + 1
    # Streamed observations survived the truncation (>= one per navigation).
    assert len(state.requests) >= len(page.goto_calls)
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


# --- Task 2: SPA interaction & navigation --------------------------------


@pytest.mark.asyncio
async def test_bounded_skips_hanging_control():
    engine = BrowserDiscoveryEngine()

    async def hangs():
        await asyncio.sleep(5)
        return "done"

    result = await engine._bounded(hangs(), 50)
    assert result is _BOUNDED_FAILED


@pytest.mark.asyncio
async def test_bounded_returns_value_on_success():
    engine = BrowserDiscoveryEngine()

    async def quick():
        return "ok"

    assert await engine._bounded(quick(), 500) == "ok"


@pytest.mark.asyncio
async def test_clear_blocking_overlays_dismisses_when_intercepted():
    class _Keyboard:
        def __init__(self):
            self.pressed = []

        async def press(self, key, timeout=None):
            self.pressed.append(key)

    class _DismissButton:
        def __init__(self, page, label):
            self.page = page
            self.label = label

        async def is_visible(self):
            return True

        async def inner_text(self, timeout=None):
            return self.label

        async def get_attribute(self, name):
            return None

        async def click(self, timeout=None):
            self.page.clicked.append(self.label)

    class _Page:
        def __init__(self):
            self.keyboard = _Keyboard()
            self.clicked = []

        async def evaluate(self, script, *args):
            return True  # overlay intercepts the viewport centre

        def locator(self, selector):
            return _FakeLocator([_DismissButton(self, "Accept")])

        async def wait_for_load_state(self, state, timeout=None):
            return None

        async def wait_for_timeout(self, timeout):
            return None

    engine = BrowserDiscoveryEngine()
    page = _Page()
    await engine._clear_blocking_overlays(page)

    assert "Escape" in page.keyboard.pressed
    assert page.clicked == ["Accept"]


@pytest.mark.asyncio
async def test_clear_blocking_overlays_noop_when_clear():
    class _Page:
        def __init__(self):
            self.evaluated = False

        async def evaluate(self, script, *args):
            self.evaluated = True
            return False  # nothing intercepting

        def locator(self, selector):  # pragma: no cover - must not be reached
            raise AssertionError("should not query controls when not blocked")

    engine = BrowserDiscoveryEngine()
    page = _Page()
    await engine._clear_blocking_overlays(page)
    assert page.evaluated is True


@pytest.mark.asyncio
async def test_settle_inflight_terminates_at_cap():
    class _Page:
        async def wait_for_load_state(self, state, timeout=None):
            return None

    engine = BrowserDiscoveryEngine()
    loop = asyncio.get_running_loop()
    start = loop.time()
    # Requests never drain -> must return at the hard cap, not hang.
    await engine._settle_inflight(_Page(), {"count": 3}, quiet_ms=50, cap_ms=150)
    elapsed_ms = (loop.time() - start) * 1000
    assert 120 <= elapsed_ms < 900


@pytest.mark.asyncio
async def test_settle_inflight_returns_when_quiet():
    class _Page:
        async def wait_for_load_state(self, state, timeout=None):
            return None

    engine = BrowserDiscoveryEngine()
    loop = asyncio.get_running_loop()
    start = loop.time()
    await engine._settle_inflight(_Page(), {"count": 0}, quiet_ms=100, cap_ms=3000)
    elapsed_ms = (loop.time() - start) * 1000
    assert elapsed_ms < 1500


@pytest.mark.asyncio
async def test_discover_routes_filters_cross_origin():
    class _Page:
        url = "http://spa.test/current"

        async def evaluate(self, script, *args):
            if "__sentry_routes" in script:
                return ["http://spa.test/pushed", "http://evil.test/x"]
            if "a[href]" in script or "routerLink" in script:
                return ["http://spa.test/link", "/relative", "http://other.test/y"]
            return []

    engine = BrowserDiscoveryEngine()
    routes = await engine._discover_routes(_Page(), "http://spa.test/")

    assert "http://spa.test/pushed" in routes
    assert "http://spa.test/link" in routes
    assert "http://spa.test/relative" in routes
    assert all("evil.test" not in r and "other.test" not in r for r in routes)


@pytest.mark.asyncio
async def test_capture_forms_returns_structured_forms():
    class _Page:
        url = "http://spa.test/page"

        async def evaluate(self, script, *args):
            return [
                {
                    "action": "/submit",
                    "method": "post",
                    "inputs": [{"name": "email", "type": "email"}],
                }
            ]

    engine = BrowserDiscoveryEngine()
    forms = await engine._capture_forms(_Page(), "http://spa.test/page")

    assert forms == [
        {
            "action": "http://spa.test/submit",
            "method": "POST",
            "inputs": [{"name": "email", "type": "email"}],
            "page_url": "http://spa.test/page",
        }
    ]


class _FakeWebSocket:
    def __init__(self, url):
        self.url = url


class _RichFakePage:
    """SPA-like fake: goto loads root+fires XHR/WS; pushState changes route +
    fires an XHR; DOM exposes one discoverable link the first time it's asked."""

    def __init__(self):
        self.url = "http://spa.test/"
        self._handlers = {}
        self.goto_calls = []
        self._link_served = False
        self._ws_served = False

    def on(self, event, handler):
        self._handlers.setdefault(event, []).append(handler)

    async def _fire(self, event, arg):
        for handler in self._handlers.get(event, []):
            result = handler(arg)
            if inspect.isawaitable(result):
                await result

    async def _fire_xhr(self, url):
        request = _FakeRequest(url, method="GET", resource_type="fetch", post_data=None)
        await self._fire("request", request)
        await self._fire("response", _FakeResponse(request))
        await self._fire("requestfinished", request)

    async def goto(self, url, wait_until=None, timeout=None):
        self.goto_calls.append(url)
        self.url = url
        await self._fire_xhr(url.rstrip("/") + "/data")
        if not self._ws_served:
            self._ws_served = True
            await self._fire("websocket", _FakeWebSocket("ws://spa.test/socket"))

    def locator(self, selector):
        return _FakeLocator([])

    async def evaluate(self, script, *args):
        if "elementFromPoint" in script:
            return False
        if "__sentry_routes" in script:
            return []
        if "routerLink" in script:  # unique to DOM_LINK_SCRIPT
            if not self._link_served:
                self._link_served = True
                return ["http://spa.test/discovered"]
            return []
        if "querySelectorAll('form')" in script:
            return []
        if "pushState" in script:
            target = args[0] if args else "/"
            self.url = "http://spa.test" + target if target.startswith("/") else target
            await self._fire_xhr(self.url.rstrip("/") + "/api")
            return None
        if "location.hash" in script:
            return None
        return None

    async def wait_for_load_state(self, state, timeout=None):
        return None

    async def wait_for_timeout(self, timeout):
        return None


@pytest.mark.asyncio
async def test_crawl_into_discovers_and_visits_client_side_routes(monkeypatch):
    page = _RichFakePage()
    _install_fake_playwright(monkeypatch, page)

    engine = BrowserDiscoveryEngine(max_interactions=1)
    state = CrawlState()
    await engine.crawl_into(state, "http://spa.test/", routes=[])

    urls = [obs.url for obs in state.requests]
    # Root loaded via goto and fired its XHR.
    assert any(u.endswith("/data") for u in urls)
    # The DOM-discovered route was enqueued and visited via client-side nav,
    # firing its own XHR (no extra goto for it).
    assert any("/discovered" in u for u in urls)
    assert page.goto_calls == ["http://spa.test/"]
    # WebSocket endpoint recorded even without a body.
    ws = [obs for obs in state.requests if obs.resource_type == "websocket"]
    assert ws and ws[0].url == "ws://spa.test/socket"
    assert ws[0].replayable is False
