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

    async def content(self):
        # Authenticated shell by default (no login form) so the liveness probe
        # does not flag a regression in storage_state tests.
        return "<html><body><app-root>dashboard</app-root></body></html>"


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
        self.new_context_kwargs = []

    async def new_context(self, **kwargs):
        self.new_context_kwargs.append(kwargs)
        return _FakeContext(self._page)

    async def close(self):
        return None


class _FakeChromium:
    def __init__(self, page):
        self._page = page
        self.last_browser = None

    async def launch(self, headless=True):
        self.last_browser = _FakeBrowser(self._page)
        return self.last_browser


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
    # Seed set is bounded by the route cap (Task B), not the per-page interaction
    # budget, so all same-origin routes are enqueued regardless of max_interactions.
    engine = BrowserDiscoveryEngine(max_interactions=3)

    targets = engine._browser_targets(
        "http://example.com/",
        [
            "http://example.com/admin",
            "http://evil.example/api",  # cross-origin -> dropped
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
        "http://example.com/ignored",
    ]
    # The cross-origin route is never a target.
    assert "http://evil.example/api" not in targets


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


# --- Task A: full authenticated storage_state propagation -------------------


@pytest.mark.asyncio
async def test_crawl_into_seeds_context_from_storage_state(monkeypatch):
    """When a storage_state blob is supplied it must be passed straight into
    ``browser.new_context(storage_state=...)`` so the SPA's own JS finds its
    token (cookies + per-origin localStorage/sessionStorage restored)."""
    page = _FakePage(goto_sleep=0.0)
    _install_fake_playwright(monkeypatch, page)

    storage_blob = {"cookies": [{"name": "s", "value": "1"}], "origins": []}
    engine = BrowserDiscoveryEngine(max_interactions=1)
    state = CrawlState()

    captured = {}
    orig_launch = _FakeChromium.launch

    async def _spy_launch(self, headless=True):
        browser = await orig_launch(self, headless=headless)
        captured["browser"] = browser
        return browser

    monkeypatch.setattr(_FakeChromium, "launch", _spy_launch)

    await engine.crawl_into(
        state, "http://spa.test/", routes=[], storage_state=storage_blob,
    )

    kwargs_seen = captured["browser"].new_context_kwargs
    assert any(kw.get("storage_state") == storage_blob for kw in kwargs_seen)


@pytest.mark.asyncio
async def test_crawl_into_falls_back_to_bare_context_without_storage_state(monkeypatch):
    """No storage_state → plain ``new_context()`` (cookie/header injection path),
    preserving the pre-Task-A behavior for cookie-auth and static-auth apps."""
    page = _FakePage(goto_sleep=0.0)
    _install_fake_playwright(monkeypatch, page)

    engine = BrowserDiscoveryEngine(max_interactions=1)
    state = CrawlState()

    captured = {}
    orig_launch = _FakeChromium.launch

    async def _spy_launch(self, headless=True):
        browser = await orig_launch(self, headless=headless)
        captured["browser"] = browser
        return browser

    monkeypatch.setattr(_FakeChromium, "launch", _spy_launch)

    await engine.crawl_into(
        state, "http://spa.test/", auth_cookies={"sid": "x"}, routes=[],
    )

    kwargs_seen = captured["browser"].new_context_kwargs
    assert all("storage_state" not in kw for kw in kwargs_seen)


@pytest.mark.asyncio
async def test_crawl_into_flags_lost_session_when_still_logged_out(monkeypatch):
    """Liveness re-check: seeding storage_state but rendering a logged-out shell
    (login form + SPA markers) must record the RC-A regression error."""

    class _LoggedOutPage(_FakePage):
        async def content(self):
            return (
                "<html><body><app-root>"
                "<form><input type='password' name='pw'></form>"
                "</app-root></body></html>"
            )

    page = _LoggedOutPage(goto_sleep=0.0)
    _install_fake_playwright(monkeypatch, page)

    engine = BrowserDiscoveryEngine(max_interactions=1)
    state = CrawlState()
    await engine.crawl_into(
        state, "http://spa.test/", routes=[],
        storage_state={"cookies": [], "origins": []},
    )

    assert state.browser_error == (
        "authenticated session did not persist into browser context"
    )


# --- Task B: value-ordered, submission-driven crawl -------------------------


def test_effective_deadline_scales_with_route_count_and_is_capped():
    engine = BrowserDiscoveryEngine()
    engine.settings.crawl_browser_base_seconds = 10.0
    engine.settings.crawl_browser_per_route_seconds = 5.0
    engine.settings.crawl_browser_route_cap = 100
    engine.settings.crawl_browser_budget_seconds = 300.0

    class _Loop:
        def time(self):
            return 1000.0

    loop = _Loop()
    # 2 routes -> base + 5*2 = 20s window.
    d2 = engine._effective_deadline(2000.0, loop, 2)
    assert d2 == 1000.0 + 20.0
    # Many routes -> scaled window would exceed configured budget -> capped.
    dbig = engine._effective_deadline(9999.0, loop, 1000)
    assert dbig == 1000.0 + 300.0
    # Never exceeds the caller's hard deadline.
    dclamped = engine._effective_deadline(1005.0, loop, 1000)
    assert dclamped == 1005.0
    # No deadline supplied -> no bound.
    assert engine._effective_deadline(None, loop, 5) is None


def test_budget_allows_interaction_gates_when_little_time_left():
    engine = BrowserDiscoveryEngine()
    engine.settings.crawl_browser_budget_seconds = 100.0

    class _Loop:
        def __init__(self, now):
            self._now = now

        def time(self):
            return self._now

    # Plenty of budget left -> interaction allowed.
    assert engine._budget_allows_interaction(1000.0, _Loop(950.0)) is True
    # Almost no budget left -> interaction gated off.
    assert engine._budget_allows_interaction(1000.0, _Loop(999.0)) is False
    # None deadline -> always allowed.
    assert engine._budget_allows_interaction(None, _Loop(0.0)) is True


class _SubmitFakePage:
    """Records fills/clicks and fires a POST XHR with a body when submitted."""

    def __init__(self):
        self.url = "http://spa.test/login"
        self._handlers = {}
        self.fills = []
        self.checks = []
        self.submit_clicks = 0

    def on(self, event, handler):
        self._handlers.setdefault(event, []).append(handler)

    async def _fire(self, event, arg):
        for handler in self._handlers.get(event, []):
            result = handler(arg)
            if inspect.isawaitable(result):
                await result

    async def fill(self, selector, value, timeout=None):
        self.fills.append((selector, value))

    async def check(self, selector, timeout=None):
        self.checks.append(selector)

    def locator(self, selector):
        page = self

        class _L:
            def __init__(self, sel):
                self._sel = sel
                self.first = self

            async def count(self):
                return 1 if "submit" in self._sel else 0

            async def click(self, timeout=None):
                page.submit_clicks += 1
                # Submitting fires the app's real POST XHR with a body.
                request = _FakeRequest(
                    "http://spa.test/rest/user/login",
                    method="POST",
                    resource_type="xhr",
                    post_data='{"email":"scanner@example.com","password":"Password123!"}',
                )
                await page._fire("request", request)
                await page._fire("requestfinished", request)

        return _L(selector)

    async def evaluate(self, script, *args):
        return None

    async def goto(self, url, wait_until=None, timeout=None):
        self.url = url


@pytest.mark.asyncio
async def test_submit_discovered_forms_fills_submits_and_captures_body():
    engine = BrowserDiscoveryEngine()
    page = _SubmitFakePage()
    captured = []
    page.on("request", lambda r: captured.append(r))

    form = {
        "action": "http://spa.test/rest/user/login",
        "method": "POST",
        "inputs": [
            {"name": "email", "type": "email"},
            {"name": "password", "type": "password"},
        ],
    }
    submitted: set = set()
    await engine._submit_discovered_forms(
        page, [form], "http://spa.test/", "http://spa.test/login", submitted,
    )

    # Both fields were filled with typed placeholders.
    assert any("email" in sel for sel, _ in page.fills)
    assert any("password" in sel for sel, _ in page.fills)
    assert page.submit_clicks == 1
    # The submission fired a POST XHR carrying a real body.
    posts = [r for r in captured if r.method == "POST" and r.post_data]
    assert posts and "password" in posts[0].post_data
    # Form key recorded for dedup.
    assert submitted


@pytest.mark.asyncio
async def test_submit_discovered_forms_skips_destructive_and_dedups():
    engine = BrowserDiscoveryEngine()
    page = _SubmitFakePage()

    destructive = {
        "action": "http://spa.test/account/delete",
        "method": "POST",
        "inputs": [{"name": "confirm", "type": "text"}],
    }
    submitted: set = set()
    await engine._submit_discovered_forms(
        page, [destructive], "http://spa.test/", "http://spa.test/account", submitted,
    )
    # Destructive form never submitted, but keyed so it is not retried.
    assert page.submit_clicks == 0
    assert submitted

    # Re-submitting an already-seen form key is a no-op.
    prev = len(page.fills)
    await engine._submit_discovered_forms(
        page, [destructive], "http://spa.test/", "http://spa.test/account", submitted,
    )
    assert len(page.fills) == prev


@pytest.mark.asyncio
async def test_crawl_into_visits_high_value_routes_first(monkeypatch):
    """A short budget must still reach high-surface routes: the priority queue
    orders auth/search/api routes ahead of generic content pages."""
    page = _FakePage(goto_sleep=0.0)
    _install_fake_playwright(monkeypatch, page)

    engine = BrowserDiscoveryEngine(max_interactions=1)
    state = CrawlState()
    routes = [
        "/about",
        "/blog",
        "/rest/user/login",
        "/search?q=test",
        "/contact",
    ]
    await engine.crawl_into(state, "http://spa.test/", routes=routes)

    # Root is visited first (seeded), then high-value routes precede generic
    # ones in goto order. Find positions of a high-value vs a generic route.
    order = page.goto_calls
    login_idx = next((i for i, u in enumerate(order) if "login" in u), None)
    about_idx = next((i for i, u in enumerate(order) if "about" in u), None)
    assert login_idx is not None and about_idx is not None
    assert login_idx < about_idx
