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


def test_client_route_key_matches_bare_and_hash_forms():
    """A route mined as a bare path and its rendered hash-router form must key
    identically, so a router-defined route is recognised at the not-found
    suppression site and kept alive (not dropped as dead)."""
    key = BrowserDiscoveryEngine._client_route_key
    assert key("http://x/#/search") == key("http://x/search") == "/search"
    assert key("http://x/#/track-result?id=1") == "/track-result"
    assert key("http://x/#!/login") == key("http://x/login/") == "/login"
    # Distinct routes stay distinct.
    assert key("http://x/#/search") != key("http://x/#/administration")


def test_server_endpoint_from_dead_route_reconstructs_query_endpoint():
    """A hash-routed SPA canonicalises a real server anchor (``./redirect?to=X``)
    into a dead hash route (``#/redirect?to=X``). When that route renders the
    not-found shell, reconstruct the same-origin HTTP endpoint from the fragment
    so the HTTP detectors receive its query params (the open-redirect miss)."""
    recon = BrowserDiscoveryEngine._server_endpoint_from_dead_route
    got = recon("http://x/#/redirect?to=https://github.com/juice-shop/juice-shop")
    assert got.startswith("http://x/redirect?")
    assert "to=" in got
    # The allowlisted target value round-trips through parse/re-encode.
    from urllib.parse import parse_qs, urlparse
    assert parse_qs(urlparse(got).query)["to"] == [
        "https://github.com/juice-shop/juice-shop"
    ]


def test_server_endpoint_from_dead_route_ignores_paramless_and_api_routes():
    """A dead route with no query (an ordinary brute-force/client dead route such
    as ``#/wp-admin``) or a root API path stays dead — never resurrected as an
    HTTP endpoint."""
    recon = BrowserDiscoveryEngine._server_endpoint_from_dead_route
    assert recon("http://x/#/wp-admin") == ""          # no query, no extension
    assert recon("http://x/#/administration") == ""    # no query, no extension
    assert recon("http://x/#/api/users?id=1") == ""    # root API path, already covered
    assert recon("http://x/#/?to=evil") == ""          # empty path


def test_server_endpoint_from_dead_route_reconstructs_served_file():
    """A hash-routed SPA canonicalises a real served-file anchor
    (``./ftp/legal.md``) into a dead hash route (``#/ftp/legal.md``). A query-less
    path whose last segment has a file extension is a real static resource the
    router swallowed — reconstruct its plain server URL (the ``/ftp/:file`` path
    traversal / arbitrary-file-read discovery miss). A bare route word stays dead."""
    recon = BrowserDiscoveryEngine._server_endpoint_from_dead_route
    assert recon("http://x/#/ftp/legal.md") == "http://x/ftp/legal.md"
    assert recon("http://x/#/ftp/package.json.bak") == "http://x/ftp/package.json.bak"
    assert recon("http://x/#!/reports/q3.pdf") == "http://x/reports/q3.pdf"
    # Extension-less client route words are NOT served files → stay dead.
    assert recon("http://x/#/search") == ""
    assert recon("http://x/#/order-history") == ""


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
        self.route_patterns = []

    async def add_cookies(self, cookies):
        return None

    async def set_extra_http_headers(self, headers):
        return None

    async def add_init_script(self, script):
        return None

    async def route(self, pattern, handler):
        self.route_patterns.append(pattern)

    async def new_page(self):
        return self._page

    async def close(self):
        return None


class _FakeBrowser:
    def __init__(self, page):
        self._page = page
        self.new_context_kwargs = []
        self.contexts = []

    async def new_context(self, **kwargs):
        self.new_context_kwargs.append(kwargs)
        context = _FakeContext(self._page)
        self.contexts.append(context)
        return context

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
async def test_crawl_into_terminates_when_a_worker_hangs_on_unbounded_await(monkeypatch):
    """A single worker stuck on an unbounded inline await must not freeze the
    whole pool. In production a never-closing response body / socket.io stream
    wedged a worker; the other workers parked in ``cond.wait()`` and the crawl
    hung forever (only Ctrl+C broke it). The pool-level watchdog must cancel a
    stuck worker at ``deadline + grace`` so the crawl always terminates and
    still merges whatever streamed in."""
    page = _FakePage(goto_sleep=0.0)
    _install_fake_playwright(monkeypatch, page)

    engine = BrowserDiscoveryEngine(max_interactions=20)
    # Small grace so the backstop fires fast in the test (default is ~20s).
    engine._pool_stuck_grace_s = 0.3

    # Every worker wedges on its first route the instant it reaches this inline
    # step — a stand-in for a body read / stream that never resolves. It is a
    # cancellable await, matching a real Playwright await (the Python task
    # unwinds on cancel even though the browser-side op may linger).
    async def _hang(_page):
        await asyncio.Event().wait()

    monkeypatch.setattr(engine, "_clear_blocking_overlays", _hang)

    state = CrawlState()
    loop = asyncio.get_running_loop()
    deadline = loop.time() + 0.5

    # Guard: if the watchdog is absent the pool never joins and this awaits
    # forever, so bound the whole call. A green run returns well under the guard.
    await asyncio.wait_for(
        engine.crawl_into(
            state,
            "http://spa.test/",
            routes=[f"/route-{i}" for i in range(6)],
            deadline=deadline,
        ),
        timeout=5.0,
    )

    # Browser launched, so availability is truthful, and truncation is recorded.
    assert state.browser_available is True
    assert state.browser_error is not None
    assert "truncat" in state.browser_error.lower()


@pytest.mark.asyncio
async def test_crawl_into_abandons_a_route_that_hangs_and_continues(monkeypatch, caplog):
    """A single route whose processing wedges on an unbounded await must be
    abandoned at the per-route cap so the worker moves on — one bad route may
    never stall a worker until the (much later) pool watchdog. The deadline is
    set far in the future so ONLY the per-route cap can rescue the run: if it is
    absent the workers hang and the guard below times out."""
    page = _FakePage(goto_sleep=0.0)
    _install_fake_playwright(monkeypatch, page)

    engine = BrowserDiscoveryEngine(max_interactions=20)
    engine.settings.crawl_browser_route_cap_seconds = 0.3  # abandon fast in-test

    async def _hang(_page):
        await asyncio.Event().wait()

    monkeypatch.setattr(engine, "_clear_blocking_overlays", _hang)

    state = CrawlState()
    loop = asyncio.get_running_loop()
    # Far-off budget: the global pool watchdog (budget + 20s grace) cannot be
    # what saves this within the guard window — only per-route abandonment can.
    deadline = loop.time() + 120.0

    with caplog.at_level("WARNING", logger="app.core.crawler.browser_engine"):
        await asyncio.wait_for(
            engine.crawl_into(
                state,
                "http://spa.test/",
                routes=[f"/route-{i}" for i in range(6)],
                deadline=deadline,
            ),
            timeout=8.0,
        )

    assert state.browser_available is True
    # Every stuck route was abandoned by name, and the crawl still finished.
    assert any("per-route cap" in r.message for r in caplog.records)


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


@pytest.mark.asyncio
async def test_crawl_into_filters_off_origin_runtime_requests(monkeypatch):
    class _MixedOriginPage(_FakePage):
        async def goto(self, url, wait_until=None, timeout=None):
            self.goto_calls.append(url)
            self.url = url
            same_origin = _FakeRequest(
                "http://spa.test/api/profile",
                method="POST",
                resource_type="fetch",
                post_data='{"name":"Ada"}',
            )
            document_post = _FakeRequest(
                "http://spa.test/profile/update",
                method="POST",
                resource_type="document",
                post_data="displayName=Ada",
                headers={"content-type": "application/x-www-form-urlencoded"},
            )
            off_origin = _FakeRequest(
                "https://analytics.example/collect",
                method="POST",
                resource_type="fetch",
                post_data='{"event":"page"}',
            )
            await self._fire("request", same_origin)
            await self._fire("response", _FakeResponse(same_origin))
            await self._fire("requestfinished", same_origin)
            await self._fire("request", document_post)
            await self._fire("response", _FakeResponse(document_post))
            await self._fire("requestfinished", document_post)
            await self._fire("request", off_origin)
            await self._fire("response", _FakeResponse(off_origin))
            await self._fire("requestfinished", off_origin)

    page = _MixedOriginPage(goto_sleep=0.0)
    _install_fake_playwright(monkeypatch, page)

    engine = BrowserDiscoveryEngine(max_interactions=1)
    state = CrawlState()
    await engine.crawl_into(state, "http://spa.test/", routes=[])

    urls = [request.url for request in state.requests]
    assert "http://spa.test/api/profile" in urls
    assert "http://spa.test/profile/update" in urls
    assert "https://analytics.example/collect" not in urls


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


def test_browser_navigable_gate_excludes_api_and_asset_leaves():
    """The browser navigation gate keeps the finite budget on HTML/app routes:
    raw API/data/asset leaves (which render as a dead <pre>/bytes and bear no
    forms or client-side routes) are excluded, while app pages and hash-router
    routes are always navigable."""
    nav = BrowserDiscoveryEngine._is_browser_navigable
    # Raw API/data/asset leaves — excluded (already covered by the HTTP crawler).
    assert nav("http://x.test/api/Feedbacks") is False
    assert nav("http://x.test/rest/products/search") is False
    assert nav("http://x.test/graphql") is False
    assert nav("http://x.test/assets/i18n/en.json") is False
    assert nav("http://x.test/main.js") is False
    assert nav("http://x.test/logo.png") is False
    # App pages and hash-router routes — always navigable.
    assert nav("http://x.test/") is True
    assert nav("http://x.test/login") is True
    assert nav("http://x.test/#/register") is True
    assert nav("http://x.test/#/search?q=test") is True
    assert nav("http://x.test/api-docs") is True  # Swagger HTML page, not an /api leaf
    assert nav("http://x.test/products/42") is True


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


@pytest.mark.parametrize(
    "raw_body",
    [
        "[{\"id\":1},{\"id\":2}]",  # top-level array — schema inference yields entries
        "[1,2,3]",                    # top-level array of primitives — empty schema
        "{}",                          # empty object — empty schema
        "\"just-a-string\"",         # top-level JSON primitive
    ],
)
def test_browser_json_body_replayable_even_when_schema_empty(raw_body):
    """P0-1: an observed JSON body must be replayable whenever it parses as
    JSON, not only when schema inference produced a non-empty field list. Empty
    objects, top-level arrays, and primitive JSON bodies were being dropped,
    collapsing ``replayable_json_bodies`` to 0 on real SPA traffic."""
    engine = BrowserDiscoveryEngine()
    _, body_schema, multipart_fields = engine._request_body_metadata(raw_body, "application/json")
    assert engine._is_replayable("POST", raw_body, "application/json", body_schema, multipart_fields)


def test_browser_json_body_not_replayable_when_unparseable():
    """A JSON content-type carrying a truncated/binary body stays non-replayable."""
    engine = BrowserDiscoveryEngine()
    assert not engine._is_replayable("POST", "{not valid json", "application/json", [], [])


@pytest.mark.asyncio
async def test_build_observation_marks_large_body_truncated_and_not_replayable():
    class _LargeRequest:
        url = "http://spa.test/api/bulk"
        method = "POST"
        resource_type = "xhr"
        redirected_from = None
        post_data = '{"blob":"' + ("x" * 70000) + '"}'

        async def all_headers(self):
            return {"content-type": "application/json"}

    engine = BrowserDiscoveryEngine()
    observation = await engine._build_request_observation(_LargeRequest())

    assert observation.body_source == "playwright_post_data"
    assert observation.body_capture_status == "truncated"
    assert observation.capture_error
    assert len(observation.post_data) == 64000
    assert observation.replayable is False


def test_auth_cookie_entries_targets_origin():
    """P1-3: auth cookies are turned into origin-scoped Playwright cookie dicts."""
    engine = BrowserDiscoveryEngine()
    entries = engine._auth_cookie_entries("http://target.test:8080/app", {"session": "abc", "csrf": "d"})
    assert {e["name"] for e in entries} == {"session", "csrf"}
    assert all(e["domain"] == "target.test" for e in entries)
    assert all(e["path"] == "/app" for e in entries)
    # No cookies -> empty list.
    assert engine._auth_cookie_entries("http://x/", {}) == []


@pytest.mark.asyncio
async def test_reseed_session_readds_cookies_and_is_failsafe():
    """P1-3: mid-crawl session recovery re-applies auth cookies, never raising."""
    engine = BrowserDiscoveryEngine()

    class _Ctx:
        def __init__(self, fail=False):
            self.added = []
            self._fail = fail

        async def add_cookies(self, entries):
            if self._fail:
                raise RuntimeError("context closed")
            self.added.extend(entries)

    entries = [{"name": "session", "value": "abc", "domain": "x", "path": "/"}]

    ok_ctx = _Ctx()
    assert await engine._reseed_session(ok_ctx, entries) is True
    assert ok_ctx.added == entries

    # No entries -> no-op, returns False.
    assert await engine._reseed_session(ok_ctx, []) is False

    # A raising context is swallowed (crawl must not abort).
    assert await engine._reseed_session(_Ctx(fail=True), entries) is False


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
async def test_build_observation_survives_binary_post_data():
    """A binary/gzip request body must not crash the on_request handler.

    Playwright's ``post_data`` raises UnicodeDecodeError on non-UTF-8 bodies;
    the engine falls back to ``post_data_buffer`` decoded leniently.
    """
    class _BinaryRequest:
        url = "http://spa.test/upload"
        method = "POST"
        resource_type = "xhr"
        redirected_from = None

        @property
        def post_data(self):
            raise UnicodeDecodeError("utf-8", b"\x1f\x8b", 1, 2, "invalid start byte")

        @property
        def post_data_buffer(self):
            return b"\x1f\x8b\x08rawgzip"

        async def all_headers(self):
            return {"content-type": "application/octet-stream"}

    engine = BrowserDiscoveryEngine()
    request = _BinaryRequest()

    # Safe accessor returns a lenient decode instead of raising.
    assert engine._safe_post_data(request) is not None
    # Full observation build does not propagate the decode error.
    observation = await engine._build_request_observation(request)
    assert observation.url == "http://spa.test/upload"
    assert observation.method == "POST"


@pytest.mark.asyncio
async def test_safe_post_data_returns_none_when_unavailable():
    class _NoBodyRequest:
        @property
        def post_data(self):
            raise UnicodeDecodeError("utf-8", b"\x8b", 0, 1, "invalid start byte")

        @property
        def post_data_buffer(self):
            return None

    engine = BrowserDiscoveryEngine()
    assert engine._safe_post_data(_NoBodyRequest()) is None


@pytest.mark.asyncio
async def test_browser_field_values_use_configured_credentials():
    class Field:
        def __init__(self, attrs):
            self.attrs = attrs

        async def get_attribute(self, name):
            return self.attrs.get(name)

    # Per-scan credentials are passed to the engine constructor, not read from env.
    engine = BrowserDiscoveryEngine(
        auth_username="alice@example.test",
        auth_password="CorrectHorseBatteryStaple",
    )

    assert await engine._value_for_field(Field({"name": "email", "type": "email"})) == "alice@example.test"
    assert await engine._value_for_field(Field({"name": "password", "type": "password"})) == "CorrectHorseBatteryStaple"


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

    # No per-scan credentials supplied: form-fill uses safe synthetic values.
    engine = BrowserDiscoveryEngine(max_interactions=5)
    page = FakePage()

    stats = await engine._exercise_page(page)

    assert page.clicked == ["Next", "Submit"]
    assert page.filled["email"] == "scanner@example.com"
    assert page.files["name"] == "sentry-upload.txt"
    assert stats["states"] >= 2
    assert stats["forms"] == 1
    assert stats["file_inputs"] == 1


@pytest.mark.asyncio
async def test_exercise_page_stops_at_time_budget(monkeypatch):
    """RC2: blind clicking must yield to a per-route time budget so one deep
    page cannot consume the budget owed to unvisited routes. ``max_seconds=0``
    stops before any interaction; ``None`` keeps the legacy count-only bound."""
    engine = BrowserDiscoveryEngine(max_interactions=50)
    interactions = {"n": 0}

    async def _noop(*args, **kwargs):
        return None

    async def _sig(*args, **kwargs):
        return f"state-{interactions['n']}"

    async def _count(*args, **kwargs):
        return 0

    class _El:
        async def click(self, timeout=None):
            interactions["n"] += 1

    async def _next(_page, _attempted):
        # A fresh control key each time so nothing is deduped away.
        return _El(), f"ctrl-{interactions['n']}"

    monkeypatch.setattr(engine, "_clear_blocking_overlays", _noop)
    monkeypatch.setattr(engine, "_ui_state_signature", _sig)
    monkeypatch.setattr(engine, "_count_locator", _count)
    monkeypatch.setattr(engine, "_prepare_interactive_inputs", _noop)
    monkeypatch.setattr(engine, "_next_interaction", _next)
    monkeypatch.setattr(engine, "_wait_after_interaction", _noop)

    # Zero budget: the loop breaks before the first interaction.
    await engine._exercise_page(object(), max_seconds=0)
    assert interactions["n"] == 0

    # No budget: the full count-based bound applies.
    interactions["n"] = 0
    await engine._exercise_page(object(), max_seconds=None)
    assert interactions["n"] == 50


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
            # One literal <form> cluster and one <form>-less orphan cluster with
            # a file input — the pattern RC-1 previously missed entirely.
            return [
                {
                    "cluster_id": 0,
                    "action": "/submit",
                    "method": "post",
                    "inputs": [{"name": "email", "type": "email", "field_id": "0:0"}],
                    "has_form": True,
                    "file_inputs": 0,
                },
                {
                    "cluster_id": 1,
                    "action": "/upload",
                    "method": "POST",
                    "inputs": [
                        {"name": "avatar", "type": "file", "field_id": "1:0"},
                        {"name": "bio", "type": "text", "field_id": "1:1"},
                    ],
                    "has_form": False,
                    "file_inputs": 1,
                },
            ]

    engine = BrowserDiscoveryEngine()
    forms = await engine._capture_forms(_Page(), "http://spa.test/page")

    assert forms == [
        {
            "action": "http://spa.test/submit",
            "method": "POST",
            "inputs": [
                {
                    "name": "email",
                    "type": "email",
                    "field_id": "0:0",
                    "named": True,
                    "hint": "",
                    "required": False,
                    "maxlength": None,
                    "minlength": None,
                    "pattern": None,
                    "min": None,
                    "max": None,
                }
            ],
            "cluster_id": 0,
            "has_form": True,
            "file_inputs": 0,
            "no_submit": False,
            "page_url": "http://spa.test/page",
            "all_named": True,
        },
        {
            "action": "http://spa.test/upload",
            "method": "POST",
            "inputs": [
                {
                    "name": "avatar",
                    "type": "file",
                    "field_id": "1:0",
                    "named": True,
                    "hint": "",
                    "required": False,
                    "maxlength": None,
                    "minlength": None,
                    "pattern": None,
                    "min": None,
                    "max": None,
                },
                {
                    "name": "bio",
                    "type": "text",
                    "field_id": "1:1",
                    "named": True,
                    "hint": "",
                    "required": False,
                    "maxlength": None,
                    "minlength": None,
                    "pattern": None,
                    "min": None,
                    "max": None,
                },
            ],
            "cluster_id": 1,
            "has_form": False,
            "file_inputs": 1,
            "no_submit": False,
            "page_url": "http://spa.test/page",
            "all_named": True,
        },
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
        if "script[src]" in script:  # unique to SPA_SHELL_PROBE_SCRIPT
            return True  # this fake page models a live SPA shell
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


# --- Change 2: resource blocking installed on the crawl context ------------


@pytest.mark.asyncio
async def test_crawl_into_installs_resource_blocking_by_default(monkeypatch):
    page = _FakePage(goto_sleep=0.0)
    _install_fake_playwright(monkeypatch, page)

    captured = {}
    orig_launch = _FakeChromium.launch

    async def _spy_launch(self, headless=True):
        browser = await orig_launch(self, headless=headless)
        captured["browser"] = browser
        return browser

    monkeypatch.setattr(_FakeChromium, "launch", _spy_launch)

    engine = BrowserDiscoveryEngine(max_interactions=1)
    monkeypatch.setattr(engine.settings, "crawl_browser_block_resources", True)
    state = CrawlState()
    await engine.crawl_into(state, "http://spa.test/", routes=[])

    context = captured["browser"].contexts[0]
    assert "**/*" in context.route_patterns


@pytest.mark.asyncio
async def test_crawl_into_skips_resource_blocking_when_disabled(monkeypatch):
    page = _FakePage(goto_sleep=0.0)
    _install_fake_playwright(monkeypatch, page)

    captured = {}
    orig_launch = _FakeChromium.launch

    async def _spy_launch(self, headless=True):
        browser = await orig_launch(self, headless=headless)
        captured["browser"] = browser
        return browser

    monkeypatch.setattr(_FakeChromium, "launch", _spy_launch)

    engine = BrowserDiscoveryEngine(max_interactions=1)
    monkeypatch.setattr(engine.settings, "crawl_browser_block_resources", False)
    state = CrawlState()
    await engine.crawl_into(state, "http://spa.test/", routes=[])

    context = captured["browser"].contexts[0]
    assert context.route_patterns == []


# --- Change 3a: no readiness-probe double-launch ---------------------------


@pytest.mark.asyncio
async def test_crawl_into_launches_chromium_exactly_once(monkeypatch):
    """The readiness probe used to cold-launch a throwaway Chromium before the
    real crawl launch. crawl_into must now launch exactly once."""
    page = _FakePage(goto_sleep=0.0)
    _install_fake_playwright(monkeypatch, page)

    launches = {"n": 0}
    orig_launch = _FakeChromium.launch

    async def _counting_launch(self, headless=True):
        launches["n"] += 1
        return await orig_launch(self, headless=headless)

    monkeypatch.setattr(_FakeChromium, "launch", _counting_launch)

    engine = BrowserDiscoveryEngine(max_interactions=1)
    state = CrawlState()
    await engine.crawl_into(state, "http://spa.test/", routes=["/a"])

    assert launches["n"] == 1


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

            def nth(self, index):
                return self

            async def is_enabled(self, timeout=None):
                # A real submit control is enabled once the form is valid.
                return "submit" in self._sel

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

    async def wait_for_timeout(self, ms):
        return None

    async def goto(self, url, wait_until=None, timeout=None):
        self.url = url


@pytest.mark.asyncio
async def test_submit_discovered_forms_fills_submits_and_captures_body():
    engine = BrowserDiscoveryEngine()
    page = _SubmitFakePage()
    captured = []
    page.on("request", lambda r: captured.append(r))

    # A <form>-less orphan cluster (has_form=False): fields are targeted by their
    # data-sentry-field ids and submission clicks the cluster-scoped control —
    # the exact path that was previously impossible without a literal <form>.
    form = {
        "action": "http://spa.test/rest/user/login",
        "method": "POST",
        "cluster_id": 0,
        "has_form": False,
        "inputs": [
            {"name": "email", "type": "email", "field_id": "0:0"},
            {"name": "password", "type": "password", "field_id": "0:1"},
        ],
    }
    submitted: set = set()
    await engine._submit_discovered_forms(
        page, [form], "http://spa.test/", "http://spa.test/login", submitted,
    )

    # Both fields were filled, targeted precisely by data-sentry-field id.
    assert any("data-sentry-field='0:0'" in sel for sel, _ in page.fills)
    assert any("data-sentry-field='0:1'" in sel for sel, _ in page.fills)
    assert page.submit_clicks == 1
    # The submission fired a POST XHR carrying a real body.
    posts = [r for r in captured if r.method == "POST" and r.post_data]
    assert posts and "password" in posts[0].post_data
    # Form key recorded for dedup.
    assert submitted


@pytest.mark.asyncio
async def test_submit_discovered_forms_threads_live_inflight_counter():
    """RC1: the crawl loop's live in-flight counter must be forwarded to the
    post-submit settle, so it waits for the submit-triggered XHR to finish
    before navigating back. Passing a throwaway ``{"count": 0}`` (the old bug)
    let the settle return early and the goto tore the frame down mid-capture,
    losing the POST body — hence ``replayable_json_bodies == 0``."""
    engine = BrowserDiscoveryEngine()
    page = _SubmitFakePage()

    seen_inflight = []

    async def _spy_settle(_page, inflight, *args, **kwargs):
        seen_inflight.append(inflight)

    engine._settle_inflight = _spy_settle

    live_inflight = {"count": 0}
    form = {
        "action": "http://spa.test/rest/user/login",
        "method": "POST",
        "cluster_id": 0,
        "has_form": False,
        "inputs": [{"name": "email", "type": "email", "field_id": "0:0"}],
    }
    await engine._submit_discovered_forms(
        page, [form], "http://spa.test/", "http://spa.test/login", set(),
        inflight=live_inflight,
    )

    # The *same* counter object is forwarded — not a fresh throwaway.
    assert seen_inflight and seen_inflight[0] is live_inflight


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
async def test_submit_discovered_forms_skips_configuration_choice_form():
    engine = BrowserDiscoveryEngine()
    page = _SubmitFakePage()
    form = {
        "action": "http://spa.test/account/settings",
        "method": "POST",
        "inputs": [
            {"name": "security_level", "type": "select"},
            {"name": "save", "type": "submit"},
        ],
    }
    submitted: set = set()

    await engine._submit_discovered_forms(
        page, [form], "http://spa.test/", "http://spa.test/account/settings", submitted,
    )

    assert page.submit_clicks == 0
    assert submitted


def test_configuration_guard_keeps_text_search_with_security_term():
    from app.core.crawler.browser_engine import _is_sensitive_configuration_form

    form = {
        "action": "http://spa.test/api/security/search",
        "method": "POST",
        "inputs": [{"name": "security_query", "type": "text", "field_id": "0:0"}],
    }

    assert _is_sensitive_configuration_form(form) is False


@pytest.mark.parametrize(
    "label",
    [
        "logout",
        "Log out",
        "Sign Out",
        "sign off",
        "LOGOUT",
        "Reset database",
        "Initialize application",
        "Change password",
    ],
)
def test_destructive_label_matches_signout_variants(label):
    # RC-4b: blind clicking / submission must never drop the authenticated
    # session by hitting a sign-out control mid-crawl.
    from app.core.crawler.browser_engine import DESTRUCTIVE_LABEL_RE

    assert DESTRUCTIVE_LABEL_RE.search(label)


@pytest.mark.asyncio
async def test_submit_discovered_forms_skips_logout_cluster():
    engine = BrowserDiscoveryEngine()
    page = _SubmitFakePage()

    logout_cluster = {
        "action": "http://spa.test/rest/user/logout",
        "method": "POST",
        "cluster_id": 0,
        "has_form": False,
        "inputs": [{"name": "confirm", "type": "text", "field_id": "0:0"}],
    }
    submitted: set = set()
    await engine._submit_discovered_forms(
        page, [logout_cluster], "http://spa.test/", "http://spa.test/", submitted,
    )
    # A logout cluster is treated as destructive: never submitted, but keyed.
    assert page.submit_clicks == 0
    assert submitted


@pytest.mark.asyncio
async def test_reacquire_cluster_fast_path_skips_navigation_when_page_stayed():
    """Perf: when the page never left the route, ``_reacquire_cluster`` must not
    navigate/settle/retry — the cluster's capture-time anchors are still bound to
    the live DOM. Paying navigate+settle per form is what exhausted the crawl
    budget once discovery breadth grew. The passed form is returned as-is when a
    cheap re-capture finds no in-place re-tag."""
    engine = BrowserDiscoveryEngine()
    page = _SubmitFakePage()  # url stays at the route; evaluate() -> no forms
    navigated_calls = []

    async def _spy_navigate(_p, target, root, allow_spa):
        navigated_calls.append(target)

    engine._navigate = _spy_navigate

    form = {
        "action": "http://spa.test/rest/user/login",
        "method": "POST",
        "cluster_id": 0,
        "has_form": False,
        "inputs": [{"name": "email", "type": "email", "field_id": "0:0"}],
    }
    target = await engine._reacquire_cluster(
        page, "http://spa.test/", page.url, form, {"count": 0},
    )
    # No navigation happened, and the original form is returned for filling.
    assert navigated_calls == []
    assert target is form


@pytest.mark.asyncio
async def test_reacquire_cluster_navigates_back_when_prior_submit_left_route():
    """When a prior submit navigated off the route, the stale anchors are gone,
    so ``_reacquire_cluster`` must navigate back and re-capture. With no match on
    the re-mounted DOM it returns ``None`` (cluster genuinely gone)."""
    engine = BrowserDiscoveryEngine()
    page = _SubmitFakePage()
    page.url = "http://spa.test/somewhere-else"  # a prior submit moved us
    navigated_calls = []

    async def _spy_navigate(_p, target, root, allow_spa):
        navigated_calls.append(target)

    async def _noop_settle(*a, **k):
        return None

    engine._navigate = _spy_navigate
    engine._settle_inflight = _noop_settle
    engine._clear_blocking_overlays = _noop_settle

    form = {
        "action": "http://spa.test/rest/user/login",
        "method": "POST",
        "cluster_id": 0,
        "has_form": False,
        "inputs": [{"name": "email", "type": "email", "field_id": "0:0"}],
    }
    target = await engine._reacquire_cluster(
        page, "http://spa.test/", "http://spa.test/login", form, {"count": 0},
    )
    # Navigated back to the route; cluster never reappeared -> None.
    assert navigated_calls == ["http://spa.test/login"]
    assert target is None


@pytest.mark.asyncio
async def test_crawl_counts_formless_clusters_and_file_inputs(monkeypatch):
    """RC-1: forms/file inputs are counted from structural clusters, so a
    <form>-less SPA route (has_form=False) still reports discovered surface."""

    class _ClusterPage:
        """Serves one <form>-less cluster (with a file input) via the capture
        script; a bare shell otherwise so nothing else fires."""

        def __init__(self):
            self.url = "http://spa.test/"
            self._handlers = {}

        def on(self, event, handler):
            self._handlers.setdefault(event, []).append(handler)

        async def goto(self, url, wait_until=None, timeout=None):
            self.url = url

        def locator(self, selector):
            return _FakeLocator([])

        async def evaluate(self, script, *args):
            if "pushState" in script or "location.hash" in script:
                raise RuntimeError("no SPA router")
            if "clusters" in script:  # FORM_CAPTURE_SCRIPT
                return [
                    {
                        "cluster_id": 0,
                        "action": "/rest/user/registration",
                        "method": "POST",
                        "inputs": [
                            {"name": "email", "type": "email", "field_id": "0:0"},
                            {"name": "avatar", "type": "file", "field_id": "0:1"},
                        ],
                        "has_form": False,
                        "file_inputs": 1,
                    }
                ]
            return ""

        async def wait_for_load_state(self, state, timeout=None):
            return None

        async def wait_for_timeout(self, timeout):
            return None

        async def content(self):
            return "<html><body><app-root>dashboard</app-root></body></html>"

    page = _ClusterPage()
    _install_fake_playwright(monkeypatch, page)

    engine = BrowserDiscoveryEngine(max_interactions=1)
    state = CrawlState()
    await engine.crawl_into(state, "http://spa.test/")

    # The <form>-less cluster and its file input were counted and captured.
    assert state.browser_forms_discovered >= 1
    assert state.file_inputs_discovered >= 1
    assert state.browser_forms and state.browser_forms[0]["has_form"] is False


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
        "/login",
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


# --- Regression: replayable-body capture root causes ------------------------
# These lock in three defects that jointly collapsed ``replayable_json_bodies``
# to 0 on real <form>-less SPAs (validated live against a hash-routed Angular
# app): (1) hash routes were deduped onto the origin so form pages were never
# reached; (2) fields whose synthetic ``data-sentry-field`` tag was dropped by a
# framework re-render never filled, leaving the submit control disabled so no
# app POST fired; (3) after the first cluster's submit navigated/re-rendered the
# page, every remaining cluster's capture-time anchor was stale.


def test_normalize_for_seen_keeps_spa_hash_routes_distinct():
    engine = BrowserDiscoveryEngine()
    root = engine._normalize_for_seen("http://spa.test/")
    login = engine._normalize_for_seen("http://spa.test/#/login")
    register = engine._normalize_for_seen("http://spa.test/#/register")
    # Hash routes are distinct application pages, not the bare origin.
    assert login != root
    assert register != root
    assert login != register
    # Trailing slash / case are normalized; a plain in-page anchor is ignored.
    assert engine._normalize_for_seen("http://spa.test/#/login/") == login
    assert engine._normalize_for_seen("http://spa.test/#section") == root


def test_browser_targets_seeds_hash_routes():
    """A hash-routed SPA's seeded routes must all survive into the work queue —
    the bug collapsed them onto the origin so only the root was ever crawled."""
    engine = BrowserDiscoveryEngine()
    targets = engine._browser_targets(
        "http://spa.test/", ["/#/login", "/#/register", "/#/contact"]
    )
    assert "http://spa.test/#/login" in targets
    assert "http://spa.test/#/register" in targets
    assert "http://spa.test/#/contact" in targets


def test_hash_routed_targets_canonicalize_path_routes_and_dedupe():
    engine = BrowserDiscoveryEngine()
    targets = engine._browser_targets(
        "http://spa.test/",
        ["/#/login", "/login", "http://spa.test/current#/login", "/api/users"],
    )

    assert targets.count("http://spa.test/#/login") == 1
    assert "http://spa.test/login" not in targets
    assert "http://spa.test/current#/login" not in targets
    assert "http://spa.test/api/users" in targets
    assert engine._normalize_for_seen("http://spa.test/current#/login") == engine._normalize_for_seen(
        "http://spa.test/#/login"
    )


def test_runtime_hash_hint_converts_flat_seed_routes_to_hash():
    """Flat routes mined from a JS bundle (``/login``) must be seeded as hash
    routes (``/#/login``) once a runtime probe reports the app is hash-routed —
    otherwise the bare path only ever loads the SPA shell and the real page's
    forms/XHR never fire. The static heuristic cannot see this because every
    seed string is a bare path with no fragment."""
    engine = BrowserDiscoveryEngine()
    flat_routes = ["/login", "/register", "/search", "/administration"]

    # Without the runtime hint the static heuristic sees no ``#/`` and leaves
    # the routes as bare paths (the pre-fix behaviour).
    static = engine._browser_targets("http://spa.test/", flat_routes)
    assert "http://spa.test/login" in static
    assert "http://spa.test/#/login" not in static

    # With the runtime hint every flat route is canonicalized into hash form.
    hashed = engine._browser_targets("http://spa.test/", flat_routes, hash_routed=True)
    for route in ("login", "register", "search", "administration"):
        assert f"http://spa.test/#/{route}" in hashed
        assert f"http://spa.test/{route}" not in hashed


def test_path_hosted_hash_spa_keeps_document_path_and_captures_root_api():
    engine = BrowserDiscoveryEngine()

    targets = engine._browser_targets(
        "http://spa.test/app/",
        ["/login", "/api/users", "/sign-out"],
        hash_routed=True,
    )

    assert "http://spa.test/app/#/login" in targets
    assert "http://spa.test/api/users" not in targets
    assert not any("sign-out" in target for target in targets)

    class _Request:
        url = "http://spa.test/api/users"
        method = "POST"
        resource_type = "xhr"

    assert engine._classify_runtime_request("http://spa.test/app/", _Request()) == "capture"


@pytest.mark.asyncio
async def test_detect_hash_routing_from_root_redirect(monkeypatch):
    """The probe returns True when loading the root leaves the URL on a
    route-bearing fragment (the app rewrote ``/`` into ``#/``)."""

    class _RootRedirectPage(_FakePage):
        async def goto(self, url, wait_until=None, timeout=None):
            self.goto_calls.append(url)
            # App boots and the router rewrites the root into a hash route.
            self.url = url.rstrip("/") + "/#/"

        async def evaluate(self, script, *args):
            return []

    page = _RootRedirectPage()
    engine = BrowserDiscoveryEngine()
    assert await engine._detect_hash_routing(page, "http://spa.test/") is True


@pytest.mark.asyncio
async def test_detect_hash_routing_from_nav_links(monkeypatch):
    """The probe returns True when the app's own same-origin links are route
    fragments (``#/login``), even if the root URL itself did not change."""

    class _HashLinkPage(_FakePage):
        async def goto(self, url, wait_until=None, timeout=None):
            self.goto_calls.append(url)
            self.url = url  # no root rewrite

        async def evaluate(self, script, *args):
            if "routerLink" in script:  # DOM_LINK_SCRIPT
                return ["http://spa.test/#/login", "http://spa.test/#/register"]
            return []

    page = _HashLinkPage()
    engine = BrowserDiscoveryEngine()
    assert await engine._detect_hash_routing(page, "http://spa.test/") is True


@pytest.mark.asyncio
async def test_detect_hash_routing_false_for_path_router(monkeypatch):
    """A path-routed app neither rewrites the root into a ``#/`` fragment nor
    links via route fragments, so the probe reports False (bare-path seeding)."""

    class _PathRouterPage(_FakePage):
        async def goto(self, url, wait_until=None, timeout=None):
            self.goto_calls.append(url)
            self.url = url

        async def evaluate(self, script, *args):
            if "routerLink" in script:  # DOM_LINK_SCRIPT
                return ["http://spa.test/login", "http://spa.test/about#section"]
            return []

    page = _PathRouterPage()
    engine = BrowserDiscoveryEngine()
    assert await engine._detect_hash_routing(page, "http://spa.test/") is False


def test_runtime_request_classifier_records_concrete_drop_reasons():
    engine = BrowserDiscoveryEngine()

    assert engine._classify_runtime_request(
        "http://spa.test/",
        _FakeRequest("https://other.test/api", method="POST", resource_type="fetch", post_data="{}"),
    ) == "off_origin"
    assert engine._classify_runtime_request(
        "http://spa.test/",
        _FakeRequest("http://spa.test/socket.io/?EIO=4&transport=polling", resource_type="fetch"),
    ) == "transport_noise"
    assert engine._classify_runtime_request(
        "http://spa.test/",
        _FakeRequest("http://spa.test/app.css", method="GET", resource_type="stylesheet"),
    ) == "resource_noise"
    assert engine._classify_runtime_request(
        "http://spa.test/",
        _FakeRequest("http://spa.test/api/profile", method="POST", resource_type="fetch", post_data="{}"),
    ) == "capture"


@pytest.mark.asyncio
async def test_capture_forms_skips_non_actionable_or_empty_clusters():
    class _Page:
        async def evaluate(self, script, *args):
            return [
                {
                    "cluster_id": 0,
                    "action": "/noop",
                    "method": "POST",
                    "inputs": [{"name": "email", "type": "email", "field_id": "0:0"}],
                    "has_form": False,
                    "action_controls": 0,
                },
                {
                    "cluster_id": 1,
                    "action": "/empty",
                    "method": "POST",
                    "inputs": [{"name": "submit", "type": "submit", "field_id": "1:0"}],
                    "has_form": True,
                    "action_controls": 1,
                },
            ]

    forms = await BrowserDiscoveryEngine()._capture_forms(_Page(), "http://spa.test/page")

    assert forms == []


def test_type_selector_maps_captured_types():
    ts = BrowserDiscoveryEngine._type_selector
    assert ts("password") == "input[type=password]"
    assert ts("email") == "input[type=email]"
    assert ts("textarea") == "textarea"
    assert ts("select") == "select"
    # Unknown/absent type (a bare <input> captured by tagName) matches any input
    # so positional resolution still reaches it.
    assert ts("input") == "input"


def test_candidate_field_selectors_fast_path_then_scoped_fallbacks():
    entry = {"name": "password", "type": "password", "field_id": "1:1"}
    candidates = BrowserDiscoveryEngine._candidate_field_selectors(
        entry, "[data-sentry-cluster='1'] ", "password", "password", 0
    )
    selectors = [sel for sel, _ in candidates]
    # Fast path (synthetic field tag) is tried first.
    assert selectors[0] == "[data-sentry-field='1:1']"
    # Positional-by-type within the cluster is the next (reliable) fallback.
    assert "[data-sentry-cluster='1'] input[type=password] >> nth=0" in selectors
    assert selectors.index("[data-sentry-cluster='1'] input[type=password] >> nth=0") == 1
    # Identifier-attribute fallbacks are cluster-scoped (never global).
    assert any("[data-sentry-cluster='1'] [name='password']" == s for s in selectors)
    assert all(s.startswith("[data-sentry-") for s in selectors)


def test_candidate_field_selectors_skips_unsafe_name_but_keeps_positional():
    # A captured "name" containing a quote must not break selector construction;
    # positional-by-type still provides a resolver.
    entry = {"name": "a' or 1", "type": "text", "field_id": ""}
    candidates = BrowserDiscoveryEngine._candidate_field_selectors(
        entry, "[data-sentry-cluster='2'] ", "a' or 1", "text", 3
    )
    selectors = [sel for sel, _ in candidates]
    assert selectors == ["[data-sentry-cluster='2'] input[type=text] >> nth=3"]


class _FallbackFillPage:
    """Fake page whose ``data-sentry-field`` selectors are 'gone' (raise, like a
    re-rendered node) but whose cluster-scoped positional selectors fill — models
    the framework-re-render case that left password fields empty."""

    def __init__(self):
        self.filled = {}

    async def fill(self, selector, value, timeout=None):
        if "data-sentry-field" in selector:
            raise RuntimeError("element not found (re-rendered)")
        self.filled[selector] = value

    async def check(self, selector, timeout=None):
        if "data-sentry-field" in selector:
            raise RuntimeError("element not found (re-rendered)")
        self.filled[selector] = "checked"

    async def evaluate(self, script, *args):
        return None

    async def wait_for_timeout(self, ms):
        return None


@pytest.mark.asyncio
async def test_fill_form_fields_falls_back_when_field_tag_is_stripped():
    engine = BrowserDiscoveryEngine()
    page = _FallbackFillPage()
    form = {
        "cluster_id": 1,
        "inputs": [
            {"name": "email", "type": "email", "field_id": "1:0"},
            {"name": "password", "type": "password", "field_id": "1:1"},
        ],
    }
    filled = await engine._fill_form_fields(page, form)
    assert filled is True
    # Both fields were reached via the cluster-scoped positional fallback, even
    # though their data-sentry-field selectors were gone.
    assert "[data-sentry-cluster='1'] input[type=email] >> nth=0" in page.filled
    assert "[data-sentry-cluster='1'] input[type=password] >> nth=0" in page.filled


@pytest.mark.asyncio
async def test_ui_state_signature_bounded_when_evaluate_hangs():
    """A route whose JS keeps the main thread busy makes ``page.evaluate()``
    never resolve. Playwright's ``evaluate`` ignores ``set_default_timeout``, so
    without an explicit bound the call hangs forever — blocking the worker inside
    ``_exercise_page``, which never returns to the deadline check, so the pool
    ``gather`` join never completes and the whole crawl hangs past its budget
    until killed. ``_ui_state_signature`` must therefore return promptly even
    when ``evaluate`` never resolves."""

    class _HangingPage:
        url = "http://spa.test/#/chatbot/conversation/1"

        async def evaluate(self, script, *args):
            await asyncio.sleep(30)  # a page whose evaluate never returns
            return "unreachable"

    engine = BrowserDiscoveryEngine()
    sig = await asyncio.wait_for(engine._ui_state_signature(_HangingPage()), timeout=3.0)
    # The route prefix is preserved; the DOM portion is empty because the hung
    # evaluate was bounded out (not awaited to completion).
    assert sig == "http://spa.test/#/chatbot/conversation/1|"
