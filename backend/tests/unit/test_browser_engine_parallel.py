"""Change 4: parallel worker-pool crawl tests.

A multi-page fake where each context gets its OWN page (true per-worker
isolation): every goto records into a shared visited log, and the root page
"discovers" the child routes via DOM links so the pool must pick them up
dynamically. Route visit order under a pool is nondeterministic, so every
assertion here is on the route SET, never the sequence.
"""

import asyncio
import inspect
import sys
import types

import pytest

from app.core.crawler.browser_engine import BrowserDiscoveryEngine
from app.core.crawler.models import CrawlState


class _Req:
    def __init__(self, url, method="POST", resource_type="xhr", post_data='{"a":1}'):
        self.url = url
        self.method = method
        self.resource_type = resource_type
        self.post_data = post_data
        self._headers = {"content-type": "application/json"}
        self.redirected_from = None

    async def all_headers(self):
        return dict(self._headers)


class _Resp:
    def __init__(self, request, status=200):
        self.request = request
        self.status = status
        self.headers = {"content-type": "application/json"}

    async def text(self):
        return "{}"


class _Locator:
    def __init__(self, elements=None):
        self._elements = elements or []

    async def count(self):
        return len(self._elements)

    def nth(self, index):
        return self._elements[index]

    def locator(self, selector):
        return _Locator([])


class _Page:
    def __init__(self, site, goto_sleep=0.01):
        self.site = site
        self.url = ""
        self._handlers = {}
        self.goto_sleep = goto_sleep

    def on(self, event, handler):
        self._handlers.setdefault(event, []).append(handler)

    def remove_listener(self, event, handler):
        handlers = self._handlers.get(event, [])
        if handler in handlers:
            handlers.remove(handler)

    async def _fire(self, event, arg):
        for handler in list(self._handlers.get(event, [])):
            result = handler(arg)
            if inspect.isawaitable(result):
                await result

    async def goto(self, url, wait_until=None, timeout=None):
        self.url = url
        self.site.visited.append(url)
        await asyncio.sleep(self.goto_sleep)
        request = _Req(url.rstrip("/") + "/xhr")
        await self._fire("request", request)
        await self._fire("response", _Resp(request))
        await self._fire("requestfinished", request)

    def locator(self, selector):
        return _Locator([])

    async def evaluate(self, script, *args):
        # SPA client-side nav "fails" so every visit is a full goto (recorded).
        if "pushState" in script or "location.hash" in script:
            raise RuntimeError("no SPA router")
        if "__sentry_routes" in script:
            return []
        # DOM link discovery: only the root page exposes the child routes.
        if "querySelectorAll" in script and "href" in script:
            if self.url.rstrip("/") == self.site.root.rstrip("/"):
                return list(self.site.child_routes)
            return []
        return ""

    async def wait_for_load_state(self, state, timeout=None):
        return None

    async def wait_for_timeout(self, timeout):
        return None

    async def content(self):
        return "<html><body><app-root>dashboard</app-root></body></html>"


class _Context:
    def __init__(self, site, goto_sleep):
        self.site = site
        self.page = _Page(site, goto_sleep=goto_sleep)

    async def add_cookies(self, cookies):
        return None

    async def set_extra_http_headers(self, headers):
        return None

    async def add_init_script(self, script):
        return None

    async def route(self, pattern, handler):
        return None

    async def new_page(self):
        return self.page

    async def close(self):
        return None


class _Browser:
    def __init__(self, site, goto_sleep):
        self.site = site
        self.goto_sleep = goto_sleep
        self.context_count = 0

    async def new_context(self, **kwargs):
        self.context_count += 1
        return _Context(self.site, self.goto_sleep)

    async def close(self):
        return None


class _Chromium:
    def __init__(self, site, goto_sleep):
        self.site = site
        self.goto_sleep = goto_sleep
        self.last_browser = None

    async def launch(self, headless=True):
        self.last_browser = _Browser(self.site, self.goto_sleep)
        return self.last_browser


class _CM:
    def __init__(self, site, goto_sleep):
        self._pw = types.SimpleNamespace(chromium=_Chromium(site, goto_sleep))

    async def __aenter__(self):
        return self._pw

    async def __aexit__(self, *exc):
        return False


class _Site:
    def __init__(self, root, child_routes):
        self.root = root
        self.child_routes = list(child_routes)
        self.visited = []


def _install(monkeypatch, site, goto_sleep=0.01):
    module = types.ModuleType("playwright.async_api")
    module.async_playwright = lambda: _CM(site, goto_sleep)
    monkeypatch.setitem(sys.modules, "playwright.async_api", module)


ROOT = "http://spa.test/"
CHILDREN = [
    "http://spa.test/a",
    "http://spa.test/b",
    "http://spa.test/c",
    "http://spa.test/d",
    "http://spa.test/e",
]
EXPECTED = {ROOT.rstrip("/")} | {c.rstrip("/") for c in CHILDREN}


@pytest.mark.asyncio
async def test_parallel_crawl_visits_all_routes_as_a_set(monkeypatch):
    site = _Site(ROOT, CHILDREN)
    _install(monkeypatch, site)

    engine = BrowserDiscoveryEngine(max_interactions=1, workers=3)
    state = CrawlState()
    # Wall-clock guard: a hung pool (worker stuck on an empty heap while another
    # is mid-route) fails here instead of hanging the suite.
    await asyncio.wait_for(engine.crawl_into(state, ROOT, routes=[]), timeout=15.0)

    # (a) All routes visited — assert on the SET (order is nondeterministic).
    visited_set = {u.rstrip("/") for u in site.visited}
    assert visited_set == EXPECTED
    # (b) No route visited twice: seen_routes claims at enqueue time.
    assert len(site.visited) == len(visited_set)
    # (c) Routes recorded in state, deduped, matching the discovered set.
    route_urls = [r.url.rstrip("/") for r in state.routes]
    assert set(route_urls) == EXPECTED
    assert len(route_urls) == len(set(route_urls))


@pytest.mark.asyncio
async def test_parallel_crawl_creates_one_context_per_worker(monkeypatch):
    site = _Site(ROOT, CHILDREN)
    _install(monkeypatch, site)

    captured = {}
    orig = _Chromium.launch

    async def _spy(self, headless=True):
        browser = await orig(self, headless=headless)
        captured["browser"] = browser
        return browser

    monkeypatch.setattr(_Chromium, "launch", _spy)

    engine = BrowserDiscoveryEngine(max_interactions=1, workers=3)
    state = CrawlState()
    await asyncio.wait_for(engine.crawl_into(state, ROOT, routes=[]), timeout=15.0)

    # One context (and its own page) per worker.
    assert captured["browser"].context_count == 3


@pytest.mark.asyncio
async def test_serial_workers_one_matches_route_set(monkeypatch):
    """workers=1 must reach the same route SET as the parallel pool (the plan's
    'workers=1 behavior matches today' guarantee)."""
    site = _Site(ROOT, CHILDREN)
    _install(monkeypatch, site)

    engine = BrowserDiscoveryEngine(max_interactions=1, workers=1)
    state = CrawlState()
    await asyncio.wait_for(engine.crawl_into(state, ROOT, routes=[]), timeout=15.0)

    visited_set = {u.rstrip("/") for u in site.visited}
    assert visited_set == EXPECTED
    assert len(site.visited) == len(visited_set)
    assert {r.url.rstrip("/") for r in state.routes} == EXPECTED


@pytest.mark.asyncio
async def test_parallel_crawl_terminates_with_more_workers_than_routes(monkeypatch):
    """Empty-heap ≠ done: with more workers than routes, idle workers wait for the
    in-flight worker then exit cleanly (no hang)."""
    site = _Site(ROOT, [])  # only the root route
    _install(monkeypatch, site)

    engine = BrowserDiscoveryEngine(max_interactions=1, workers=5)
    state = CrawlState()
    await asyncio.wait_for(engine.crawl_into(state, ROOT, routes=[]), timeout=15.0)

    assert {u.rstrip("/") for u in site.visited} == {ROOT.rstrip("/")}
    assert state.browser_available is True


@pytest.mark.asyncio
async def test_partial_results_survive_hard_cancellation(monkeypatch):
    """RC-1 durability under the pool: a hard cancellation (the spider's safety
    timeout) still yields whatever each worker streamed — the merge runs in
    ``finally`` so per-worker partial observations are never discarded."""

    class _SlowFirePage(_Page):
        async def goto(self, url, wait_until=None, timeout=None):
            self.url = url
            self.site.visited.append(url)
            # Fire the observation immediately, THEN hang, so a cancellation
            # mid-run still has a streamed request to preserve.
            request = _Req(url.rstrip("/") + "/xhr")
            await self._fire("request", request)
            await self._fire("response", _Resp(request))
            await self._fire("requestfinished", request)
            await asyncio.sleep(30)

    class _SlowFireContext(_Context):
        def __init__(self, site, goto_sleep):
            self.site = site
            self.page = _SlowFirePage(site)

    class _SlowFireBrowser(_Browser):
        async def new_context(self, **kwargs):
            self.context_count += 1
            return _SlowFireContext(self.site, self.goto_sleep)

    class _SlowFireChromium(_Chromium):
        async def launch(self, headless=True):
            self.last_browser = _SlowFireBrowser(self.site, self.goto_sleep)
            return self.last_browser

    class _SlowFireCM:
        def __init__(self, site):
            self._pw = types.SimpleNamespace(chromium=_SlowFireChromium(site, 0.0))

        async def __aenter__(self):
            return self._pw

        async def __aexit__(self, *exc):
            return False

    site = _Site(ROOT, CHILDREN)
    module = types.ModuleType("playwright.async_api")
    module.async_playwright = lambda: _SlowFireCM(site)
    monkeypatch.setitem(sys.modules, "playwright.async_api", module)

    engine = BrowserDiscoveryEngine(max_interactions=1, workers=2)
    state = CrawlState()

    # Hard cancellation after the first observations streamed but before the
    # (never-arriving) settle completes — mirrors the spider's safety timeout.
    with pytest.raises(asyncio.TimeoutError):
        await asyncio.wait_for(engine.crawl_into(state, ROOT, routes=[]), timeout=0.3)

    # Partial observations were merged despite the cancellation.
    assert len(state.requests) >= 1
    assert state.browser_available is True


@pytest.mark.asyncio
async def test_parallel_crawl_truncates_on_deadline(monkeypatch):
    """A tight deadline truncates the parallel crawl cleanly and records the
    honest truncation error (coverage reporting stays truthful under the pool)."""
    site = _Site(ROOT, CHILDREN)
    _install(monkeypatch, site, goto_sleep=0.25)  # slow pages so the deadline bites

    engine = BrowserDiscoveryEngine(max_interactions=1, workers=2)
    state = CrawlState()
    loop = asyncio.get_running_loop()
    deadline = loop.time() + 0.3
    await asyncio.wait_for(
        engine.crawl_into(state, ROOT, routes=[], deadline=deadline), timeout=15.0
    )

    assert state.browser_error is not None
    assert "truncat" in state.browser_error.lower()
    assert len(site.visited) < len(EXPECTED)
