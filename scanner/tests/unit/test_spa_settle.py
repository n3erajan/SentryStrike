import asyncio
import inspect

import pytest

from app.core.crawler.spa import (
    BLOCKED_RESOURCE_TYPES,
    install_resource_blocking,
    settle_page,
)


class _SettlePage:
    """Fake page whose in-flight requests never let ``networkidle`` fire.

    ``fire_forever`` keeps one request perpetually in flight so the settle can
    only end by hitting ``cap_ms`` (the networkidle-never-idles case). Otherwise
    a single request opens and closes, so the settle ends at ``quiet_ms``.
    """

    def __init__(self, *, fire_forever=False):
        self._handlers = {}
        self.fire_forever = fire_forever
        self.load_states = []

    def on(self, event, handler):
        self._handlers.setdefault(event, []).append(handler)

    def remove_listener(self, event, handler):
        handlers = self._handlers.get(event, [])
        if handler in handlers:
            handlers.remove(handler)

    def _emit(self, event, arg=None):
        for handler in list(self._handlers.get(event, [])):
            handler(arg)

    async def wait_for_load_state(self, state, timeout=None):
        self.load_states.append(state)
        return None

    def handler_count(self):
        return sum(len(v) for v in self._handlers.values())


@pytest.mark.asyncio
async def test_settle_page_drains_at_quiet_ms():
    page = _SettlePage()
    # One request that opens then finishes: the counter drops to zero and the
    # settle ends after quiet_ms without waiting for cap_ms.
    page.on("_seed", lambda _a: None)

    async def _traffic():
        await asyncio.sleep(0.02)
        page._emit("request", object())
        await asyncio.sleep(0.02)
        page._emit("requestfinished", object())

    loop = asyncio.get_running_loop()
    start = loop.time()
    await asyncio.gather(
        settle_page(page, quiet_ms=150.0, cap_ms=5000.0),
        _traffic(),
    )
    elapsed_ms = (loop.time() - start) * 1000.0
    # Ended well before the 5s cap (drained on quiet), and did not hang.
    assert elapsed_ms < 2000.0


@pytest.mark.asyncio
async def test_settle_page_caps_when_network_never_idles():
    page = _SettlePage(fire_forever=True)
    # A request that never finishes: the counter stays > 0 forever, so settle
    # can only end at cap_ms. This is the networkidle-never-fires SPA case.
    page._emit("request", object())  # no matching requestfinished, ever

    async def _keep_busy():
        for _ in range(20):
            page._emit("request", object())
            await asyncio.sleep(0.02)

    loop = asyncio.get_running_loop()
    start = loop.time()
    await asyncio.gather(
        settle_page(page, quiet_ms=200.0, cap_ms=400.0),
        _keep_busy(),
    )
    elapsed_ms = (loop.time() - start) * 1000.0
    # Capped: finished near cap_ms, not hung forever.
    assert 350.0 <= elapsed_ms < 1500.0


@pytest.mark.asyncio
async def test_settle_page_detaches_its_temporary_listeners():
    page = _SettlePage()
    before = page.handler_count()
    await settle_page(page, quiet_ms=100.0, cap_ms=300.0)
    # The temporary request/requestfinished/requestfailed listeners are gone.
    assert page.handler_count() == before


@pytest.mark.asyncio
async def test_settle_page_with_external_counter_attaches_no_listeners():
    page = _SettlePage()
    inflight = {"count": 0}
    await settle_page(page, inflight=inflight, quiet_ms=100.0, cap_ms=300.0)
    # Engine mode: caller owns the counter, so settle attaches nothing.
    assert page.handler_count() == 0


# --- Resource blocking (Change 2) ------------------------------------------


class _Route:
    def __init__(self, request):
        self.request = request
        self.action = None

    async def abort(self):
        self.action = "abort"

    async def continue_(self):
        self.action = "continue"


class _Req:
    def __init__(self, url, resource_type):
        self.url = url
        self.resource_type = resource_type


class _RoutingContext:
    def __init__(self):
        self.route_pattern = None
        self._handler = None

    async def route(self, pattern, handler):
        self.route_pattern = pattern
        self._handler = handler

    async def dispatch(self, url, resource_type):
        route = _Route(_Req(url, resource_type))
        await self._handler(route)
        return route.action


@pytest.mark.asyncio
async def test_install_resource_blocking_registers_catch_all_route():
    ctx = _RoutingContext()
    await install_resource_blocking(ctx)
    assert ctx.route_pattern == "**/*"


@pytest.mark.asyncio
async def test_blocks_images_fonts_media_stylesheets():
    ctx = _RoutingContext()
    await install_resource_blocking(ctx)
    for rtype in sorted(BLOCKED_RESOURCE_TYPES):
        action = await ctx.dispatch(f"http://spa.test/asset.{rtype}", rtype)
        assert action == "abort", rtype


@pytest.mark.asyncio
async def test_allows_same_origin_xhr_document_script():
    ctx = _RoutingContext()
    await install_resource_blocking(ctx)
    for rtype in ("xhr", "fetch", "document", "script"):
        action = await ctx.dispatch("http://spa.test/api/data", rtype)
        assert action == "continue", rtype


@pytest.mark.asyncio
async def test_blocks_known_tracker_hosts_even_for_scripts():
    ctx = _RoutingContext()
    await install_resource_blocking(ctx)
    action = await ctx.dispatch(
        "https://www.google-analytics.com/analytics.js", "script"
    )
    assert action == "abort"


def test_auth_manager_no_longer_waits_on_networkidle():
    """Change 1 guard: the auth browser methods must not block on a load state
    (``networkidle``) that never fires on SPAs — they use ``settle_page`` now."""
    import inspect as _inspect

    from app.core.crawler import auth_manager

    source = _inspect.getsource(auth_manager)
    assert "networkidle" not in source
