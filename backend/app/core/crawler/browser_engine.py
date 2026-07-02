from __future__ import annotations

import asyncio
import heapq
import json
import logging
import re
from typing import Any
from urllib.parse import parse_qs, urljoin, urlparse

from app.config import get_settings
from app.core.crawler.api_extractor import ApiExtractor
from app.core.crawler.models import ApiEndpoint, CrawlState, RequestObservation, RouteCandidate, RouteSource
from app.core.crawler.route_priority import score_route_surface
from app.core.crawler.spa import SpaFallbackDetector

logger = logging.getLogger(__name__)


DESTRUCTIVE_LABEL_RE = re.compile(
    r"\b(delete|remove|destroy|purchase|checkout|pay|confirm|transfer|withdraw|subscribe|unsubscribe)\b",
    re.I,
)
COOKIE_BANNER_LABEL_RE = re.compile(r"\b(accept|agree|allow|ok|got it|continue|close|dismiss)\b", re.I)
SAFE_SUBMIT_LABEL_RE = re.compile(
    r"\b(login|log in|sign in|register|sign up|submit|send|save|search|reset|upload|continue|next)\b",
    re.I,
)
INTERACTIVE_SELECTOR = (
    "a[href], button, [role=button], input[type=submit], input[type=button], "
    "input[type=checkbox], input[type=radio], [tabindex]:not([tabindex='-1'])"
)
SAFE_FIELD_VALUES = {
    "email": "scanner@example.com",
    "search": "test",
    "q": "test",
    "query": "test",
    "name": "Scanner Test",
    "message": "Scanner test message",
    "comment": "Scanner test comment",
    "quantity": "1",
    "qty": "1",
    "id": "1",
    "url": "https://example.com/",
    "file": "sample.txt",
    "filename": "sample.txt",
}
VOLATILE_REQUEST_HEADERS = {
    "accept-encoding",
    "connection",
    "content-length",
    "host",
    "proxy-authorization",
    "proxy-connection",
    "sec-ch-ua",
    "sec-ch-ua-mobile",
    "sec-ch-ua-platform",
    "sec-fetch-dest",
    "sec-fetch-mode",
    "sec-fetch-site",
    "sec-fetch-user",
    "te",
    "upgrade-insecure-requests",
}

# Sentinel returned by _bounded when an operation times out or errors, so a
# successful call returning None (e.g. Playwright click) is distinguishable
# from a skipped one.
_BOUNDED_FAILED = object()

# Injected at context creation so programmatic SPA route changes (pushState /
# replaceState / hashchange / popstate) are captured into a global array the
# engine polls. Framework-agnostic (React Router, Vue Router, Angular, Next).
SPA_ROUTE_HOOK_SCRIPT = """
() => {
  try {
    window.__sentry_routes = window.__sentry_routes || [];
    const push = (u) => { try { window.__sentry_routes.push(String(u || location.href)); } catch (e) {} };
    const wrap = (name) => {
      const orig = history[name];
      if (!orig || orig.__sentry_wrapped) return;
      const fn = function () { const r = orig.apply(this, arguments); push(location.href); return r; };
      fn.__sentry_wrapped = true;
      history[name] = fn;
    };
    wrap('pushState');
    wrap('replaceState');
    window.addEventListener('hashchange', () => push(location.href));
    window.addEventListener('popstate', () => push(location.href));
  } catch (e) {}
}
"""

# Returns strictly `true` when a blocking full-viewport overlay intercepts the
# viewport centre. Generic: high z-index fixed/absolute cover, role=dialog /
# aria-modal, or overlay/backdrop/modal class names.
OVERLAY_DETECT_SCRIPT = """
() => {
  try {
    const w = window.innerWidth, h = window.innerHeight;
    const el = document.elementFromPoint(Math.floor(w / 2), Math.floor(h / 2));
    if (!el) return false;
    let node = el;
    while (node && node !== document.body) {
      const s = getComputedStyle(node);
      const r = node.getBoundingClientRect();
      const big = (r.width * r.height) > (0.6 * w * h);
      const fixed = s.position === 'fixed' || s.position === 'absolute';
      const zi = parseInt(s.zIndex || '0', 10) || 0;
      const cls = (node.className && node.className.toString) ? node.className.toString() : '';
      const modal = node.getAttribute && (node.getAttribute('role') === 'dialog' || node.getAttribute('aria-modal') === 'true');
      if ((fixed && big && zi >= 1) || modal || /overlay|backdrop|modal/i.test(cls)) return true;
      node = node.parentElement;
    }
    return false;
  } catch (e) { return false; }
}
"""

# Collect in-DOM navigation targets: anchors plus framework router directives.
DOM_LINK_SCRIPT = """
() => {
  const out = [];
  try {
    document.querySelectorAll('a[href]').forEach((a) => { if (a.href) out.push(a.href); });
    document.querySelectorAll('[routerLink],[data-href],[ng-reflect-router-link]').forEach((el) => {
      const v = el.getAttribute('routerLink') || el.getAttribute('data-href') || el.getAttribute('ng-reflect-router-link');
      if (v) out.push(v);
    });
  } catch (e) {}
  return out;
}
"""

# Extract structured forms after the DOM has settled and overlays are cleared.
FORM_CAPTURE_SCRIPT = """
() => {
  const forms = [];
  try {
    document.querySelectorAll('form').forEach((f) => {
      const inputs = [];
      f.querySelectorAll('input,textarea,select').forEach((el) => {
        inputs.push({
          name: el.getAttribute('name') || el.getAttribute('id') || '',
          type: (el.getAttribute('type') || el.tagName.toLowerCase() || 'text').toLowerCase(),
        });
      });
      forms.push({
        action: f.getAttribute('action') || location.href,
        method: (f.getAttribute('method') || 'GET').toUpperCase(),
        inputs: inputs,
      });
    });
  } catch (e) {}
  return forms;
}
"""


class BrowserDiscoveryEngine:
    """Optional Playwright-backed crawler for SPAs.

    The engine is deliberately isolated so the HTTP crawler remains usable when
    browser binaries are unavailable. It records runtime navigation and network
    activity that static crawling cannot see.
    """

    def __init__(self, max_interactions: int = 25) -> None:
        self.max_interactions = max_interactions
        self.settings = get_settings()

    @staticmethod
    async def check_readiness() -> tuple[bool, str | None]:
        try:
            from playwright.async_api import async_playwright
        except Exception as exc:
            return False, f"Playwright import failed: {exc}"

        try:
            async with async_playwright() as pw:
                browser = await pw.chromium.launch(headless=True)
                await browser.close()
        except Exception as exc:
            return False, f"Playwright browser launch failed: {exc}"
        return True, None

    async def crawl(
        self,
        root_url: str,
        auth_cookies: dict[str, str] | None = None,
        auth_headers: dict[str, str] | None = None,
        routes: list[str] | None = None,
        deadline: float | None = None,
        storage_state: dict | None = None,
    ) -> CrawlState:
        """Crawl into a fresh :class:`CrawlState` and return it.

        Thin wrapper preserved for existing callers/tests. The heavy lifting
        lives in :meth:`crawl_into`, which streams observations into the state
        as they arrive so partial results survive truncation/errors.
        """
        state = CrawlState()
        await self.crawl_into(
            state,
            root_url,
            auth_cookies=auth_cookies,
            auth_headers=auth_headers,
            routes=routes,
            deadline=deadline,
            storage_state=storage_state,
        )
        return state

    async def crawl_into(
        self,
        state: CrawlState,
        root_url: str,
        auth_cookies: dict[str, str] | None = None,
        auth_headers: dict[str, str] | None = None,
        routes: list[str] | None = None,
        deadline: float | None = None,
        storage_state: dict | None = None,
    ) -> CrawlState:
        """Stream browser observations into ``state`` as they arrive.

        ``state`` is mutated in place so a caller holding a reference always
        sees whatever was discovered before a timeout/exception truncated the
        run (the RC-1 fix: partial results are never discarded).
        ``browser_available`` is set ``True`` the moment Chromium launches;
        ``deadline`` (a monotonic ``loop.time()`` value) bounds the overall run
        and is checked before each navigation so truncation is a clean break
        (no ``TargetClosedError``) rather than a hard cancellation.
        """
        try:
            from playwright.async_api import async_playwright
        except Exception as exc:
            logger.warning("Playwright is unavailable; skipping browser discovery: %s", exc)
            state.browser_available = False
            state.browser_error = f"Playwright import failed: {exc}"
            return state

        loop = asyncio.get_running_loop()
        by_key: dict[tuple[str, str, str], RequestObservation] = {}

        def _register(observation: RequestObservation) -> RequestObservation:
            key = self._observation_key(observation.url, observation.method, observation.post_data)
            existing = by_key.get(key)
            if existing is not None:
                return existing
            by_key[key] = observation
            state.requests.append(observation)
            return observation

        async with async_playwright() as pw:
            try:
                browser = await pw.chromium.launch(headless=True)
            except Exception as exc:
                logger.warning("Playwright browser launch failed; skipping browser discovery: %s", exc)
                state.browser_available = False
                state.browser_error = f"Playwright browser launch failed: {exc}"
                return state

            # The browser is live: record availability immediately so a later
            # truncation still reports True rather than the None default.
            state.browser_available = True

            # Seed the context from a full authenticated storage_state when one
            # was captured by a browser_spa login: this restores cookies AND the
            # per-origin localStorage/sessionStorage the SPA reads its token from,
            # so its own bootstrap JS renders the logged-in shell. Falls back to
            # bare cookie/header injection when absent (cookie-auth apps, static
            # auth only). Generic: storage_state is an opaque per-origin blob.
            if storage_state:
                try:
                    context = await browser.new_context(storage_state=storage_state)
                except Exception as exc:
                    logger.warning(
                        "failed to seed browser context from storage_state; "
                        "falling back to cookie injection: %s",
                        exc,
                    )
                    context = await browser.new_context()
            else:
                context = await browser.new_context()

            # Capture programmatic SPA route changes across all pages.
            try:
                await context.add_init_script(SPA_ROUTE_HOOK_SCRIPT)
            except Exception:
                pass

            if auth_cookies:
                parsed = urlparse(root_url)
                domain = parsed.netloc.split(":")[0]
                path = parsed.path or "/"
                cookies_list = []
                for name, value in auth_cookies.items():
                    cookies_list.append(
                        {
                            "name": name,
                            "value": value,
                            "domain": domain,
                            "path": path,
                        }
                    )
                await context.add_cookies(cookies_list)

            if auth_headers:
                await context.set_extra_http_headers(auth_headers)

            page = await context.new_page()

            # Inflight counter for deterministic, networkidle-free settling.
            inflight = {"count": 0}

            def _inc_inflight(_request):
                inflight["count"] += 1

            def _dec_inflight(_request):
                inflight["count"] = max(0, inflight["count"] - 1)

            async def on_request(request):
                if request.resource_type in {"xhr", "fetch", "websocket"}:
                    # Append to state.requests immediately (dedup by observation
                    # key) so partial results are durable before any merge.
                    _register(await self._build_request_observation(request))

            async def on_response(response):
                request = response.request
                if request.resource_type not in {"xhr", "fetch", "websocket"}:
                    return
                observation_key = self._observation_key(request.url, request.method, request.post_data)
                observed = by_key.get(observation_key)
                if observed is None:
                    observed = _register(await self._build_request_observation(request))
                headers = dict(response.headers)
                observed.response_status = response.status
                observed.response_headers = headers
                observed.response_content_type = headers.get("content-type")
                observed.redirect_chain = self._redirect_chain(request)
                try:
                    observed.response_snippet = (await response.text())[:1000]
                except Exception:
                    observed.response_snippet = None

            def on_websocket(ws):
                # Record WS endpoints even without a body so they surface in
                # coverage and to detectors.
                try:
                    url = ws.url
                except Exception:
                    return
                _register(
                    RequestObservation(
                        url=url,
                        method="GET",
                        resource_type="websocket",
                        replayable=False,
                    )
                )

            page.on("request", on_request)
            page.on("request", _inc_inflight)
            page.on("requestfinished", _dec_inflight)
            page.on("requestfailed", _dec_inflight)
            page.on("response", on_response)
            try:
                page.on("websocket", on_websocket)
            except Exception:
                pass

            try:
                route_budget = max(1, min(self.settings.crawl_max_urls, self.settings.crawl_browser_route_cap))
                # Value-ordered priority queue (Task B): a max-heap keyed by
                # descending surface score, tie-broken by insertion order for
                # determinism. High-surface routes (auth/forms/API-bearing) are
                # popped first so meaningful coverage lands before truncation.
                heap: list[tuple[int, int, str]] = []
                seen_routes: set[str] = set()
                submitted_form_keys: set[tuple[str, str, tuple[str, ...]]] = set()
                counter = 0

                def _enqueue(url: str, evidence: str = "") -> None:
                    nonlocal counter
                    key = self._normalize_for_seen(url)
                    if key in seen_routes or len(seen_routes) >= route_budget:
                        return
                    seen_routes.add(key)
                    # Negate score so heapq (a min-heap) pops highest score first;
                    # the monotonic counter preserves FIFO among equal scores.
                    heapq.heappush(heap, (-score_route_surface(url, evidence), counter, url))
                    counter += 1

                # Seed known static routes (already carry auth/forms/API surface)
                # with their score before the crawl starts so even a short budget
                # reaches them. The root target is always included.
                for target in self._browser_targets(root_url, routes or []):
                    _enqueue(target, evidence="seed")

                # Effective budget scaled to route count: small apps finish fast,
                # large apps get proportionally more, always capped by the
                # configured overall budget. The per-route deadline checks below
                # still guarantee a clean truncation regardless.
                effective_deadline = self._effective_deadline(deadline, loop, len(seen_routes))

                first = True
                while heap:
                    now = loop.time()
                    if effective_deadline is not None and now >= effective_deadline:
                        state.browser_error = (
                            state.browser_error
                            or "browser discovery truncated: overall budget reached before all routes were visited"
                        )
                        break
                    _, _, target_url = heapq.heappop(heap)
                    # Per-route interaction gating: once little of the overall
                    # budget remains, stop blind clicking (expensive, low-yield)
                    # but always still navigate + settle + capture/submit forms
                    # (cheap, high-yield). Derived from remaining fraction.
                    allow_interaction = self._budget_allows_interaction(effective_deadline, loop)
                    try:
                        # Root/first target always does a full load; later
                        # same-origin routes prefer client-side navigation.
                        was_first = first
                        await self._navigate(page, target_url, root_url, allow_spa=not first)
                        first = False
                        await self._settle_inflight(page, inflight)
                        await self._clear_blocking_overlays(page)
                        # Post-auth liveness re-check (generic): if we seeded an
                        # authenticated storage_state but the root still renders the
                        # logged-out shell, the session did not persist into the
                        # browser context. Surface it (RC-A regression) rather than
                        # silently crawling an unauthenticated surface.
                        if was_first and storage_state and not state.browser_error:
                            if await self._looks_logged_out(page):
                                state.browser_error = (
                                    "authenticated session did not persist into browser context"
                                )
                        state.add_route(
                            RouteCandidate(
                                url=self._current_url(page, target_url),
                                source=RouteSource.browser,
                                priority=75,
                                evidence="browser_navigation",
                            )
                        )
                        if allow_interaction:
                            workflow_stats = await self._exercise_page(page)
                            state.workflow_states_visited += workflow_stats.get("states", 0)
                            state.browser_forms_discovered += workflow_stats.get("forms", 0)
                            state.file_inputs_discovered += workflow_stats.get("file_inputs", 0)
                        captured_forms = await self._capture_forms(page, target_url)
                        for form in captured_forms:
                            state.add_browser_form(form)
                        # Active form submission (Task B): fire the app's real
                        # POST/PUT/PATCH XHR with a real body shape so on_request
                        # captures a replayable observation. Skips destructive forms.
                        await self._submit_discovered_forms(
                            page, captured_forms, root_url, target_url, submitted_form_keys,
                        )
                        # Enqueue newly-discovered same-origin routes (scored).
                        for new_route in await self._discover_routes(page, root_url):
                            _enqueue(new_route, evidence="browser_discovered")
                    except Exception as exc:
                        logger.warning("browser discovery failed for %s: %s", target_url, exc)
            finally:
                # Derive endpoints/params from whatever streamed in — runs even
                # on truncation so partial coverage yields testable surface.
                self._derive_endpoints(state)
                try:
                    await context.close()
                except Exception:
                    pass
                try:
                    await browser.close()
                except Exception:
                    pass
        return state

    def _derive_endpoints(self, state: CrawlState) -> None:
        """Build API endpoints/parameters from streamed observations.

        ``state.requests`` is left untouched (already deduped by observation key
        during streaming); endpoint derivation applies the coarser URL-template
        dedup so equivalent REST calls collapse to one endpoint. ``add_*`` are
        idempotent, so this is safe to call once in the crawl ``finally``.
        """
        for observation in self._dedupe_observations(state.requests):
            endpoint = ApiEndpoint(
                url=observation.url,
                method=observation.method,
                source=RouteSource.browser,
                content_type=observation.request_content_type,
                request_body=observation.post_data,
                body_schema=list(observation.body_schema),
                multipart_fields=list(observation.multipart_fields),
                replayable=observation.replayable,
                headers=observation.request_headers,
                evidence=f"{observation.resource_type}:{observation.response_status or 'unknown'}",
            )
            state.add_api_endpoint(endpoint)
            for parameter in ApiExtractor.parameters_from_endpoint(endpoint):
                parameter.source = "browser_request"
                parameter.context["replayable"] = observation.replayable
                parameter.context["cookies"] = dict(observation.request_cookies)
                state.add_parameter(parameter)

    @staticmethod
    def _observation_key(url: str, method: str, post_data: Any = None) -> tuple[str, str, str]:
        return (method.upper(), url, str(post_data or ""))

    async def _bounded(self, coro: Any, ms: float) -> Any:
        """Await ``coro`` with a hard millisecond deadline.

        Returns the coroutine result on success or :data:`_BOUNDED_FAILED` on
        timeout/error, so a single hanging control can never consume the budget.
        """
        try:
            return await asyncio.wait_for(coro, timeout=max(0.05, ms / 1000.0))
        except Exception:
            return _BOUNDED_FAILED

    async def _looks_logged_out(self, page: Any) -> bool:
        """Generic post-auth liveness heuristic.

        Reuses :meth:`SpaFallbackDetector.looks_like_spa_shell` on the rendered
        DOM: a still-logged-out SPA renders its bare shell (login markers, no
        authenticated content). Returns ``False`` on any error so a flaky probe
        never fabricates a regression. No app-specific strings.
        """
        html = await self._bounded(page.content(), 3000)
        if html is _BOUNDED_FAILED or not isinstance(html, str):
            return False
        url = self._current_url(page, "")
        # A login form on the root is the strongest generic "logged-out" signal.
        lowered = html.lower()
        has_login_form = "<form" in lowered and any(
            token in lowered for token in ("password", "type=\"password\"", "type='password'")
        )
        return has_login_form and SpaFallbackDetector.looks_like_spa_shell(url, html)

    @staticmethod
    def _current_url(page: Any, fallback: str) -> str:
        try:
            return page.url or fallback
        except Exception:
            return fallback

    @staticmethod
    async def _force_click(element: Any) -> None:
        await element.click(timeout=800, force=True)

    async def _navigate(self, page: Any, target_url: str, root_url: str, allow_spa: bool) -> None:
        """Navigate to ``target_url``, preferring client-side routing for SPAs."""
        if allow_spa and self._origin(target_url) == self._origin(root_url):
            if await self._navigate_spa_route(page, target_url):
                return
        await self._bounded(
            page.goto(target_url, wait_until="domcontentloaded", timeout=15000), 16000
        )

    async def _navigate_spa_route(self, page: Any, route: str) -> bool:
        """Exercise the SPA router without a full reload.

        Hash routes set ``location.hash``; path routes call ``history.pushState``
        and dispatch ``popstate`` so the framework router reacts. Returns False
        (caller falls back to ``page.goto``) if the programmatic change errors.
        """
        parsed = urlparse(route)
        try:
            if parsed.fragment:
                script = "(h) => { location.hash = h; }"
                result = await self._bounded(page.evaluate(script, parsed.fragment), 800)
            else:
                target = parsed.path or "/"
                if parsed.query:
                    target = f"{target}?{parsed.query}"
                script = (
                    "(p) => { history.pushState({}, '', p); "
                    "window.dispatchEvent(new PopStateEvent('popstate')); }"
                )
                result = await self._bounded(page.evaluate(script, target), 800)
        except Exception:
            return False
        if result is _BOUNDED_FAILED:
            return False
        # Bounded settle for the router to react before the caller proceeds.
        await self._bounded(page.wait_for_timeout(200), 400)
        return True

    async def _settle_inflight(
        self,
        page: Any,
        inflight: dict[str, int],
        quiet_ms: float = 300.0,
        cap_ms: float = 2500.0,
    ) -> None:
        """Wait until in-flight requests drain, with a hard cap.

        ``networkidle`` never fires on apps with persistent sockets/polling, so
        we watch an inflight counter and return once it stays at zero for
        ``quiet_ms`` or ``cap_ms`` elapses — whichever comes first.
        """
        loop = asyncio.get_running_loop()
        start = loop.time()
        quiet_start: float | None = None
        while True:
            now = loop.time()
            if (now - start) * 1000.0 >= cap_ms:
                break
            if inflight.get("count", 0) <= 0:
                if quiet_start is None:
                    quiet_start = now
                elif (now - quiet_start) * 1000.0 >= quiet_ms:
                    break
            else:
                quiet_start = None
            await asyncio.sleep(0.05)
        await self._bounded(page.wait_for_load_state("domcontentloaded"), 1000)

    async def _clear_blocking_overlays(self, page: Any) -> None:
        """Dismiss a blocking full-viewport overlay before interacting.

        Detects interception generically (``elementFromPoint`` at the viewport
        centre) and, if blocked, tries Escape then a generic dismiss control
        (accept/close/got-it/…). Never clicks destructive controls.
        """
        blocking = await self._bounded(page.evaluate(OVERLAY_DETECT_SCRIPT), 800)
        if blocking is not True:
            return
        keyboard = getattr(page, "keyboard", None)
        if keyboard is not None:
            await self._bounded(keyboard.press("Escape"), 500)
        await self._dismiss_common_dialogs(page)

    async def _capture_forms(self, page: Any, page_url: str) -> list[dict[str, Any]]:
        """Return structured forms (action/method/inputs) rendered on the page."""
        result = await self._bounded(page.evaluate(FORM_CAPTURE_SCRIPT), 1000)
        if result is _BOUNDED_FAILED or not isinstance(result, list):
            return []
        forms: list[dict[str, Any]] = []
        for entry in result:
            if not isinstance(entry, dict):
                continue
            inputs = entry.get("inputs") if isinstance(entry.get("inputs"), list) else []
            forms.append(
                {
                    "action": urljoin(page_url, str(entry.get("action") or page_url)),
                    "method": str(entry.get("method") or "GET").upper(),
                    "inputs": [
                        {"name": str(i.get("name", "")), "type": str(i.get("type", "text"))}
                        for i in inputs
                        if isinstance(i, dict)
                    ],
                    "page_url": page_url,
                }
            )
        return forms

    def _effective_deadline(self, deadline: float | None, loop: Any, route_count: int) -> float | None:
        """Scale the browser budget to the number of routes to visit (Task B).

        ``base + per_route * min(routes, cap)`` clamped by the configured overall
        budget, so small apps finish fast and large apps get proportionally more.
        Returns ``None`` (no bound) only when the caller supplied no ``deadline``.
        The per-route deadline checks in the crawl loop still guarantee a clean
        truncation regardless of this value.
        """
        if deadline is None:
            return None
        base = float(getattr(self.settings, "crawl_browser_base_seconds", 30.0))
        per_route = float(getattr(self.settings, "crawl_browser_per_route_seconds", 6.0))
        cap = max(1, int(getattr(self.settings, "crawl_browser_route_cap", 120)))
        configured = float(getattr(self.settings, "crawl_browser_budget_seconds", 300.0))
        scaled = base + per_route * min(max(route_count, 1), cap)
        effective = min(configured, scaled)
        # Never exceed the caller's hard deadline; only ever shrink it.
        return min(deadline, loop.time() + effective)

    def _budget_allows_interaction(self, effective_deadline: float | None, loop: Any) -> bool:
        """Gate expensive blind clicking behind remaining-budget fraction.

        Navigation + settle + form capture/submit are always performed (cheap,
        high-yield). Blind ``_exercise_page`` clicking is skipped once less than
        ~25% of the effective budget remains, so the tail of the run spends its
        time reaching more high-value routes rather than exercising one.
        """
        if effective_deadline is None:
            return True
        remaining = effective_deadline - loop.time()
        total = float(getattr(self.settings, "crawl_browser_budget_seconds", 300.0))
        # Skip interaction only when comfortably little time is left in absolute
        # AND relative terms; early in the crawl interaction always runs.
        return remaining > max(0.0, 0.25 * total) or remaining > 45.0

    async def _submit_discovered_forms(
        self,
        page: Any,
        forms: list[dict[str, Any]],
        root_url: str,
        route_url: str,
        submitted_keys: set[tuple[str, str, tuple[str, ...]]],
    ) -> None:
        """Actively submit non-destructive forms to generate real request bodies.

        For each captured form, fill inputs with type-appropriate synthetic
        values (reusing the generic typed-placeholder logic) and submit it, so
        the app fires its real ``POST/PUT/PATCH`` XHR with a real body shape that
        ``on_request`` captures as a replayable observation. Destructive forms
        (delete/pay/logout/…) are never submitted. Auth forms are submitted with
        synthetic creds — capturing the request body is the goal even when the
        credentials are invalid. Each form key is submitted at most once across
        the whole crawl (dedup via :meth:`CrawlState._form_key`).
        """
        from app.core.crawler.models import CrawlState

        for form in forms:
            key = CrawlState._form_key(form)
            if key in submitted_keys:
                continue
            inputs = form.get("inputs") or []
            # Skip destructive forms: check action + input names generically.
            haystack = " ".join(
                [str(form.get("action", ""))] + [str(i.get("name", "")) for i in inputs]
            )
            if DESTRUCTIVE_LABEL_RE.search(haystack):
                submitted_keys.add(key)
                continue
            submitted_keys.add(key)
            try:
                filled = await self._fill_form_fields(page, inputs)
                if not filled:
                    continue
                await self._submit_form(page, form)
                await self._settle_inflight(page, {"count": 0})
                # A submit can navigate away; return to the route so the queue's
                # subsequent captures stay meaningful. Bounded.
                if self._current_url(page, route_url) != route_url:
                    await self._bounded(
                        page.goto(route_url, wait_until="domcontentloaded", timeout=8000),
                        9000,
                    )
            except Exception as exc:
                logger.debug("form submission failed on %s: %s", route_url, exc)

    async def _fill_form_fields(self, page: Any, inputs: list[dict[str, Any]]) -> bool:
        """Fill a form's inputs with generic typed placeholders. Returns True if
        at least one field was filled (so an empty/hidden-only form is skipped)."""
        filled = False
        for entry in inputs:
            name = str(entry.get("name", "") or "")
            itype = str(entry.get("type", "text") or "text").lower()
            if not name or itype in ("hidden", "submit", "button", "file", "image", "reset"):
                continue
            value = ApiExtractor._baseline_for_name(name)
            selector = f"[name='{name}']"
            if itype in ("checkbox", "radio"):
                res = await self._bounded(page.check(selector, timeout=800), 1000)
                filled = filled or res is not _BOUNDED_FAILED
                continue
            res = await self._bounded(page.fill(selector, str(value), timeout=800), 1000)
            filled = filled or res is not _BOUNDED_FAILED
        return filled

    async def _submit_form(self, page: Any, form: dict[str, Any]) -> None:
        """Submit a form by clicking its submit control or pressing Enter."""
        # Prefer an explicit submit control scoped to the form's action.
        for selector in (
            "button[type=submit]",
            "input[type=submit]",
            "button:not([type])",
        ):
            loc = page.locator(selector)
            res = await self._bounded(loc.count(), 500)
            if isinstance(res, int) and res > 0:
                clicked = await self._bounded(loc.first.click(timeout=800), 1000)
                if clicked is not _BOUNDED_FAILED:
                    return
        # Fallback: submit the form element directly via requestSubmit/submit.
        await self._bounded(
            page.evaluate(
                "() => { const f = document.querySelector('form'); "
                "if (f) { (f.requestSubmit ? f.requestSubmit() : f.submit()); } }"
            ),
            1000,
        )

    async def _discover_routes(self, page: Any, root_url: str) -> list[str]:
        """Collect same-origin routes from captured SPA nav + in-DOM links."""
        found: list[str] = []
        captured = await self._bounded(
            page.evaluate("() => (window.__sentry_routes || []).splice(0)"), 1000
        )
        if isinstance(captured, list):
            found.extend(str(item) for item in captured)
        links = await self._bounded(page.evaluate(DOM_LINK_SCRIPT), 1000)
        if isinstance(links, list):
            found.extend(str(item) for item in links)
        current = self._current_url(page, "")
        if current:
            found.append(current)

        root_origin = self._origin(root_url)
        result: list[str] = []
        emitted: set[str] = set()
        for item in found:
            if not item:
                continue
            absolute = urljoin(root_url, item)
            if self._origin(absolute) != root_origin:
                continue
            key = self._normalize_for_seen(absolute)
            if key in emitted:
                continue
            emitted.add(key)
            result.append(absolute)
        return result

    async def _exercise_page(self, page: Any) -> dict[str, int]:
        seen_states: set[str] = set()
        attempted_controls: set[str] = set()
        forms_seen = 0
        file_inputs_seen = 0

        await self._clear_blocking_overlays(page)
        for _ in range(self.max_interactions):
            state_signature = await self._ui_state_signature(page)
            if state_signature not in seen_states:
                seen_states.add(state_signature)

            forms_seen = max(forms_seen, await self._count_locator(page, "form"))
            file_inputs_seen = max(file_inputs_seen, await self._count_locator(page, "input[type=file]"))
            await self._prepare_interactive_inputs(page)

            # Clear overlays right before selecting/clicking so a modal that
            # appeared after the last action cannot intercept this one.
            await self._clear_blocking_overlays(page)
            element, control_key = await self._next_interaction(page, attempted_controls)
            if element is None or control_key is None:
                break
            attempted_controls.add(control_key)

            # Hard-bounded click; on interception, clear overlays and try one
            # forced click (still never a destructive control — filtered above).
            result = await self._bounded(element.click(timeout=800), 900)
            if result is _BOUNDED_FAILED:
                await self._clear_blocking_overlays(page)
                await self._bounded(self._force_click(element), 900)
            await self._wait_after_interaction(page)
            await self._clear_blocking_overlays(page)

        return {
            "states": len(seen_states),
            "forms": forms_seen,
            "file_inputs": file_inputs_seen,
        }

    async def _prepare_interactive_inputs(self, page: Any) -> None:
        await self._fill_safe_fields(page)
        await self._select_safe_options(page)
        await self._fill_file_inputs(page)

    async def _fill_safe_fields(self, page: Any) -> None:
        input_selector = "input:not([type=hidden]):not([type=file])"
        if not self.settings.authentication_password:
            input_selector = "input:not([type=hidden]):not([type=password]):not([type=file])"
        fields = page.locator(
            f"{input_selector}, textarea, [contenteditable=true]"
        )
        count = min(await fields.count(), self.max_interactions)
        for index in range(count):
            try:
                field = fields.nth(index)
                if not await field.is_visible():
                    continue
                await field.fill(await self._value_for_field(field), timeout=1000)
                if await self._looks_like_search(field):
                    await field.press("Enter", timeout=1000)
                    await self._settle(page)
            except Exception:
                continue

    async def _select_safe_options(self, page: Any) -> None:
        selects = page.locator("select")
        count = min(await selects.count(), self.max_interactions)
        for index in range(count):
            try:
                select = selects.nth(index)
                if not await select.is_visible():
                    continue
                options = select.locator("option")
                option_count = await options.count()
                for option_index in range(option_count):
                    option = options.nth(option_index)
                    value = await option.get_attribute("value")
                    disabled = await option.get_attribute("disabled")
                    if disabled is not None:
                        continue
                    if value:
                        await select.select_option(value, timeout=1000)
                        break
            except Exception:
                continue

    async def _fill_file_inputs(self, page: Any) -> None:
        file_inputs = page.locator("input[type=file]")
        count = min(await file_inputs.count(), self.max_interactions)
        for index in range(count):
            try:
                field = file_inputs.nth(index)
                multiple = await field.get_attribute("multiple")
                files = self._benign_upload_files()
                await field.set_input_files(files if multiple is not None else files[0], timeout=1000)
            except Exception:
                continue

    def _benign_upload_files(self) -> list[dict[str, Any]]:
        return [
            {
                "name": "sentry-upload.txt",
                "mimeType": "text/plain",
                "buffer": b"SENTRY_UPLOAD_TEST_CANARY",
            },
            {
                "name": "sentry-upload.json",
                "mimeType": "application/json",
                "buffer": b'{"canary":"SENTRY_UPLOAD_TEST_CANARY"}',
            },
            {
                "name": "sentry-upload.png",
                "mimeType": "image/png",
                "buffer": b"\x89PNG\r\n\x1a\n",
            },
        ]

    async def _next_interaction(self, page: Any, attempted: set[str]) -> tuple[Any | None, str | None]:
        controls = page.locator(INTERACTIVE_SELECTOR)
        count = min(await controls.count(), self.max_interactions * 2)
        fallback: tuple[Any | None, str | None] = (None, None)
        for index in range(count):
            try:
                element = controls.nth(index)
                if not await element.is_visible():
                    continue
                label = await self._control_label(element)
                control_key = await self._control_key(element, index, label)
                if control_key in attempted:
                    continue
                if self._is_destructive_control(label):
                    continue
                if self._is_submit_like_control(label):
                    return element, control_key
                if fallback == (None, None):
                    fallback = (element, control_key)
            except Exception:
                continue
        return fallback

    async def _control_label(self, element: Any) -> str:
        return " ".join(
            part
            for part in [
                await self._safe_inner_text(element),
                await element.get_attribute("aria-label") or "",
                await element.get_attribute("title") or "",
                await element.get_attribute("name") or "",
                await element.get_attribute("id") or "",
                await element.get_attribute("type") or "",
                await element.get_attribute("value") or "",
                await element.get_attribute("href") or "",
            ]
            if part
        )

    async def _control_key(self, element: Any, index: int, label: str) -> str:
        attrs = [
            await element.get_attribute("href") or "",
            await element.get_attribute("name") or "",
            await element.get_attribute("id") or "",
            await element.get_attribute("type") or "",
            label,
        ]
        return f"{index}:{'|'.join(attrs).strip().lower()}"

    def _is_destructive_control(self, label: str) -> bool:
        if self.settings.scan_mode.lower() == "aggressive":
            return False
        return bool(DESTRUCTIVE_LABEL_RE.search(label or ""))

    @staticmethod
    def _is_submit_like_control(label: str) -> bool:
        return bool(SAFE_SUBMIT_LABEL_RE.search(label or ""))

    async def _dismiss_common_dialogs(self, page: Any) -> None:
        controls = page.locator("button, [role=button], input[type=button]")
        count = min(await controls.count(), 10)
        for index in range(count):
            try:
                element = controls.nth(index)
                if not await element.is_visible():
                    continue
                label = await self._control_label(element)
                if COOKIE_BANNER_LABEL_RE.search(label) and not DESTRUCTIVE_LABEL_RE.search(label):
                    await element.click(timeout=750)
                    await self._wait_after_interaction(page)
            except Exception:
                continue

    async def _ui_state_signature(self, page: Any) -> str:
        try:
            route = page.url
        except Exception:
            route = ""
        try:
            dom_signature = await page.evaluate(
                """() => {
                    const visible = (el) => {
                        const style = window.getComputedStyle(el);
                        const rect = el.getBoundingClientRect();
                        return style && style.visibility !== 'hidden' && style.display !== 'none' && rect.width > 0 && rect.height > 0;
                    };
                    const controls = [...document.querySelectorAll('form,input,textarea,select,button,a[href],[role=button]')]
                        .filter(visible)
                        .slice(0, 80)
                        .map((el) => [
                            el.tagName.toLowerCase(),
                            el.getAttribute('type') || '',
                            el.getAttribute('name') || '',
                            el.getAttribute('id') || '',
                            el.getAttribute('href') || '',
                            (el.innerText || el.value || '').trim().slice(0, 40)
                        ].join(':'));
                    return controls.join('|');
                }"""
            )
        except Exception:
            dom_signature = ""
        return f"{route}|{dom_signature}"[:2000]

    async def _count_locator(self, page: Any, selector: str) -> int:
        try:
            return await page.locator(selector).count()
        except Exception:
            return 0

    async def _wait_after_interaction(self, page: Any) -> None:
        await self._settle(page)

    async def _settle(self, page: Any) -> None:
        """Bounded settle for SPAs whose network never goes idle.

        ``networkidle`` never fires on apps with persistent connections or
        polling (e.g. Angular apps with a service worker), so we wait for the
        DOM to be ready with a short cap and fall back to a fixed pause.
        """
        try:
            await page.wait_for_load_state("domcontentloaded", timeout=1500)
        except Exception:
            pass
        try:
            await page.wait_for_timeout(400)
        except Exception:
            pass

    async def _value_for_field(self, field: Any) -> str:
        attrs = await self._field_attrs(field)
        joined = " ".join(attrs).lower()
        if "password" in joined and self.settings.authentication_password:
            return self.settings.authentication_password
        if self.settings.authentication_username and any(
            token in joined for token in ("email", "username", "user", "login", "account")
        ):
            return self.settings.authentication_username
        for token, value in SAFE_FIELD_VALUES.items():
            if token in joined:
                return value
        return "test"

    async def _looks_like_search(self, field: Any) -> bool:
        joined = " ".join(await self._field_attrs(field)).lower()
        return any(token in joined for token in ("search", "q", "query"))

    async def _field_attrs(self, field: Any) -> list[str]:
        return [
            await field.get_attribute("name") or "",
            await field.get_attribute("id") or "",
            await field.get_attribute("placeholder") or "",
            await field.get_attribute("type") or "",
            await field.get_attribute("aria-label") or "",
        ]

    async def _safe_inner_text(self, element: Any) -> str:
        try:
            return await element.inner_text(timeout=250)
        except Exception:
            return ""

    def _browser_targets(self, root_url: str, routes: list[str]) -> list[str]:
        root_origin = self._origin(root_url)
        targets = [root_url]
        seen = {self._normalize_for_seen(root_url)}
        # Seed all known static routes up to the route cap (Task B): high-value
        # auth/form/API routes must be enqueued with their score before the
        # crawl starts so even a short budget reaches them. Bounding the seed set
        # by the per-run route cap (not the per-page interaction budget) keeps
        # that guarantee decoupled from how much clicking each page gets.
        seed_cap = max(1, min(self.settings.crawl_max_urls, self.settings.crawl_browser_route_cap))
        for route in routes:
            absolute = urljoin(root_url, route)
            if self._origin(absolute) != root_origin:
                continue
            key = self._normalize_for_seen(absolute)
            if key in seen:
                continue
            seen.add(key)
            targets.append(absolute)
            if len(targets) >= seed_cap:
                break
        return targets

    def _dedupe_observations(self, observations: Any) -> list[RequestObservation]:
        deduped: dict[tuple[str, str, str | None, tuple[str, ...]], RequestObservation] = {}
        for observation in observations:
            content_type = (
                observation.request_content_type
                or (observation.request_headers or {}).get("content-type")
                or observation.response_content_type
            )
            key = (
                observation.method.upper(),
                self._template_url(observation.url),
                content_type,
                tuple(sorted(observation.body_schema or self._body_schema(observation.post_data))),
            )
            existing = deduped.get(key)
            if existing is None or (existing.response_status is None and observation.response_status is not None):
                deduped[key] = observation
        return list(deduped.values())

    async def _build_request_observation(self, request: Any) -> RequestObservation:
        headers = await self._request_headers(request)
        normalized_headers = self._normalize_request_headers(headers)
        content_type = self._header_value(normalized_headers, "content-type")
        cookies = self._parse_cookie_header(self._header_value(normalized_headers, "cookie") or "")
        post_data = request.post_data
        body_kind, body_schema, multipart_fields = self._request_body_metadata(post_data, content_type)
        replayable = self._is_replayable(request.method, post_data, content_type, body_schema, multipart_fields)
        return RequestObservation(
            url=request.url,
            method=request.method,
            resource_type=request.resource_type,
            request_headers=normalized_headers,
            request_cookies=cookies,
            request_content_type=content_type,
            post_data=post_data,
            body_kind=body_kind,
            body_schema=body_schema,
            multipart_fields=multipart_fields,
            replayable=replayable,
        )

    async def _request_headers(self, request: Any) -> dict[str, str]:
        try:
            return dict(await request.all_headers())
        except Exception:
            return dict(getattr(request, "headers", {}) or {})

    def _normalize_request_headers(self, headers: dict[str, str]) -> dict[str, str]:
        normalized: dict[str, str] = {}
        for name, value in (headers or {}).items():
            lowered = str(name).lower()
            if lowered in VOLATILE_REQUEST_HEADERS:
                continue
            if value is None:
                continue
            normalized[lowered] = str(value)
        return normalized

    @staticmethod
    def _header_value(headers: dict[str, str], name: str) -> str | None:
        lowered = name.lower()
        for header_name, value in (headers or {}).items():
            if header_name.lower() == lowered:
                return value
        return None

    @staticmethod
    def _parse_cookie_header(cookie_header: str) -> dict[str, str]:
        cookies: dict[str, str] = {}
        for part in cookie_header.split(";"):
            if "=" not in part:
                continue
            name, value = part.split("=", 1)
            name = name.strip()
            if name:
                cookies[name] = value.strip()
        return cookies

    def _request_body_metadata(
        self,
        body: Any,
        content_type: str | None,
    ) -> tuple[str | None, list[str], list[dict[str, Any]]]:
        if isinstance(body, bytes):
            body = body.decode("utf-8", "ignore")
        if not isinstance(body, str) or not body.strip():
            return None, [], []

        lowered = (content_type or "").lower()
        if "json" in lowered:
            return "json", sorted(self._body_schema(body)), []
        if "application/x-www-form-urlencoded" in lowered:
            names = sorted(name for name in parse_qs(body, keep_blank_values=True) if name)
            return "form", names, [{"name": name, "type": "text"} for name in names]
        if "multipart/form-data" in lowered:
            fields = self._multipart_field_metadata(body)
            return "multipart", sorted(field["name"] for field in fields if field.get("name")), fields
        return None, [], []

    def _multipart_field_metadata(self, body: str) -> list[dict[str, Any]]:
        fields: list[dict[str, Any]] = []
        seen: set[str] = set()
        for match in re.finditer(
            r'Content-Disposition:\s*form-data;\s*name="(?P<name>[^"]+)"(?P<rest>[^\r\n]*)',
            body,
            re.I,
        ):
            name = match.group("name")
            if not name or name in seen:
                continue
            seen.add(name)
            rest = match.group("rest") or ""
            filename_match = re.search(r'filename="(?P<filename>[^"]*)"', rest, re.I)
            fields.append(
                {
                    "name": name,
                    "type": "file" if filename_match else "text",
                    "filename": filename_match.group("filename") if filename_match else None,
                }
            )
        return fields

    @staticmethod
    def _is_replayable(
        method: str,
        body: Any,
        content_type: str | None,
        body_schema: list[str],
        multipart_fields: list[dict[str, Any]],
    ) -> bool:
        method = method.upper()
        if method in {"GET", "HEAD", "OPTIONS"}:
            return True
        if not body:
            return False
        lowered = (content_type or "").lower()
        if "json" in lowered:
            return bool(body_schema)
        if "application/x-www-form-urlencoded" in lowered:
            return bool(body_schema)
        if "multipart/form-data" in lowered:
            return bool(multipart_fields)
        return False

    def _template_url(self, url: str) -> str:
        parsed = urlparse(url)
        path = re.sub(r"/(?:[0-9]+|[0-9a-f]{8,}(?:-[0-9a-f]{4,})*)", "/{id}", parsed.path, flags=re.I)
        query_names = sorted(part.split("=", 1)[0] for part in parsed.query.split("&") if part)
        query_suffix = f"?{'&'.join(query_names)}" if query_names else ""
        return f"{parsed.scheme}://{parsed.netloc}{path}{query_suffix}"

    def _body_schema(self, body: Any) -> set[str]:
        if not isinstance(body, str) or not body.strip():
            return set()
        try:
            parsed = json.loads(body)
        except Exception:
            return set()
        schema: set[str] = set()

        def walk(value: Any, prefix: str = "") -> None:
            if isinstance(value, dict):
                for key, child in value.items():
                    path = f"{prefix}.{key}" if prefix else key
                    schema.add(path)
                    walk(child, path)
            elif isinstance(value, list):
                for item in value[:1]:
                    walk(item, f"{prefix}[]")

        walk(parsed)
        return schema

    def _redirect_chain(self, request: Any) -> list[str]:
        chain: list[str] = []
        current = getattr(request, "redirected_from", None)
        if callable(current):
            current = current()
        while current is not None:
            url = getattr(current, "url", None)
            if url:
                chain.insert(0, url)
            current = getattr(current, "redirected_from", None)
            if callable(current):
                current = current()
        return chain

    def _origin(self, url: str) -> str:
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}".lower()

    def _normalize_for_seen(self, url: str) -> str:
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}".rstrip("/").lower()
