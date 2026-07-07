from __future__ import annotations

import asyncio
import heapq
import json
import logging
import re
from typing import Any
from urllib.parse import parse_qs, urljoin, urlparse, urlunparse

from app.config import get_settings
from app.core.crawler.api_extractor import ApiExtractor
from app.core.crawler.models import ApiEndpoint, CrawlState, RequestObservation, RouteCandidate, RouteSource
from app.core.crawler.route_priority import score_route_surface
from app.core.crawler.spa import SpaFallbackDetector, install_resource_blocking, settle_page

logger = logging.getLogger(__name__)


DESTRUCTIVE_LABEL_RE = re.compile(
    r"\b(delete|remove|destroy|purchase|checkout|pay|confirm|transfer|withdraw|subscribe|unsubscribe"
    r"|logout|log ?out|sign ?out|sign ?off)\b",
    re.I,
)
COOKIE_BANNER_LABEL_RE = re.compile(r"\b(accept|agree|allow|ok|got it|continue|close|dismiss)\b", re.I)
SAFE_SUBMIT_LABEL_RE = re.compile(
    r"\b(login|log in|sign in|register|sign up|submit|send|save|search|reset|upload|continue|next)\b",
    re.I,
)
# Confirm/repeat fields (password-confirm, retype-email, …). A generic
# equality-validator satisfier: a field whose name matches this echoes the value
# just filled into the primary same-type field so "must match" validators pass,
# regardless of the app-specific field name. No target-specific tokens.
CONFIRM_FIELD_RE = re.compile(
    r"(confirm|repeat|verify|retype|re-?enter|re-?type|again|match|_2\b|2$)",
    re.I,
)
# Ask the browser to submit a form element (honours HTML5 validity). Returns
# true only when a form was actually submitted, so the caller can tell whether
# this fallback fired anything.
REQUEST_SUBMIT_JS = (
    "(sel) => { const f = document.querySelector(sel); if (!f) return false; "
    "const form = f.tagName === 'FORM' ? f : f.querySelector('form'); "
    "if (!form) return false; "
    "if (form.requestSubmit) { form.requestSubmit(); } else { form.submit(); } "
    "return true; }"
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
MAX_CAPTURED_BODY_CHARS = 64_000
TRANSPORT_NOISE_PATHS = ("/socket.io", "/engine.io", "/sockjs", "/signalr")
ROOT_API_PATH_RE = re.compile(r"^/(?:api|rest|graphql|gql|v[0-9]+|rpc|trpc|oauth|session)(?:/|$)", re.I)

# Sentinel returned by _bounded when an operation times out or errors, so a
# successful call returning None (e.g. Playwright click) is distinguishable
# from a skipped one.
_BOUNDED_FAILED = object()


def _parses_as_json(body: Any) -> bool:
    """True when ``body`` decodes to valid JSON (any top-level type)."""
    if isinstance(body, (bytes, bytearray)):
        body = bytes(body).decode("utf-8", "ignore")
    if not isinstance(body, str) or not body.strip():
        return False
    try:
        json.loads(body)
        return True
    except Exception:
        return False

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

# Extract structured input clusters after the DOM has settled and overlays are
# cleared. Framework-agnostic: covers both literal <form> elements AND orphan
# input groups (the React/Angular/Vue pattern where inputs bind to JS handlers
# and submit via fetch/XHR with no <form> wrapper). Each cluster's root node is
# tagged `data-sentry-cluster=N` and each fillable field `data-sentry-field=N:i`
# so the engine can fill/submit precisely via Playwright's React-aware setters,
# regardless of whether the inputs carry a `name`. Keys on DOM structure only.
FORM_CAPTURE_SCRIPT = """
() => {
  const clusters = [];
  try {
    const SUBMIT = 'button,input[type=submit],input[type=button],[role=button]';
    const isVisible = (el) => {
      try {
        const s = getComputedStyle(el);
        const r = el.getBoundingClientRect();
        return s && s.visibility !== 'hidden' && s.display !== 'none' && r.width > 0 && r.height > 0;
      } catch (e) { return false; }
    };
    const fieldName = (el) => (
      el.getAttribute('name') || el.getAttribute('id') || el.getAttribute('formcontrolname') ||
      el.getAttribute('ng-reflect-name') || el.getAttribute('data-testid') ||
      el.getAttribute('placeholder') || el.getAttribute('aria-label') || ''
    );
    const fieldType = (el) => (el.getAttribute('type') || el.tagName.toLowerCase() || 'text').toLowerCase();
    let cid = 0;
    const emit = (root, fieldEls, action, method, hasForm) => {
      const inputs = [];
      let fileInputs = 0;
      let fieldIndex = 0;
      fieldEls.forEach((el) => {
        if (!isVisible(el)) return;
        const type = fieldType(el);
        if (type === 'file') fileInputs++;
        const fieldId = cid + ':' + fieldIndex;
        try { el.setAttribute('data-sentry-field', fieldId); } catch (e) {}
        // Never emit an empty name. When the framework name cascade fails (common
        // pre-hydration on SPAs), fall back to the stable positional field_id so
        // the field remains addressable for fill + body synthesis.
        const resolvedName = fieldName(el) || ('field_' + fieldId.replace(':', '_'));
        inputs.push({ name: resolvedName, type: type, field_id: fieldId, named: !!fieldName(el) });
        fieldIndex++;
      });
      if (!inputs.length) return;
      const actionable = [...root.querySelectorAll(SUBMIT)].filter(isVisible).length;
      const fillable = inputs.filter((i) => !['hidden','submit','button','image','reset'].includes(i.type)).length;
      if (!fillable) return;
      if (!hasForm && actionable < 1) return;
      try { root.setAttribute('data-sentry-cluster', String(cid)); } catch (e) {}
      const namedFillable = inputs.filter(
        (i) => i.named && !['hidden','submit','button','image','reset'].includes(i.type)
      ).length;
      clusters.push({
        cluster_id: cid,
        action: action || location.href,
        method: (method || 'GET').toUpperCase(),
        inputs: inputs,
        has_form: !!hasForm,
        file_inputs: fileInputs,
        action_controls: actionable,
        // Hydration signal: true when every fillable field resolved a real
        // framework name (not just a positional fallback). A cluster with
        // zero named fillable fields is a candidate for a post-settle recapture.
        all_named: namedFillable > 0 && namedFillable === fillable,
        named_fillable: namedFillable,
      });
      cid++;
    };

    // 1) Literal <form> elements (unchanged behaviour, now cluster-shaped).
    document.querySelectorAll('form').forEach((f) => {
      emit(
        f,
        [...f.querySelectorAll('input,textarea,select')],
        f.getAttribute('action') || location.href,
        f.getAttribute('method') || 'GET',
        true
      );
    });

    // 2) Orphan input clusters: inputs with no <form> ancestor, grouped by the
    // nearest container that also holds a submit-like control (climb <=6 levels).
    const orphans = [...document.querySelectorAll('input,textarea,select')]
      .filter((el) => !el.closest('form') && isVisible(el) && fieldType(el) !== 'hidden');
    const rootOf = (el) => {
      let node = el;
      for (let i = 0; i < 6 && node.parentElement; i++) {
        if (node.parentElement.querySelector(SUBMIT)) { return node.parentElement; }
        node = node.parentElement;
      }
      return null;
    };
    const seenRoots = [];
    orphans.forEach((el) => {
      const root = rootOf(el);
      if (!root) return;
      if (seenRoots.indexOf(root) !== -1) return;
      seenRoots.push(root);
      const fields = [...root.querySelectorAll('input,textarea,select')]
        .filter((x) => !x.closest('form'));
      if (fields.length) emit(root, fields, location.href, 'POST', false);
    });
  } catch (e) {}
  return clusters;
}
"""


# Given a cluster_id, report whether its submit control is enabled (or the form
# is natively valid) and, if not, enumerate the still-invalid required controls
# so the filler can target them. DOM-anchored on ``data-sentry-cluster`` /
# ``data-sentry-field`` so it survives framework re-renders.
_CLUSTER_VALIDITY_SCRIPT = """
(cid) => {
  const out = { submittable: false, invalid_fields: [] };
  try {
    const root = document.querySelector("[data-sentry-cluster='" + cid + "']");
    if (!root) return out;
    const SUBMIT = 'button[type=submit],input[type=submit],button:not([type]),button,[role=button]';
    const controls = [...root.querySelectorAll(SUBMIT)];
    const anyEnabled = controls.some((c) => !c.disabled);
    let formValid = true;
    const form = root.tagName === 'FORM' ? root : root.closest('form');
    if (form && typeof form.checkValidity === 'function') {
      try { formValid = form.checkValidity(); } catch (e) { formValid = true; }
    }
    // Submittable when a control is enabled AND (no form or the form is valid).
    out.submittable = anyEnabled && formValid;
    if (out.submittable) return out;
    const fields = [...root.querySelectorAll('input,textarea,select')];
    fields.forEach((el) => {
      const type = (el.getAttribute('type') || el.tagName.toLowerCase() || 'text').toLowerCase();
      if (['hidden','submit','button','image','reset'].includes(type)) return;
      let invalid = false;
      try { invalid = typeof el.checkValidity === 'function' ? !el.checkValidity() : false; } catch (e) { invalid = false; }
      const empty = !(el.value && String(el.value).length);
      if (invalid || (el.required && empty)) {
        out.invalid_fields.push({
          name: el.getAttribute('name') || el.getAttribute('id') || el.getAttribute('formcontrolname') || '',
          type: type,
          field_id: el.getAttribute('data-sentry-field') || '',
        });
      }
    });
  } catch (e) {}
  return out;
}
"""


class BrowserDiscoveryEngine:
    """Optional Playwright-backed crawler for SPAs.

    The engine is deliberately isolated so the HTTP crawler remains usable when
    browser binaries are unavailable. It records runtime navigation and network
    activity that static crawling cannot see.
    """

    def __init__(self, max_interactions: int = 25, workers: int | None = None) -> None:
        self.max_interactions = max_interactions
        self.settings = get_settings()
        # Number of parallel crawl workers (each its own context/page). None =
        # read from settings at crawl time so a per-scan override can be threaded
        # in by the caller (as the spider does for max_interactions).
        self._workers = workers

    @staticmethod
    async def check_readiness() -> tuple[bool, str | None]:
        try:
            from playwright.async_api import async_playwright
        except Exception as exc:
            return False, f"Playwright import failed: {exc}"

        try:
            async with async_playwright() as pw:
                browser = await BrowserDiscoveryEngine._launch_chromium(pw.chromium)
                await browser.close()
        except Exception as exc:
            return False, f"Playwright browser launch failed: {exc}"
        return True, None

    @staticmethod
    async def _launch_chromium(chromium: Any) -> Any:
        try:
            return await chromium.launch(headless=True)
        except Exception as first_exc:
            executable_path = getattr(chromium, "executable_path", None)
            if executable_path:
                try:
                    return await chromium.launch(headless=True, executable_path=executable_path)
                except Exception:
                    pass
            raise first_exc

    async def _create_seeded_context(
        self,
        browser: Any,
        storage_state: dict | None,
        auth_cookie_entries: list[dict[str, str]],
        auth_headers: dict[str, str] | None,
    ) -> Any:
        """Create a browser context seeded for authenticated crawling.

        Restores the full ``storage_state`` blob when supplied (cookies +
        per-origin localStorage/sessionStorage so the SPA's own bootstrap renders
        the logged-in shell), else a bare context with cookie/header injection.
        Installs resource blocking (gated), the SPA route hook, auth cookies, and
        extra headers. One of these is built per worker so each parallel page has
        its own isolated session context.
        """
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

        # Abort non-essential resource loads (images/media/fonts/stylesheets +
        # known trackers) so every navigation settles faster. Never blocks
        # same-origin script/xhr/fetch/document (those can drive SPA data loads).
        if getattr(self.settings, "crawl_browser_block_resources", True):
            await install_resource_blocking(context)

        # Capture programmatic SPA route changes across all pages.
        try:
            await context.add_init_script(SPA_ROUTE_HOOK_SCRIPT)
        except Exception:
            pass

        if auth_cookie_entries:
            await context.add_cookies(auth_cookie_entries)
        if auth_headers:
            await context.set_extra_http_headers(auth_headers)
        return context

    def _wire_page_observers(
        self,
        page: Any,
        wstate: CrawlState,
        by_key: dict[tuple[str, str, str], RequestObservation],
        inflight: dict[str, int],
        pending_observers: set[asyncio.Task],
        root_origin_url: str,
    ) -> None:
        """Attach the request/response/websocket observers to a worker's page.

        Each worker owns its ``wstate``/``by_key``/``inflight`` so observations
        stream into per-worker state (merged under lock at the end) and the
        inflight counter reaches quiescence independently — a single shared
        counter never drains while any worker is still loading.
        """

        def _register(observation: RequestObservation) -> RequestObservation:
            key = self._observation_key(observation.url, observation.method, observation.post_data)
            existing = by_key.get(key)
            if existing is not None:
                return existing
            by_key[key] = observation
            if observation.drop_reason is None:
                wstate.requests.append(observation)
            wstate.request_audit.append(observation)
            self._record_request_audit_reason(wstate, observation)
            return observation

        def _inc_inflight(_request):
            inflight["count"] += 1

        def _dec_inflight(_request):
            inflight["count"] = max(0, inflight["count"] - 1)

        def _track(coro: Any) -> None:
            task = asyncio.create_task(coro)
            pending_observers.add(task)
            task.add_done_callback(pending_observers.discard)

        async def on_request(request):
            try:
                decision = self._classify_runtime_request(root_origin_url, request)
                if decision == "off_origin":
                    return
                observation = await self._build_request_observation(
                    request,
                    drop_reason=None if decision == "capture" else decision,
                )
                _register(observation)
            except Exception as exc:
                logger.debug("request observation capture failed for %s: %s", getattr(request, "url", ""), exc)

        async def on_response(response):
            request = response.request
            if self._classify_runtime_request(root_origin_url, request) == "off_origin":
                return
            observation_key = self._observation_key(
                request.url, request.method, self._safe_post_data(request)
            )
            observed = by_key.get(observation_key)
            try:
                if observed is None:
                    decision = self._classify_runtime_request(root_origin_url, request)
                    observed = _register(
                        await self._build_request_observation(
                            request,
                            drop_reason=None if decision == "capture" else decision,
                        )
                    )
            except Exception as exc:
                logger.debug("response observation capture failed for %s: %s", getattr(request, "url", ""), exc)
                return
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
            try:
                url = ws.url
            except Exception:
                return
            if not self._same_origin_or_websocket(root_origin_url, url):
                return
            _register(
                RequestObservation(
                    url=url,
                    method="GET",
                    resource_type="websocket",
                    replayable=False,
                )
            )

        page.on("request", lambda request: _track(on_request(request)))
        page.on("request", _inc_inflight)
        page.on("requestfinished", _dec_inflight)
        page.on("requestfailed", _dec_inflight)
        page.on("response", lambda response: _track(on_response(response)))
        try:
            page.on("websocket", on_websocket)
        except Exception:
            pass

    async def _drain_observer_tasks(
        self,
        pending_observers: set[asyncio.Task],
        timeout_s: float = 2.0,
    ) -> None:
        """Wait briefly for asynchronous request/response observers to finish."""
        if not pending_observers:
            return
        done, pending = await asyncio.wait(
            list(pending_observers),
            timeout=max(0.05, timeout_s),
        )
        for task in done:
            try:
                task.result()
            except Exception as exc:
                logger.debug("browser observer task failed: %s", exc)
        for task in pending:
            task.cancel()

    @staticmethod
    def _merge_worker_state(
        target: CrawlState,
        source: CrawlState,
        seen_observations: set[tuple[str, str, str]],
    ) -> None:
        """Fold a worker's local :class:`CrawlState` into ``target`` under no
        contention (called once per worker after the pool joins).

        ``add_*`` already dedup routes/endpoints/params/forms; requests are
        deduped across workers by observation key via ``seen_observations`` (each
        worker already deduped internally, so this only drops cross-worker
        duplicates while preserving the first-seen enriched observation).
        """
        for route in source.routes:
            target.add_route(route)
        for form in source.browser_forms:
            target.add_browser_form(form)
        target.workflow_states_visited += source.workflow_states_visited
        target.browser_forms_discovered += source.browser_forms_discovered
        target.browser_forms_submitted += source.browser_forms_submitted
        target.file_inputs_discovered += source.file_inputs_discovered
        for observation in source.requests:
            key = BrowserDiscoveryEngine._observation_key(
                observation.url, observation.method, observation.post_data
            )
            if key in seen_observations:
                continue
            seen_observations.add(key)
            target.requests.append(observation)
        seen_audit = {
            (
                observation.method.upper(),
                observation.url,
                str(observation.post_data or ""),
                observation.drop_reason or "",
            )
            for observation in target.request_audit
        }
        for observation in source.request_audit:
            key = (
                observation.method.upper(),
                observation.url,
                str(observation.post_data or ""),
                observation.drop_reason or "",
            )
            if key in seen_audit:
                continue
            seen_audit.add(key)
            target.request_audit.append(observation)
        for reason, count in source.request_audit_summary.items():
            target.request_audit_summary[reason] = target.request_audit_summary.get(reason, 0) + count

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
        root_origin_url = root_url

        async with async_playwright() as pw:
            try:
                browser = await self._launch_chromium(pw.chromium)
            except Exception as exc:
                logger.warning("Playwright browser launch failed; skipping browser discovery: %s", exc)
                state.browser_available = False
                state.browser_error = f"Playwright browser launch failed: {exc}"
                return state

            # The browser is live: record availability immediately so a later
            # truncation still reports True rather than the None default.
            state.browser_available = True

            auth_cookie_entries = self._auth_cookie_entries(root_url, auth_cookies)

            # --- Shared, value-ordered work queue guarded by a single lock -----
            # A max-heap keyed by descending surface score, tie-broken by insertion
            # order for determinism. High-surface routes (auth/forms/API-bearing)
            # are popped first so meaningful coverage lands before truncation.
            route_budget = max(1, min(self.settings.crawl_max_urls, self.settings.crawl_browser_route_cap))
            heap: list[tuple[int, int, str]] = []
            seen_routes: set[str] = set()
            submitted_form_keys: set[tuple[str, str, tuple[str, ...]]] = set()
            counter = 0
            lock = asyncio.Lock()
            cond = asyncio.Condition(lock)

            def _enqueue(url: str, evidence: str = "") -> None:
                """Claim + queue a route. MUST be called while holding ``lock``.

                Adding to ``seen_routes`` at enqueue time claims the route the
                instant it is queued, so two workers never grab the same one.
                """
                nonlocal counter
                key = self._normalize_for_seen(url)
                if key in seen_routes or len(seen_routes) >= route_budget:
                    return
                seen_routes.add(key)
                # Negate score so heapq (a min-heap) pops highest score first;
                # the monotonic counter preserves FIFO among equal scores.
                heapq.heappush(heap, (-score_route_surface(url, evidence), counter, url))
                counter += 1

            # Seed known static routes before the crawl starts (no contention yet,
            # single task) so even a short budget reaches them.
            for target in self._browser_targets(root_url, routes or []):
                _enqueue(target, evidence="seed")

            # Effective budget scaled to route count: small apps finish fast, large
            # apps get proportionally more, always capped by the configured overall
            # budget. Per-route deadline checks still guarantee a clean truncation.
            effective_deadline = self._effective_deadline(deadline, loop, len(seen_routes))
            budget_s = (
                round(effective_deadline - loop.time(), 1)
                if effective_deadline is not None else None
            )

            num_workers = max(1, int(self._workers if self._workers is not None
                                     else getattr(self.settings, "crawl_browser_workers", 4)))
            logger.info(
                "browser discovery starting for %s: seed_routes=%d budget_s=%s workers=%d",
                root_url, len(seen_routes), budget_s, num_workers,
            )

            # --- Worker-pool coordination --------------------------------------
            worker_states: list[CrawlState] = []
            routes_visited = 0
            idle_workers = 0
            running_workers = num_workers
            finished = False

            def _record_truncation() -> None:
                nonlocal finished
                finished = True
                if not state.browser_error:
                    state.browser_error = (
                        "browser discovery truncated: overall budget reached before all routes were visited"
                    )

            async def _worker(worker_id: int) -> None:
                nonlocal routes_visited, idle_workers, running_workers, finished

                wstate = CrawlState()
                worker_states.append(wstate)
                by_key: dict[tuple[str, str, str], RequestObservation] = {}
                inflight = {"count": 0}
                pending_observers: set[asyncio.Task] = set()

                # Each worker gets its own seeded context/page: isolated session,
                # isolated inflight counter (a shared counter never drains while
                # any worker is loading), isolated observation stream.
                try:
                    context = await self._create_seeded_context(
                        browser, storage_state, auth_cookie_entries, auth_headers
                    )
                    page = await context.new_page()
                except Exception as exc:
                    logger.warning("worker %d could not open a context: %s", worker_id, exc)
                    async with lock:
                        running_workers -= 1
                        cond.notify_all()
                    return

                self._wire_page_observers(
                    page,
                    wstate,
                    by_key,
                    inflight,
                    pending_observers,
                    root_origin_url,
                )
                first = True
                try:
                    while True:
                        # --- Acquire the next route (or terminate) -------------
                        async with lock:
                            target_url = None
                            while True:
                                if finished:
                                    return
                                if effective_deadline is not None and loop.time() >= effective_deadline:
                                    _record_truncation()
                                    cond.notify_all()
                                    return
                                if heap:
                                    _, _, target_url = heapq.heappop(heap)
                                    routes_visited += 1
                                    break
                                # Heap empty: go idle. If every still-running worker
                                # is idle with an empty heap, the crawl is done.
                                idle_workers += 1
                                if idle_workers >= running_workers:
                                    finished = True
                                    cond.notify_all()
                                    return
                                await cond.wait()
                                idle_workers -= 1
                                if finished:
                                    return
                                # Loop back to re-check heap/deadline.

                        # --- Process the route on this worker's own page -------
                        allow_interaction = self._budget_allows_interaction(effective_deadline, loop)
                        try:
                            # Each worker's first navigation is a full load (its
                            # page starts blank); later same-origin routes prefer
                            # client-side navigation.
                            await self._navigate(page, target_url, root_url, allow_spa=not first)
                            first = False
                            await self._settle_inflight(page, inflight)
                            await self._drain_observer_tasks(pending_observers)
                            await self._clear_blocking_overlays(page)
                            # Post-auth liveness re-check (generic). On the root a
                            # logged-out shell means the seeded storage_state never
                            # persisted (RC-A); on other routes it means interaction
                            # dropped the session mid-crawl (P1-3). Re-seed cookies
                            # when we have them rather than crawl unauthenticated.
                            is_root = self._normalize_for_seen(target_url) == self._normalize_for_seen(root_url)
                            if (storage_state or auth_cookie_entries) and await self._looks_logged_out(page):
                                reseeded = await self._reseed_session(context, auth_cookie_entries)
                                if reseeded:
                                    logger.info(
                                        "browser session looked logged-out on %s; re-seeded auth cookies",
                                        target_url,
                                    )
                                elif is_root and storage_state and not state.browser_error:
                                    state.browser_error = (
                                        "authenticated session did not persist into browser context"
                                    )
                            wstate.add_route(
                                RouteCandidate(
                                    url=self._current_url(page, target_url),
                                    source=RouteSource.browser,
                                    priority=75,
                                    evidence="browser_navigation",
                                )
                            )
                            # Form capture + active submission is the highest-yield
                            # body-producing work, so it runs BEFORE blind
                            # interaction — otherwise ``_exercise_page`` consumes the
                            # per-route budget first and the submit path (which fires
                            # the app's real POST/PUT/PATCH XHR that on_request
                            # captures as a replayable body) is starved on truncation.
                            # Count forms/file inputs from structural clusters (RC-1):
                            # runs on every route, not gated on literal <form>s.
                            captured_forms = await self._capture_forms(page, target_url)
                            # Hydration-aware recapture: if any cluster's fields
                            # resolved no real framework name (pre-hydration SPA
                            # capture), let the framework settle and capture once
                            # more so late-bound names (formcontrolname etc.) land.
                            if self._forms_need_hydration_recapture(captured_forms):
                                await self._settle_inflight(page, inflight, cap_ms=1200.0)
                                recaptured = await self._capture_forms(page, target_url)
                                if recaptured:
                                    captured_forms = recaptured
                            wstate.browser_forms_discovered += len(captured_forms)
                            wstate.file_inputs_discovered += sum(
                                int(form.get("file_inputs", 0)) for form in captured_forms
                            )
                            for form in captured_forms:
                                wstate.add_browser_form(form)
                            # Atomically claim un-submitted form keys under the lock
                            # so two workers never submit the same form; then submit
                            # outside the lock (slow) against a throwaway dedup set.
                            async with lock:
                                new_forms = []
                                for form in captured_forms:
                                    key = CrawlState._form_key(form)
                                    if key not in submitted_form_keys:
                                        submitted_form_keys.add(key)
                                        new_forms.append(form)
                            # Active form submission (Task B): fire the app's real
                            # POST/PUT/PATCH XHR so on_request captures a replayable
                            # observation. Skips destructive forms.
                            wstate.browser_forms_submitted += await self._submit_discovered_forms(
                                page, new_forms, root_url, target_url, set(),
                                inflight=inflight,
                            )
                            await self._drain_observer_tasks(pending_observers)
                            # Blind interaction runs last, on whatever budget the
                            # high-yield submit path left, so it can never starve
                            # form submission or route coverage.
                            if allow_interaction:
                                # RC2: bound blind clicking to this route's budget
                                # share so no single page starves route coverage.
                                interaction_budget = float(
                                    getattr(self.settings, "crawl_browser_per_route_seconds", 6.0)
                                )
                                if effective_deadline is not None:
                                    interaction_budget = min(
                                        interaction_budget,
                                        max(0.0, effective_deadline - loop.time()),
                                    )
                                if interaction_budget > 0.0:
                                    workflow_stats = await self._exercise_page(
                                        page, max_seconds=interaction_budget
                                    )
                                    wstate.workflow_states_visited += workflow_stats.get("states", 0)
                                await self._drain_observer_tasks(pending_observers)
                            # Enqueue newly-discovered same-origin routes (scored),
                            # then wake any idle workers to pick them up.
                            discovered = await self._discover_routes(page, root_url)
                            async with lock:
                                for new_route in discovered:
                                    _enqueue(new_route, evidence="browser_discovered")
                                cond.notify_all()
                        except Exception as exc:
                            logger.warning("browser discovery failed for %s: %s", target_url, exc)
                finally:
                    # This worker is leaving the pool: drop it from the running
                    # count and wake the others so termination re-evaluates.
                    async with lock:
                        running_workers -= 1
                        cond.notify_all()
                    try:
                        await self._drain_observer_tasks(pending_observers)
                    except Exception:
                        pass
                    try:
                        await context.close()
                    except Exception:
                        pass

            try:
                await asyncio.gather(
                    *[_worker(i) for i in range(num_workers)], return_exceptions=True
                )
            finally:
                # Merge each worker's local state into the shared state. This runs
                # in ``finally`` — even under a hard-timeout cancellation — so the
                # per-worker partial observations (streamed into each ``wstate`` in
                # place during the run) are never discarded (the RC-1 durability
                # guarantee, preserved despite per-worker accumulation). add_*
                # dedup; requests dedup by observation key across workers.
                seen_observations: set[tuple[str, str, str]] = set()
                for wstate in worker_states:
                    self._merge_worker_state(state, wstate, seen_observations)
                # Derive endpoints/params from whatever streamed in — runs even on
                # truncation so partial coverage yields testable surface.
                self._derive_endpoints(state)
                # Visibility summary: read as forms_submitted>0 but post_bodies==0
                # => submits fire but bodies are lost; json_bodies>0 => RC1 works.
                post_bodies = [r for r in state.requests if getattr(r, "post_data", None)]
                replayable_bodies = [r for r in post_bodies if getattr(r, "replayable", True)]
                json_bodies = [
                    r for r in post_bodies
                    if "json" in (getattr(r, "request_content_type", "") or "").lower()
                ]
                logger.info(
                    "browser discovery finished for %s: routes_visited=%d requests=%d "
                    "forms_captured=%d forms_submitted=%d file_inputs=%d "
                    "post_bodies=%d replayable_bodies=%d json_bodies=%d error=%s",
                    root_url,
                    routes_visited,
                    len(state.requests),
                    state.browser_forms_discovered,
                    state.browser_forms_submitted,
                    state.file_inputs_discovered,
                    len(post_bodies),
                    len(replayable_bodies),
                    len(json_bodies),
                    state.browser_error,
                )
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
                parameter.context["body_schema"] = list(observation.body_schema)
                if observation.non_replayable_reason:
                    parameter.context["non_replayable_reason"] = observation.non_replayable_reason
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

    @staticmethod
    def _auth_cookie_entries(root_url: str, auth_cookies: dict[str, str] | None) -> list[dict[str, str]]:
        """Playwright cookie dicts for the target origin, or an empty list."""
        if not auth_cookies:
            return []
        parsed = urlparse(root_url)
        domain = parsed.netloc.split(":")[0]
        path = parsed.path or "/"
        return [
            {"name": name, "value": value, "domain": domain, "path": path}
            for name, value in auth_cookies.items()
        ]

    async def _reseed_session(self, context: Any, entries: list[dict[str, str]]) -> bool:
        """Re-apply auth cookies to a live context (mid-crawl session recovery).

        Returns True when cookies were re-added. Never raises: a failed re-seed
        must not abort the crawl. Recovers cookie-session apps that dropped their
        session during interaction; storage_state/bearer apps are handled by the
        caller (which surfaces a browser_error instead)."""
        if not entries:
            return False
        try:
            await context.add_cookies(entries)
            return True
        except Exception as exc:
            logger.debug("session re-seed failed: %s", exc)
            return False

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

        Thin wrapper over the shared :func:`spa.settle_page`, passing the crawl
        loop's persistent inflight counter (already wired to the page's request
        events) so there is exactly one settle implementation. ``networkidle``
        never fires on apps with persistent sockets/polling, so we watch the
        counter and return once it stays at zero for ``quiet_ms`` or ``cap_ms``
        elapses — whichever comes first.
        """
        await settle_page(page, inflight=inflight, quiet_ms=quiet_ms, cap_ms=cap_ms)

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
        """Return structured input clusters rendered on the page.

        A "form" here is a structural input cluster (see :data:`FORM_CAPTURE_SCRIPT`):
        either a literal ``<form>`` or an orphan input group (the ``<form>``-less
        SPA pattern). Each carries ``cluster_id``/``has_form``/``file_inputs`` and
        per-input ``field_id`` so :meth:`_fill_form_fields`/:meth:`_submit_form`
        can target it precisely. Legacy keys (action/method/inputs/page_url) are
        preserved so ``CrawlState._form_key``/``add_browser_form`` are unchanged.
        """
        result = await self._bounded(page.evaluate(FORM_CAPTURE_SCRIPT), 1000)
        if result is _BOUNDED_FAILED or not isinstance(result, list):
            return []
        forms: list[dict[str, Any]] = []
        for entry in result:
            if not isinstance(entry, dict):
                continue
            inputs = entry.get("inputs") if isinstance(entry.get("inputs"), list) else []
            normalized_inputs = [
                {
                    "name": str(i.get("name", "")),
                    "type": str(i.get("type", "text")),
                    "field_id": str(i.get("field_id", "")),
                    # True when a real framework name resolved (not a positional
                    # field_id fallback). Drives hydration-aware recapture.
                    "named": bool(i.get("named", True)),
                }
                for i in inputs
                if isinstance(i, dict)
            ]
            fillable_inputs = [
                item for item in normalized_inputs
                if item["type"].lower() not in {"hidden", "submit", "button", "image", "reset"}
            ]
            has_form = bool(entry.get("has_form", True))
            action_controls = int(entry.get("action_controls", 1) or 0)
            if not fillable_inputs:
                continue
            if not has_form and action_controls < 1:
                continue
            forms.append(
                {
                    "action": urljoin(page_url, str(entry.get("action") or page_url)),
                    "method": str(entry.get("method") or "GET").upper(),
                    "inputs": normalized_inputs,
                    "cluster_id": entry.get("cluster_id"),
                    "has_form": has_form,
                    "file_inputs": int(entry.get("file_inputs", 0) or 0),
                    "page_url": page_url,
                    "all_named": bool(entry.get("all_named", True)),
                }
            )
        return forms

    def _forms_need_hydration_recapture(self, forms: list[dict[str, Any]]) -> bool:
        """True when at least one captured cluster has no real framework names.

        Pre-hydration SPA captures yield fields whose name cascade fell through to
        the positional field_id fallback (``all_named`` False). Re-running capture
        after the framework settles usually resolves the real names.
        """
        return any(not bool(form.get("all_named", True)) for form in forms or [])

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
        inflight: dict[str, int] | None = None,
    ) -> int:
        """Actively submit non-destructive forms to generate real request bodies.

        For each captured form, fill inputs with type-appropriate synthetic
        values (reusing the generic typed-placeholder logic) and submit it, so
        the app fires its real ``POST/PUT/PATCH`` XHR with a real body shape that
        ``on_request`` captures as a replayable observation. Destructive forms
        (delete/pay/logout/…) are never submitted. Auth forms are submitted with
        synthetic creds — capturing the request body is the goal even when the
        credentials are invalid. Each form key is submitted at most once across
        the whole crawl (dedup via :meth:`CrawlState._form_key`).

        ``inflight`` is the crawl loop's live in-flight-request counter. It is
        threaded in so the post-submit settle waits for the submit-triggered XHR
        to *finish* before we navigate back: otherwise the navigation tears the
        frame down while ``on_request`` is still asynchronously reading the
        request body, and the observation (with its POST body) is lost — the
        real cause of ``replayable_json_bodies == 0`` despite forms being
        submitted. Falls back to a throwaway counter only for direct-call tests.

        Returns the number of forms actually filled-and-submitted (skipped
        destructive/empty/duplicate clusters are not counted).
        """
        from app.core.crawler.models import CrawlState

        inflight_counter = inflight if inflight is not None else {"count": 0}
        submitted = 0
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
                logger.debug(
                    "form submit skipped (destructive) on %s: action=%s",
                    route_url, form.get("action", ""),
                )
                submitted_keys.add(key)
                continue
            submitted_keys.add(key)
            try:
                # Re-anchor before filling. A prior cluster's submit can navigate
                # away or re-render the DOM, which invalidates the capture-time
                # ``data-sentry-cluster``/``data-sentry-field`` anchors of every
                # not-yet-submitted cluster (they were tagged against a DOM that no
                # longer exists). Returning to the route and re-capturing re-tags
                # the live DOM so this cluster's selectors resolve — otherwise the
                # fill silently no-ops and the app POST never fires, which (with a
                # navigating first cluster such as a header search box) collapsed
                # per-route submission to a single low-value form.
                target = await self._reacquire_cluster(
                    page, root_url, route_url, form, inflight_counter
                )
                if target is None:
                    logger.debug(
                        "form submit skipped (cluster not present after re-capture) on %s: fields=%s",
                        route_url, [i.get("name") for i in inputs],
                    )
                    continue
                filled = await self._fill_form_fields(page, target)
                if not filled:
                    logger.debug(
                        "form submit skipped (no fillable field) on %s: action=%s fields=%s",
                        route_url, target.get("action", ""),
                        [i.get("name") for i in inputs],
                    )
                    continue
                # Fill-to-valid: a reactive form keeps its submit control disabled
                # until every required field is valid. If the first pass left it
                # invalid, re-fill the still-invalid required fields (fields that
                # mounted late or needed a matching/typed value) so the submit
                # actually enables and the app fires its real mutating XHR.
                await self._fill_to_valid(page, target)
                # Reactive frameworks enable the submit control a microtask after
                # the final field's input event; give it a brief moment so the
                # enabled-control click actually fires instead of racing the
                # disabled→enabled transition.
                await self._await_submit_enabled(page, target)
                fired = await self._submit_and_detect_fire(page, target, inflight_counter)
                if fired:
                    submitted += 1
                    logger.debug(
                        "form submitted on %s: action=%s method=%s fields=%s",
                        route_url, target.get("action", ""), target.get("method", "GET"),
                        [i.get("name") for i in inputs],
                    )
                else:
                    logger.debug(
                        "form submit fired no mutating request on %s: fields=%s",
                        route_url, [i.get("name") for i in inputs],
                    )
            except Exception as exc:
                logger.debug("form submission failed on %s: %s", route_url, exc)
        return submitted

    async def _submit_and_detect_fire(
        self, page: Any, form: dict[str, Any], inflight_counter: dict[str, int]
    ) -> bool:
        """Submit ``form`` and return True only when a MUTATING request (non
        GET/HEAD/OPTIONS) actually fires during the submit+settle window.

        ``browser_forms_submitted`` must count submissions that produced a real
        request, not attempts: a disabled/invalid reactive form can be "clicked"
        or ``requestSubmit``-ed yet fire nothing (validation blocks it), and
        counting those made the metric claim coverage that never happened. A
        transient request listener records whether the app actually sent a
        body-bearing request, which is exactly what makes an observation
        replayable downstream."""
        saw = {"fired": False}

        def _watch(request: Any) -> None:
            try:
                method = str(getattr(request, "method", "GET")).upper()
            except Exception:
                return
            if method not in ("GET", "HEAD", "OPTIONS"):
                saw["fired"] = True

        attached = False
        if hasattr(page, "on"):
            try:
                page.on("request", _watch)
                attached = True
            except Exception:
                attached = False
        try:
            await self._submit_form(page, form)
            # The submit XHR body is captured by ``on_request`` the instant the
            # request *fires*, not when it completes, so a short cap is enough to
            # let it leave the page; the full 2.5s cap mostly idles on persistent
            # sockets that never reach networkidle.
            await self._settle_inflight(page, inflight_counter, cap_ms=1200.0)
        finally:
            if attached and hasattr(page, "remove_listener"):
                try:
                    page.remove_listener("request", _watch)
                except Exception:
                    pass
        return saw["fired"]

    async def _await_submit_enabled(
        self, page: Any, form: dict[str, Any], attempts: int = 3, delay: float = 0.12
    ) -> None:
        """Briefly poll for the cluster's submit control to become enabled.

        Returns as soon as an enabled submit-like control is found (usually the
        first probe) or after ``attempts`` short waits — bounded to well under
        half a second so it never dominates the per-form budget."""
        cluster_id = form.get("cluster_id")
        scope = f"[data-sentry-cluster='{cluster_id}'] " if cluster_id is not None else ""
        selector = (
            f"{scope}button[type=submit], {scope}input[type=submit], {scope}button"
        )
        for attempt in range(attempts):
            loc = page.locator(selector)
            count = await self._bounded(loc.count(), 300)
            if isinstance(count, int) and count > 0:
                enabled = await self._bounded(loc.first.is_enabled(timeout=150), 300)
                if enabled is True:
                    return
            if attempt < attempts - 1:
                await asyncio.sleep(delay)

    async def _reacquire_cluster(
        self,
        page: Any,
        root_url: str,
        route_url: str,
        form: dict[str, Any],
        inflight: dict[str, int],
    ) -> dict[str, Any] | None:
        """Return a cluster on the current DOM matching ``form`` (by structural
        key), re-tagged against the live DOM.

        If a prior submit navigated the page off ``route_url``, navigate back
        first (SPA-aware) and re-capture so the cluster is freshly tagged; its
        capture-time anchors are otherwise stale. Matches by the structural
        :meth:`CrawlState._form_key` (action/method/sorted input names), stable
        across captures. When the page did NOT navigate, the originally-passed
        ``form`` is still anchored to the same DOM it was captured from, so it is
        returned as a fallback if re-capture yields no match (also keeps the path
        working when a capture eval transiently fails). Returns ``None`` only when
        the route genuinely changed shape (e.g. after login) and the cluster is
        gone.
        """
        from app.core.crawler.models import CrawlState

        key = CrawlState._form_key(form)
        cluster_id = form.get("cluster_id")

        def _match(candidates: list[dict[str, Any]]) -> dict[str, Any] | None:
            # Prefer the DOM-anchored cluster_id (stable across framework re-tags
            # and late-bound names); fall back to the structural name-derived key
            # only when cluster_id is unavailable/unmatched. This keeps re-capture
            # matching even when framework field names arrive after capture.
            if cluster_id is not None:
                for candidate in candidates:
                    if candidate.get("cluster_id") == cluster_id:
                        return candidate
            for candidate in candidates:
                if CrawlState._form_key(candidate) == key:
                    return candidate
            return None

        navigated = self._current_url(page, route_url) != route_url
        if not navigated:
            # Hot path: the page never left the route since capture, so this
            # cluster's ``data-sentry-cluster``/``data-sentry-field`` anchors are
            # still bound to the live DOM. A single cheap re-capture picks up any
            # in-place framework re-tag; on no match the passed ``form`` is as
            # valid as at capture time. No navigation, no settle, no retry sleep —
            # in an XHR-driven SPA most submits fire without leaving the route, so
            # paying that cost per form is what exhausted the crawl budget.
            fresh = await self._capture_forms(page, route_url)
            matched = _match(fresh)
            return matched if matched is not None else form
        # A prior submit left the route: navigate back and re-capture against the
        # freshly-mounted DOM, which needs a beat to settle before the cluster
        # exists — otherwise the stale anchors resolve to nothing. Only this
        # genuinely-changed case pays the navigate + settle + retry cost.
        await self._navigate(page, route_url, root_url, allow_spa=True)
        await self._settle_inflight(page, inflight)
        await self._clear_blocking_overlays(page)
        for attempt in range(2):
            fresh = await self._capture_forms(page, route_url)
            matched = _match(fresh)
            if matched is not None:
                return matched
            # The cluster may mount slightly late; brief settle then retry once.
            if attempt == 0:
                await asyncio.sleep(0.3)
        # Navigated but the cluster never reappeared — it is genuinely gone.
        return None

    async def _fill_form_fields(self, page: Any, form: Any) -> bool:
        """Fill a cluster's inputs with generic typed placeholders. Returns True
        if at least one field was filled (so an empty/hidden-only cluster is
        skipped).

        Fields are resolved by a cascade of selectors, not by a single synthetic
        attribute. The ``data-sentry-field`` tag set by the capture script is the
        fast path, but frameworks (Angular Material, React, Vue) frequently
        re-create an input node right after first render — discarding any foreign
        attribute — so that tag is *gone* on exactly the fields that most need
        filling (password/matInput wrappers). When it is missing, filling falls
        back to cluster-scoped selectors anchored on the ``data-sentry-cluster``
        attribute (which sits on a stable container and survives re-render):
        positional-by-type first (reliable, single selector), then the captured
        field name matched against common identifier attributes.

        A field that never fills leaves a framework reactive-form invalid, which
        keeps its submit control ``disabled`` and means the app never fires its
        real POST/PUT/PATCH XHR — the true cause of ``replayable_json_bodies == 0``
        on <form>-less SPAs. Playwright's ``fill``/``check`` drive controlled
        inputs correctly (native setters + input/change events).

        ``form`` may be the full cluster dict (preferred, carries ``cluster_id``)
        or a bare ``inputs`` list (legacy/direct-call compatibility).
        """
        if isinstance(form, dict):
            inputs = form.get("inputs") or []
            cluster_id = form.get("cluster_id")
        else:
            inputs = form or []
            cluster_id = None
        scope = f"[data-sentry-cluster='{cluster_id}'] " if cluster_id is not None else ""

        filled = False
        # Per-type occurrence index so positional fallbacks target the right
        # element when a cluster has several inputs of the same type.
        type_seen: dict[str, int] = {}
        # Last value filled per type, so a confirm/repeat field can echo the
        # primary field's value and satisfy generic "must match" validators.
        last_value_by_type: dict[str, str] = {}
        for entry in inputs:
            name = str(entry.get("name", "") or "")
            itype = str(entry.get("type", "text") or "text").lower()
            if itype in ("hidden", "submit", "button", "file", "image", "reset"):
                continue
            nth = type_seen.get(itype, 0)
            type_seen[itype] = nth + 1
            value = self._synthetic_value(name, itype)
            # A confirm/repeat field must equal the value already entered into
            # the primary field of the same type; echo it when we have one.
            if CONFIRM_FIELD_RE.search(name) and itype in last_value_by_type:
                value = last_value_by_type[itype]
            elif itype not in last_value_by_type:
                last_value_by_type[itype] = value
            if await self._fill_single_input(page, entry, scope, name, itype, nth, value=value):
                filled = True
        return filled

    async def _fill_to_valid(
        self, page: Any, form: dict[str, Any], max_rounds: int = 2
    ) -> bool:
        """Iterate filling until the cluster's submit control enables (or budget).

        A reactive form disables its submit until every required field is valid.
        After the first :meth:`_fill_form_fields` pass some required fields may
        still be invalid (mounted late, needed a matching confirm value, or a
        typed/format value). This queries the live cluster for still-invalid
        required controls and re-fills them, up to ``max_rounds`` times. Returns
        True once a submit control reports ``:enabled`` (or native form validity),
        else False — best-effort; the submit path still attempts either way.
        """
        cluster_id = form.get("cluster_id")
        if cluster_id is None:
            return False
        scope = f"[data-sentry-cluster='{cluster_id}'] "
        for _ in range(max_rounds):
            state = await self._bounded(
                page.evaluate(_CLUSTER_VALIDITY_SCRIPT, str(cluster_id)), 800
            )
            if state is _BOUNDED_FAILED or not isinstance(state, dict):
                return False
            if state.get("submittable"):
                return True
            invalid = state.get("invalid_fields")
            if not isinstance(invalid, list) or not invalid:
                # Nothing actionable left to fix (e.g. an impossible pattern).
                return False
            filled_any = False
            type_seen: dict[str, int] = {}
            for field in invalid:
                if not isinstance(field, dict):
                    continue
                name = str(field.get("name", "") or "")
                itype = str(field.get("type", "text") or "text").lower()
                if itype in ("hidden", "submit", "button", "file", "image", "reset"):
                    continue
                nth = type_seen.get(itype, 0)
                type_seen[itype] = nth + 1
                entry = {
                    "name": name,
                    "type": itype,
                    "field_id": str(field.get("field_id", "") or ""),
                }
                value = self._synthetic_value(name, itype)
                if await self._fill_single_input(page, entry, scope, name, itype, nth, value=value):
                    filled_any = True
            if not filled_any:
                return False
        # Final validity check after the last fill round.
        state = await self._bounded(
            page.evaluate(_CLUSTER_VALIDITY_SCRIPT, str(cluster_id)), 800
        )
        return bool(isinstance(state, dict) and state.get("submittable"))

    async def _fill_single_input(
        self,
        page: Any,
        entry: dict[str, Any],
        scope: str,
        name: str,
        itype: str,
        nth: int,
        value: str | None = None,
    ) -> bool:
        """Fill one captured input, trying each candidate selector until one
        succeeds. Returns True once any candidate fills/checks/selects the field.

        ``<select>`` elements are driven through ``select_option`` (Playwright's
        ``fill`` raises on them, which left every required dropdown empty and the
        form invalid); checkboxes/radios through ``check``; everything else
        through ``fill``. ``value`` overrides the per-field synthetic value so a
        caller can echo a confirm/repeat field's primary value."""
        if value is None:
            value = self._synthetic_value(name, itype)
        is_toggle = itype in ("checkbox", "radio")
        is_select = itype in ("select", "select-one", "select-multiple")
        for selector, timeout_ms in self._candidate_field_selectors(entry, scope, name, itype, nth):
            if is_toggle:
                res = await self._bounded(page.check(selector, timeout=timeout_ms), timeout_ms + 200)
            elif is_select:
                res = await self._bounded(self._select_first_option(page, selector, timeout_ms), timeout_ms + 300)
            else:
                res = await self._bounded(page.fill(selector, str(value), timeout=timeout_ms), timeout_ms + 200)
            if res is not _BOUNDED_FAILED:
                return True
        return False

    @staticmethod
    async def _select_first_option(page: Any, selector: str, timeout_ms: float) -> None:
        """Choose the first enabled, non-placeholder option of a ``<select>``.

        Reactive forms treat an empty/placeholder option as "no selection" and
        keep the form invalid, so pick the first option with a non-empty value
        (falling back to the last option, then to index 0). Raises on failure so
        the bounded caller records a miss and tries the next selector."""
        loc = page.locator(selector).first
        values = await loc.evaluate(
            "el => Array.from((el && el.options) || [])"
            ".filter(o => !o.disabled).map(o => o.value)"
        )
        chosen: str | None = None
        for candidate in values or []:
            if str(candidate).strip():
                chosen = candidate
                break
        if chosen is None and values:
            chosen = values[-1]
        if chosen is None:
            await loc.select_option(index=0, timeout=timeout_ms)
        else:
            await loc.select_option(chosen, timeout=timeout_ms)

    @staticmethod
    def _candidate_field_selectors(
        entry: dict[str, Any],
        scope: str,
        name: str,
        itype: str,
        nth: int,
    ) -> list[tuple[str, int]]:
        """Ordered ``(selector, timeout_ms)`` candidates for locating one input.

        Order is by reliability/cost: the synthetic field tag (fast, exact when
        it survives), then cluster-scoped positional-by-type (a single selector
        that resolves re-rendered fields), then cluster-scoped identifier-attribute
        matches on the captured name. All fallbacks are cluster-scoped so they
        never reach into an unrelated cluster on the page.
        """
        candidates: list[tuple[str, int]] = []
        field_id = str(entry.get("field_id", "") or "")
        if field_id:
            candidates.append((f"[data-sentry-field='{field_id}']", 800))
        if scope:
            type_sel = BrowserDiscoveryEngine._type_selector(itype)
            candidates.append((f"{scope}{type_sel} >> nth={nth}", 800))
        # Identifier-attribute fallbacks: only when the captured name is safe to
        # embed in a selector (no quote/backslash that would break it).
        safe_name = name if name and "'" not in name and "\\" not in name else ""
        if safe_name:
            for attr in ("name", "formcontrolname", "id", "placeholder", "aria-label", "data-testid"):
                prefix = scope if scope else ""
                candidates.append((f"{prefix}[{attr}='{safe_name}']", 500))
        if not scope and field_id == "" and not safe_name:
            # Nothing to anchor on; nothing to try.
            return []
        return candidates

    @staticmethod
    def _type_selector(itype: str) -> str:
        """CSS selector matching an input of the captured ``itype`` (used for
        positional fallback). Unknown/absent types (e.g. a bare ``input`` tag with
        no ``type`` attribute) match any input so the positional index still
        resolves them."""
        if itype == "textarea":
            return "textarea"
        if itype in ("select", "select-one", "select-multiple"):
            return "select"
        known = {
            "text", "email", "password", "search", "tel", "url", "number",
            "checkbox", "radio", "date", "time", "datetime-local", "month",
            "week", "color", "range",
        }
        if itype in known:
            return f"input[type={itype}]"
        return "input"

    def _synthetic_value(self, name: str, itype: str) -> str:
        """Type-appropriate placeholder for a captured input (name+type only).

        Uses the configured scan credentials for password/identity fields so an
        auth cluster submits with real creds (capturing the request body is the
        goal even if they are rejected), else the generic name-keyed baseline.
        """
        joined = f"{name} {itype}".lower()
        if "password" in joined and self.settings.authentication_password:
            return self.settings.authentication_password
        if self.settings.authentication_username and any(
            token in joined for token in ("email", "username", "user", "login", "account")
        ):
            return self.settings.authentication_username
        # Format-valid value keyed on the input TYPE. Reactive/HTML5 validators
        # reject a generic string in a date/number/url/tel field, which leaves
        # the form invalid and its submit control disabled — so an app never
        # fires its POST XHR and no body is captured. A type-appropriate value
        # keeps such fields valid. Name-based hints still win for plain text.
        typed = self._typed_placeholder(itype)
        if typed is not None:
            return typed
        return str(ApiExtractor._baseline_for_name(name))

    @staticmethod
    def _typed_placeholder(itype: str) -> str | None:
        """Format-valid synthetic value for an input's HTML type, or None when
        the type carries no format constraint (plain text handled by name hint)."""
        itype = (itype or "").lower()
        return {
            "email": "scanner@example.com",
            "url": "https://example.com/",
            "tel": "+15555550123",
            "number": "1",
            "range": "1",
            "date": "2020-01-01",
            "datetime-local": "2020-01-01T12:00",
            "time": "12:00",
            "month": "2020-01",
            "week": "2020-W01",
            "color": "#336699",
        }.get(itype)

    async def _submit_form(self, page: Any, form: dict[str, Any]) -> bool:
        """Submit an input cluster to fire the app's real request.

        Returns ``True`` only when a submit action was actually performed (an
        enabled control clicked, a ``<form>`` submitted, or Enter pressed), so
        the caller does not count a doomed no-op as a submission.

        Reactive forms disable their submit control until the form is valid, and
        clicking a disabled control merely burns the click-actionability timeout
        (~800ms) and fires nothing — the dominant reason ``replayable_json_bodies``
        stayed at ~0 despite many "submitted" forms. So we skip disabled controls
        with a fast :meth:`~Locator.is_enabled` check instead of paying that
        timeout, preferring a real ``submit``-type control scoped to the cluster.
        Literal ``<form>`` clusters fall back to ``requestSubmit`` (which honours
        HTML validity); orphan clusters fall back to pressing Enter in their first
        fillable field. Destructive clusters are filtered upstream in
        :meth:`_submit_discovered_forms`.
        """
        cluster_id = form.get("cluster_id")
        scope = f"[data-sentry-cluster='{cluster_id}'] " if cluster_id is not None else ""
        if await self._click_first_enabled(
            page,
            (
                f"{scope}button[type=submit]",
                f"{scope}input[type=submit]",
                f"{scope}button:not([type])",
                f"{scope}button",
                f"{scope}[role=button]",
            ),
        ):
            return True
        # No enabled submit control (all disabled, or none present). Literal
        # <form>: ask the browser to submit it directly.
        if form.get("has_form", True):
            selector = (
                f"[data-sentry-cluster='{cluster_id}']" if cluster_id is not None else "form"
            )
            res = await self._bounded(page.evaluate(REQUEST_SUBMIT_JS, selector), 1000)
            if res is not _BOUNDED_FAILED and res:
                return True
        # Orphan cluster with no clickable control: press Enter in a filled field.
        for entry in form.get("inputs", []):
            field_id = str(entry.get("field_id", "") or "")
            itype = str(entry.get("type", "") or "").lower()
            if field_id and itype not in (
                "hidden", "submit", "button", "file", "image", "reset",
                "checkbox", "radio", "select", "select-one", "select-multiple",
            ):
                res = await self._bounded(
                    page.press(f"[data-sentry-field='{field_id}']", "Enter", timeout=800), 1000
                )
                return res is not _BOUNDED_FAILED
        return False

    async def _click_first_enabled(self, page: Any, selectors: tuple[str, ...]) -> bool:
        """Click the first ENABLED control matching any of ``selectors``.

        Disabled controls are skipped via a fast ``is_enabled`` probe rather than
        clicked-and-timed-out, so an invalid reactive form costs milliseconds
        (not seconds) and never counts as a submission. Only a few matches per
        selector are probed so a page full of buttons cannot blow the budget."""
        for selector in selectors:
            loc = page.locator(selector)
            count = await self._bounded(loc.count(), 400)
            if not isinstance(count, int) or count <= 0:
                continue
            for index in range(min(count, 5)):
                item = loc.nth(index)
                enabled = await self._bounded(item.is_enabled(timeout=200), 400)
                if enabled is not True:
                    continue
                clicked = await self._bounded(item.click(timeout=800), 1000)
                if clicked is not _BOUNDED_FAILED:
                    return True
        return False

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
        hash_routed = self._looks_hash_routed(root_url, found)
        result: list[str] = []
        emitted: set[str] = set()
        for item in found:
            if not item:
                continue
            absolute = self._canonical_route_url(root_url, item, hash_routed=hash_routed)
            if self._origin(absolute) != root_origin:
                continue
            key = self._normalize_for_seen(absolute)
            if key in emitted:
                continue
            emitted.add(key)
            result.append(absolute)
        return result

    async def _exercise_page(self, page: Any, max_seconds: float | None = None) -> dict[str, int]:
        """Blind-interact with the page to surface dynamic state/requests.

        ``max_seconds`` caps the wall-clock time spent here (RC2): the interaction
        loop stops once the per-route budget share elapses even if fewer than
        ``max_interactions`` controls were tried, so a single deep page never
        consumes the budget owed to unvisited routes. ``None`` preserves the
        legacy count-only bound (used by direct-call tests).
        """
        seen_states: set[str] = set()
        attempted_controls: set[str] = set()
        forms_seen = 0
        file_inputs_seen = 0

        loop = asyncio.get_running_loop()
        start = loop.time()

        await self._clear_blocking_overlays(page)
        for _ in range(self.max_interactions):
            if max_seconds is not None and (loop.time() - start) >= max_seconds:
                break
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

    def _looks_hash_routed(self, root_url: str, candidates: list[str]) -> bool:
        urls = [root_url, *[str(candidate) for candidate in candidates or []]]
        return any(self._route_fragment(urlparse(urljoin(root_url, url)).fragment) for url in urls)

    def _canonical_route_url(self, root_url: str, candidate: str, *, hash_routed: bool = False) -> str:
        candidate = str(candidate or "").strip()
        if not candidate:
            return root_url
        root = urlparse(root_url)
        root_base = urlunparse((root.scheme, root.netloc, "/", "", "", ""))
        if candidate.startswith(("#/", "#!/")):
            fragment = self._route_fragment(candidate[1:]) or candidate[1:]
            return urlunparse((root.scheme, root.netloc, "/", "", "", fragment))

        absolute = urljoin(root_url, candidate)
        parsed = urlparse(absolute)
        route_fragment = self._route_fragment(parsed.fragment)
        if route_fragment:
            return urlunparse((parsed.scheme, parsed.netloc, "/", "", "", route_fragment))

        path = parsed.path or "/"
        if hash_routed and path != "/" and not self._is_root_api_path(path):
            fragment = path
            if parsed.query:
                fragment = f"{fragment}?{parsed.query}"
            return urlunparse((parsed.scheme, parsed.netloc, "/", "", "", fragment))

        if self._is_root_relative_api_candidate(candidate):
            return urljoin(root_base, candidate.lstrip("/"))
        return absolute

    @staticmethod
    def _route_fragment(fragment: str) -> str:
        fragment = str(fragment or "")
        if fragment.startswith("!/"):
            return "/" + fragment[2:].lstrip("/")
        if fragment.startswith("/"):
            return fragment
        return ""

    @staticmethod
    def _is_root_api_path(path: str) -> bool:
        return bool(ROOT_API_PATH_RE.search(path or ""))

    @staticmethod
    def _is_root_relative_api_candidate(candidate: str) -> bool:
        candidate = str(candidate or "").strip()
        if candidate.startswith(("http://", "https://", "//", "#")):
            return False
        parsed = urlparse(candidate)
        path = parsed.path or candidate
        if path.startswith("/"):
            return BrowserDiscoveryEngine._is_root_api_path(path)
        return BrowserDiscoveryEngine._is_root_api_path(f"/{path}")

    def _browser_targets(self, root_url: str, routes: list[str]) -> list[str]:
        root_origin = self._origin(root_url)
        hash_routed = self._looks_hash_routed(root_url, routes)
        targets = [root_url]
        seen = {self._normalize_for_seen(root_url)}
        # Seed all known static routes up to the route cap (Task B): high-value
        # auth/form/API routes must be enqueued with their score before the
        # crawl starts so even a short budget reaches them. Bounding the seed set
        # by the per-run route cap (not the per-page interaction budget) keeps
        # that guarantee decoupled from how much clicking each page gets.
        seed_cap = max(1, min(self.settings.crawl_max_urls, self.settings.crawl_browser_route_cap))
        for route in routes:
            absolute = self._canonical_route_url(root_url, route, hash_routed=hash_routed)
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

    @staticmethod
    def _safe_post_data(request: Any) -> str | None:
        """Read a request body without crashing on binary/compressed payloads.

        Playwright's ``request.post_data`` base64-decodes the body and then
        ``.decode()``s it as UTF-8, raising ``UnicodeDecodeError`` for binary
        bodies (gzip, protobuf, images) — which, unhandled, propagates out of the
        ``on_request``/``on_response`` event callbacks. Fall back to the raw
        ``post_data_buffer`` decoded leniently so such requests are still observed
        (as a best-effort text body) instead of blowing up the handler.
        """
        body, _source, _status, _error = BrowserDiscoveryEngine._capture_post_data(request)
        return body

    @staticmethod
    def _capture_post_data(request: Any) -> tuple[str | None, str | None, str, str | None]:
        """Return bounded request body text plus capture provenance/status."""
        body_source: str | None = None
        capture_error: str | None = None
        try:
            body = request.post_data
            body_source = "playwright_post_data"
        except UnicodeDecodeError as exc:
            body = None
            capture_error = str(exc)
        except Exception as exc:
            return None, None, "unavailable", str(exc)

        if body is None:
            try:
                buffer = request.post_data_buffer
                body_source = "playwright_post_data_buffer"
            except Exception as exc:
                return None, body_source, "unavailable", str(exc)
            if not buffer:
                return None, body_source, "not_applicable", capture_error
            if isinstance(buffer, (bytes, bytearray)):
                body = bytes(buffer).decode("utf-8", "ignore")
            else:
                body = str(buffer)

        if isinstance(body, (bytes, bytearray)):
            body = bytes(body).decode("utf-8", "ignore")
        elif body is not None and not isinstance(body, str):
            body = str(body)

        if not body:
            return None, body_source, "not_applicable", capture_error
        if len(body) > MAX_CAPTURED_BODY_CHARS:
            return (
                body[:MAX_CAPTURED_BODY_CHARS],
                body_source,
                "truncated",
                f"body exceeded {MAX_CAPTURED_BODY_CHARS} characters",
            )
        return body, body_source, "captured", capture_error

    async def _build_request_observation(
        self,
        request: Any,
        *,
        drop_reason: str | None = None,
    ) -> RequestObservation:
        headers = await self._request_headers(request)
        normalized_headers = self._normalize_request_headers(headers)
        content_type = self._header_value(normalized_headers, "content-type")
        cookies = self._parse_cookie_header(self._header_value(normalized_headers, "cookie") or "")
        post_data, body_source, body_capture_status, capture_error = self._capture_post_data(request)
        body_kind, body_schema, multipart_fields = self._request_body_metadata(post_data, content_type)
        replayable = self._is_replayable(request.method, post_data, content_type, body_schema, multipart_fields)
        non_replayable_reason = self._non_replayable_reason(
            request.method,
            post_data,
            content_type,
            body_capture_status,
            body_kind,
            replayable,
            drop_reason,
        )
        if non_replayable_reason:
            replayable = False
        return RequestObservation(
            url=request.url,
            method=request.method,
            resource_type=request.resource_type,
            request_headers=normalized_headers,
            request_cookies=cookies,
            request_content_type=content_type,
            post_data=post_data,
            body_source=body_source,
            body_capture_status=body_capture_status,
            body_kind=body_kind,
            body_schema=body_schema,
            multipart_fields=multipart_fields,
            replayable=replayable,
            capture_error=capture_error,
            initiator_url=self._request_initiator_url(request),
            drop_reason=drop_reason,
            non_replayable_reason=non_replayable_reason,
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

    @staticmethod
    def _non_replayable_reason(
        method: str,
        body: Any,
        content_type: str | None,
        body_capture_status: str,
        body_kind: str | None,
        replayable: bool,
        drop_reason: str | None,
    ) -> str | None:
        if drop_reason:
            return drop_reason
        if replayable:
            return None
        method = str(method or "GET").upper()
        if method in {"GET", "HEAD", "OPTIONS"} and not body:
            return None
        if body_capture_status == "truncated":
            return "body_capture_truncated"
        if body_capture_status == "unavailable":
            return "body_capture_unavailable"
        if not body:
            return "empty_body"
        lowered = (content_type or "").lower()
        if "json" in lowered:
            return "unparseable_json"
        if "application/x-www-form-urlencoded" in lowered:
            return "form_body_without_fields"
        if "multipart/form-data" in lowered:
            return "multipart_without_fields"
        if body_kind is None:
            return "unsupported_content_type"
        return "non_replayable"

    @staticmethod
    def _request_initiator_url(request: Any) -> str | None:
        try:
            frame = getattr(request, "frame", None)
            if frame is not None:
                url = getattr(frame, "url", None)
                if url:
                    return str(url)
        except Exception:
            pass
        try:
            headers = getattr(request, "headers", {}) or {}
            return headers.get("referer") or headers.get("referrer")
        except Exception:
            return None

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
        # JSON is replayable whenever the observed body actually parses as JSON —
        # inferring the schema from the captured body rather than requiring a
        # pre-existing non-empty ``body_schema``. This keeps top-level arrays,
        # empty objects, and primitive JSON bodies (schema inference yields
        # nothing for these) from being silently dropped, which was collapsing
        # ``replayable_json_bodies`` to 0 on real SPA/JSON-API traffic. Bodies
        # that carry a JSON content-type but fail to parse (truncated/binary)
        # remain non-replayable.
        if "json" in lowered:
            if body_schema:
                return True
            return _parses_as_json(body)
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

    def _same_origin_or_websocket(self, root_url: str, candidate_url: str) -> bool:
        try:
            root = urlparse(root_url)
            candidate = urlparse(candidate_url)
        except Exception:
            return False
        if root.hostname != candidate.hostname:
            return False

        def default_port(scheme: str) -> int | None:
            if scheme in {"http", "ws"}:
                return 80
            if scheme in {"https", "wss"}:
                return 443
            return None

        root_port = root.port or default_port(root.scheme)
        candidate_port = candidate.port or default_port(candidate.scheme)
        if root_port != candidate_port:
            return False
        return (root.scheme, candidate.scheme) in {
            ("http", "http"),
            ("http", "ws"),
            ("https", "https"),
            ("https", "wss"),
        }

    def _classify_runtime_request(self, root_url: str, request: Any) -> str:
        try:
            url = request.url
            method = str(getattr(request, "method", "GET") or "GET").upper()
            resource_type = str(getattr(request, "resource_type", "") or "")
        except Exception:
            return "invalid_request"
        if not self._same_origin_or_websocket(root_url, url):
            return "off_origin"
        if self._is_transport_noise_url(url, resource_type):
            return "transport_noise"
        if resource_type in {"xhr", "fetch", "websocket"}:
            return "capture"
        if method not in {"GET", "HEAD", "OPTIONS"}:
            return "capture"
        return "resource_noise"

    def _should_capture_runtime_request(self, root_url: str, request: Any) -> bool:
        return self._classify_runtime_request(root_url, request) == "capture"

    @staticmethod
    def _is_transport_noise_url(url: str, resource_type: str = "") -> bool:
        try:
            parsed = urlparse(url)
            path = parsed.path.lower()
            query = parse_qs(parsed.query)
        except Exception:
            return False
        if resource_type == "websocket":
            return True
        if any(token in path for token in TRANSPORT_NOISE_PATHS):
            return True
        if "EIO" in query and "transport" in query:
            return True
        if "transport" in query and any(token in path for token in ("hub", "negotiate", "connect")):
            return True
        return False

    @staticmethod
    def _record_request_audit_reason(state: CrawlState, observation: RequestObservation) -> None:
        reason = observation.drop_reason or observation.non_replayable_reason
        if reason is None:
            reason = "replayable" if observation.replayable else "observed"
        state.request_audit_summary[reason] = state.request_audit_summary.get(reason, 0) + 1

    def _normalize_for_seen(self, url: str) -> str:
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}".rstrip("/").lower()
        # SPA hash routes (``#/path``, ``#!/path``) are distinct application
        # pages, not in-page anchors. Fold a route-like fragment into the dedup
        # key so a hash-routed SPA's entire route space is not collapsed onto the
        # root: without this, every ``#/login``/``#/register``/... normalizes to
        # the bare origin and is discarded at seeding/enqueue time, so form pages
        # are never navigated and no request bodies are ever produced. A plain
        # ``#section`` anchor (same page, different scroll) is still ignored.
        fragment = self._route_fragment(parsed.fragment)
        if fragment:
            origin_base = f"{parsed.scheme}://{parsed.netloc}".lower()
            return f"{origin_base}#{fragment.rstrip('/').lower()}"
        return base
