import asyncio
import logging
import pathlib
import re
from dataclasses import dataclass, field
from types import SimpleNamespace
from urllib import robotparser
from urllib.parse import urlparse

import httpx
from bs4 import BeautifulSoup

from app.config import get_settings
from app.schemas.scan_schema import ScanConfig
from app.core.crawler.auth_manager import (
    ModernAuthManager,
    SmartAuthenticator,
    AuthReplayState,
    AuthVerificationState,
    redact_secret,
)
from app.core.crawler.api_extractor import ApiExtractor
from app.core.crawler.browser_engine import BrowserDiscoveryEngine
from app.core.crawler.models import ApiEndpoint, CrawlState, ParameterCandidate, RouteCandidate, RouteSource
from app.core.crawler.param_discovery import ParamDiscovery
from app.core.crawler.spa import SpaFallbackDetector
from app.core.crawler.url_parser import STATIC_EXTENSIONS, normalize_url, same_domain, normalize_for_dedupe
from app.utils.http_logging import make_httpx_response_logger
from app.utils.scan_http import create_scan_client

logger = logging.getLogger(__name__)

# STATIC_EXTENSIONS is the shared static-asset set (now includes ``.txt``) and
# lives in url_parser so the crawler and the detectors classify assets the same
# way. Imported above and re-exported here for existing references.


@dataclass
class FormInput:
    name: str
    input_type: str = "text"
    value: str = ""


@dataclass
class HtmlForm:
    page_url: str
    action: str
    method: str
    inputs: list[FormInput] = field(default_factory=list)
    # Provenance: "html" for a literal server-rendered <form>, "browser_cluster"
    # for an input cluster captured at runtime by the browser engine. SPA clusters
    # submit JSON to an API, so they get a best-effort JSON-body synthesis fallback
    # (see AttackSurface._synthesize_form_cluster_targets) when the live submit
    # never produced an observed request body.
    source: str = "html"


@dataclass
class CrawlResult:
    urls: list[str] = field(default_factory=list)
    forms: list[HtmlForm] = field(default_factory=list)
    session_cookies: dict[str, str] = field(default_factory=dict)
    is_spa: bool = False
    spa_root_html: str = ""
    routes: list[RouteCandidate] = field(default_factory=list)
    api_endpoints: list[ApiEndpoint] = field(default_factory=list)
    parameters: list[ParameterCandidate] = field(default_factory=list)
    requests: list[object] = field(default_factory=list)
    request_audit: list[object] = field(default_factory=list)
    request_audit_summary: dict[str, int] = field(default_factory=dict)
    assets: list[str] = field(default_factory=list)
    js_extractions: list[dict[str, object]] = field(default_factory=list)
    api_docs: list[str] = field(default_factory=list)
    dead_routes: list[RouteCandidate] = field(default_factory=list)
    auth_state: AuthVerificationState = AuthVerificationState.unauthenticated
    auth_headers: dict[str, str] = field(default_factory=dict)
    auth_verification_evidence: str = ""
    auth_storage_state: dict | None = None
    # The concrete login recipe (endpoint/method/payload) that authenticated the
    # main account. Reused to log in second/admin accounts via the *same* winning
    # path instead of re-running the whole strategy cascade from scratch.
    auth_replay_state: AuthReplayState | None = None
    browser_available: bool | None = None
    browser_error: str | None = None
    workflow_states_visited: int = 0
    browser_forms_discovered: int = 0
    browser_forms_submitted: int = 0
    buttons_clicked: int = 0
    button_mutations_fired: int = 0
    file_inputs_discovered: int = 0
    browser_forms: list[dict[str, object]] = field(default_factory=list)


class WebSpider:
    def __init__(self) -> None:
        self.settings = get_settings()
        self.session_cookies = {}
        self._auth_replay_state: AuthReplayState | None = None
        self._configured_auth_cookies: dict[str, str] = {}
        self._auth_headers: dict[str, str] = {}
        self._is_spa: bool = False
        self._auth_state: AuthVerificationState = AuthVerificationState.unauthenticated
        self._auth_verification_evidence: str = ""
        # Full Playwright storage_state captured by a browser_spa login (cookies +
        # per-origin localStorage/sessionStorage). Replayed into the discovery and
        # XSS browser contexts so the app's own JS finds its token. Generic: opaque blob.
        self._auth_storage_state: dict | None = None
        # Per-scan main-account credentials submitted with the scan (overrides
        # env-based SCAN_AUTH_* settings for this crawl). See ScanAuthAccount.
        self._auth_override = None
        # Per-scan configuration overrides.
        self._scan_config: ScanConfig | None = None
        self._reauth_attempts: int = 0

    def _snapshot_cookies(self, cookies: httpx.Cookies) -> dict[str, str]:
        return ModernAuthManager.snapshot_cookies(cookies)

    def _reset_scan_auth_state(self) -> None:
        self.session_cookies = {}
        self._auth_headers = {}
        self._auth_replay_state = None
        self._auth_state = AuthVerificationState.unauthenticated
        self._auth_verification_evidence = ""
        self._auth_storage_state = None
        self._reauth_attempts = 0

    @staticmethod
    def _redact_headers(headers: dict[str, str]) -> dict[str, str]:
        redacted = dict(headers)
        for key, value in list(redacted.items()):
            if key.lower() in {"authorization", "proxy-authorization", "x-api-key", "api-key"}:
                scheme, _, token = value.partition(" ")
                redacted[key] = f"{scheme} {redact_secret(token)}" if token else redact_secret(value)
        return redacted

    async def crawl(self, root_url: str, max_depth: int | None = None, auth_override=None, scan_config: ScanConfig | None = None) -> CrawlResult:
        self._reset_scan_auth_state()
        self._auth_override = auth_override
        self._scan_config = scan_config
        self._is_spa = False
        max_depth = max_depth if max_depth is not None else (
            scan_config.get_val("crawl_depth", self.settings.crawl_depth) if scan_config 
            else self.settings.crawl_depth
        )
        effective_max_urls = self._scan_config.get_val("crawl_max_urls", self.settings.crawl_max_urls) if self._scan_config else self.settings.crawl_max_urls
        visited: set[str] = set()
        queue = asyncio.Queue()
        forms: list[HtmlForm] = []
        discovered_urls: list[str] = []
        discovered_set: set[str] = set()
        crawl_state = CrawlState()
        dead_routes: list[RouteCandidate] = []
        spa_detector = SpaFallbackDetector()
        spa_root_html = ""
        lock = asyncio.Lock()

        def should_enqueue(url_candidate: str, depth: int) -> bool:
            if max_depth is not None and depth > max_depth:
                return False

            # Scope guard: never crawl or test off-origin URLs. Every enqueue
            # source (HTML links, JS-mined URLs, form actions, browser routes,
            # sitemap, brute paths) funnels through here, so this is the single
            # chokepoint that keeps the scan strictly same-origin with the target
            # and prevents payloads/requests reaching third-party hosts.
            if not same_domain(root_url, url_candidate):
                logger.debug("skipping off-origin URL (out of scope): %s", url_candidate)
                return False

            p = urlparse(url_candidate)
            ext = pathlib.PurePosixPath(p.path).suffix.lower()
            if ext in STATIC_EXTENSIONS:
                logger.debug("skipping static asset: %s", url_candidate)
                return False

            norm = normalize_for_dedupe(url_candidate)
            if norm not in visited:
                visited.add(norm)
                return True
            return False

        # Helper to safely call should_enqueue and put to queue
        async def safe_enqueue(url_candidate: str, depth: int, source: RouteSource = RouteSource.html, priority: int = 50):
            async with lock:
                if should_enqueue(url_candidate, depth):
                    crawl_state.add_route(RouteCandidate(url=url_candidate, source=source, priority=priority, depth=depth))
                    await queue.put((url_candidate, depth, source))

        await safe_enqueue(root_url, 0, RouteSource.html, 100)

        robots = await self._load_robots(root_url)

        effective_timeout = self._scan_config.get_val("request_timeout_seconds", self.settings.request_timeout_seconds) if self._scan_config else self.settings.request_timeout_seconds
        async with create_scan_client(
            timeout=effective_timeout,
            follow_redirects=True,
            headers={"User-Agent": "SentryStrikeScanner/1.0"},
            event_hooks={"response": [make_httpx_response_logger("crawler", "crawl")]},
        ) as client:
            # Perform authentication if configured
            await self._authenticate_session(client, root_url)
            try:
                root_response = await client.get(root_url)
                if "text/html" in root_response.headers.get("content-type", ""):
                    spa_detector.configure_root(root_url, root_response.text)
                    spa_root_html = root_response.text
                    self._is_spa = self._is_spa or spa_detector.root_looks_like_spa()
            except Exception as exc:
                logger.debug("failed to prefetch root shell for SPA fallback detection: %s", exc)

            # 1. Parse Sitemap directives from robots.txt if possible
            sitemap_urls = []
            try:
                robots_url = normalize_url(root_url, "/robots.txt")
                robots_response = await client.get(robots_url)
                if robots_response.status_code == 200:
                    for line in robots_response.text.splitlines():
                        if line.lower().startswith("sitemap:"):
                            parts = line.split(":", 1)
                            if len(parts) > 1:
                                sitemap_urls.append(parts[1].strip())
            except Exception as e:
                logger.warning("Failed to check sitemaps from robots.txt: %s", e)

            for sitemap_url in sitemap_urls:
                try:
                    resp = await client.get(sitemap_url)
                    if resp.status_code == 200:
                        locs = re.findall(r"<loc>(.*?)</loc>", resp.text, re.I)
                        for loc in locs:
                            loc_clean = loc.strip()
                            if loc_clean and same_domain(root_url, loc_clean):
                                await safe_enqueue(loc_clean, 0, RouteSource.sitemap, 80)
                except Exception as e:
                    logger.warning("Failed to fetch sitemap %s: %s", sitemap_url, e)

            # 2. Add common directory brute force paths
            common_paths = [
                "/admin", "/api", "/backup", "/db", "/config", "/settings", 
                "/setup", "/install", "/administrator", "/console", "/panel",
                "/private", "/db_backup", "/wp-admin", "/robots.txt", "/sitemap.xml",
                "/api/v1", "/phpmyadmin", "/.env", "/.git", "/backup.sql"
            ]
            for path in common_paths:
                brute_url = normalize_url(root_url, path)
                await safe_enqueue(brute_url, 0, RouteSource.brute_force, 20)

            await self._inspect_api_documentation(client, root_url, crawl_state)

            # 3. Main crawling loop with concurrency
            import time
            rate_limit = self._scan_config.get_val("crawl_rate_limit_per_second", self.settings.crawl_rate_limit_per_second) if self._scan_config else self.settings.crawl_rate_limit_per_second
            request_interval = 1.0 / rate_limit if rate_limit > 0 else 0
            last_request_time = time.time()

            async def rate_limit_sleep():
                if request_interval <= 0:
                    return
                nonlocal last_request_time
                delay = 0
                async with lock:
                    now = time.time()
                    if last_request_time < now:
                        last_request_time = now
                    next_allowed = last_request_time + request_interval
                    delay = next_allowed - now
                    if delay > 0:
                        last_request_time = next_allowed
                    else:
                        last_request_time = now
                        delay = 0

                if delay > 0:
                    await asyncio.sleep(delay)

            async def worker():
                nonlocal spa_root_html
                while True:
                    try:
                        async with lock:
                            if len(discovered_urls) >= effective_max_urls:
                                break
                        
                        item = await queue.get()
                        if item is None:
                            queue.task_done()
                            break
                        url, depth, source = item
                    except asyncio.CancelledError:
                        break

                    if robots is not None and not robots.can_fetch("*", url):
                        queue.task_done()
                        continue

                    # Respect rate limit
                    await rate_limit_sleep()

                    try:
                        response = await self._request_with_session_keeper(client, "GET", url)
                    except Exception as exc:
                        logger.warning("crawl failed for %s: %s", url, exc)
                        queue.task_done()
                        continue

                    async with lock:
                        if len(discovered_urls) >= effective_max_urls:
                            queue.task_done()
                            break

                        # Detect the SPA shell fallback for EVERY discovery source
                        # and even file-like paths (``allow_file_like_path=True``).
                        # In a SPA the server returns the same ``index.html`` shell
                        # for any path with no distinct resource — client routes
                        # (``/login``, ``/accounting``, ``/order-completion/:id``),
                        # dead brute-force guesses (``/.env``, ``/.git``), and
                        # mistyped file paths all render byte-identical HTML. Such a
                        # URL is NOT a distinct HTTP resource: it must never enter
                        # ``discovered_urls`` or every detector re-tests the same
                        # shell under dozens of different URLs (the ``/.env``,
                        # ``/accounting`` … stored-XSS noise). The default
                        # ``allow_file_like_path=False`` skipped extensioned paths,
                        # so shell-returning guesses like ``/.env`` slipped through.
                        fallback_signal = spa_detector.detect(
                            url,
                            response.status_code,
                            response.headers.get("content-type", ""),
                            response.text if "text/html" in response.headers.get("content-type", "") else "",
                            allow_file_like_path=True,
                        )
                        if url == root_url and "text/html" in response.headers.get("content-type", ""):
                            spa_detector.configure_root(root_url, response.text)
                            spa_root_html = response.text
                            self._is_spa = self._is_spa or spa_detector.root_looks_like_spa()

                        if fallback_signal.is_fallback and url != root_url:
                            # A shell fallback is kept OUT of the HTTP-testable URL
                            # set regardless of source. Brute-force guesses were
                            # probes for a resource that does not exist, so they are
                            # additionally recorded as dead (reported/suppressed).
                            # Real client routes (js/html/sitemap) are NOT dead —
                            # they remain in ``crawl_state.routes`` so the browser
                            # engine still visits them via SPA navigation; they are
                            # only excluded from the raw-HTTP detector surface.
                            if source == RouteSource.brute_force:
                                dead_routes.append(
                                    RouteCandidate(
                                        url=url,
                                        source=source,
                                        priority=0,
                                        depth=depth,
                                        evidence=fallback_signal.reason,
                                        is_spa_fallback=True,
                                        is_dead=True,
                                    )
                                )
                            queue.task_done()
                            continue

                        # Add to discovered_urls if request was successful/interesting
                        if response.status_code in [200, 301, 302, 403]:
                            if url not in discovered_set:
                                discovered_set.add(url)
                                discovered_urls.append(url)

                    if "text/html" not in response.headers.get("content-type", ""):
                        queue.task_done()
                        continue

                    # Note: SPA shell fallbacks (any source) already `continue`d
                    # above, so they never reach HTML parsing here — no duplicate
                    # link/form extraction from identical shells.

                    async with lock:
                        # Update cookies in case session updated
                        self.session_cookies.update(self._snapshot_cookies(client.cookies))

                    page_forms, links = self._parse_html(url, response.text)
                    
                    async with lock:
                        forms.extend(page_forms)

                    # Add form actions as links so we can scan the endpoints
                    for form in page_forms:
                        links.append(form.action)

                    for link in links:
                        normalized = normalize_url(url, link)
                        if same_domain(root_url, normalized):
                            parsed_link = urlparse(normalized)
                            ext = pathlib.PurePosixPath(parsed_link.path).suffix.lower()
                            if ext == ".js":
                                await self._inspect_javascript_asset(client, normalized, root_url, crawl_state, safe_enqueue, depth + 1)
                            else:
                                await safe_enqueue(normalized, depth + 1, RouteSource.html, 50)

                    queue.task_done()

            # Spawn concurrent workers
            effective_concurrency = self._scan_config.get_val("scanner_concurrency", self.settings.scanner_concurrency) if self._scan_config else self.settings.scanner_concurrency
            workers = [asyncio.create_task(worker()) for _ in range(effective_concurrency)]

            try:
                # Wait until queue is empty and all tasks are done, OR we reached max URLs
                join_task = asyncio.create_task(queue.join())
                while not join_task.done():
                    async with lock:
                        if len(discovered_urls) >= effective_max_urls:
                            break
                    await asyncio.sleep(0.1)
                
                if not join_task.done():
                    join_task.cancel()
            except Exception as e:
                logger.error("Error in crawl wait: %s", e)
            finally:
                # Cancel workers
                for w in workers:
                    w.cancel()
                await asyncio.gather(*workers, return_exceptions=True)

            if self._should_run_browser(self._is_spa or spa_detector.root_looks_like_spa()):
                browser_routes = [
                    route.url for route in crawl_state.routes 
                    if route.source in (RouteSource.javascript, RouteSource.html, RouteSource.sitemap, RouteSource.brute_force)
                    and not getattr(route, "is_dead", False)
                ]
                await self._run_browser_discovery(crawl_state, root_url, browser_routes)

        # P4: browser-navigated routes with query strings hold real parameter
        # values (e.g. /redirect?to=https://...) that the HTTP worker never saw
        # because they redirect externally or were visited browser-only. Extend
        # discovered_urls so ParamDiscovery parses their query parameters and all
        # detectors (open_redirect, file_inclusion, ssrf, …) receive them.
        if crawl_state.browser_available:
            _seen_for_p4 = {normalize_for_dedupe(u) for u in discovered_urls}
            for _route in crawl_state.routes:
                if getattr(_route, "is_dead", False):
                    continue
                if _route.source not in (RouteSource.browser,):
                    continue
                if "?" not in _route.url:
                    continue
                # Scope guard: a browser route may have followed a redirect to a
                # third-party host (e.g. /redirect?to=https://github.com/...).
                # Never back-feed off-origin URLs into the tested URL set.
                if not same_domain(root_url, _route.url):
                    continue
                _norm = normalize_for_dedupe(_route.url)
                if _norm not in _seen_for_p4:
                    _seen_for_p4.add(_norm)
                    discovered_urls.append(_route.url)

        forms = self._merge_browser_forms(root_url, forms, crawl_state.browser_forms)

        for endpoint in crawl_state.api_endpoints:
            for parameter in ApiExtractor.parameters_from_endpoint(endpoint):
                crawl_state.add_parameter(parameter)
        for parameter in ParamDiscovery.build_parameter_inventory(discovered_urls, forms, api_endpoints=crawl_state.api_endpoints):
            crawl_state.add_parameter(parameter)

        result = CrawlResult(
            urls=discovered_urls,
            forms=forms,
            session_cookies=self.session_cookies,
            is_spa=self._is_spa or spa_detector.root_looks_like_spa(),
            spa_root_html=spa_root_html,
            routes=crawl_state.routes,
            api_endpoints=crawl_state.api_endpoints,
            parameters=crawl_state.parameters,
            requests=crawl_state.requests,
            request_audit=crawl_state.request_audit,
            request_audit_summary=dict(crawl_state.request_audit_summary),
            assets=sorted(crawl_state.assets),
            js_extractions=list(crawl_state.js_extractions),
            api_docs=list(crawl_state.api_docs),
            dead_routes=dead_routes,
            auth_state=self._auth_state,
            auth_headers=dict(self._auth_headers),
            auth_verification_evidence=self._auth_verification_evidence,
            auth_storage_state=self._auth_storage_state,
            auth_replay_state=self._auth_replay_state,
            browser_available=crawl_state.browser_available,
            browser_error=crawl_state.browser_error,
            workflow_states_visited=crawl_state.workflow_states_visited,
            browser_forms_discovered=crawl_state.browser_forms_discovered,
            browser_forms_submitted=crawl_state.browser_forms_submitted,
            buttons_clicked=crawl_state.buttons_clicked,
            button_mutations_fired=crawl_state.button_mutations_fired,
            file_inputs_discovered=crawl_state.file_inputs_discovered,
            browser_forms=list(crawl_state.browser_forms),
        )
        self._log_crawl_inventory(root_url, result)
        return result

    @staticmethod
    def _merge_browser_forms(
        root_url: str,
        forms: list[HtmlForm],
        browser_forms: list[dict],
    ) -> list[HtmlForm]:
        merged = list(forms)
        seen = {
            (
                form.action,
                form.method.upper(),
                tuple(sorted(inp.name for inp in form.inputs if inp.name)),
            )
            for form in merged
        }
        for form in browser_forms or []:
            action = str(form.get("action") or form.get("page_url") or "")
            page_url = str(form.get("page_url") or action or root_url)
            if not action:
                action = page_url
            if not same_domain(root_url, action):
                continue
            inputs: list[FormInput] = []
            for raw_input in form.get("inputs") or []:
                if not isinstance(raw_input, dict):
                    continue
                # Synthetic positional fallback names (field_<cid>_<idx>) are
                # internal handles for fill/submit addressing, never real backend
                # parameter names. Dropping them here prevents useless injection
                # targets against names the server doesn't recognize. The live
                # submit path uses field_id (data-sentry-field attr), not the name,
                # so this does not affect form submission.
                if raw_input.get("named") is False:
                    continue
                input_type = str(raw_input.get("type") or "text").lower()
                name = str(raw_input.get("name") or "").strip()
                if not name and input_type == "file":
                    name = "file"
                if not name:
                    continue
                inputs.append(FormInput(name=name, input_type=input_type, value=str(raw_input.get("value") or "")))
            key = (
                action,
                str(form.get("method") or "GET").upper(),
                tuple(sorted(inp.name for inp in inputs if inp.name)),
            )
            if key in seen:
                continue
            seen.add(key)
            merged.append(
                HtmlForm(
                    page_url=page_url,
                    action=action,
                    method=str(form.get("method") or "GET").upper(),
                    inputs=inputs,
                    source="browser_cluster",
                )
            )
        return merged

    async def fetch_single(self, target_url: str) -> CrawlResult:
        """Fetch one URL only - no link discovery, sitemaps, or path brute-force."""
        self._reset_scan_auth_state()
        self._is_spa = False
        forms: list[HtmlForm] = []
        discovered_urls: list[str] = []
        is_spa = False
        spa_root_html = ""

        async with create_scan_client(
            timeout=self.settings.request_timeout_seconds,
            follow_redirects=True,
            headers={"User-Agent": "SentryStrikeScanner/1.0"},
            event_hooks={"response": [make_httpx_response_logger("crawler", "fetch_single")]},
        ) as client:
            await self._authenticate_session(client, target_url)

            try:
                response = await self._request_with_session_keeper(client, "GET", target_url)
            except Exception as exc:
                logger.warning("fetch_single failed for %s: %s", target_url, exc)
                return CrawlResult(urls=[], forms=[], session_cookies=self.session_cookies)

            if response.status_code in {200, 301, 302, 403}:
                discovered_urls.append(target_url)

            if "text/html" in response.headers.get("content-type", ""):
                self.session_cookies.update(self._snapshot_cookies(client.cookies))
                spa_root_html = response.text
                is_spa = SpaFallbackDetector.looks_like_spa_shell(target_url, response.text)
                page_forms, _ = self._parse_html(target_url, response.text)
                forms.extend(page_forms)

        parameters = ParamDiscovery.build_parameter_inventory(discovered_urls, forms)
        result = CrawlResult(
            urls=discovered_urls,
            forms=forms,
            session_cookies=self.session_cookies,
            is_spa=is_spa,
            spa_root_html=spa_root_html,
            parameters=parameters,
            auth_state=self._auth_state,
            auth_headers=dict(self._auth_headers),
            auth_verification_evidence=self._auth_verification_evidence,
        )
        self._log_crawl_inventory(target_url, result)
        return result

    async def _inspect_javascript_asset(self, client, script_url: str, root_url: str, crawl_state: CrawlState, enqueue_fn, depth: int) -> None:
        if script_url in crawl_state.assets:
            return
        crawl_state.assets.add(script_url)
        try:
            response = await self._request_with_session_keeper(client, "GET", script_url)
        except Exception as exc:
            logger.debug("failed to inspect javascript asset %s: %s", script_url, exc)
            return
        if response.status_code >= 400:
            return
        routes, endpoints = ApiExtractor.extract_from_javascript(script_url, response.text)
        crawl_state.js_extractions.append(
            {
                "asset_url": script_url,
                "script_size": len(response.text),
                "routes_extracted": len(routes),
                "api_endpoints_extracted": len(endpoints),
                "body_templates_extracted": len([endpoint for endpoint in endpoints if endpoint.request_body is not None]),
            }
        )
        for route in routes:
            if same_domain(root_url, route):
                await enqueue_fn(route, depth, RouteSource.javascript, 70)
        for endpoint in endpoints:
            if same_domain(root_url, endpoint.url):
                crawl_state.add_api_endpoint(endpoint)

    async def _inspect_api_documentation(self, client, root_url: str, crawl_state: CrawlState) -> None:
        doc_paths = [
            "/openapi.json",
            "/swagger.json",
            "/api-docs",
            "/api-docs.json",
            "/v3/api-docs",
            "/swagger/v1/swagger.json",
            "/docs/openapi.json",
        ]
        for path in doc_paths:
            doc_url = normalize_url(root_url, path)
            try:
                response = await self._request_with_session_keeper(client, "GET", doc_url)
            except Exception:
                continue
            if response.status_code >= 400:
                continue
            endpoints = ApiExtractor.extract_from_openapi(root_url, response.text)
            if not endpoints:
                continue
            crawl_state.api_docs.append(doc_url)
            for endpoint in endpoints:
                if same_domain(root_url, endpoint.url):
                    crawl_state.add_api_endpoint(endpoint)

    def _should_run_browser(self, is_spa: bool) -> bool:
        """Decide whether dynamic browser discovery should run.

        ``crawl_browser_enabled`` (legacy) forces it on. Otherwise honour
        ``crawl_browser_mode``: ``always`` runs for any target, ``never`` is
        static-only, and ``auto`` runs only when the target looks like an SPA.
        """
        if self.settings.crawl_browser_enabled:
            return True
        mode = (self._scan_config.get_val("crawl_browser_mode", self.settings.crawl_browser_mode) if self._scan_config else self.settings.crawl_browser_mode or "auto")
        mode = mode.strip().lower()
        if mode == "never":
            return False
        if mode == "always":
            return True
        return bool(is_spa)  # auto

    async def _run_browser_discovery(
        self,
        crawl_state: CrawlState,
        root_url: str,
        routes: list[str],
    ) -> None:
        """Run browser discovery, always merging partial results.

        The engine streams observations into ``browser_state`` as they arrive
        and honours ``deadline`` per-route, so a timeout/exception truncates
        coverage but never discards it: the ``finally`` merge always runs and
        ``browser_available`` (set True by the engine at launch) is preserved.

        A hard safety timeout guards against a genuine hang (e.g. a wedged
        Playwright call); it is deliberately larger than the per-route budget so
        the clean in-engine deadline stop normally fires first. Partial results
        already streamed into ``browser_state`` survive either path.
        """
        # No separate readiness probe: ``crawl_into`` detects Playwright/browser
        # availability inline on its own launch (setting ``browser_available``
        # True the moment Chromium starts, or ``browser_error`` + False on import/
        # launch failure), so the old ``check_readiness()`` throwaway launch — a
        # second cold Chromium start every run — is gone. A launch failure merges
        # cleanly as static-only via the ``finally`` merge below.
        loop = asyncio.get_running_loop()
        budget = self._scan_config.get_val("crawl_browser_budget_seconds", self.settings.crawl_browser_budget_seconds) if self._scan_config else self.settings.crawl_browser_budget_seconds
        deadline = loop.time() + budget
        browser_state = CrawlState()
        engine = BrowserDiscoveryEngine(
            max_interactions=self._scan_config.get_val("crawl_browser_max_interactions", self.settings.crawl_browser_max_interactions) if self._scan_config else self.settings.crawl_browser_max_interactions,
            workers=self._scan_config.get_val("crawl_browser_workers", self.settings.crawl_browser_workers) if self._scan_config else self.settings.crawl_browser_workers,
        )
        task = asyncio.create_task(
            engine.crawl_into(
                browser_state,
                root_url,
                auth_cookies=self.session_cookies,
                auth_headers=self._auth_headers,
                routes=routes,
                deadline=deadline,
                storage_state=self._auth_storage_state,
            )
        )
        safety_timeout = budget + max(30.0, budget * 0.5)
        try:
            await asyncio.wait_for(task, timeout=safety_timeout)
        except asyncio.TimeoutError:
            logger.warning(
                "browser discovery exceeded hard safety budget of %.0fs; using partial results",
                safety_timeout,
            )
            browser_state.browser_error = (
                browser_state.browser_error
                or "browser discovery aborted: hard safety timeout reached"
            )
        except Exception as exc:  # noqa: BLE001 - never let browser discovery fail the crawl
            logger.warning("browser discovery errored: %s; using partial results", exc)
            browser_state.browser_error = browser_state.browser_error or repr(exc)
        finally:
            self._merge_crawl_state(crawl_state, browser_state)

    @staticmethod
    def _merge_crawl_state(target: CrawlState, source: CrawlState) -> None:
        for route in source.routes:
            target.add_route(route)
        for endpoint in source.api_endpoints:
            target.add_api_endpoint(endpoint)
        for parameter in source.parameters:
            target.add_parameter(parameter)
        target.requests.extend(source.requests)
        target.assets.update(source.assets)
        target.js_extractions.extend(source.js_extractions)
        target.api_docs.extend(source.api_docs)
        target.workflow_states_visited += source.workflow_states_visited
        target.browser_forms_discovered += source.browser_forms_discovered
        target.browser_forms_submitted += source.browser_forms_submitted
        target.buttons_clicked += source.buttons_clicked
        target.button_mutations_fired += source.button_mutations_fired
        target.file_inputs_discovered += source.file_inputs_discovered
        for form in source.browser_forms:
            target.add_browser_form(form)
        if source.browser_available is not None:
            target.browser_available = source.browser_available
        if source.browser_error:
            target.browser_error = source.browser_error

    def _log_crawl_inventory(self, root_url: str, result: CrawlResult) -> None:
        if not logger.isEnabledFor(logging.INFO):
            return

        parameters_by_url: dict[str, list[ParameterCandidate]] = {}
        for parameter in result.parameters:
            parameters_by_url.setdefault(parameter.url, []).append(parameter)

        route_urls: list[str] = []
        seen_urls: set[str] = set()
        for route in sorted(result.routes, key=lambda r: (-r.priority, r.depth, r.url)):
            if route.url not in seen_urls:
                route_urls.append(route.url)
                seen_urls.add(route.url)
        for url in result.urls:
            if url not in seen_urls:
                route_urls.append(url)
                seen_urls.add(url)
        for endpoint in result.api_endpoints:
            if endpoint.url not in seen_urls:
                route_urls.append(endpoint.url)
                seen_urls.add(endpoint.url)

        # Dynamic-discovery body-surface counters: a SPA reports forms=0 (no
        # static <form>s) even when the browser captured/submitted clusters, so
        # the static forms count alone hides whether dynamic discovery yielded
        # testable POST-body surface. These make it visible on one line.
        requests = getattr(result, "requests", []) or []
        post_bodies = [r for r in requests if getattr(r, "post_data", None)]
        json_bodies = [
            r for r in post_bodies
            if "json" in (getattr(r, "request_content_type", "") or "").lower()
        ]
        logger.info(
            "crawler finished for %s: urls=%d routes=%d api_endpoints=%d parameters=%d "
            "forms=%d dead_routes=%d assets=%d | browser_available=%s "
            "browser_forms_captured=%d browser_forms_submitted=%d "
            "buttons_clicked=%d button_mutations=%d file_inputs=%d "
            "requests=%d post_bodies=%d json_bodies=%d browser_error=%s",
            root_url,
            len(result.urls),
            len(result.routes),
            len(result.api_endpoints),
            len(result.parameters),
            len(result.forms),
            len(result.dead_routes),
            len(result.assets),
            getattr(result, "browser_available", None),
            getattr(result, "browser_forms_discovered", 0),
            getattr(result, "browser_forms_submitted", 0),
            getattr(result, "buttons_clicked", 0),
            getattr(result, "button_mutations_fired", 0),
            getattr(result, "file_inputs_discovered", 0),
            len(requests),
            len(post_bodies),
            len(json_bodies),
            getattr(result, "browser_error", None),
        )

        for url in route_urls:
            route = next((candidate for candidate in result.routes if candidate.url == url), None)
            params = parameters_by_url.get(url, [])
            logger.info(
                "crawler route: url=%s source=%s depth=%s priority=%s params=%s",
                url,
                route.source.value if route else "observed",
                route.depth if route else "-",
                route.priority if route else "-",
                self._format_parameter_log(params),
            )

        for endpoint in sorted(result.api_endpoints, key=lambda ep: (ep.url, ep.method, ep.operation or "")):
            params = parameters_by_url.get(endpoint.url, [])
            logger.info(
                "crawler api_endpoint: method=%s url=%s source=%s operation=%s params=%s",
                endpoint.method,
                endpoint.url,
                endpoint.source.value,
                endpoint.operation or "-",
                self._format_parameter_log(params),
            )

        for dead_route in sorted(result.dead_routes, key=lambda route: route.url):
            logger.info(
                "crawler dead_route: url=%s source=%s reason=%s spa_fallback=%s",
                dead_route.url,
                dead_route.source.value,
                dead_route.evidence or "-",
                dead_route.is_spa_fallback,
            )

    @staticmethod
    def _format_parameter_log(parameters: list[ParameterCandidate]) -> str:
        if not parameters:
            return "[]"
        formatted: list[str] = []
        for parameter in sorted(parameters, key=lambda p: (p.location.value, p.method, p.name, p.parent_path or "")):
            relevance = ",".join(sorted(parameter.security_relevance)) or "-"
            path_suffix = f" path={parameter.parent_path}" if parameter.parent_path else ""
            formatted.append(
                f"{parameter.method}:{parameter.location.value}:{parameter.name}"
                f"{path_suffix}:source={parameter.source}:relevance={relevance}"
            )
        return "[" + "; ".join(formatted) + "]"

    async def _request_with_session_keeper(
        self,
        client: httpx.AsyncClient,
        method: str,
        url: str,
        *,
        retry_on_login: bool = True,
        **kwargs,
    ) -> httpx.Response:
        if self._auth_headers:
            kwargs.setdefault("headers", {})
            kwargs["headers"].update(self._auth_headers)

        response = await client.request(method, url, **kwargs)
        if not retry_on_login:
            return response

        if not self._session_keeper_enabled():
            return response

        if not self._looks_like_session_loss(response, url):
            return response

        logger.info("crawler session appears expired at %s; refreshing auth state and retrying once", url)
        await self._authenticate_session(client, url, force=True)

        if self._auth_headers:
            kwargs.setdefault("headers", {})
            kwargs["headers"].update(self._auth_headers)

        return await client.request(method, url, **kwargs)

    def _session_keeper_enabled(self) -> bool:
        return bool(
            self.settings.authentication_cookie
            or (self.settings.authentication_username and self.settings.authentication_password)
            or self._auth_replay_state
            or self._auth_headers
        )

    def _looks_like_session_loss(self, response: httpx.Response, requested_url: str = "") -> bool:
        final_path = response.url.path.lower()
        requested_path = urlparse(requested_url).path.lower()
        
        # Exclude known login/auth/registration paths from session loss logic
        if any(token in requested_path for token in ("/login", "/signin", "/register", "/signup", "/auth")):
            return False

        if response.status_code in {401, 403, 419, 440}:
            return True
        if final_path != requested_path and any(token in final_path for token in ("/login", "/signin", "/auth", "/session")):
            return True
        content_type = response.headers.get("content-type", "").lower()
        if "text/html" not in content_type:
            return False
        body = response.text.lower()
        has_login_form = "<form" in body and any(token in body for token in ("password", "username", "login", "signin"))
        has_session_message = any(
            token in body
            for token in (
                "session expired",
                "please log in",
                "please login",
                "you must log in",
                "authentication required",
                "unauthorized",
                "token expired",
                "invalid token",
            )
        )
        return has_session_message or (has_login_form and has_session_message)

    @staticmethod
    def _merged_auth_settings(global_settings, override) -> SimpleNamespace:
        """Merge global auth settings with per-account overrides.

        ``SmartAuthenticator`` reads attributes via ``getattr(self.settings, name, None)``
        so a ``SimpleNamespace`` works as a drop-in. Per-account values take precedence.
        """
        merged = {
            "authentication_login_url": None,
            "authentication_success_url": None,
            "authentication_success_text": None,
            "authentication_success_regex": None,
            "authentication_failure_text": None,
            "authentication_failure_regex": None,
            "authentication_validation_url": None,
        }
        for key in merged:
            # Prefer per-account override, fall back to global setting.
            override_val = getattr(override, key.replace("authentication_", ""), None) if override else None
            merged[key] = override_val or getattr(global_settings, key, None)
        # Carry over all other settings the authenticator may access.
        for attr in dir(global_settings):
            if attr not in merged and not attr.startswith("_"):
                merged[attr] = getattr(global_settings, attr)
        return SimpleNamespace(**merged)

    async def _authenticate_session(self, client: httpx.AsyncClient, root_url: str, force: bool = False):
        """Authenticate session using cookies or credentials.

        Per-scan credentials submitted with the scan (``self._auth_override``)
        take precedence over the env-based ``SCAN_AUTH_*`` settings so users can
        authenticate the crawl without setting environment variables.
        """
        if self._auth_state in {AuthVerificationState.authenticated_unverified, AuthVerificationState.authenticated_verified} and not force:
            return

        if force:
            self._reauth_attempts += 1
            if self._reauth_attempts >= 3:
                logger.warning(
                    "[auth] Maximum re-authentication attempts reached (%d); skipping re-auth cascade to save budget.",
                    self._reauth_attempts
                )
                return

        override = self._auth_override
        auth_cookie = (getattr(override, "cookie", None) or self.settings.authentication_cookie)
        auth_header_cfg = (getattr(override, "header", None) or self.settings.authentication_header)
        username = (getattr(override, "username", None) or self.settings.authentication_username)
        password = (getattr(override, "password", None) or self.settings.authentication_password)
        login_url = (getattr(override, "login_url", None) or root_url)

        # 1. Parse cookie string if provided
        if auth_cookie:
            if not self._configured_auth_cookies or force:
                cookies = {}
                for cookie in auth_cookie.split(";"):
                    cookie = cookie.strip()
                    if "=" in cookie:
                        k, v = cookie.split("=", 1)
                        cookies[k] = v
                self._configured_auth_cookies = cookies
            cookies = self._configured_auth_cookies
            client.cookies.update(cookies)
            self.session_cookies.update(cookies)
            self._auth_state = AuthVerificationState.authenticated_unverified
            self._auth_verification_evidence = "configured cookie supplied"
            logger.info("Session configured via provided cookie string")

        if auth_header_cfg:
            header_name, _, header_value = auth_header_cfg.partition(":")
            if header_name and header_value:
                self._auth_headers[header_name.strip()] = header_value.strip()
                client.headers[header_name.strip()] = header_value.strip()
                self._auth_state = AuthVerificationState.authenticated_unverified
                self._auth_verification_evidence = "configured authentication header supplied"

        if auth_cookie or auth_header_cfg:
            auth_settings = self._merged_auth_settings(self.settings, override)
            result = await SmartAuthenticator(auth_settings)._verify_auth(client)
            self._auth_state = result.state
            self._auth_verification_evidence = result.verification_evidence or self._auth_verification_evidence
            if result.bearer_token:
                self._auth_headers["Authorization"] = f"Bearer {result.bearer_token}"
                client.headers["Authorization"] = f"Bearer {result.bearer_token}"
            return

        if force and self._auth_replay_state is not None:
            try:
                state = self._auth_replay_state
                await client.get(state.login_url)
                if state.headers:
                    client.headers.update(state.headers)
                
                if state.method == "POST":
                    if state.is_json:
                        await client.post(state.action, json=state.payload)
                    else:
                        await client.post(state.action, data=state.payload)
                else:
                    await client.get(state.action, params=state.payload)
                
                self.session_cookies.update(self._snapshot_cookies(client.cookies))
                auth_header = client.headers.get("Authorization")
                if auth_header:
                    self._auth_headers["Authorization"] = auth_header
                auth_settings = self._merged_auth_settings(self.settings, override)
                result = await SmartAuthenticator(auth_settings)._verify_auth(client)
                self._auth_state = result.state
                self._auth_verification_evidence = result.verification_evidence
                logger.info("Session refreshed via stored login replay state")
                return
            except Exception as e:
                logger.warning("Stored login replay failed, attempting fresh authentication: %s", e)
                self._auth_state = AuthVerificationState.expired

        # 2. Check if username and password are provided
        if username and password:
            try:
                auth_settings = self._merged_auth_settings(self.settings, override)
                authenticator = SmartAuthenticator(auth_settings)
                result = await authenticator.authenticate(client, login_url, username, password)
                self._is_spa = self._is_spa or result.is_spa
                if result.authenticated:
                    self.session_cookies.update(result.cookies)
                    if result.bearer_token:
                        self._auth_headers["Authorization"] = f"Bearer {result.bearer_token}"
                        client.headers["Authorization"] = f"Bearer {result.bearer_token}"
                    if result.storage_state:
                        self._auth_storage_state = result.storage_state
                    if result.replay_state:
                        self._auth_replay_state = result.replay_state
                    self._auth_state = result.state
                    self._auth_verification_evidence = result.verification_evidence
                    logger.info(
                        "Session authenticated successfully. Cookies: %s, Headers: %s",
                        self.session_cookies,
                        self._redact_headers(self._auth_headers),
                    )
                else:
                    self._auth_state = result.state if result.state else AuthVerificationState.attempted
                    self._auth_verification_evidence = result.verification_evidence
                    logger.warning("Authentication failed using all strategies")
            except Exception as e:
                logger.error("Smart authentication cascade error: %s", e)
                self._auth_state = AuthVerificationState.attempted

        self.session_cookies.update(self._snapshot_cookies(client.cookies))

    async def _load_robots(self, root_url: str) -> robotparser.RobotFileParser | None:
        robots_url = normalize_url(root_url, "/robots.txt")
        parser = robotparser.RobotFileParser()
        try:
            async with create_scan_client(timeout=5.0) as client:
                response = await client.get(robots_url)
            if response.status_code >= 400:
                return None
            parser.parse(response.text.splitlines())
            return parser
        except Exception:
            return None

    @staticmethod
    def _normalize_malformed_forms(html: str) -> str:
        """Convert self-closing <form ... /> tags into proper open tags.

        DVWA and other legacy PHP apps sometimes emit XML-style self-closing
        form tags. HTML parsers treat those as empty elements, so every input
        that follows becomes a sibling instead of a child of the form.
        """
        return re.sub(r"<form\b([^>]*?)/>", r"<form\1>", html, flags=re.I)

    def _parse_html(self, page_url: str, html: str) -> tuple[list[HtmlForm], list[str]]:
        soup = BeautifulSoup(self._normalize_malformed_forms(html), "html.parser")

        # Extract links from multiple tags: a, iframe, script, link, img
        links = []
        for tag, attr in [("a", "href"), ("iframe", "src"), ("script", "src"), ("link", "href"), ("img", "src")]:
            for element in soup.find_all(tag):
                val = element.get(attr, "")
                if val and not val.startswith("javascript:"):
                    links.append(val)

        # Follow meta refresh redirects
        meta_refresh = soup.find("meta", attrs={"http-equiv": re.compile("^refresh$", re.I)})
        if meta_refresh:
            content = meta_refresh.get("content", "")
            match = re.search(r"url=['\"]?([^'\";]+)", content, re.I)
            if match:
                links.append(match.group(1))

        # Follow JS redirects
        for script in soup.find_all("script"):
            if script.string:
                for match in re.finditer(r"(?:window|document)\.location(?:\.href)?\s*=\s*['\"]([^'\"]+)['\"]", script.string, re.I):
                    links.append(match.group(1))
                for match in re.finditer(r"location\.replace\(['\"]([^'\"]+)['\"]\)", script.string, re.I):
                    links.append(match.group(1))

        forms: list[HtmlForm] = []
        for form in soup.find_all("form"):
            action = form.get("action", page_url)
            method = form.get("method", "GET").upper()
            inputs = []
            for inp in form.find_all(["input", "textarea", "select", "button"]):
                name = inp.get("name")
                if not name:
                    continue
                if inp.name == "textarea":
                    inp_type = "textarea"
                elif inp.name == "select":
                    inp_type = "select"
                elif inp.name == "button":
                    inp_type = getattr(inp, "type", "button") if hasattr(inp, "type") else "button"
                else:
                    inp_type = inp.get("type", "text")
                value = inp.get("value", "")
                if inp.name == "textarea":
                    value = inp.get_text("", strip=False)
                inputs.append(FormInput(name=name, input_type=inp_type, value=value))
            forms.append(HtmlForm(page_url=page_url, action=normalize_url(page_url, action), method=method, inputs=inputs))

        return forms, links
