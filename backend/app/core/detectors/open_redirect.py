import asyncio
import logging
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from app.config import get_settings
from app.core.detectors.attack_surface import AttackSurface, AttackTarget
from app.core.detectors.base_detector import BaseDetector, Finding
from app.core.detectors.param_selection import REDIRECT_NAME_TOKENS, redirect_candidate
from app.core.verification.verification_framework import HttpVerifier
from app.models.vulnerability import OwaspCategory, SeverityLevel
from app.utils.scan_http import build_scan_headers

try:  # Playwright is optional; the browser sweep no-ops without it.
    from playwright.async_api import async_playwright
    PLAYWRIGHT_AVAILABLE = True
except Exception:  # pragma: no cover - import guard
    async_playwright = None
    PLAYWRIGHT_AVAILABLE = False

logger = logging.getLogger(__name__)


class OpenRedirectDetector(BaseDetector):
    name = "open_redirect"

    # Name half of the name-OR-value selection (see param_selection).
    redirect_param_tokens = REDIRECT_NAME_TOKENS

    # Scanner-controlled external marker host. Every payload below is crafted so
    # that a successful redirect resolves — the way a browser resolves an
    # authority — to this host, so confirmation is a single host-equality check.
    _MARKER_HOST = "sentrystrike.invalid"

    # Generic open-redirect payload families. All are framework-agnostic and all
    # resolve to ``_MARKER_HOST`` when followed, so a matched Location proves an
    # external redirect regardless of the app's redirect mechanism:
    #   1. direct absolute external URL
    #   2. protocol-relative URL (//host)
    #   3. encoded absolute (percent-encoded scheme separators)
    #   4. backslash scheme-confusion (https:\\host — browsers fold \ to /)
    #   5. encoded backslash scheme-confusion
    #   6. path-relative backslash (/\host → //host)
    #   7. userinfo confusion (user@host — the real host follows the @)
    payloads = (
        "https://sentrystrike.invalid/open-redirect",
        "//sentrystrike.invalid/open-redirect",
        "https:%2f%2fsentrystrike.invalid%2fopen-redirect",
        "https:\\\\sentrystrike.invalid\\open-redirect",
        "https:%5c%5csentrystrike.invalid%5copen-redirect",
        "/\\sentrystrike.invalid/open-redirect",
        "https://allowed.test@sentrystrike.invalid/open-redirect",
    )

    async def detect(self, urls: list[str], forms: list[object], **kwargs: object) -> list[Finding]:
        session_cookies = kwargs.get("session_cookies") or {}
        auth_headers = kwargs.get("auth_headers")

        # Build the surface unfiltered, then select on name-OR-value so params
        # whose name is generic but whose value looks like a URL/path qualify.
        candidates = [
            candidate
            for candidate in AttackSurface.build(
                urls,
                forms,
                parameters=kwargs.get("parameters") or [],
                api_endpoints=kwargs.get("api_endpoints") or [],
                requests=kwargs.get("requests") or [],
            )
            if redirect_candidate(candidate.parameter, candidate.value)
        ]

        findings: list[Finding] = []

        if candidates:
            semaphore = asyncio.Semaphore(4)
            verifier = HttpVerifier(
                cookies=session_cookies,
                headers=build_scan_headers(auth_headers),
                follow_redirects=False,
            )
            verifier.set_request_context(module="open_redirect")

            async def verify_candidate(candidate: AttackTarget) -> list[Finding]:
                async with semaphore:
                    verifier.set_request_context(parameter=candidate.parameter)
                    # A payload that drives the redirect to the scanner marker is
                    # the only accepted signal: it proves an ATTACKER-controlled
                    # target (a real open redirect / allowlist bypass). An app that
                    # merely redirects the observed value to its own allowlisted
                    # host is NOT reported — that destination is not attacker
                    # controllable, so flagging it would be a false positive.
                    for payload in self._candidate_payloads(candidate):
                        prepared = candidate.build_request(payload)
                        response = await verifier.send_request(
                            prepared.url,
                            prepared.method,
                            prepared.params,
                            prepared.data,
                            headers=prepared.headers,
                            cookies=prepared.cookies,
                            json_body=prepared.json_body,
                            test_phase="open_redirect",
                            payload=payload,
                        )
                        location = self._location_header(response.headers)
                        if response.status_code in {301, 302, 303, 307, 308} and self._is_payload_location(location):
                            return [
                                Finding(
                                    category=OwaspCategory.a01,
                                    vuln_type="Open Redirect",
                                    severity=SeverityLevel.medium,
                                    url=candidate.url,
                                    parameter=candidate.parameter,
                                    method=candidate.method,
                                    payload=payload,
                                    evidence=f"Parameter redirects to attacker-controlled Location header: {location}",
                                    confidence_score=90.0,
                                    detection_method="location_header_redirect",
                                    reproducible=True,
                                    verified=True,
                                    verification_request_snippet=response.request_snippet,
                                    verification_response_snippet=response.response_snippet,
                                    detection_evidence={"location": location},
                                )
                            ]
                return []

            try:
                results = await asyncio.gather(*(verify_candidate(candidate) for candidate in candidates))
            finally:
                await verifier.close()

            for result in results:
                findings.extend(result)

        # Browser-navigation sweep for client-side (SPA hash-route) redirects,
        # which leave no HTTP 302 and whose params are deliberately dropped from
        # the HTTP attack surface. Bounded and gated on a real browser.
        findings.extend(
            await self._browser_redirect_sweep(
                routes=kwargs.get("routes") or [],
                session_cookies=session_cookies,
                auth_headers=auth_headers,
                browser_available=bool(kwargs.get("browser_available")),
                storage_state=kwargs.get("auth_storage_state"),
                scan_config=kwargs.get("scan_config"),
                already_found={(f.url, f.parameter) for f in findings},
            )
        )
        return findings

    def _candidate_payloads(self, candidate: AttackTarget) -> tuple[str, ...]:
        """Static payload families plus data-driven allowlist-substring bypasses.

        Two data-driven bypass sources, both framework-agnostic and both taken
        from the target itself (never hardcoded):

        1. The parameter's observed VALUE, when it is an absolute URL the app
           already emitted (hence a value its allowlist accepts). Embedding that
           exact string in a marker-resolving URL defeats naive
           ``includes``/``endsWith`` allowlist checks generically.
        2. The app's own origin, for apps that allowlist themselves.

        All resolve, the way a browser resolves an authority, to the scanner
        marker host, so a matched Location proves an attacker-controlled redirect.
        """
        payloads = list(self.payloads)
        marker = f"https://{self._MARKER_HOST}/open-redirect"
        # Allowlist-substring bypass seeded from the app's OWN observed value.
        # When the discovered parameter value is a URL the app already emitted
        # (e.g. ``/redirect?to=https://github.com/…`` mined from a real link),
        # that value is — by construction — one the app's allowlist accepts.
        # Embed it, verbatim, as a substring of a marker-resolving URL: a naive
        # ``includes``/``endsWith`` allowlist check still sees the allowed string,
        # yet the authority a browser resolves is the scanner marker. The allowed
        # substring is taken from the target's own value, never hardcoded.
        observed = str(candidate.value or "").strip()
        if self._value_is_external_url(observed):
            payloads.extend(
                [
                    f"{marker}?next={observed}",   # allowed URL as a trailing param
                    f"{marker}#{observed}",        # allowed URL in the fragment
                    f"https://{self._MARKER_HOST}/{observed}",  # allowed URL in the path
                ]
            )
        allowed = self._allowed_prefix(candidate)
        if allowed:
            payloads.extend(
                [
                    # userinfo confusion carrying the allowed host as userinfo
                    f"https://{allowed}@{self._MARKER_HOST}/open-redirect",
                    # nested redirect: allowed value with the marker embedded as data
                    f"{allowed}/{marker}",
                    f"{allowed}?next={marker}",
                ]
            )
        # De-dupe while preserving order.
        seen: set[str] = set()
        ordered: list[str] = []
        for payload in payloads:
            if payload not in seen:
                seen.add(payload)
                ordered.append(payload)
        return tuple(ordered)

    def _allowed_prefix(self, candidate: AttackTarget) -> str:
        """Return an allowed-looking host to seed allowlist-bypass payloads.

        Prefers the candidate URL's own origin (an app almost always allowlists
        itself). Falls back to the host of the observed baseline value when that
        value already looks like an absolute URL.
        """
        host = urlparse(candidate.url).netloc
        if host:
            return host
        parsed_value = urlparse(str(candidate.value or ""))
        if parsed_value.scheme in {"http", "https"} and parsed_value.netloc:
            return parsed_value.netloc
        return ""

    @staticmethod
    def _location_header(headers: dict) -> str:
        for key, value in (headers or {}).items():
            if key.lower() == "location":
                return str(value)
        return ""

    # ------------------------------------------------------------------ #
    # Browser-navigation sweep (client-side / SPA hash-route redirects)
    # ------------------------------------------------------------------ #

    def _select_browser_redirect_jobs(
        self, routes: list[object], max_jobs: int
    ) -> list[tuple[str, str]]:
        """Pick (route_url, param) probes from routes carrying a redirect param.

        Mines both the ordinary query and the fragment query of hash routes
        (``/#/redirect?to=``) — the latter are dropped from the HTTP surface, so
        this is the only path that reaches a client-side redirect sink. Selection
        reuses the shared name-OR-value predicate, so it stays generic.
        """
        jobs: list[tuple[str, str]] = []
        seen: set[tuple[str, str]] = set()
        for route in routes:
            route_url = getattr(route, "url", None) or (route if isinstance(route, str) else None)
            if not route_url:
                continue
            for name, value in self._route_query_pairs(route_url):
                if not redirect_candidate(name, value):
                    continue
                key = (route_url, name)
                if key in seen:
                    continue
                seen.add(key)
                jobs.append(key)
                if len(jobs) >= max_jobs:
                    return jobs
        return jobs

    @staticmethod
    def _route_query_pairs(url: str) -> list[tuple[str, str]]:
        """(name, value) pairs from a route's query string AND fragment query."""
        pairs: list[tuple[str, str]] = []
        try:
            parsed = urlparse(url)
        except Exception:
            return pairs
        parts = [parsed.query]
        fragment = parsed.fragment or ""
        if "?" in fragment:
            parts.append(fragment.split("?", 1)[1])
        for part in parts:
            pairs.extend(parse_qsl(part, keep_blank_values=True))
        return pairs

    @staticmethod
    def _inject_redirect_param(route_url: str, param: str, payload: str) -> str:
        """Set ``param=payload`` in whichever query (search or fragment) holds it."""
        parsed = urlparse(route_url)

        def _replace(qs: str) -> tuple[str, bool]:
            pairs = parse_qsl(qs, keep_blank_values=True)
            hit = False
            out = []
            for name, value in pairs:
                if name == param:
                    out.append((name, payload))
                    hit = True
                else:
                    out.append((name, value))
            return urlencode(out), hit

        fragment = parsed.fragment or ""
        if "?" in fragment:
            base, _, fq = fragment.partition("?")
            new_fq, hit = _replace(fq)
            if hit:
                return urlunparse(parsed._replace(fragment=f"{base}?{new_fq}"))
        new_q, hit = _replace(parsed.query)
        if hit:
            return urlunparse(parsed._replace(query=new_q))
        return route_url

    async def _browser_redirect_sweep(
        self,
        routes: list[object],
        session_cookies: dict,
        auth_headers: dict | None,
        browser_available: bool,
        storage_state: dict | None,
        scan_config,
        already_found: set[tuple[str, str]],
    ) -> list[Finding]:
        """Confirm client-side redirects by navigating a real browser.

        A SPA route like ``#/redirect?to=<marker>`` sets ``window.location`` in
        JS, so there is no HTTP 302 to observe. We navigate with the marker host
        as the redirect target and confirm if the browser attempts a top-level
        navigation to that host (the marker never resolves, so any such attempt
        is proof the app honoured the untrusted target). Bounded in jobs + time.
        """
        if not browser_available or not PLAYWRIGHT_AVAILABLE:
            return []
        settings = get_settings()
        max_jobs = max(0, scan_config.open_redirect_browser_max_jobs if scan_config else getattr(settings, "open_redirect_browser_max_jobs", 10))
        budget = float(scan_config.open_redirect_browser_budget_seconds if scan_config else getattr(settings, "open_redirect_browser_budget_seconds", 45.0))
        if max_jobs == 0 or budget <= 0:
            return []

        jobs = [job for job in self._select_browser_redirect_jobs(routes, max_jobs) if job not in already_found]
        if not jobs:
            return []

        findings: list[Finding] = []
        loop = asyncio.get_event_loop()
        deadline = loop.time() + budget
        payload = f"https://{self._MARKER_HOST}/open-redirect"
        p = None
        context = None
        try:
            p = await async_playwright().start()
            browser = await p.chromium.launch(headless=True)
            context = await self._new_browser_context(browser, jobs[0][0], session_cookies, storage_state)
            for route_url, param in jobs:
                if loop.time() >= deadline:
                    logger.debug("open_redirect: browser sweep hit time budget.")
                    break
                probe_url = self._inject_redirect_param(route_url, param, payload)
                try:
                    reached = await asyncio.wait_for(
                        self._navigate_and_detect_external(context, probe_url),
                        timeout=min(12.0, max(1.0, deadline - loop.time())),
                    )
                except asyncio.TimeoutError:
                    continue
                except Exception as exc:
                    logger.debug("open_redirect: browser probe failed for %s param=%s: %s", route_url, param, exc)
                    continue
                if not reached:
                    continue
                findings.append(
                    Finding(
                        category=OwaspCategory.a01,
                        vuln_type="Open Redirect",
                        severity=SeverityLevel.medium,
                        url=route_url,
                        parameter=param,
                        method="GET",
                        payload=payload,
                        evidence=(
                            "Client-side redirect confirmed: navigating the SPA route with "
                            f"parameter '{param}' set to an external marker caused the browser to "
                            f"attempt a top-level navigation to {self._MARKER_HOST}, with no "
                            "dependency on an HTTP Location header."
                        ),
                        confidence_score=88.0,
                        detection_method="browser_client_side_redirect",
                        reproducible=True,
                        verified=True,
                        detection_evidence={
                            "parameter": param,
                            "browser_navigation_confirmed": True,
                            "marker_host": self._MARKER_HOST,
                        },
                    )
                )
        except Exception as exc:
            logger.debug("open_redirect: browser sweep aborted: %s", exc)
        finally:
            if context is not None:
                try:
                    await context.close()
                except Exception:
                    pass
            if p is not None:
                try:
                    await p.stop()
                except Exception:
                    pass
        return findings

    async def _new_browser_context(self, browser, route_url: str, session_cookies: dict, storage_state: dict | None):
        context = None
        if storage_state:
            try:
                context = await browser.new_context(
                    ignore_https_errors=True, user_agent="SentryStrikeScanner/1.0", storage_state=storage_state,
                )
            except Exception:
                context = None
        if context is None:
            context = await browser.new_context(
                ignore_https_errors=True, user_agent="SentryStrikeScanner/1.0",
            )
        if session_cookies:
            domain = urlparse(route_url).netloc.split(":")[0]
            cookies = [
                {"name": str(k), "value": str(v), "domain": domain, "path": "/"}
                for k, v in session_cookies.items()
            ]
            try:
                await context.add_cookies(cookies)
            except Exception:
                pass
        return context

    async def _navigate_and_detect_external(self, context, probe_url: str) -> bool:
        """Navigate probe_url; return True if the browser attempts to reach the marker host.

        Watches top-level navigation requests. The marker host is unresolvable, so
        any navigation whose host is the marker proves the app followed the
        untrusted redirect target (either via ``window.location`` or a <meta>/anchor).
        """
        page = await context.new_page()
        reached = {"hit": False}

        def _on_request(request):
            try:
                if not request.is_navigation_request():
                    return
                if urlparse(request.url).hostname == self._MARKER_HOST:
                    reached["hit"] = True
            except Exception:
                pass

        page.on("request", _on_request)
        try:
            try:
                await page.goto(probe_url, wait_until="commit", timeout=8000)
            except Exception:
                # A navigation to the unresolvable marker raises — that's expected
                # and the request handler has already recorded the attempt.
                pass
            # Give client-side JS a moment to perform the redirect.
            try:
                await page.wait_for_timeout(1200)
            except Exception:
                pass
            # Final-URL fallback: some redirects land on the marker origin directly.
            try:
                if urlparse(page.url).hostname == self._MARKER_HOST:
                    reached["hit"] = True
            except Exception:
                pass
        finally:
            try:
                page.remove_listener("request", _on_request)
            except Exception:
                pass
            try:
                await page.close()
            except Exception:
                pass
        return reached["hit"]

    @classmethod
    def _effective_redirect_host(cls, location: str) -> str:
        """Resolve the host a browser would navigate to for *location*.

        Mirrors user-agent authority resolution: folds backslashes to forward
        slashes (browsers treat ``\\`` as ``/`` in the authority) and strips any
        ``userinfo@`` prefix, so ``https://allowed.test@evil`` resolves to
        ``evil`` — the userinfo-confusion bypass. Percent-encoding is *not*
        decoded: an encoded payload counts only when the server itself decoded
        it into a literal ``//``/``\\`` authority, which is the actual redirect
        condition. Returns "" for a relative or same-origin-only Location.
        """
        if not location:
            return ""
        text = location.strip().replace("\\", "/")
        netloc = urlparse(text).netloc
        if "@" in netloc:
            netloc = netloc.rsplit("@", 1)[1]
        return netloc.split(":", 1)[0].lower()

    @classmethod
    def _is_payload_location(cls, location: str) -> bool:
        return cls._effective_redirect_host(location) == cls._MARKER_HOST

    @staticmethod
    def _value_is_external_url(value: object) -> bool:
        parsed = urlparse(str(value or ""))
        return parsed.scheme in {"http", "https"} and bool(parsed.netloc)
