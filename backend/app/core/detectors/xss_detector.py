import asyncio
import logging

from app.config import get_settings
from app.core.crawler.models import ParameterLocation
from app.core.detectors.attack_surface import AttackSurface, AttackTarget
from app.core.detectors.base_detector import BaseDetector, Finding
from app.core.verification.response_analyzer import ResponseAnalyzer, ResponseData
from app.core.verification.xss_verifier import (
    PLAYWRIGHT_AVAILABLE,
    PendingBrowserVerification,
    XSSVerifier,
    async_playwright,
)
from app.models.vulnerability import OwaspCategory, SeverityLevel

logger = logging.getLogger(__name__)


class XSSDetector(BaseDetector):
    name = "xss"

    # Parameter name heuristics to select smart candidates
    reflective_param_names = {
        # Search / query
        "q", "query", "search", "s", "keyword", "keywords", "term", "terms",
        "find", "lookup", "filter", "input",
        # User content
        "comment", "message", "msg", "note", "notes", "body",
        "text", "content", "description", "summary", "bio", "about",
        "title", "subject", "heading", "caption", "label",
        "feedback", "review", "reply", "post", "answer", "question",
        "announcement", "bulletin", "status", "tweet", "update",
        # Identity
        "name", "fullname", "full_name", "firstname", "first_name",
        "lastname", "last_name", "username", "uname", "nickname",
        "displayname", "display_name", "alias",
        "email", "mail", "e_mail",
        "company", "org", "organization",
        "address", "city", "state", "country",
        "phone", "telephone", "mobile",
        # Navigation / redirect
        "return", "next", "redirect", "redirect_to", "redirect_url",
        "return_to", "return_url", "goto", "go", "continue",
        "url", "link", "href", "src", "source", "target", "dest",
        "destination", "back", "forward",
        "ref", "referral", "referrer", "from",
        # Page / layout
        "page", "view", "template", "layout", "theme", "format",
        "lang", "language", "locale",
        # Auth / misc
        "token", "code", "key", "error", "reason", "info",
        "callback", "jsonp", "cb",
        "data", "value", "val", "param",
        "output", "out", "result", "response",
        "tag", "tags", "category", "cat",
    }

    _reflective_tokens = (
        "q", "search", "query", "keyword", "redirect", "return", "next",
        "url", "link", "href", "src", "name", "email", "text", "content",
        "title", "comment", "message", "input", "data", "value", "tag",
        "ref", "callback", "jsonp", "output", "error", "param",
    )

    _form_input_prefixes = ("txt", "mtx", "inp", "tb", "tf", "ta", "fld", "ctl")

    # Headers that are commonly reflected into response bodies.
    # These are injected as extra headers in header-injection candidates.
    _injectable_headers = (
        "Referer",
        "User-Agent",
        "X-Forwarded-For",
        "X-Original-URL",
    )

    # Parameters that indicate a JSONP endpoint - use a dedicated payload.
    _jsonp_param_names = {"callback", "jsonp", "cb", "json_callback", "jsoncallback"}

    async def detect(self, urls: list[str], forms: list[object], **kwargs: object) -> list[Finding]:
        findings: list[Finding] = []
        session_cookies = kwargs.get("session_cookies") or {}
        # auth_headers carries the Bearer token for apps that use header-based auth
        # (JWT in localStorage) rather than cookies. Applied to all HTTP verifier
        # instances so authenticated endpoints receive valid credentials.
        auth_headers: dict[str, str] = kwargs.get("auth_headers") or {}

        if not session_cookies and not auth_headers:
            logger.warning(
                "XSSDetector: no session_cookies provided. Requests to "
                "authenticated endpoints will be redirected to login and "
                "XSS payloads will never be reflected. Pass session_cookies "
                "via kwargs to enable authenticated scanning."
            )

        findings.extend(await self._static_dom_findings_with_browser_confirmation(kwargs, session_cookies))

        browser_available = bool(kwargs.get("browser_available"))
        is_spa = bool(kwargs.get("is_spa", False))
        routes = kwargs.get("routes") or []
        # Full authenticated storage_state (Task A): seed the DOM-sweep browser
        # so authed-only routes render during confirmation. Opaque per-origin blob.
        storage_state = kwargs.get("auth_storage_state")

        def xss_filter(param_name: str) -> bool:
            param_lower = param_name.lower()
            is_reflective = (
                param_lower in self.reflective_param_names
                or any(tok in param_lower for tok in self._reflective_tokens)
            )
            has_xss_prefix = param_lower[:3] in self._form_input_prefixes
            return is_reflective or has_xss_prefix

        planner = kwargs.get("attack_planner")
        if planner is not None and hasattr(planner, "targets_for"):
            targets = [
                target for target in planner.targets_for(self.name)
                if xss_filter(target.parameter)
            ]
        else:
            targets = AttackSurface.build(
                urls,
                forms,
                parameters=kwargs.get("parameters") or [],
                api_endpoints=kwargs.get("api_endpoints") or [],
                requests=kwargs.get("requests") or [],
                filter_fn=xss_filter,
            )
        candidates: list[AttackTarget | tuple] = list(targets)

        # Supplement with header-injection candidates for every discovered URL.
        # These are 4-tuples like URL candidates but carry the header name in
        # the ``param`` slot; XSSVerifier.verify() recognises them via the
        # ``header_injection=True`` flag encoded in the method field.
        header_candidates = self._build_header_candidates(
            urls,
            is_spa=is_spa,
            root_url=kwargs.get("root_url"),
        )
        candidates = list(candidates) + header_candidates

        if not candidates:
            logger.debug(
                "XSSDetector: no testable candidates found across %d URLs and %d forms.",
                len(urls), len(forms),
            )
            return findings

        logger.debug("XSSDetector: testing %d candidates.", len(candidates))

        scan_config = kwargs.get("scan_config")
        settings = get_settings()
        effective_concurrency = scan_config.scanner_concurrency if scan_config else settings.scanner_concurrency
        worker_count = max(1, min(4, effective_concurrency // 2 or 1))
        stored_probe_urls = XSSVerifier.select_stored_probe_urls(
            list(dict.fromkeys([*urls, *(target.url for target in targets)]))
        )
        shared_baselines = await self._prefetch_stored_baselines(
            stored_probe_urls, session_cookies,
        )

        # ── Phase 0: Batch stored-XSS discovery ─────────────────────────────────
        # Group body-parameter candidates by (url, method) and inject a unique
        # canary into every parameter of each group in a single request, then
        # probe each display URL once. This discovers which (param, display_url)
        # pairs reflect *before* the per-payload fan-out, collapsing the stored
        # probe from O(params × payloads × urls) to O(1 injection + urls).
        # Only body/form/json candidates batch; query/path/header candidates are
        # tested individually by the per-candidate verify loop below.
        stored_display_overrides: dict[str, set[str]] = {}
        batch_groups: dict[tuple[str, str], list[AttackTarget]] = {}
        for cand in candidates:
            if not isinstance(cand, AttackTarget):
                continue
            if cand.location in {ParameterLocation.json_body, ParameterLocation.graphql_variable, ParameterLocation.form}:
                key = (cand.url, cand.method.upper())
                batch_groups.setdefault(key, []).append(cand)

        # Run batch discovery for groups with 2+ body parameters — single-param
        # groups get no batching benefit and are handled by the normal per-candidate
        # verify loop. Run all batches concurrently.
        async def run_batch_discovery(
            group_key: tuple[str, str], group_cands: list[AttackTarget],
        ) -> dict[str, set[str]]:
            batch_verifier = XSSVerifier()
            batch_verifier.http_verifier.cookies = session_cookies
            if auth_headers:
                batch_verifier.http_verifier.headers = {
                    **batch_verifier.http_verifier.headers, **auth_headers,
                }
            try:
                return await batch_verifier._batch_stored_discovery(
                    group_cands,
                    stored_probe_urls,
                    stored_baselines=shared_baselines,
                )
            except Exception as e:
                logger.debug("Batch stored discovery failed for %s: %s", group_key[0], e)
                return {}
            finally:
                await batch_verifier.close()

        batchable_groups = {
            key: cands for key, cands in batch_groups.items() if len(cands) >= 2
        }
        if batchable_groups:
            logger.debug(
                "XSSDetector: running batch stored discovery for %d groups (%d total params)",
                len(batchable_groups),
                sum(len(c) for c in batchable_groups.values()),
            )
            batch_results = await asyncio.gather(
                *(run_batch_discovery(k, c) for k, c in batchable_groups.items()),
                return_exceptions=True,
            )
            for result in batch_results:
                if isinstance(result, Exception):
                    logger.debug("Batch stored discovery group failed: %s", result)
                    continue
                for param, display_urls in result.items():
                    stored_display_overrides.setdefault(param, set()).update(display_urls)

            if stored_display_overrides:
                logger.debug(
                    "XSSDetector: batch discovery confirmed %d stored parameter(s)",
                    len(stored_display_overrides),
                )

        # ── Phase 1: HTTP-only scanning ───────────────────────────────────────────
        pending_browser_jobs: list[PendingBrowserVerification] = []

        async def verify_candidate(
            cand: AttackTarget | tuple,
        ) -> tuple[list[Finding], list[PendingBrowserVerification]]:
            target = cand if isinstance(cand, AttackTarget) else None
            if isinstance(cand, AttackTarget):
                cand_url = cand.url
                param = cand.parameter
                method = cand.method
                val = str(cand.value)
                form_inputs = cand.form_inputs
            elif len(cand) == 5:
                cand_url, param, method, val, form_inputs = cand
            else:
                cand_url, param, method, val = cand
                form_inputs = None

            verifier = XSSVerifier()
            verifier.http_verifier.cookies = session_cookies
            # P0-3: on SPA targets the header-stored GET-replay oracle cannot
            # observe client-rendered reflection; the verifier uses this flag to
            # disable that fan-out and defer the stored-header hypothesis to the
            # browser-DOM sweep instead.
            verifier.spa_mode = is_spa
            if auth_headers:
                verifier.http_verifier.headers = {**verifier.http_verifier.headers, **auth_headers}
            try:
                result = await verifier.verify(
                    cand_url, param, method, val,
                    form_inputs=form_inputs,
                    stored_display_urls=stored_probe_urls,
                    stored_baselines=shared_baselines,
                    target=target,
                    stored_display_overrides=stored_display_overrides if stored_display_overrides else None,
                )
                pending: list[PendingBrowserVerification] = []
                if result.evidence.get("browser_verification_pending"):
                    job = result.evidence.get("pending_job")
                    if job:
                        pending.append(job)
                    return [], pending
                if result.is_vulnerable:
                    return result.findings, []
            except Exception as e:
                logger.error("XSS verification failed for %s param %s: %s", cand_url, param, e)
            finally:
                await verifier.close()
            return [], []

        queue: asyncio.Queue[AttackTarget | tuple] = asyncio.Queue()
        for cand in candidates:
            queue.put_nowait(cand)

        async def worker() -> tuple[list[Finding], list[PendingBrowserVerification]]:
            local_findings: list[Finding] = []
            local_pending: list[PendingBrowserVerification] = []
            while True:
                try:
                    cand = queue.get_nowait()
                except asyncio.QueueEmpty:
                    break
                cand_findings, cand_pending = await verify_candidate(cand)
                local_findings.extend(cand_findings)
                local_pending.extend(cand_pending)
            return local_findings, local_pending

        worker_results = await asyncio.gather(
            *[worker() for _ in range(worker_count)],
            return_exceptions=True,
        )
        for result in worker_results:
            if isinstance(result, Exception):
                logger.warning("XSS worker failed: %s", result)
                continue
            cand_findings, cand_pending = result
            findings.extend(cand_findings)
            pending_browser_jobs.extend(cand_pending)

        # ── Phase 2: Browser verification - runs after ALL HTTP scanning is done ──
        if pending_browser_jobs:
            logger.debug(
                "XSSDetector: HTTP phase complete. Running browser verification for %d candidates.",
                len(pending_browser_jobs),
            )
            browser_verifier = XSSVerifier()
            browser_verifier.http_verifier.cookies = session_cookies
            if auth_headers:
                browser_verifier.http_verifier.headers = {**browser_verifier.http_verifier.headers, **auth_headers}
            try:
                for job in pending_browser_jobs:
                    browser_findings = await browser_verifier.run_browser_verification(job)
                    findings.extend(browser_findings)
            finally:
                await browser_verifier.close()

        # ── Phase 1.5: Browser-driven DOM reflection sweep ────────────────────────
        # Detect XSS that only executes in the rendered DOM (the dominant SPA
        # class), independent of HTTP-body reflection. Gated on a real browser
        # and bounded in both job count and wall-clock.
        findings.extend(
            await self._browser_dom_reflection_sweep(
                targets, routes, session_cookies, browser_available, findings,
                storage_state=storage_state, scan_config=scan_config,
                auth_headers=auth_headers,
            )
        )

        return findings

    async def _browser_dom_reflection_sweep(
        self,
        targets: list[AttackTarget],
        routes: list[object],
        session_cookies: dict,
        browser_available: bool,
        existing_findings: list[Finding],
        storage_state: dict | None = None,
        scan_config=None,
        auth_headers: dict | None = None,
    ) -> list[Finding]:
        """Navigate SPA routes with an executing canary and confirm DOM execution.

        Prioritises reflective params (and those the HTTP phase echoed), bounds
        the number of probes and total time, and reuses one browser context for
        the whole sweep. Skips silently when no browser is available.
        """
        if not browser_available:
            logger.debug("XSSDetector: browser unavailable, skipping DOM reflection sweep.")
            return []
        if not PLAYWRIGHT_AVAILABLE:
            return []

        settings = get_settings()
        max_jobs = max(0, scan_config.xss_browser_dom_max_jobs if scan_config else int(getattr(settings, "xss_browser_dom_max_jobs", 12)))
        budget = float(scan_config.xss_browser_dom_budget_seconds if scan_config else getattr(settings, "xss_browser_dom_budget_seconds", 60.0))
        if max_jobs == 0 or budget <= 0:
            return []

        jobs = self._select_dom_reflection_jobs(targets, existing_findings, max_jobs, routes=routes)
        if not jobs:
            return []

        # Routes discovered by the crawler are valid SPA navigation surfaces; any
        # candidate whose URL is a known route (or carries a query param) qualifies.
        route_urls = {getattr(route, "url", None) or str(route) for route in routes}

        findings: list[Finding] = []
        seen_hits: set[tuple[str, str]] = set()
        loop = asyncio.get_event_loop()
        deadline = loop.time() + budget

        verifier = XSSVerifier()
        verifier.http_verifier.cookies = session_cookies
        if auth_headers:
            verifier.http_verifier.headers = {**verifier.http_verifier.headers, **auth_headers}
        context = None
        p = None
        try:
            p = await async_playwright().start()
            browser = await p.chromium.launch(headless=True)
            for route_url, param, location in jobs:
                if loop.time() >= deadline:
                    logger.debug("XSSDetector: DOM reflection sweep hit time budget.")
                    break
                key = (route_url, param)
                if key in seen_hits:
                    continue
                if context is None:
                    context = await verifier._new_reflection_context(
                        browser, route_url, storage_state=storage_state,
                    )
                canary = ResponseAnalyzer.generate_probe_canary()
                try:
                    result = await asyncio.wait_for(
                        verifier.verify_reflected_dom(
                            route_url, param, location, canary=canary, context=context,
                        ),
                        timeout=min(15.0, max(1.0, deadline - loop.time())),
                    )
                except asyncio.TimeoutError:
                    continue
                except Exception as exc:
                    logger.debug("DOM reflection sweep failed for %s param=%s: %s", route_url, param, exc)
                    continue
                if not (result and result.get("fired")):
                    continue
                seen_hits.add(key)
                winning_vector = result.get("vector")
                winning_surface = result.get("surface")
                winning_payload = result.get("payload") or (
                    f"<img src=x onerror=window.sentry_hook('{canary}')>"
                )
                findings.append(
                    verifier._create_finding(
                        category=OwaspCategory.a05,
                        vuln_type="DOM-Based XSS",
                        severity=SeverityLevel.high,
                        url=route_url,
                        parameter=param,
                        payload=winning_payload,
                        evidence=(
                            "Browser execution confirmed: a uniquely-hooked canary injected into "
                            f"parameter '{param}' via the {winning_surface or location} surface "
                            f"(vector: {winning_vector or 'img_onerror'}) executed in the rendered "
                            "DOM, with no dependency on HTTP-body reflection."
                        ),
                        confidence_score=90.0,
                        detection_method="dom_xss_browser_execution",
                        method="GET",
                        detection_evidence={
                            "parameter": param,
                            "injection_location": winning_surface or location,
                            "winning_vector": winning_vector,
                            "winning_surface": winning_surface,
                            "browser_execution_confirmed": True,
                            "route_backed": route_url in route_urls,
                        },
                        reproducible=True,
                        verified=True,
                    )
                )
        except Exception as exc:
            logger.debug("XSSDetector: DOM reflection sweep aborted: %s", exc)
        finally:
            if context is not None:
                try:
                    await context.close()
                except Exception:
                    pass
            await verifier.close()
            if p is not None:
                try:
                    await p.stop()
                except Exception:
                    pass
        return findings

    def _select_dom_reflection_jobs(
        self,
        targets: list[AttackTarget],
        existing_findings: list[Finding],
        max_jobs: int,
        routes: list[object] | None = None,
    ) -> list[tuple[str, str, str]]:
        """Pick a bounded, prioritised set of (route_url, param, location) probes.

        Priority: params the HTTP phase already echoed (partial reflection), then
        classic reflective names, then everything else. Only query/fragment-
        reachable GET targets are eligible — SPAs read these from
        location.search/hash.

        Jobs come from two sources: replayable GET attack targets AND the query
        parameters carried on discovered SPA routes. The latter matters because a
        hash route such as ``/#/search?q=x`` is deliberately dropped from the HTTP
        attack surface (its fragment never reaches the server), so its ``q``
        parameter would otherwise never be probed for DOM XSS even though the SPA
        reads it client-side from ``location.hash``.
        """
        echoed_params = {
            f.parameter for f in existing_findings if getattr(f, "parameter", None)
        }
        prioritized: list[tuple[str, str, str]] = []
        fallback: list[tuple[str, str, str]] = []
        seen: set[tuple[str, str]] = set()

        def consider(url: str, param: str) -> None:
            if not url or not param:
                return
            key = (url, param)
            if key in seen:
                return
            seen.add(key)
            # SPAs read from both search and hash; probe both.
            entry = (url, param, "both")
            param_lower = param.lower()
            reflective = (
                param_lower in self.reflective_param_names
                or any(tok in param_lower for tok in self._reflective_tokens)
            )
            if param in echoed_params:
                prioritized.insert(0, entry)
            elif reflective:
                prioritized.append(entry)
            else:
                fallback.append(entry)

        for target in targets:
            if not isinstance(target, AttackTarget):
                continue
            if target.method.upper() != "GET":
                continue
            if target.location not in (ParameterLocation.query, ParameterLocation.path):
                continue
            consider(target.url, target.parameter)

        # Route-derived jobs: query params on discovered SPA routes (including the
        # fragment query of hash routes) that the target sweep above did not cover.
        for route in routes or []:
            route_url = getattr(route, "url", None) or (route if isinstance(route, str) else None)
            if not route_url:
                continue
            for param in self._route_query_params(route_url):
                consider(route_url, param)

        ordered = prioritized + fallback
        return ordered[:max_jobs]

    @staticmethod
    def _route_query_params(url: str) -> list[str]:
        """Query-parameter names carried on a route URL.

        Reads both the ordinary query string (``?a=1``) and the query embedded in
        a client-side route fragment (``/#/search?q=x`` → ``q``), so hash-router
        parameters become DOM-XSS probe candidates.
        """
        from urllib.parse import parse_qs, urlparse

        names: list[str] = []
        try:
            parsed = urlparse(url)
        except Exception:
            return names
        parts = [parsed.query]
        fragment = parsed.fragment or ""
        if "?" in fragment:
            parts.append(fragment.split("?", 1)[1])
        for part in parts:
            for name in parse_qs(part, keep_blank_values=True):
                if name and name not in names:
                    names.append(name)
        return names

    @staticmethod
    def _static_dom_findings(kwargs: dict[str, object]) -> list[Finding]:
        """Analyze crawled HTML and response snippets for source-to-sink DOM XSS hints."""
        verifier = XSSVerifier()
        findings: list[Finding] = []
        seen: set[tuple[str, str]] = set()

        def add(url: str, body: str, source_name: str) -> None:
            if not body:
                return
            finding = verifier._check_dom_xss(url, body, source_name=source_name)
            if not finding:
                return
            key = (finding.url, ",".join(finding.detection_evidence.get("found_sinks", [])))
            if key in seen:
                return
            seen.add(key)
            findings.append(finding)

        root_url = str(kwargs.get("root_url") or "")
        add(root_url, str(kwargs.get("spa_root_html") or ""), "spa_root_html")

        for request in kwargs.get("requests") or []:
            url = getattr(request, "url", root_url)
            snippet = getattr(request, "response_snippet", "") or ""
            add(url, snippet, "browser_response_snippet")

        return findings

    @staticmethod
    async def _static_dom_findings_with_browser_confirmation(
        kwargs: dict[str, object],
        session_cookies: dict,
    ) -> list[Finding]:
        findings = XSSDetector._static_dom_findings(kwargs)
        if not findings:
            return findings

        verifier = XSSVerifier()
        verifier.http_verifier.cookies = session_cookies
        try:
            confirmed_urls: set[str] = set()
            for finding in findings:
                if not finding.url or finding.url in confirmed_urls:
                    continue
                try:
                    confirmed = await verifier.verify_dom_xss_execution(finding.url)
                except Exception as exc:
                    logger.debug("DOM XSS browser confirmation failed for %s: %s", finding.url, exc)
                    continue
                if not confirmed:
                    continue
                confirmed_urls.add(finding.url)
                finding.verified = True
                finding.confidence_score = max(finding.confidence_score, 90.0)
                finding.detection_method = "dom_xss_browser_execution"
                finding.evidence = (
                    "Browser execution confirmed for a DOM XSS canary on a route containing "
                    "client-side user-controlled sources and risky sinks."
                )
                finding.detection_evidence["browser_execution_confirmed"] = True
        finally:
            await verifier.close()

        return findings

    @staticmethod
    async def _prefetch_stored_baselines(
        probe_urls: list[str],
        session_cookies: dict,
    ) -> dict[str, ResponseData]:
        """Fetch stored-XSS baselines once and share them across all candidates."""
        if not probe_urls:
            return {}

        verifier = XSSVerifier()
        verifier.http_verifier.cookies = session_cookies
        baselines: dict[str, ResponseData] = {}
        try:
            for probe_url in probe_urls:
                try:
                    baselines[probe_url] = await verifier._send(
                        probe_url, "GET", test_phase="stored_pre_test_baseline",
                    )
                except Exception as e:
                    logger.debug("Failed to pre-fetch shared baseline for %s: %s", probe_url, e)
        finally:
            await verifier.close()
        return baselines
    
    # ---------------------------------------------------------------------- #
    # Header-injection candidate builder
    # ---------------------------------------------------------------------- #

    def _build_header_candidates(
        self,
        urls: list[str],
        is_spa: bool = False,
        root_url: str | None = None,
    ) -> list[tuple]:
        """
        Build 4-tuple candidates for header-based XSS testing.

        The ``method`` slot is set to ``"HEADER:<header-name>"`` so that
        XSSVerifier can route them to the header-injection code path without
        any change to the 4-tuple contract used everywhere else.
        """
        seen: set[str] = set()
        candidates: list[tuple] = []
        
        normalized_root = None
        if root_url:
            try:
                parsed = urlparse(root_url)
                normalized_root = parsed.path.rstrip("/") or "/"
            except Exception:
                pass

        from urllib.parse import urlparse

        for url in urls:
            base = url.split("?")[0]
            if base in seen:
                continue
            seen.add(base)
            
            if is_spa and normalized_root:
                try:
                    parsed_base = urlparse(base)
                    path = parsed_base.path.rstrip("/") or "/"
                    if path != normalized_root:
                        continue
                except Exception:
                    pass

            for header in self._injectable_headers:
                candidates.append((base, header, f"HEADER:{header}", ""))
        return candidates
