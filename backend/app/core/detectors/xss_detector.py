import asyncio
import logging

from app.config import get_settings
from app.core.detectors.attack_surface import AttackSurface, query_or_form_targets
from app.core.detectors.base_detector import BaseDetector, Finding
from app.core.verification.response_analyzer import ResponseData
from app.core.verification.xss_verifier import PendingBrowserVerification, XSSVerifier

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

        if not session_cookies:
            logger.warning(
                "XSSDetector: no session_cookies provided. Requests to "
                "authenticated endpoints will be redirected to login and "
                "XSS payloads will never be reflected. Pass session_cookies "
                "via kwargs to enable authenticated scanning."
            )

        def xss_filter(param_name: str) -> bool:
            param_lower = param_name.lower()
            is_reflective = (
                param_lower in self.reflective_param_names
                or any(tok in param_lower for tok in self._reflective_tokens)
            )
            has_xss_prefix = param_lower[:3] in self._form_input_prefixes
            return is_reflective or has_xss_prefix

        targets = AttackSurface.build(
            urls,
            forms,
            parameters=kwargs.get("parameters") or [],
            api_endpoints=kwargs.get("api_endpoints") or [],
            requests=kwargs.get("requests") or [],
            filter_fn=xss_filter,
        )
        candidates = query_or_form_targets(targets)

        # Supplement with header-injection candidates for every discovered URL.
        # These are 4-tuples like URL candidates but carry the header name in
        # the ``param`` slot; XSSVerifier.verify() recognises them via the
        # ``header_injection=True`` flag encoded in the method field.
        header_candidates = self._build_header_candidates(urls)
        candidates = list(candidates) + header_candidates

        if not candidates:
            logger.debug(
                "XSSDetector: no testable candidates found across %d URLs and %d forms.",
                len(urls), len(forms),
            )
            return []

        logger.debug("XSSDetector: testing %d candidates.", len(candidates))

        settings = get_settings()
        worker_count = max(1, min(4, settings.scanner_concurrency // 2 or 1))
        stored_probe_urls = XSSVerifier.select_stored_probe_urls(urls)
        shared_baselines = await self._prefetch_stored_baselines(
            stored_probe_urls, session_cookies,
        )

        # ── Phase 1: HTTP-only scanning ───────────────────────────────────────────
        pending_browser_jobs: list[PendingBrowserVerification] = []

        async def verify_candidate(
            cand: tuple,
        ) -> tuple[list[Finding], list[PendingBrowserVerification]]:
            if len(cand) == 5:
                cand_url, param, method, val, form_inputs = cand
            else:
                cand_url, param, method, val = cand
                form_inputs = None

            verifier = XSSVerifier()
            verifier.http_verifier.cookies = session_cookies
            try:
                result = await verifier.verify(
                    cand_url, param, method, val,
                    form_inputs=form_inputs,
                    stored_display_urls=stored_probe_urls,
                    stored_baselines=shared_baselines,
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

        queue: asyncio.Queue[tuple] = asyncio.Queue()
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
            try:
                for job in pending_browser_jobs:
                    browser_findings = await browser_verifier.run_browser_verification(job)
                    findings.extend(browser_findings)
            finally:
                await browser_verifier.close()

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

    def _build_header_candidates(self, urls: list[str]) -> list[tuple]:
        """
        Build 4-tuple candidates for header-based XSS testing.

        The ``method`` slot is set to ``"HEADER:<header-name>"`` so that
        XSSVerifier can route them to the header-injection code path without
        any change to the 4-tuple contract used everywhere else.
        """
        seen: set[str] = set()
        candidates: list[tuple] = []
        for url in urls:
            base = url.split("?")[0]
            if base in seen:
                continue
            seen.add(base)
            for header in self._injectable_headers:
                candidates.append((base, header, f"HEADER:{header}", ""))
        return candidates
