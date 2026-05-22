import asyncio
import logging
from urllib.parse import parse_qsl, urlparse

from app.core.detectors.base_detector import BaseDetector, Finding
from app.core.verification.xss_verifier import XSSVerifier
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

    async def detect(self, urls: list[str], forms: list[object], **kwargs: object) -> list[Finding]:
        findings: list[Finding] = []
        session_cookies = kwargs.get("session_cookies") or {}

        # BUG 3 FIX: Warn early if session cookies are missing.
        # Authenticated apps redirect to login without cookies, so payloads
        # never appear in the response body and all candidates will silently
        # produce zero findings.
        if not session_cookies:
            logger.warning(
                "XSSDetector: no session_cookies provided. Requests to "
                "authenticated endpoints will be redirected to login and "
                "XSS payloads will never be reflected. Pass session_cookies "
                "via kwargs to enable authenticated scanning."
            )

        from app.core.crawler.param_discovery import ParamDiscovery

        def xss_filter(param_name: str) -> bool:
            param_lower = param_name.lower()
            is_reflective = (
                param_lower in self.reflective_param_names
                or any(tok in param_lower for tok in self._reflective_tokens)
            )
            has_xss_prefix = param_lower[:3] in self._form_input_prefixes
            return is_reflective or has_xss_prefix

        candidates = ParamDiscovery.build_candidates(
            urls, forms, filter_fn=xss_filter
        )

        if not candidates:
            logger.debug("XSSDetector: no testable candidates found across %d URLs and %d forms.", len(urls), len(forms))
            return []

        logger.debug("XSSDetector: testing %d candidates.", len(candidates))

        # ------------------------------------------------------------------ #
        # 3. Active Verification
        # ------------------------------------------------------------------ #
        semaphore = asyncio.Semaphore(4)
        verifier = XSSVerifier()
        verifier.http_verifier.cookies = session_cookies

        async def verify_candidate(cand: tuple) -> list[Finding]:
            # Unpack — 5-tuple means POST form candidate (has raw_inputs),
            # 4-tuple means GET/URL candidate (no form_inputs needed).
            if len(cand) == 5:
                cand_url, param, method, val, form_inputs = cand
            else:
                cand_url, param, method, val = cand
                form_inputs = None

            async with semaphore:
                try:
                    result = await verifier.verify(
                        cand_url, param, method, val, form_inputs=form_inputs
                    )
                    if result.is_vulnerable:
                        return result.findings
                except Exception as e:
                    logger.error(
                        "XSS verification failed for %s param %s: %s",
                        cand_url, param, e,
                    )
                return []

        tasks = [verify_candidate(c) for c in candidates]
        results = await asyncio.gather(*tasks)
        for res in results:
            findings.extend(res)

        await verifier.close()
        return findings