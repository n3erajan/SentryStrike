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

        # BUG 1 FIX: Use a list + seen set instead of a bare set().
        # The original code used set() for deduplication, but form candidates
        # are 5-tuples whose 5th element is a list (raw_inputs). Lists are not
        # hashable, so every form candidate raised TypeError: unhashable type:
        # 'list' and was silently dropped, meaning forms were never tested.
        candidates: list[tuple] = []
        seen_keys: set[tuple] = set()  # hashable dedup key: (url, param, method)

        def _add_candidate(*args) -> None:
            """Add a candidate only if (url, param, method) not already seen."""
            key = (args[0], args[1], args[2])  # url, param, method
            if key not in seen_keys:
                seen_keys.add(key)
                candidates.append(args)

        # ------------------------------------------------------------------ #
        # 1. URL Parameter Candidate Selection
        #    Picks up params that already appear in crawled URLs with query
        #    strings (e.g. /search?q=foo captured during crawl).
        # ------------------------------------------------------------------ #
        for url in urls:
            parsed = urlparse(url)
            query_params = parse_qsl(parsed.query, keep_blank_values=True)
            for param_name, param_value in query_params:
                param_lower = param_name.lower()
                if (
                    param_lower in self.reflective_param_names
                    or any(tok in param_lower for tok in self._reflective_tokens)
                ):
                    _add_candidate(url, param_name, "GET", param_value)

        # ------------------------------------------------------------------ #
        # 2. Form Input Candidate Selection
        #    BUG 2 FIX: GET forms are now also added as URL parameter
        #    candidates instead of only as form-POST candidates.
        #    Previously, GET forms (e.g. DVWA /xss_r/?name=) would only
        #    appear in the URL list if the crawler had already submitted them
        #    and recorded the resulting URL with the query string. That rarely
        #    happens, so GET form inputs were effectively invisible.
        # ------------------------------------------------------------------ #
        for form in forms:
            form_url = getattr(form, "action", getattr(form, "page_url", ""))
            form_method = getattr(form, "method", "POST").upper()
            raw_inputs = list(getattr(form, "inputs", []))

            for inp in raw_inputs:
                inp_name = getattr(inp, "name", "")
                inp_type = getattr(inp, "input_type", "text").lower()

                if not inp_name:
                    continue

                is_testable_type = inp_type in {
                    "text", "search", "url", "email", "textarea",
                    "tel", "hidden", "",
                }
                has_xss_prefix = inp_name.lower()[:3] in self._form_input_prefixes

                if not (is_testable_type or has_xss_prefix):
                    continue

                if form_method == "GET":
                    # BUG 2 FIX: Treat GET form fields as URL query parameters.
                    # Inject directly into the URL query string — no form_inputs
                    # needed because GET params are self-contained.
                    _add_candidate(form_url, inp_name, "GET", "")
                else:
                    # POST form: pass the full raw_inputs list so the verifier
                    # can reconstruct the complete form body.
                    # BUG 1 FIX: raw_inputs is stored in a list-based candidate
                    # tuple, not in a set, so the unhashable-list crash is gone.
                    _add_candidate(form_url, inp_name, form_method, "", raw_inputs)

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