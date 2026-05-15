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

        # Deduplicate candidates to avoid redundant testing
        candidates = set()
        
        # 1. URL Parameter Candidate Selection
        for url in urls:
            parsed = urlparse(url)
            query_params = parse_qsl(parsed.query, keep_blank_values=True)
            for param_name, param_value in query_params:
                param_lower = param_name.lower()
                if param_lower in self.reflective_param_names or any(tok in param_lower for tok in self._reflective_tokens):
                    candidates.add((url, param_name, "GET", param_value))

        # 2. Form Input Candidate Selection
        for form in forms:
            form_url = getattr(form, "action", getattr(form, "page_url", ""))
            form_method = getattr(form, "method", "POST").upper()
            raw_inputs = list(getattr(form, "inputs", []))
            for inp in raw_inputs:
                inp_name = getattr(inp, "name", "")
                inp_type = getattr(inp, "input_type", "text").lower()
                if inp_name and (
                    inp_type in {"text", "search", "url", "email", "textarea", "tel", "hidden", ""}
                    or inp_name.lower()[:3] in self._form_input_prefixes
                ):
                    candidates.add((form_url, inp_name, form_method, "", raw_inputs))

        if not candidates:
            return []

        # 3. Active Verification
        # Using a semaphore to manage concurrency and rate limit active scanning
        semaphore = asyncio.Semaphore(4)
        verifier = XSSVerifier()
        verifier.http_verifier.cookies = session_cookies

        async def verify_candidate(cand) -> list[Finding]:
            form_inputs = None
            if len(cand) == 5:
                cand_url, param, method, val, form_inputs = cand
            else:
                cand_url, param, method, val = cand
            async with semaphore:
                try:
                    result = await verifier.verify(cand_url, param, method, val, form_inputs=form_inputs)
                    if result.is_vulnerable:
                        return result.findings
                except Exception as e:
                    logger.error("XSS verification failed for %s param %s: %s", cand_url, param, e)
                return []

        tasks = [verify_candidate(c) for c in candidates]
        results = await asyncio.gather(*tasks)
        for res in results:
            findings.extend(res)

        await verifier.close()
        return findings