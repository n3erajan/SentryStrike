import asyncio
import logging
from urllib.parse import parse_qsl, urlparse

from app.core.detectors.base_detector import BaseDetector, Finding
from app.core.verification.command_verifier import CommandInjectionVerifier
from app.models.vulnerability import OwaspCategory

logger = logging.getLogger(__name__)


class CommandInjectionDetector(BaseDetector):
    name = "command_injection"

    cmd_param_tokens = {
        "ip", "host", "cmd", "exec", "ping", "command", "run", "args", "query", "target", "addr", "address"
    }

    async def detect(self, urls: list[str], forms: list[object], **kwargs: object) -> list[Finding]:
        findings: list[Finding] = []
        session_cookies = kwargs.get("session_cookies") or {}

        # 1. Candidate extraction
        candidates = set()
        
        # URL Parameters
        for url in urls:
            parsed = urlparse(url)
            query_params = parse_qsl(parsed.query, keep_blank_values=True)
            for param_name, param_value in query_params:
                param_lower = param_name.lower()
                if param_lower in self.cmd_param_tokens or any(token in param_lower for token in ["cmd", "command", "exec"]):
                    candidates.add((url, param_name, "GET", param_value))

        # Form Inputs
        for form in forms:
            form_url = getattr(form, "action", getattr(form, "page_url", ""))
            form_method = getattr(form, "method", "POST").upper()
            raw_inputs = list(getattr(form, "inputs", []))
            for inp in raw_inputs:
                inp_name = getattr(inp, "name", "")
                inp_type = getattr(inp, "input_type", "text").lower()
                if inp_name:
                    inp_name_lower = inp_name.lower()
                    if inp_name_lower in self.cmd_param_tokens or inp_type in {"text"}:
                        candidates.add((form_url, inp_name, form_method, ""))

        if not candidates:
            return []

        # 2. Active Verification
        semaphore = asyncio.Semaphore(4)
        verifier = CommandInjectionVerifier(timeout_seconds=10.0)
        # Apply session cookies
        verifier.http_verifier.cookies = session_cookies

        async def verify_candidate(cand) -> list[Finding]:
            cand_url, param, method, val = cand
            async with semaphore:
                try:
                    result = await verifier.verify(cand_url, param, method, val)
                    if result.is_vulnerable:
                        return result.findings
                except Exception as e:
                    logger.error("Command injection verification failed for %s param %s: %s", cand_url, param, e)
                return []

        tasks = [verify_candidate(c) for c in candidates]
        results = await asyncio.gather(*tasks)
        for res in results:
            findings.extend(res)

        await verifier.close()
        return findings
