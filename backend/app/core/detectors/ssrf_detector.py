import asyncio
import logging
from urllib.parse import parse_qsl, urlparse

from app.core.detectors.base_detector import BaseDetector, Finding
from app.core.verification.verification_framework import HttpVerifier, URLParameterBuilder
from app.models.vulnerability import OwaspCategory, SeverityLevel

logger = logging.getLogger(__name__)


class SSRFDetector(BaseDetector):
    name = "ssrf"

    ssrf_param_tokens = {
        "url", "link", "src", "dest", "redirect", "fetch", "load", "uri", "path", "domain", "host", "proxy", "site"
    }

    # SSRF verification payloads
    SSRF_PAYLOADS = [
        ("http://127.0.0.1:80/", r"Sentry Strike|Apache|nginx|IIS|html|doctype", "Localhost HTTP fetch"),
        ("http://169.254.169.254/latest/meta-data/", r"ami-id|instance-id|security-groups", "AWS/Cloud Metadata fetch"),
    ]

    async def detect(self, urls: list[str], forms: list[object], **kwargs: object) -> list[Finding]:
        findings: list[Finding] = []
        session_cookies = kwargs.get("session_cookies") or {}

        # 1. Candidate extraction
        candidates = set()

        for url in urls:
            parsed = urlparse(url)
            query_params = parse_qsl(parsed.query, keep_blank_values=True)
            for param_name, param_value in query_params:
                param_lower = param_name.lower()
                if param_lower in self.ssrf_param_tokens or any(tok in param_lower for tok in ["url", "link", "redirect"]):
                    candidates.add((url, param_name, "GET", param_value))

        for form in forms:
            form_url = getattr(form, "action", getattr(form, "page_url", ""))
            form_method = getattr(form, "method", "POST").upper()
            raw_inputs = list(getattr(form, "inputs", []))
            for inp in raw_inputs:
                inp_name = getattr(inp, "name", "")
                if inp_name:
                    inp_name_lower = inp_name.lower()
                    if inp_name_lower in self.ssrf_param_tokens or any(tok in inp_name_lower for tok in ["url", "link"]):
                        candidates.add((form_url, inp_name, form_method, ""))

        if not candidates:
            return []

        # 2. Active Verification
        semaphore = asyncio.Semaphore(4)
        verifier = HttpVerifier(cookies=session_cookies)
        verifier.set_request_context(module="ssrf")

        async def verify_candidate(cand) -> list[Finding]:
            cand_url, param, method, val = cand
            cand_findings = []

            async with semaphore:
                verifier.set_request_context(parameter=param)
                try:
                    # Retrieve baseline first
                    baseline_url, baseline_params, baseline_data = URLParameterBuilder.inject_parameter(
                        cand_url, param, val, method
                    )
                    baseline = await verifier.send_request(
                        baseline_url, method, baseline_params, baseline_data, test_phase="baseline"
                    )

                    for payload, regex_pattern, desc in self.SSRF_PAYLOADS:
                        # Make sure baseline doesn't already trigger the signature
                        if baseline.status_code == 200 and re.search(regex_pattern, baseline.body, re.I):
                            continue

                        injected_url, injected_params, injected_data = URLParameterBuilder.inject_parameter(
                            cand_url, param, payload, method
                        )
                        injected = await verifier.send_request(
                            injected_url, method, injected_params, injected_data,
                            test_phase="ssrf_injection", payload=payload,
                        )

                        # Check if internal content successfully loaded into the response
                        if injected.status_code == 200 and re.search(regex_pattern, injected.body, re.I):
                            cand_findings.append(
                                Finding(
                                    category=OwaspCategory.a10,
                                    vuln_type="Server-Side Request Forgery (SSRF)",
                                    severity=SeverityLevel.high,
                                    url=cand_url,
                                    parameter=param,
                                    method=method,
                                    payload=payload,
                                    evidence=f"SSRF verified via payload '{payload}' ({desc}). Response contains internal host signature.",
                                    confidence_score=95.0,
                                    detection_method="ssrf_reflection",
                                    reproducible=True,
                                    verified=True,
                                    verification_request_snippet=injected.request_snippet,
                                    verification_response_snippet=injected.response_snippet,
                                )
                            )
                            break
                except Exception as e:
                    logger.error("SSRF verification failed for %s param %s: %s", cand_url, param, e)
            return cand_findings

        # Import re dynamically to support clean execution
        import re

        tasks = [verify_candidate(c) for c in candidates]
        results = await asyncio.gather(*tasks)
        for res in results:
            findings.extend(res)

        await verifier.close()
        return findings
