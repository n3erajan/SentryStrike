import asyncio
import logging
import re

from app.core.detectors.base_detector import BaseDetector, Finding
from app.core.detectors.attack_surface import AttackSurface, AttackTarget, build_json_body
from app.core.crawler.models import ParameterLocation
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

        def ssrf_filter(param_name: str) -> bool:
            param_lower = param_name.lower()
            return param_lower in self.ssrf_param_tokens or any(
                tok in param_lower for tok in ["url", "link", "redirect"]
            )

        candidates = AttackSurface.build(
            urls,
            forms,
            parameters=kwargs.get("parameters") or [],
            api_endpoints=kwargs.get("api_endpoints") or [],
            requests=kwargs.get("requests") or [],
            filter_fn=ssrf_filter,
        )

        if not candidates:
            return []

        # 2. Active Verification
        semaphore = asyncio.Semaphore(4)
        verifier = HttpVerifier(cookies=session_cookies)
        verifier.set_request_context(module="ssrf")

        def build_request(cand: AttackTarget, value: str):
            if cand.location in {ParameterLocation.json_body, ParameterLocation.graphql_variable}:
                return cand.url, None, None, build_json_body(cand.json_template, cand, value), cand.headers
            request_url, params, data = URLParameterBuilder.inject_parameter(
                cand.url, cand.parameter, value, cand.method, cand.form_inputs
            )
            return request_url, params, data, None, None

        async def verify_candidate(cand: AttackTarget) -> list[Finding]:
            cand_findings = []

            async with semaphore:
                verifier.set_request_context(parameter=cand.parameter)
                try:
                    # Retrieve baseline first
                    baseline_url, baseline_params, baseline_data, baseline_json, baseline_headers = build_request(
                        cand, str(cand.value or "")
                    )
                    baseline = await verifier.send_request(
                        baseline_url,
                        cand.method,
                        baseline_params,
                        baseline_data,
                        headers=baseline_headers,
                        json_body=baseline_json,
                        test_phase="baseline",
                    )

                    for payload, regex_pattern, desc in self.SSRF_PAYLOADS:
                        # Make sure baseline doesn't already trigger the signature
                        if baseline.status_code == 200 and re.search(regex_pattern, baseline.body, re.I):
                            continue

                        injected_url, injected_params, injected_data, injected_json, injected_headers = build_request(
                            cand, payload
                        )
                        injected = await verifier.send_request(
                            injected_url,
                            cand.method,
                            injected_params,
                            injected_data,
                            headers=injected_headers,
                            json_body=injected_json,
                            test_phase="ssrf_injection", payload=payload,
                        )

                        # Check if internal content successfully loaded into the response
                        if injected.status_code == 200 and re.search(regex_pattern, injected.body, re.I):
                            cand_findings.append(
                                Finding(
                                    category=OwaspCategory.a01,
                                    vuln_type="Server-Side Request Forgery (SSRF)",
                                    severity=SeverityLevel.high,
                                    url=cand.url,
                                    parameter=cand.parameter,
                                    method=cand.method,
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
                    logger.error("SSRF verification failed for %s param %s: %s", cand.url, cand.parameter, e)
            return cand_findings

        tasks = [verify_candidate(c) for c in candidates]
        results = await asyncio.gather(*tasks)
        for res in results:
            findings.extend(res)

        await verifier.close()
        return findings
