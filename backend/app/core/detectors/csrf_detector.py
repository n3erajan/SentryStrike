import asyncio
import logging
from urllib.parse import parse_qsl, urlparse

from app.core.detectors.base_detector import BaseDetector, Finding
from app.core.verification.verification_framework import HttpVerifier, URLParameterBuilder
from app.models.vulnerability import OwaspCategory, SeverityLevel

logger = logging.getLogger(__name__)


class CSRFDetector(BaseDetector):
    name = "csrf"

    csrf_keywords = {"token", "csrf", "xsrf", "user_token", "session_token"}
    state_changing_actions = {"password", "update", "change", "profile", "user", "admin", "delete", "add", "create", "settings", "save"}
    login_indicators = {"login", "signin", "sign-in", "authenticate", "auth", "session"}

    async def detect(self, urls: list[str], forms: list[object], **kwargs: object) -> list[Finding]:
        findings: list[Finding] = []
        session_cookies = kwargs.get("session_cookies") or {}

        if not session_cookies:
            # CSRF active verification requires session state to determine if actions successfully change state
            return []

        # Authed client to perform actions
        verifier = HttpVerifier(cookies=session_cookies)
        semaphore = asyncio.Semaphore(4)

        # Detect candidate forms
        form_candidates = []
        for form in forms:
            form_url = getattr(form, "action", getattr(form, "page_url", ""))
            form_method = getattr(form, "method", "POST").upper()
            raw_inputs = list(getattr(form, "inputs", []))
            input_names_lower = {getattr(inp, "name", "").lower() for inp in raw_inputs}
            
            # Check if form controls state-changing action
            url_path_lower = urlparse(form_url).path.lower()
            is_state_changing = any(kw in url_path_lower for kw in self.state_changing_actions)

            # Skip login/auth forms (handled by auth detector)
            if any(tok in url_path_lower for tok in self.login_indicators):
                continue
            if "password" in input_names_lower and (
                "username" in input_names_lower or "email" in input_names_lower
            ):
                continue
            
            if form_method == "POST" or is_state_changing:
                form_candidates.append((form_url, form_method, raw_inputs))

        async def verify_csrf(candidate) -> list[Finding]:
            form_url, method, raw_inputs = candidate
            cand_findings = []

            # Identify if a CSRF token parameter exists
            csrf_param = None
            inputs_payload = {}
            for inp in raw_inputs:
                inp_name = getattr(inp, "name", "")
                inp_type = getattr(inp, "input_type", "text").lower()
                if not inp_name:
                    continue
                # Set dummy/default value for other inputs
                if inp_type == "password":
                    inputs_payload[inp_name] = "sntry_password123"
                elif inp_type == "submit" or inp_type == "button":
                    inputs_payload[inp_name] = getattr(inp, "value", "Submit") or "Submit"
                else:
                    inputs_payload[inp_name] = "sntry_test_val"

                if inp_name.lower() in self.csrf_keywords:
                    csrf_param = inp_name

            # If no CSRF token is present on a POST form at all, it's heuristically vulnerable,
            # but we can verify it by submitting the form and looking if it processes (returns 200/302).
            # If a token IS present, we verify by removing/tampering with it and checking if the server still accepts it!
            async with semaphore:
                try:
                    # Build request without the token or with modified token
                    test_payload = inputs_payload.copy()
                    if csrf_param:
                        # Tamper with the token
                        test_payload[csrf_param] = "invalid_token_xyz"
                    
                    # Submit the form
                    injected_url, injected_params, injected_data = URLParameterBuilder.inject_parameter(
                        form_url, csrf_param or "dummy", "tampered", method
                    )
                    
                    # Overwrite injected data with complete form payload
                    if method == "POST":
                        injected_data = test_payload
                    else:
                        injected_params = test_payload

                    response = await verifier.send_request(injected_url, method, injected_params, injected_data)

                    # Criteria for CSRF vulnerability:
                    # 1. HTTP 200 or 302 redirect (success indicator)
                    # 2. Response body doesn't contain a clear CSRF/token validation error (like "CSRF token invalid", "Forbidden", etc.)
                    if response.status_code in [200, 302, 303]:
                        body_lower = response.body.lower()
                        error_terms = [
                            "csrf token", "invalid token", "csrf validation failed",
                            "unauthorized request", "token mismatch", "forbidden",
                            "access denied", "request verification", "invalid request",
                            "security token", "form token",
                        ]
                        if not any(term in body_lower for term in error_terms):
                            evidence_msg = "Form submitted successfully with a tampered/missing CSRF token."
                            if csrf_param:
                                evidence_msg = f"Form contains CSRF token parameter '{csrf_param}', but successfully accepted submission when it was tampered with."
                            
                            cand_findings.append(
                                Finding(
                                    category=OwaspCategory.a01,
                                    vuln_type="Cross-Site Request Forgery (CSRF)",
                                    severity=SeverityLevel.high,
                                    url=form_url,
                                    parameter=csrf_param or "missing_token",
                                    method=method,
                                    evidence=evidence_msg,
                                    confidence_score=90.0,
                                    detection_method="token_bypass",
                                    reproducible=True,
                                    verified=True,
                                    verification_request_snippet=response.request_snippet,
                                    verification_response_snippet=response.response_snippet,
                                )
                            )
                except Exception as e:
                    logger.error("CSRF verification failed for %s: %s", form_url, e)
            return cand_findings

        tasks = [verify_csrf(c) for c in form_candidates]
        results = await asyncio.gather(*tasks)
        for res in results:
            findings.extend(res)

        await verifier.close()
        return findings
