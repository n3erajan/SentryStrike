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
        verifier.set_request_context(module="csrf")
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
            
            # Phase 3: Setup routes
            setup_tokens = {"setup", "install", "wizard", "onboarding"}
            is_setup_route = any(tok in url_path_lower for tok in setup_tokens)

            
            if form_method == "POST" or is_state_changing:
                form_candidates.append((form_url, form_method, raw_inputs, is_setup_route))

        async def verify_csrf(candidate) -> list[Finding]:
            form_url, method, raw_inputs, is_setup_route = candidate
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
                    inputs_payload[inp_name] = "sentry_password123"
                elif inp_type == "submit" or inp_type == "button":
                    inputs_payload[inp_name] = getattr(inp, "value", "Submit") or "Submit"
                else:
                    inputs_payload[inp_name] = "sentry_test_val"

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

                    response = await verifier.send_request(
                        injected_url, method, injected_params, injected_data, test_phase="token_tamper"
                    )

                    # Phase 3: Add optional Origin/Referer bypass test
                    bypass_headers = {
                        "Origin": "https://evil.example",
                        "Referer": "https://evil.example/malicious"
                    }
                    # Send bypass request if the original request succeeded (to minimize requests), 
                    # but we can also just send it and check its success.
                    bypass_response = await verifier.send_request(
                        injected_url, method, injected_params, injected_data,
                        headers=bypass_headers, test_phase="origin_bypass",
                    )

                    # Criteria for CSRF vulnerability:
                    # 1. HTTP 200 or 302 redirect (success indicator)
                    # 2. Response body doesn't contain a clear CSRF/token validation error
                    response_to_check = bypass_response if bypass_response.status_code in [200, 302, 303] else response

                    if response_to_check.status_code in [200, 302, 303]:
                        body_lower = response_to_check.body.lower()
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
                            
                            # Phase 3: SameSite and Exploitation Context
                            samesite_attr = None
                            for resp in [response, bypass_response]:
                                set_cookie_headers = [v for k, v in resp.headers.items() if k.lower() == "set-cookie"]
                                for header in set_cookie_headers:
                                    cookie_parts = [p.strip().lower() for p in header.split(";")]
                                    cookie_name = cookie_parts[0].split("=")[0] if "=" in cookie_parts[0] else ""
                                    if cookie_name in session_cookies or any(tok in cookie_name for tok in ["session", "token", "sess"]):
                                        for p in cookie_parts:
                                            if p.startswith("samesite"):
                                                samesite_attr = p.split("=")[1] if "=" in p else "strict"

                            severity = SeverityLevel.low # CVSS profile alignment
                            if samesite_attr == "strict":
                                evidence_msg += " (Note: SameSite=Strict provides partial mitigation)."
                            elif samesite_attr == "lax" and method == "GET":
                                evidence_msg += " (Note: SameSite=Lax provides mitigation for safe HTTP methods)."
                            elif samesite_attr == "lax" and method == "POST":
                                severity = SeverityLevel.medium
                                evidence_msg += " (Note: SameSite=Lax mitigates some cross-site POSTs in modern browsers)."
                            else:
                                if bypass_response.status_code in [200, 302, 303] and not is_setup_route:
                                    severity = SeverityLevel.high
                                elif is_setup_route:
                                    evidence_msg += " (Downgraded: Setup/onboarding route)."
                                    severity = SeverityLevel.low
                                else:
                                    severity = SeverityLevel.medium

                            if bypass_response.status_code in [200, 302, 303]:
                                evidence_msg += " Exploit succeeded even with foreign Origin/Referer."

                            cand_findings.append(
                                Finding(
                                    category=OwaspCategory.a07,
                                    vuln_type="Cross-Site Request Forgery (CSRF)",
                                    severity=severity,
                                    url=form_url,
                                    parameter=csrf_param or "missing_token",
                                    method=method,
                                    evidence=evidence_msg,
                                    confidence_score=90.0,
                                    detection_method="token_bypass",
                                    reproducible=True,
                                    verified=True,
                                    verification_request_snippet=response_to_check.request_snippet,
                                    verification_response_snippet=response_to_check.response_snippet,
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
