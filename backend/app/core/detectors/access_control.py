import asyncio
import logging
import re
from urllib.parse import parse_qsl, urlparse

from app.core.detectors.base_detector import BaseDetector, Finding
from app.core.verification.response_analyzer import ResponseAnalyzer
from app.core.verification.verification_framework import HttpVerifier
from app.models.vulnerability import OwaspCategory, SeverityLevel

logger = logging.getLogger(__name__)


class AccessControlDetector(BaseDetector):
    name = "access_control"

    sensitive_path_tokens = {
        "admin", "manage", "internal", "debug", "private", "config", "settings",
        "backup", "console", "panel", "restricted", "staff", "db", "database",
    }

    idor_param_tokens = {
        "id", "user", "user_id", "account", "account_id", "order", "order_id",
        "record", "record_id", "profile", "uid",
    }

    NON_ID_VALUES = {"on", "off", "true", "false", "yes", "no"}
    IDOR_VALUE_PATTERN = re.compile(
        r"^(\d+|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[a-zA-Z0-9]{1,8})$"
    )

    async def detect(self, urls: list[str], forms: list[object], **kwargs: object) -> list[Finding]:
        findings: list[Finding] = []
        session_cookies = kwargs.get("session_cookies") or {}

        # 1. Instantiate verifiers
        # Authed client (using session cookies)
        authed_verifier = HttpVerifier(cookies=session_cookies)
        authed_verifier.set_request_context(module="access_control")
        # Unauthed client (to check access control bypasses)
        unauthed_verifier = HttpVerifier()
        unauthed_verifier.set_request_context(module="access_control")

        # 2. Forced Browsing / Sensitive Directory Exposure Verification
        paths_to_test = set()
        for url in urls:
            parsed = urlparse(url)
            path_tokens = {segment.lower() for segment in parsed.path.split("/") if segment}
            if path_tokens.intersection(self.sensitive_path_tokens):
                test_url = parsed.scheme + "://" + parsed.netloc + parsed.path
                paths_to_test.add(test_url)

        for test_url in paths_to_test:
            try:
                # Try accessing unauthenticated
                resp = await unauthed_verifier.send_request(test_url, "GET", test_phase="forced_browsing")
                if resp.status_code == 200:
                    body_lower = resp.body.lower()
                    # Skip if it is actually just a login redirect rendering the login page
                    if "login" in body_lower and ("password" in body_lower or "username" in body_lower):
                        continue

                    findings.append(
                        Finding(
                            category=OwaspCategory.a01,
                            vuln_type="Forced Browsing / Sensitive Directory Exposure",
                            severity=SeverityLevel.high,
                            url=test_url,
                            evidence="Sensitive directory/file is publicly exposed without authentication.",
                            verified=True,
                            verification_request_snippet=resp.request_snippet,
                            verification_response_snippet=resp.response_snippet,
                            reproducible=True,
                        )
                    )
            except Exception as e:
                logger.error("Forced browsing verification failed for %s: %s", test_url, e)

        # 3. IDOR / Access Control Verification
        idor_candidates = set()
        
        # Collect URL parameter candidates
        for url in urls:
            parsed = urlparse(url)
            query_params = parse_qsl(parsed.query, keep_blank_values=True)
            for param_name, param_value in query_params:
                param_lower = param_name.lower()
                if param_lower in self.idor_param_tokens or any(token in param_lower for token in ["id", "user", "account", "order", "record"]):
                    val = str(param_value or "")
                    if not val:
                        continue
                    if val.lower() in self.NON_ID_VALUES:
                        continue
                    if not self.IDOR_VALUE_PATTERN.match(val):
                        continue
                    idor_candidates.add((url, param_name, "GET", val))

        # Collect Form parameter candidates
        for form in forms:
            form_url = getattr(form, "action", getattr(form, "page_url", ""))
            form_method = getattr(form, "method", "POST").upper()
            raw_inputs = list(getattr(form, "inputs", []))
            for inp in raw_inputs:
                inp_name = getattr(inp, "name", "")
                if inp_name.lower() in self.idor_param_tokens:
                    idor_candidates.add((form_url, inp_name, form_method, "1"))

        if not idor_candidates:
            await authed_verifier.close()
            await unauthed_verifier.close()
            return findings

        # Verification with concurrency control
        semaphore = asyncio.Semaphore(4)

        async def verify_idor_candidate(cand) -> list[Finding]:
                    cand_url, param, method, val = cand
                    cand_findings = []
                    
                    # 1. Calculate a modified ID to test horizontal privilege escalation
                    try:
                        num_val = int(val)
                        modified_val = str(num_val + 1)
                    except ValueError:
                        modified_val = "2" if val == "1" else "1"

                    async with semaphore:
                        try:
                            from app.core.verification.verification_framework import URLParameterBuilder
                            
                            # --- STEP 1: Establish Baseline (Is this just a public page?) ---
                            unauth_url, unauth_params, unauth_data = URLParameterBuilder.inject_parameter(cand_url, param, val, method)
                            unauth_resp = await unauthed_verifier.send_request(
                                unauth_url, method, unauth_params, unauth_data, test_phase="idor_unauth_base"
                            )
                            
                            unauth_mod_url, unauth_mod_params, unauth_mod_data = URLParameterBuilder.inject_parameter(cand_url, param, modified_val, method)
                            unauth_mod_resp = await unauthed_verifier.send_request(
                                unauth_mod_url, method, unauth_mod_params, unauth_mod_data, test_phase="idor_unauth_mod"
                            )

                            # If both unauthenticated requests return 200 OK and don't render a login page,
                            # this is an intentionally PUBLIC endpoint (e.g., a public article), NOT an IDOR.
                            if unauth_resp.status_code == 200 and unauth_mod_resp.status_code == 200:
                                body_lower = unauth_resp.body.lower()
                                if not ("login" in body_lower and ("password" in body_lower or "username" in body_lower)):
                                    # Abort to prevent false positives.
                                    return []

                            # --- STEP 2: Test IDOR (Horizontal Escalation) ---
                            # Now we know the endpoint is protected. Let's see if our Authed session 
                            # can access the modified (other user's) ID.
                            authed_verifier.set_request_context(parameter=param)
                            auth_mod_url, auth_mod_params, auth_mod_data = URLParameterBuilder.inject_parameter(cand_url, param, modified_val, method)
                            auth_mod_resp = await authed_verifier.send_request(
                                auth_mod_url, method, auth_mod_params, auth_mod_data, test_phase="idor_authed_mod"
                            )

                            # If the request succeeds (200 OK) instead of being blocked (401/403/Redirect)
                            if auth_mod_resp.status_code == 200:
                                body_lower = auth_mod_resp.body.lower()
                                
                                # Ensure it didn't just quietly redirect us to a 200 OK login/dashboard page
                                if not ("login" in body_lower and ("password" in body_lower or "username" in body_lower)):
                                    cand_findings.append(
                                        Finding(
                                            category=OwaspCategory.a01,
                                            vuln_type="Insecure Direct Object Reference (IDOR)",
                                            severity=SeverityLevel.high,
                                            url=cand_url,
                                            parameter=param,
                                            method=method,
                                            payload=modified_val,
                                            evidence=f"Access control bypass: Object reference '{param}'={modified_val} was accessible by the current session, despite lacking unauthenticated access.",
                                            verified=True,
                                            verification_request_snippet=auth_mod_resp.request_snippet,
                                            verification_response_snippet=auth_mod_resp.response_snippet,
                                            reproducible=True,
                                        )
                                    )
                        except Exception as e:
                            logger.error("IDOR verification failed for %s param %s: %s", cand_url, param, e)
                            
                    return cand_findings

        tasks = [verify_idor_candidate(c) for c in idor_candidates]
        results = await asyncio.gather(*tasks)
        for res in results:
            findings.extend(res)

        await authed_verifier.close()
        await unauthed_verifier.close()
        return findings
