import asyncio
import logging
from urllib.parse import parse_qsl, urlparse

from app.core.detectors.base_detector import BaseDetector, Finding
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
        "record", "record_id", "doc", "file", "item", "profile", "uid",
    }

    async def detect(self, urls: list[str], forms: list[object], **kwargs: object) -> list[Finding]:
        findings: list[Finding] = []
        session_cookies = kwargs.get("session_cookies") or {}

        # 1. Instantiate verifiers
        # Authed client (using session cookies)
        authed_verifier = HttpVerifier(cookies=session_cookies)
        # Unauthed client (to check access control bypasses)
        unauthed_verifier = HttpVerifier()

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
                resp = await unauthed_verifier.send_request(test_url, "GET")
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
                    idor_candidates.add((url, param_name, "GET", param_value))

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
            
            # Manipulate ID value (increment numeric, or swap common IDs)
            try:
                num_val = int(val)
                modified_val = str(num_val + 1)
            except ValueError:
                modified_val = "2" if val == "1" else "1"

            async with semaphore:
                try:
                    from app.core.verification.verification_framework import URLParameterBuilder
                    
                    # A. Query with authentication to check if resource exists
                    base_url, base_params, base_data = URLParameterBuilder.inject_parameter(cand_url, param, val, method)
                    authed_resp = await authed_verifier.send_request(base_url, method, base_params, base_data)
                    
                    if authed_resp.status_code != 200:
                        return []

                    # B. Query unauthenticated to see if access control is broken
                    unauth_url, unauth_params, unauth_data = URLParameterBuilder.inject_parameter(cand_url, param, val, method)
                    unauth_resp = await unauthed_verifier.send_request(unauth_url, method, unauth_params, unauth_data)
                    
                    if unauth_resp.status_code == 200:
                        body_lower = unauth_resp.body.lower()
                        # Make sure it's not a generic login/auth redirect returning a 200
                        if not ("login" in body_lower and ("password" in body_lower or "username" in body_lower)):
                            cand_findings.append(
                                Finding(
                                    category=OwaspCategory.a01,
                                    vuln_type="Insecure Direct Object Reference (IDOR)",
                                    severity=SeverityLevel.high,
                                    url=cand_url,
                                    parameter=param,
                                    method=method,
                                    payload=val,
                                    evidence=f"Object reference parameter '{param}' is accessible without authentication.",
                                    verified=True,
                                    verification_request_snippet=unauth_resp.request_snippet,
                                    verification_response_snippet=unauth_resp.response_snippet,
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
