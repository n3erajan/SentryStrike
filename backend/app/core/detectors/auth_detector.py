import asyncio
import base64
import copy
import json
import logging
import re
import statistics
import time
from urllib.parse import parse_qsl, urlparse

from app.config import get_settings
from app.core.detectors.base_detector import BaseDetector, Finding
from app.models.vulnerability import OwaspCategory, SeverityLevel

logger = logging.getLogger(__name__)


class AuthenticationFailuresDetector(BaseDetector):
    name = "authentication_failures"

    # ---------------------------------------------------------------------------
    # URL path / domain token sets
    # ---------------------------------------------------------------------------

    login_tokens = {
        "login", "signin", "sign-in", "sign_in", "logon", "log-in", "log_in",
        "auth", "authenticate", "authentication", "authorize", "authorization",
        "session", "sso", "saml", "oauth", "oidc", "openid",
        "access", "portal", "gateway", "entry", "connect",
    }

    logout_tokens = {
        "logout", "signout", "sign-out", "sign_out", "logoff", "log-out",
        "log_out", "disconnect", "end-session", "endsession",
    }

    reset_tokens = {
        "reset", "forgot", "recover", "recovery",
        "forgot-password", "forgot_password",
        "password-reset", "password_reset", "resetpassword",
        "change-password", "change_password", "changepassword",
        "new-password", "new_password", "set-password", "set_password",
        "update-password", "update_password",
    }

    register_tokens = {
        "register", "registration", "signup", "sign-up", "sign_up",
        "create-account", "create_account", "createaccount",
        "new-account", "new_account", "newaccount",
        "enroll", "enrollment", "join", "onboard", "onboarding",
    }

    admin_tokens = {
        "admin", "administrator", "administration",
        "superuser", "super-user", "super_user",
        "root", "manage", "manager", "management",
        "console", "panel", "dashboard", "cp", "controlpanel",
        "control-panel", "control_panel", "backend", "backoffice",
        "back-office", "back_office", "staff", "ops", "internal",
        "sysadmin", "sys-admin", "sys_admin",
    }

    api_auth_tokens = {
        "api/auth", "api/login", "api/token", "api/session",
        "api/v1/auth", "api/v2/auth", "api/v1/login", "api/v2/login",
        "oauth/token", "oauth2/token", "connect/token",
        "auth/token", "auth/refresh", "auth/revoke",
        "token/refresh", "token/revoke",
    }

    mfa_tokens = {
        "otp", "mfa", "2fa", "totp", "hotp",
        "two-factor", "two_factor", "twofactor",
        "second-factor", "second_factor",
        "verify", "verification", "challenge",
        "authenticator", "security-code", "security_code",
        "backup-code", "backup_code", "recovery-code", "recovery_code",
    }

    # ---------------------------------------------------------------------------
    # Form input credential tokens
    # ---------------------------------------------------------------------------

    credential_tokens = {
        # Usernames
        "username", "user", "user_name", "uname", "login",
        "email", "e_mail", "mail",
        "phone", "mobile", "telephone",
        "account", "account_id", "accountid",
        "member_id", "memberid",
        "employee_id", "employeeid", "staff_id",
        # Passwords
        "password", "pass", "passwd", "pwd", "passcode",
        "passphrase", "secret", "credential",
        "current_password", "old_password", "new_password",
        "confirm_password", "password_confirm",
        # MFA / OTP
        "otp", "mfa", "2fa", "totp", "hotp",
        "code", "auth_code", "verification_code", "security_code",
        "token", "access_token", "auth_token", "session_token",
        "pin", "pincode", "pin_code",
        "backup_code", "recovery_code",
        # SSO / OAuth
        "assertion", "saml_response", "id_token",
        "access_code", "authorization_code",
    }

    # Tokens that indicate a security control is present (lowers false-positive rate)
    _security_control_tokens = {
        "token", "reset_token", "csrf", "code", "nonce",
        "state", "signature", "hmac", "hash", "otp",
    }

    # Sensitive parameter names that should never appear in URLs (GET)
    _sensitive_get_params = {
        "password", "passwd", "pass", "pwd", "secret",
        "token", "access_token", "auth_token", "session_token",
        "api_key", "apikey", "private_key",
        "otp", "code", "pin",
        "ssn", "credit_card", "cvv",
    }

    # Headers / cookies that signal session/auth (for evidence strings)
    _session_cookie_names = {
        "session", "sessionid", "sessid", "sess",
        "auth", "authtoken", "access_token",
        "jwt", "token", "remember_me", "rememberme",
        "asp.net_sessionid", "phpsessid", "jsessionid",
        "cfid", "cftoken",
    }

    _rate_limit_terms = {
        "too many attempts", "too many requests", "rate limit", "rate-limit",
        "throttle", "throttled", "temporarily locked", "account locked",
        "lockout", "try again later", "challenge required",
        "429", "slow down",
        # CAPTCHA challenge indicators (not bare "captcha" - too many false positives from nav menus)
        "g-recaptcha", "h-captcha", "cf-turnstile",
        "captcha required", "captcha verification", "captcha code",
        "captcha challenge", "captcha input",
    }

    # ---------------------------------------------------------------------------
    # Internal helpers
    # ---------------------------------------------------------------------------

    def _path_hits(self, path_tokens: set[str], token_set: set[str]) -> bool:
        return bool(path_tokens.intersection(token_set))

    def _url_contains(self, lowered_url: str, token_set: set[str]) -> bool:
        return any(tok in lowered_url for tok in token_set)

    def _sensitive_query_params(self, query_params: list[tuple[str, str]], lowered_url: str) -> set[str]:
        credential_params = {"password", "passwd", "pass", "pwd", "secret", "api_key", "apikey", "private_key"}
        contextual_params = self._sensitive_get_params - credential_params
        auth_context = self._url_contains(
            lowered_url,
            self.login_tokens
            | self.reset_tokens
            | self.api_auth_tokens
            | self.mfa_tokens
            | {"oauth", "authorize", "callback", "session"},
        )

        leaked: set[str] = set()
        for key, value in query_params:
            key_lower = key.lower()
            value = value or ""
            if key_lower in credential_params and value:
                leaked.add(key_lower)
                continue
            if key_lower not in contextual_params or not value:
                continue
            value_lower = value.lower()
            looks_secret = (
                len(value) >= 16
                or value_lower.count(".") == 2
                or any(ch.isdigit() for ch in value) and any(ch.isalpha() for ch in value) and len(value) >= 8
            )
            if auth_context or looks_secret:
                leaked.add(key_lower)
        return leaked

    def _finding(
        self,
        vuln_type: str,
        url: str,
        evidence: str,
        severity: SeverityLevel,
        method: str | None = None,
        parameter: str | None = None,
        payload: str | None = None,
        verified: bool = False,
        detection_method: str = "heuristic",
        confidence_score: float = 0.0,
        category: OwaspCategory = OwaspCategory.a07,
        verification_request_snippet: str | None = None,
        verification_response_snippet: str | None = None,
        detection_evidence: dict | None = None,
    ) -> Finding:
        kwargs: dict = dict(
            category=category,
            vuln_type=vuln_type,
            severity=severity,
            url=url,
            evidence=evidence,
            verified=verified,
            detection_method=detection_method,
            confidence_score=confidence_score,
            verification_request_snippet=verification_request_snippet,
            verification_response_snippet=verification_response_snippet,
        )
        if detection_evidence is not None:
            kwargs["detection_evidence"] = detection_evidence
        if method is not None:
            kwargs["method"] = method
        if parameter is not None:
            kwargs["parameter"] = parameter
        if payload is not None:
            kwargs["payload"] = payload
        return Finding(**kwargs)

    def _rate_limit_signals_present(self, responses: list[object]) -> bool:
        for response in responses:
            if getattr(response, "status_code", 0) in {401, 403, 423, 429}:
                body_lower = (getattr(response, "body", "") or "").lower()
                if getattr(response, "status_code", 0) in {423, 429}:
                    return True
                if any(term in body_lower for term in self._rate_limit_terms):
                    return True
            body_lower = (getattr(response, "body", "") or "").lower()
            if any(term in body_lower for term in self._rate_limit_terms):
                return True
        return False

    @staticmethod
    def _response_signature(response: object) -> tuple:
        body = getattr(response, "body", "") or ""
        return (
            getattr(response, "status_code", 0),
            len(body),
        )

    def _burst_responses_stable(self, burst_results: list[dict]) -> bool:
        """Return True when burst responses show no server-side protection signal.

        Stability is assessed on two axes that actually indicate a control is
        present:

        1. **Status-code diversity** - any non-2xx code (401, 403, 423, 429,
           302 to a lockout page, etc.) in *any* burst means the server reacted.
        2. **Body-length divergence** - a consistent shift in response size
           (e.g. an error page replacing the login form) is a real signal.

        Timing alone is intentionally *not* used as a stability gate.  A server
        that simply slows down under concurrent load looks identical to one that
        is rate-limiting by delay, and on low-spec targets (like DVWA on a VM)
        the final large burst routinely inflates mean latency by 500-1500 ms
        with no actual protection in place.  Timing *trends* are therefore only
        used as a *supporting* signal when body/status changes are also present,
        not as an independent disqualifier.
        """
        responses = [r for result in burst_results for r in result["responses"]]
        if not responses:
            return False

        # --- 1. Status-code check -------------------------------------------
        # Any response outside the 2xx range is a hard signal that the server
        # reacted (lockout, challenge, redirect to error page).
        for r in responses:
            code = getattr(r, "status_code", 0)
            if not (200 <= code < 300):
                return False

        # --- 2. Body-length stability ----------------------------------------
        # A consistent change in response body size across bursts indicates the
        # server started returning a different page (e.g. lockout notice).
        # We use a per-burst mean rather than a global mean so a single slow
        # request in the last burst doesn't skew the calculation.
        body_lengths = [len(getattr(r, "body", "") or "") for r in responses]
        mean_length = statistics.mean(body_lengths) if body_lengths else 0
        tolerance = max(200, mean_length * 0.15)
        if any(abs(length - mean_length) > tolerance for length in body_lengths):
            return False

        return True

    # ---------------------------------------------------------------------------
    # Main detect method
    # ---------------------------------------------------------------------------

    async def _test_active_auth(self, form_url: str, method: str, raw_inputs: list, session_cookies: dict) -> list[Finding]:
        findings = []
        from app.core.verification.verification_framework import HttpVerifier, URLParameterBuilder

        # Construct credentials payload
        payload = {}
        username_param = None
        password_param = None
        csrf_param = None

        for inp in raw_inputs:
            name = getattr(inp, "name", "")
            inp_type = getattr(inp, "input_type", "text").lower()
            if not name:
                continue
            name_lower = name.lower()
            if "user" in name_lower or "email" in name_lower or ("login" in name_lower and inp_type == "text"):
                username_param = name
                payload[name] = "sentry_invalid_user_xyz"
            elif "pass" in name_lower:
                password_param = name
                payload[name] = "sentry_wrong_password_xyz"
            elif inp_type == "hidden":
                payload[name] = getattr(inp, "value", "")
                if "csrf" in name_lower or "token" in name_lower:
                    csrf_param = name

        if not username_param or not password_param:
            return []

        verifier = HttpVerifier(cookies=session_cookies)
        verifier.set_request_context(module="auth")

        try:
            # Test 1: CSRF on Auth Form
            try:
                csrf_payload = payload.copy()
                if csrf_param:
                    csrf_payload[csrf_param] = "invalid_token_123"

                csrf_url, csrf_params, csrf_data = URLParameterBuilder.inject_parameter(
                    form_url, username_param, "test", method
                )
                if method == "POST":
                    csrf_data = csrf_payload
                else:
                    csrf_params = csrf_payload

                csrf_resp = await verifier.send_request(
                    csrf_url, method, csrf_params, csrf_data,
                    test_phase="csrf_check", parameter=csrf_param or username_param,
                )
                body_lower = csrf_resp.body.lower()
                if csrf_resp.status_code in [200, 302]:
                    if csrf_param and not any(err in body_lower for err in ["csrf", "token invalid", "bad request"]):
                        findings.append(
                            self._finding(
                                vuln_type="Authentication Form Lacks CSRF Protection",
                                url=form_url,
                                method=method,
                                severity=SeverityLevel.high,
                                evidence=f"Authentication form at '{form_url}' accepted login submission even when CSRF token '{csrf_param}' was tampered.",
                                parameter=csrf_param,
                                verified=True,
                                detection_method="csrf_tamper_test",
                                confidence_score=85.0,
                                category=OwaspCategory.a01,
                                verification_request_snippet=csrf_resp.request_snippet,
                                verification_response_snippet=csrf_resp.response_snippet,
                            )
                        )
                    elif not csrf_param:
                        findings.append(
                            self._finding(
                                vuln_type="Authentication Form Lacks CSRF Protection",
                                url=form_url,
                                method=method,
                                severity=SeverityLevel.high,
                                evidence=f"Authentication form at '{form_url}' has no CSRF token parameter, allowing credentials to be submitted without validation.",
                                verified=True,
                                detection_method="csrf_missing_param",
                                confidence_score=80.0,
                                category=OwaspCategory.a01,
                                verification_request_snippet=csrf_resp.request_snippet,
                                verification_response_snippet=csrf_resp.response_snippet,
                            )
                        )
            except Exception as e:
                logger.warning("CSRF test failed for %s: %s", form_url, e)

            # -------------------------------------------------------------------
            # Tests 2 + 3: Combined credential sequence
            #
            # All three auth-volume checks - brute-force protection, credential
            # stuffing, and default credentials - share the same mechanism: send
            # repeated login attempts and observe whether the server blocks.
            # Running them as separate passes was wasteful (105+ requests) because
            # every pass re-proved the same thing with different payloads.
            #
            # The redesign uses ONE sequential request list that serves all three
            # purposes simultaneously:
            #
            #   Phase A - default pairs (varied username + password)
            #             → detects Default Credentials Accepted (critical)
            #             → each failed attempt contributes to the lockout counter
            #
            #   Phase B - stuffing passwords (fixed bogus username, varied password)
            #             → detects No Lockout / Credential-Stuffing weakness (high)
            #             → extends the attempt count for the brute-force check
            #
            # After the sequential pass a small 10-request parallel burst fires to
            # test the concurrency axis (some WAFs rate-limit bursts but not slow
            # sequential traffic). Total requests: ~28 sequential + 10 parallel,
            # vs the previous ~105.
            #
            # The first request (known-bad credentials) doubles as the baseline
            # for default-creds success detection - no extra baseline request.
            #
            # OWASP 2025 mappings:
            #   Brute-force / stuffing → A07 / CWE-307
            #   Default credentials   → A02 + A07 / CWE-1392, CWE-1393
            # -------------------------------------------------------------------
            all_seq_responses: list = []   # every sequential response, in order
            seq_blocked        = False     # True once any protection signal fires
            default_cred_hit: tuple | None = None  # (user, pass, resp) if login succeeded

            # Positive-login indicators present on post-auth pages but not on the
            # wrong-password page.
            _login_success_terms = {
                "logout", "log out", "sign out", "signout",
                "welcome", "dashboard", "profile", "my account",
                "account settings", "logged in", "you are logged",
            }

            # --- Build the combined sequence -----------------------------------
            # Phase A: default pairs (varied username).
            # The very first pair uses the known-bogus username so its response
            # becomes the baseline body length / status for success detection.
            _default_pairs: list[tuple[str, str]] = [
                # bogus first - establishes the failure baseline
                (payload[username_param], payload[password_param]),
                # real default pairs ordered by real-world frequency
                ("admin",         "admin"),
                ("admin",         "password"),
                ("admin",         "admin123"),
                ("admin",         "1234"),
                ("admin",         ""),
                ("root",          "root"),
                ("root",          "password"),
                ("root",          ""),
                ("administrator", "administrator"),
                ("administrator", "password"),
                ("test",          "test"),
                ("guest",         "guest"),
                ("user",          "user"),
                ("demo",          "demo"),
                ("operator",      "operator"),
                ("service",       "service"),
                ("support",       "support"),
                ("manager",       "manager"),
            ]

            # Phase B: stuffing passwords for the fixed bogus username.
            # These extend the sequential attempt count without re-testing default
            # usernames, covering the pure password-spray / stuffing scenario.
            _stuffing_passwords = [
                "password", "password1", "password123", "123456",
                "letmein", "welcome", "monkey", "dragon",
                "qwerty123", "iloveyou",
            ]
            _stuffing_pairs: list[tuple[str, str]] = [
                (payload[username_param], pw) for pw in _stuffing_passwords
            ]

            _combined_pairs = _default_pairs + _stuffing_pairs
            # Index past which attempts use the fixed bogus username (stuffing phase)
            _stuffing_start = len(_default_pairs)

            try:
                baseline_body_len: int = 0
                baseline_status:   int = 0

                for attempt_idx, (cred_user, cred_pass) in enumerate(_combined_pairs):
                    attempt_payload = payload.copy()
                    attempt_payload[username_param] = cred_user
                    attempt_payload[password_param] = cred_pass

                    a_url, a_params, a_data = URLParameterBuilder.inject_parameter(
                        form_url, username_param, cred_user, method
                    )
                    if method == "POST":
                        a_data = attempt_payload
                    else:
                        a_params = attempt_payload

                    phase_label = (
                        "default_creds_probe" if attempt_idx < _stuffing_start
                        else "credential_stuffing"
                    )
                    resp = await verifier.send_request(
                        a_url, method, a_params, a_data,
                        test_phase=phase_label,
                        parameter=username_param,
                        payload=f"{cred_user}:{cred_pass}",
                    )
                    all_seq_responses.append(resp)

                    resp_body     = getattr(resp, "body", "") or ""
                    resp_body_len = len(resp_body)
                    resp_body_low = resp_body.lower()
                    resp_status   = getattr(resp, "status_code", 0)

                    # First request establishes the failure baseline.
                    if attempt_idx == 0:
                        baseline_body_len = resp_body_len
                        baseline_status   = resp_status
                        continue   # skip success/block checks for the baseline itself

                    # --- Default credentials: success detection -----------------
                    if attempt_idx < _stuffing_start and default_cred_hit is None:
                        size_delta  = abs(resp_body_len - baseline_body_len)
                        size_change = size_delta > max(200, baseline_body_len * 0.20)
                        auth_words  = any(t in resp_body_low for t in _login_success_terms)
                        status_shift = (
                            resp_status in {302, 303}
                            and baseline_status not in {302, 303}
                        )
                        if size_change or auth_words or status_shift:
                            default_cred_hit = (cred_user, cred_pass, resp,
                                                size_delta, auth_words,
                                                baseline_status, resp_status)

                    # --- Protection signal: stop the sequence early -------------
                    if resp_status in {401, 403, 423, 429}:
                        seq_blocked = True
                        break
                    if any(term in resp_body_low for term in self._rate_limit_terms):
                        seq_blocked = True
                        break

            except Exception as e:
                logger.warning("Combined credential sequence failed for %s: %s", form_url, e)

            # --- Emit findings from the sequential pass ------------------------
            try:
                total_seq = len(all_seq_responses)

                # Finding A: Default credentials accepted (critical)
                if default_cred_hit is not None:
                    dc_user, dc_pass, dc_resp, size_delta, auth_words, bl_status, dc_status = default_cred_hit
                    findings.append(
                        self._finding(
                            vuln_type="Default Credentials Accepted",
                            url=form_url,
                            method=method,
                            severity=SeverityLevel.critical,
                            parameter=username_param,
                            payload=f"{dc_user}:{dc_pass}",
                            evidence=(
                                f"Login form accepted the default credential pair "
                                f"'{dc_user}' / '{dc_pass}'. "
                                f"Response differed from the known-bad baseline: "
                                f"status {bl_status} → {dc_status}, "
                                f"body size delta {size_delta} bytes"
                                + (", post-auth language detected in body" if auth_words else "") + ". "
                            ),
                            verified=True,
                            detection_method="default_credentials_probe",
                            confidence_score=90.0,
                            verification_request_snippet=dc_resp.request_snippet,
                            verification_response_snippet=dc_resp.response_snippet,
                        )
                    )

                # Findings B + C: only relevant when no protection fired.
                if not seq_blocked and total_seq == len(_combined_pairs):
                    seq_bodies  = [len(getattr(r, "body", "") or "") for r in all_seq_responses]
                    seq_codes   = {getattr(r, "status_code", 0) for r in all_seq_responses}
                    seq_mean    = statistics.mean(seq_bodies) if seq_bodies else 0
                    seq_stable  = (
                        len(seq_codes) == 1
                        and all(abs(l - seq_mean) <= max(200, seq_mean * 0.15) for l in seq_bodies)
                    )

                    if seq_stable:
                        last_seq = all_seq_responses[-1]

                        # Finding B: no lockout against credential stuffing (high)
                        # Only emit if default creds weren't accepted - if they were,
                        # the critical finding already captures the lack of protection.
                        if default_cred_hit is None:
                            stuffing_count = total_seq - _stuffing_start
                            findings.append(
                                self._finding(
                                    vuln_type="No Lockout or Challenge After Sequential Failed Logins (Credential Stuffing)",
                                    url=form_url,
                                    method=method,
                                    severity=SeverityLevel.high,
                                    evidence=(
                                        f"Sent {total_seq} sequential login attempts "
                                        f"({len(_default_pairs) - 1} default-credential pairs + "
                                        f"{stuffing_count} password-spray attempts) with no lockout, "
                                        "rate-limit status code, or CAPTCHA challenge observed. "
                                        "The endpoint does not defend against credential-stuffing "
                                        "or password-spray attacks. "
                                    ),
                                    verified=True,
                                    detection_method="credential_stuffing_probe",
                                    confidence_score=80.0,
                                    verification_request_snippet=last_seq.request_snippet,
                                    verification_response_snippet=last_seq.response_snippet,
                                )
                            )

                        # Finding C: parallel-burst concurrency check (high)
                        # A small concurrent burst tests whether WAF/rate-limiting
                        # treats parallel requests differently from sequential ones.
                        try:
                            burst_semaphore = asyncio.Semaphore(10)

                            async def _burst_req(_idx: int):
                                async with burst_semaphore:
                                    b_url, b_params, b_data = URLParameterBuilder.inject_parameter(
                                        form_url, username_param, payload[username_param], method
                                    )
                                    bp = payload.copy()
                                    if method == "POST":
                                        b_data = bp
                                    else:
                                        b_params = bp
                                    return await verifier.send_request(
                                        b_url, method, b_params, b_data,
                                        test_phase="brute_force_burst",
                                        parameter=username_param,
                                    )

                            burst_responses = list(await asyncio.gather(
                                *[_burst_req(i) for i in range(10)]
                            ))
                            burst_times = [float(getattr(r, "response_time_ms", 0.0) or 0.0)
                                           for r in burst_responses]
                            burst_mean  = statistics.mean(burst_times) if burst_times else 0.0
                            burst_stdev = statistics.pstdev(burst_times) if len(burst_times) > 1 else 0.0
                            burst_blocked = self._rate_limit_signals_present(burst_responses)

                            if not burst_blocked:
                                burst_result = [{
                                    "size": 10, "responses": burst_responses,
                                    "mean_ms": burst_mean, "stdev_ms": burst_stdev,
                                }]
                                if self._burst_responses_stable(burst_result):
                                    findings.append(
                                        self._finding(
                                            vuln_type="Lack of Brute-Force Protection on Login Form",
                                            url=form_url,
                                            method=method,
                                            severity=SeverityLevel.high,
                                            evidence=(
                                                f"10 concurrent login requests returned stable responses "
                                                f"(mean={burst_mean:.0f}ms, stdev={burst_stdev:.0f}ms) "
                                                "with no rate-limit or lockout signal, confirming the "
                                                "endpoint does not throttle parallel authentication attempts. "
                                            ),
                                            verified=True,
                                            detection_method="active_bruteforce_probe",
                                            confidence_score=85.0,
                                            verification_request_snippet=burst_responses[-1].request_snippet,
                                            verification_response_snippet=burst_responses[-1].response_snippet,
                                        )
                                    )
                        except Exception as e:
                            logger.warning("Parallel burst check failed for %s: %s", form_url, e)

            except Exception as e:
                logger.warning("Credential finding evaluation failed for %s: %s", form_url, e)

            # Test 4: CAPTCHA Bypass
            try:
                captcha_param = None
                for inp in raw_inputs:
                    name = getattr(inp, "name", "").lower()
                    if any(tok in name for tok in [
                        "captcha", "recaptcha", "g-recaptcha-response",
                        "h-captcha-response", "cf-turnstile-response",
                        "captcha_token", "captcha_code", "verify_code",
                    ]):
                        captcha_param = getattr(inp, "name", "")
                        break

                if captcha_param:
                    bypass_payload = payload.copy()
                    bypass_payload.pop(captcha_param, None)

                    bypass_url, bypass_params, bypass_data = URLParameterBuilder.inject_parameter(
                        form_url, username_param, "test", method
                    )
                    if method == "POST":
                        bypass_data = bypass_payload
                    else:
                        bypass_params = bypass_payload

                    resp = await verifier.send_request(
                        bypass_url, method, bypass_params, bypass_data, test_phase="captcha_bypass"
                    )
                    body_lower = resp.body.lower()

                    if resp.status_code in [200, 302]:
                        captcha_error_terms = [
                            "captcha", "verification failed", "human verification",
                            "robot", "bot detection", "challenge required",
                        ]
                        if not any(term in body_lower for term in captcha_error_terms):
                            findings.append(
                                self._finding(
                                    vuln_type="CAPTCHA Bypass - Form Accepts Submission Without CAPTCHA",
                                    url=form_url,
                                    method=method,
                                    severity=SeverityLevel.high,
                                    parameter=captcha_param,
                                    evidence=(
                                        f"Form with CAPTCHA field '{captcha_param}' accepted submission "
                                        "when the CAPTCHA value was omitted entirely."
                                    ),
                                    verified=True,
                                    detection_method="captcha_omission_test",
                                    confidence_score=80.0,
                                    verification_request_snippet=resp.request_snippet,
                                    verification_response_snippet=resp.response_snippet,
                                )
                            )
            except Exception as e:
                logger.warning("CAPTCHA bypass test failed for %s: %s", form_url, e)

            # Test 3: Session Cookie Attributes check
            # Reads from all_seq_responses (the combined sequential pass) plus
            # any burst responses collected during the concurrency check.
            try:
                for r in all_seq_responses:
                    set_cookie_headers = [v for k, v in r.headers.items() if k.lower() == "set-cookie"]
                    for header in set_cookie_headers:
                        cookie_parts = [p.strip().lower() for p in header.split(";")]
                        cookie_name = cookie_parts[0].split("=")[0] if "=" in cookie_parts[0] else ""

                        if any(name in cookie_name for name in ["session", "token", "phpsessid", "jsessionid", "jwt"]):
                            missing_attrs = []
                            if "httponly" not in cookie_parts:
                                missing_attrs.append("HttpOnly")
                            if "secure" not in cookie_parts:
                                missing_attrs.append("Secure")
                            if not any(p.startswith("samesite") for p in cookie_parts):
                                missing_attrs.append("SameSite")

                            if missing_attrs:
                                findings.append(
                                    self._finding(
                                        vuln_type="Insecure Session Cookie Attributes",
                                        url=form_url,
                                        severity=SeverityLevel.medium,
                                        evidence=f"Session cookie '{cookie_name}' set in response lacks secure attributes: {', '.join(missing_attrs)}.",
                                        verified=True,
                                        detection_method="cookie_header_inspection",
                                        confidence_score=90.0,
                                        verification_request_snippet=r.request_snippet,
                                        verification_response_snippet=r.response_snippet,
                                    )
                                )
            except Exception as e:
                logger.warning("Session cookie check failed for %s: %s", form_url, e)
        finally:
            await verifier.close()

        return findings

    # ---------------------------------------------------------------------------
    # API-first authentication workflow checks
    # ---------------------------------------------------------------------------

    @staticmethod
    def _json_body(value: object) -> dict | None:
        if isinstance(value, dict):
            return copy.deepcopy(value)
        if not isinstance(value, str) or not value.strip():
            return None
        try:
            parsed = json.loads(value)
        except Exception:
            return None
        return parsed if isinstance(parsed, dict) else None

    @staticmethod
    def _body_paths(body: dict, prefix: str = "") -> list[tuple[str, object]]:
        paths: list[tuple[str, object]] = []
        for key, value in body.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            paths.append((path, value))
            if isinstance(value, dict):
                paths.extend(AuthenticationFailuresDetector._body_paths(value, path))
        return paths

    @staticmethod
    def _set_body_path(body: dict, path: str, value: object) -> None:
        current = body
        parts = path.split(".")
        for part in parts[:-1]:
            next_value = current.get(part)
            if not isinstance(next_value, dict):
                next_value = {}
                current[part] = next_value
            current = next_value
        current[parts[-1]] = value

    def _classify_api_auth_fields(self, body: dict) -> dict[str, str | None]:
        fields: dict[str, str | None] = {
            "username": None,
            "password": None,
            "current_password": None,
            "new_password": None,
            "confirm_password": None,
            "token": None,
            "mfa_code": None,
        }
        for path, _ in self._body_paths(body):
            key = path.rsplit(".", 1)[-1].lower()
            normalized = key.replace("-", "_")
            if fields["username"] is None and normalized in {
                "email", "username", "user", "login", "identifier", "account", "phone", "mobile",
            }:
                fields["username"] = path
            elif fields["password"] is None and normalized in {"password", "pass", "passwd", "pwd"}:
                fields["password"] = path
            elif fields["current_password"] is None and normalized in {
                "current_password", "old_password", "existing_password",
            }:
                fields["current_password"] = path
            elif fields["new_password"] is None and normalized in {
                "new_password", "newpassword", "password_new", "newpass", "new_pass",
            }:
                fields["new_password"] = path
            elif fields["confirm_password"] is None and normalized in {
                "confirm_password", "confirmpassword", "password_confirm", "passwordconfirm",
                "password_confirmation", "confirm",
            }:
                fields["confirm_password"] = path
            elif fields["token"] is None and any(
                token in normalized for token in ("token", "nonce", "state", "signature", "reset")
            ):
                fields["token"] = path
            elif fields["mfa_code"] is None and normalized in {
                "otp", "mfa", "mfa_code", "totp", "code", "verification_code", "security_code",
            }:
                fields["mfa_code"] = path
        return fields

    def _api_records(self, kwargs: dict[str, object]) -> list[dict]:
        records: list[dict] = []
        seen: set[tuple[str, str, str]] = set()

        def add(url: str, method: str, body: object, headers: object, source: str) -> None:
            json_body = self._json_body(body)
            if not url or json_body is None:
                return
            method_upper = (method or "GET").upper()
            key = (url, method_upper, json.dumps(json_body, sort_keys=True, default=str))
            if key in seen:
                return
            seen.add(key)
            records.append(
                {
                    "url": url,
                    "method": method_upper,
                    "body": json_body,
                    "headers": dict(headers or {}),
                    "source": source,
                    "fields": self._classify_api_auth_fields(json_body),
                }
            )

        for request in kwargs.get("requests") or []:
            add(
                str(getattr(request, "url", "") or ""),
                str(getattr(request, "method", "GET") or "GET"),
                getattr(request, "post_data", None),
                getattr(request, "request_headers", {}) or {},
                "browser_request",
            )
        for endpoint in kwargs.get("api_endpoints") or []:
            add(
                str(getattr(endpoint, "url", "") or ""),
                str(getattr(endpoint, "method", "GET") or "GET"),
                getattr(endpoint, "request_body", None),
                getattr(endpoint, "headers", {}) or {},
                "api_endpoint",
            )
        return records

    def _api_flow_type(self, record: dict) -> str | None:
        lowered_url = str(record["url"]).lower()
        path_tokens = {seg for seg in urlparse(str(record["url"])).path.lower().replace("_", "-").split("/") if seg}
        fields = record["fields"]

        if fields.get("new_password") or "change-password" in lowered_url or "password/change" in lowered_url:
            return "password_change"
        if self._url_contains(lowered_url, self.reset_tokens):
            return "password_reset"
        if self._url_contains(lowered_url, self.mfa_tokens) or self._path_hits(path_tokens, self.mfa_tokens):
            return "mfa"
        if fields.get("username") and fields.get("password") and (
            self._url_contains(lowered_url, self.login_tokens | self.api_auth_tokens)
            or self._path_hits(path_tokens, self.login_tokens)
        ):
            return "login"
        return None

    async def _test_api_login_rate_limit(
        self,
        record: dict,
        session_cookies: dict,
    ) -> list[Finding]:
        from app.core.verification.verification_framework import HttpVerifier

        fields = record["fields"]
        username_path = fields.get("username")
        password_path = fields.get("password")
        if not username_path or not password_path:
            return []

        verifier = HttpVerifier(cookies=session_cookies)
        verifier.set_request_context(module="auth", parameter=username_path)
        responses: list[object] = []
        try:
            for idx in range(6):
                body = copy.deepcopy(record["body"])
                self._set_body_path(body, username_path, f"sentry_invalid_{idx}@example.invalid")
                self._set_body_path(body, password_path, f"sentry_wrong_password_{idx}")
                headers = {**record["headers"], "Content-Type": "application/json"}
                resp = await verifier.send_request(
                    record["url"],
                    record["method"],
                    None,
                    None,
                    headers=headers,
                    json_body=body,
                    test_phase="api_login_rate_limit",
                    parameter=username_path,
                    payload="invalid-api-login",
                )
                responses.append(resp)
                if self._rate_limit_signals_present([resp]):
                    return []
        finally:
            await verifier.close()

        if len(responses) < 6 or not self._burst_responses_stable([{"size": len(responses), "responses": responses}]):
            return []

        last = responses[-1]
        return [
            self._finding(
                vuln_type="API Login Lacks Safe-Probe Rate-Limit Signal",
                url=record["url"],
                method=record["method"],
                parameter=username_path,
                severity=SeverityLevel.medium,
                evidence=(
                    "Sent 6 bounded invalid JSON login attempts to a replayable API login flow. "
                    "Responses stayed stable and no lockout, rate-limit status, or challenge signal was observed."
                ),
                verified=True,
                detection_method="api_login_rate_limit_probe",
                confidence_score=70.0,
                verification_request_snippet=getattr(last, "request_snippet", None),
                verification_response_snippet=getattr(last, "response_snippet", None),
                detection_evidence={"attempts": len(responses), "source": record["source"]},
            )
        ]

    async def _test_api_single_request_control(
        self,
        record: dict,
        *,
        session_cookies: dict,
        auth_headers: dict,
        flow_type: str,
    ) -> list[Finding]:
        from app.core.verification.verification_framework import HttpVerifier

        fields = record["fields"]
        body = copy.deepcopy(record["body"])
        headers = {**record["headers"], **auth_headers, "Content-Type": "application/json"}
        vuln_type = ""
        parameter = None
        severity = SeverityLevel.high
        evidence = ""
        detection_method = ""

        if flow_type == "password_reset":
            if not fields.get("new_password") or fields.get("token") or fields.get("mfa_code"):
                return []
            parameter = fields.get("new_password")
            self._set_body_path(body, parameter, f"SentryStrikeResetCheck{int(time.time())}!")
            vuln_type = "Password Reset API May Not Enforce Reset Token"
            severity = SeverityLevel.critical
            evidence = (
                "Replayable password-reset API body sets a new password without any token, code, nonce, "
                "or signature field. The endpoint accepted the safe verification request without a token error."
            )
            detection_method = "api_reset_token_enforcement_probe"
        elif flow_type == "password_change":
            if not fields.get("new_password") or fields.get("current_password"):
                return []
            parameter = fields.get("new_password")
            self._set_body_path(body, parameter, f"SentryStrikeChangeCheck{int(time.time())}!")
            if fields.get("confirm_password"):
                self._set_body_path(body, fields["confirm_password"], f"SentryStrikeChangeCheck{int(time.time())}!")
            vuln_type = "Password Change API Missing Current Password Requirement"
            evidence = (
                "Authenticated password-change API body contains a new-password field but no current-password "
                "field. A safe verification request was accepted without a current-password error."
            )
            detection_method = "api_password_change_current_password_probe"
        elif flow_type == "mfa":
            if fields.get("mfa_code") or fields.get("token"):
                return []
            parameter = fields.get("username") or "mfa"
            vuln_type = "MFA API Flow Missing Verification Code Parameter"
            evidence = (
                "Replayable MFA/verification API request was accepted even though the JSON body contains no "
                "OTP, verification code, token, or signed challenge field."
            )
            detection_method = "api_mfa_missing_code_probe"
        else:
            return []

        verifier = HttpVerifier(cookies=session_cookies)
        verifier.set_request_context(module="auth", parameter=str(parameter))
        try:
            resp = await verifier.send_request(
                record["url"],
                record["method"],
                None,
                None,
                headers=headers,
                json_body=body,
                test_phase=detection_method,
                parameter=str(parameter),
            )
        finally:
            await verifier.close()

        body_lower = (getattr(resp, "body", "") or "").lower()
        rejection_terms = {
            "invalid", "required", "missing", "token", "code", "otp", "current password",
            "old password", "unauthorized", "forbidden", "csrf", "mfa",
        }
        success_terms = {"success", "updated", "changed", "reset", "ok", "verified"}
        accepted = 200 <= getattr(resp, "status_code", 0) < 400
        rejected = any(term in body_lower for term in rejection_terms)
        explicit_success = any(term in body_lower for term in success_terms)
        if not accepted or rejected or not explicit_success:
            return []

        return [
            self._finding(
                vuln_type=vuln_type,
                url=record["url"],
                method=record["method"],
                parameter=str(parameter),
                severity=severity,
                evidence=evidence,
                verified=True,
                detection_method=detection_method,
                confidence_score=85.0,
                verification_request_snippet=getattr(resp, "request_snippet", None),
                verification_response_snippet=getattr(resp, "response_snippet", None),
                detection_evidence={"flow_type": flow_type, "source": record["source"]},
            )
        ]

    async def _test_api_auth_workflows(
        self,
        kwargs: dict[str, object],
        session_cookies: dict,
    ) -> list[Finding]:
        findings: list[Finding] = []
        auth_headers = dict(kwargs.get("auth_headers") or {})
        for record in self._api_records(kwargs):
            flow_type = self._api_flow_type(record)
            if flow_type == "login":
                findings.extend(await self._test_api_login_rate_limit(record, session_cookies))
            elif flow_type in {"password_reset", "password_change", "mfa"}:
                findings.extend(
                    await self._test_api_single_request_control(
                        record,
                        session_cookies=session_cookies,
                        auth_headers=auth_headers,
                        flow_type=flow_type,
                    )
                )
        return findings

    # ---------------------------------------------------------------------------
    # JWT/session token checks
    # ---------------------------------------------------------------------------

    @staticmethod
    def _looks_like_jwt(token: str) -> bool:
        parts = token.split(".")
        return len(parts) == 3 and all(parts[:2]) and len(token) > 40

    @staticmethod
    def _b64url_decode_json(segment: str) -> dict | None:
        try:
            padded = segment + "=" * (-len(segment) % 4)
            decoded = base64.urlsafe_b64decode(padded.encode("ascii"))
            parsed = json.loads(decoded.decode("utf-8"))
        except Exception:
            return None
        return parsed if isinstance(parsed, dict) else None

    def _decode_jwt(self, token: str) -> tuple[dict, dict] | None:
        if not self._looks_like_jwt(token):
            return None
        header_segment, payload_segment, _signature = token.split(".", 2)
        header = self._b64url_decode_json(header_segment)
        payload = self._b64url_decode_json(payload_segment)
        if header is None or payload is None:
            return None
        return header, payload

    @staticmethod
    def _extract_bearer(headers: dict) -> str | None:
        for key, value in (headers or {}).items():
            if key.lower() == "authorization":
                match = re.match(r"Bearer\s+(.+)", str(value), re.I)
                if match:
                    return match.group(1).strip()
        return None

    def _tokens_from_context(self, kwargs: dict[str, object], session_cookies: dict) -> list[dict]:
        tokens: list[dict] = []
        auth_headers = dict(kwargs.get("auth_headers") or {})
        bearer = self._extract_bearer(auth_headers)
        if bearer:
            tokens.append({"token": bearer, "source": "auth_headers.Authorization", "url": str(kwargs.get("root_url") or "")})

        for name, value in (session_cookies or {}).items():
            if self._looks_like_jwt(str(value)):
                tokens.append({"token": str(value), "source": f"session_cookie.{name}", "url": str(kwargs.get("root_url") or "")})

        for request in kwargs.get("requests") or []:
            request_headers = getattr(request, "request_headers", {}) or {}
            bearer = self._extract_bearer(dict(request_headers))
            if bearer:
                tokens.append({"token": bearer, "source": "observed_request.Authorization", "url": getattr(request, "url", "")})
            cookie_header = next((v for k, v in dict(request_headers).items() if k.lower() == "cookie"), "")
            for cookie_part in str(cookie_header).split(";"):
                if "=" not in cookie_part:
                    continue
                name, value = [part.strip() for part in cookie_part.split("=", 1)]
                if self._looks_like_jwt(value):
                    tokens.append({"token": value, "source": f"observed_request.cookie.{name}", "url": getattr(request, "url", "")})

        seen: set[str] = set()
        unique: list[dict] = []
        for item in tokens:
            if item["token"] in seen:
                continue
            seen.add(item["token"])
            unique.append(item)
        return unique

    def _jwt_findings(self, kwargs: dict[str, object], session_cookies: dict) -> list[Finding]:
        # JWT weaknesses are a server token-policy issue, not an endpoint-specific
        # one. Aggregate per (host, vuln_type) so a single policy gap is reported
        # once per host instead of fanning out across every URL/token that carried it.
        now = int(time.time())
        sensitive_claim_terms = (
            "password", "passwd", "pwd", "secret", "api_key", "apikey", "private_key",
            "reset_token", "refresh_token", "access_token", "hash",
        )
        root_url = str(kwargs.get("root_url") or "")

        decoded_tokens: list[dict] = []
        for item in self._tokens_from_context(kwargs, session_cookies):
            decoded = self._decode_jwt(item["token"])
            if not decoded:
                continue
            header, payload = decoded
            url = str(item.get("url") or root_url)
            decoded_tokens.append({
                "header": header,
                "payload": payload,
                "source": str(item.get("source") or "jwt"),
                "url": url,
                "host": urlparse(url).netloc,
            })

        groups: dict[tuple[str, str], dict] = {}

        def _add(
            host: str,
            vuln_type: str,
            severity: SeverityLevel,
            evidence: str,
            detection_method: str,
            confidence: float,
            token: dict,
            extra: dict,
        ) -> None:
            key = (host, vuln_type)
            group = groups.get(key)
            if group is None:
                group = {
                    "vuln_type": vuln_type,
                    "severity": severity,
                    "evidence": evidence,
                    "detection_method": detection_method,
                    "confidence_score": confidence,
                    "sources": [],
                    "urls": [],
                    "claim_sets": [],
                    "extras": [],
                }
                groups[key] = group
            if token["source"] not in group["sources"]:
                group["sources"].append(token["source"])
            if token["url"] not in group["urls"]:
                group["urls"].append(token["url"])
            claim_set = sorted(token["payload"].keys())
            if claim_set not in group["claim_sets"]:
                group["claim_sets"].append(claim_set)
            group["extras"].append(extra)

        for token in decoded_tokens:
            header = token["header"]
            payload = token["payload"]
            host = token["host"]
            alg = str(header.get("alg", "")).lower()
            if alg == "none":
                _add(
                    host,
                    "JWT Uses alg=none",
                    SeverityLevel.critical,
                    "Bearer/session JWT declares alg=none, meaning signature verification may be disabled.",
                    "jwt_metadata_inspection",
                    95.0,
                    token,
                    {"header": header},
                )

            exp = payload.get("exp")
            if exp is None:
                _add(
                    host,
                    "JWT Missing Expiration Claim",
                    SeverityLevel.high,
                    "Bearer/session JWT has no exp claim, so token lifetime cannot be bounded by the token itself.",
                    "jwt_claim_inspection",
                    85.0,
                    token,
                    {"claims": sorted(payload.keys())},
                )
            else:
                try:
                    exp_int = int(exp)
                    iat_int = int(payload.get("iat", now))
                    if exp_int - iat_int > 60 * 60 * 24 * 30 or exp_int - now > 60 * 60 * 24 * 30:
                        _add(
                            host,
                            "JWT Expiration Is Excessively Long",
                            SeverityLevel.medium,
                            "Bearer/session JWT remains valid for more than 30 days.",
                            "jwt_claim_inspection",
                            80.0,
                            token,
                            {"exp": exp_int, "iat": payload.get("iat")},
                        )
                except Exception:
                    pass

            sensitive_claims = [
                key for key in payload.keys()
                if any(term in str(key).lower() for term in sensitive_claim_terms)
            ]
            if sensitive_claims:
                _add(
                    host,
                    "JWT Contains Sensitive Claims",
                    SeverityLevel.high,
                    f"JWT payload exposes sensitive claim names: {sorted(sensitive_claims)}.",
                    "jwt_sensitive_claim_inspection",
                    90.0,
                    token,
                    {"sensitive_claims": sorted(sensitive_claims)},
                )

        findings: list[Finding] = []
        for (host, vuln_type), group in groups.items():
            rep_url = (
                root_url
                if root_url and urlparse(root_url).netloc == host
                else (group["urls"][0] if group["urls"] else root_url)
            )
            detection_evidence: dict = {
                "sources": group["sources"],
                "urls": group["urls"],
                "claim_sets": group["claim_sets"],
            }
            if vuln_type == "JWT Uses alg=none":
                detection_evidence["headers"] = [
                    e["header"] for e in group["extras"] if e.get("header") is not None
                ]
            elif vuln_type == "JWT Expiration Is Excessively Long":
                detection_evidence["exp_values"] = [
                    e["exp"] for e in group["extras"] if e.get("exp") is not None
                ]
                detection_evidence["iat_values"] = [
                    e["iat"] for e in group["extras"] if e.get("iat") is not None
                ]
            elif vuln_type == "JWT Contains Sensitive Claims":
                detection_evidence["sensitive_claims"] = sorted(
                    {s for e in group["extras"] for s in (e.get("sensitive_claims") or [])}
                )

            evidence = group["evidence"]
            if len(group["sources"]) > 1:
                evidence += (
                    f" Observed across {len(group['sources'])} token source(s) on host {host}."
                )

            findings.append(
                self._finding(
                    vuln_type=vuln_type,
                    url=rep_url,
                    severity=group["severity"],
                    evidence=evidence,
                    verified=True,
                    detection_method=group["detection_method"],
                    confidence_score=group["confidence_score"],
                    detection_evidence=detection_evidence,
                )
            )
        return findings

    def _cookie_attribute_findings(self, kwargs: dict[str, object]) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[tuple[str, str]] = set()
        for request in kwargs.get("requests") or []:
            headers = getattr(request, "response_headers", {}) or {}
            set_cookie_values = [v for k, v in dict(headers).items() if k.lower() == "set-cookie"]
            for header in set_cookie_values:
                parts = [part.strip().lower() for part in str(header).split(";")]
                if not parts or "=" not in parts[0]:
                    continue
                cookie_name = parts[0].split("=", 1)[0]
                if not any(token in cookie_name for token in self._session_cookie_names):
                    continue
                missing = []
                if "httponly" not in parts:
                    missing.append("HttpOnly")
                if "secure" not in parts:
                    missing.append("Secure")
                if not any(part.startswith("samesite") for part in parts):
                    missing.append("SameSite")
                if not missing:
                    continue
                key = (str(getattr(request, "url", "") or ""), cookie_name)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(
                    self._finding(
                        vuln_type="Insecure Session Cookie Attributes",
                        url=key[0],
                        severity=SeverityLevel.medium,
                        evidence=f"Observed session cookie '{cookie_name}' lacks secure attributes: {', '.join(missing)}.",
                        verified=True,
                        detection_method="observed_set_cookie_inspection",
                        confidence_score=90.0,
                        detection_evidence={"missing_attributes": missing},
                    )
                )
        return findings

    async def _logout_token_reuse_findings(
        self,
        kwargs: dict[str, object],
        session_cookies: dict,
    ) -> list[Finding]:
        from app.core.verification.verification_framework import HttpVerifier

        auth_headers = dict(kwargs.get("auth_headers") or {})
        bearer = self._extract_bearer(auth_headers)
        if not bearer:
            return []

        requests = list(kwargs.get("requests") or [])
        logout = next(
            (
                request for request in requests
                if self._url_contains(str(getattr(request, "url", "")).lower(), self.logout_tokens)
            ),
            None,
        )
        protected = next(
            (
                request for request in requests
                if str(getattr(request, "method", "GET")).upper() == "GET"
                and not self._url_contains(str(getattr(request, "url", "")).lower(), self.logout_tokens | self.login_tokens)
            ),
            None,
        )
        if logout is None or protected is None:
            return []

        verifier = HttpVerifier(cookies=session_cookies)
        verifier.set_request_context(module="auth", parameter="Authorization")
        try:
            baseline = await verifier.send_request(
                str(getattr(protected, "url", "")),
                "GET",
                None,
                None,
                headers=auth_headers,
                test_phase="token_reuse_baseline",
            )
            await verifier.send_request(
                str(getattr(logout, "url", "")),
                str(getattr(logout, "method", "POST") or "POST").upper(),
                None,
                None,
                headers=auth_headers,
                test_phase="logout_revoke",
            )
            replay = await verifier.send_request(
                str(getattr(protected, "url", "")),
                "GET",
                None,
                None,
                headers=auth_headers,
                test_phase="token_reuse_after_logout",
            )
        finally:
            await verifier.close()

        if not (200 <= getattr(baseline, "status_code", 0) < 300):
            return []
        if not (200 <= getattr(replay, "status_code", 0) < 300):
            return []
        baseline_body = getattr(baseline, "body", "") or ""
        replay_body = getattr(replay, "body", "") or ""
        if abs(len(baseline_body) - len(replay_body)) > max(200, len(baseline_body) * 0.20):
            return []

        return [
            self._finding(
                vuln_type="Bearer Token Accepted After Logout",
                url=str(getattr(protected, "url", "")),
                method="GET",
                parameter="Authorization",
                severity=SeverityLevel.high,
                evidence=(
                    "Observed logout flow was replayed with the bearer token, then the same token still "
                    "successfully accessed a protected API request."
                ),
                verified=True,
                detection_method="logout_token_reuse_probe",
                confidence_score=85.0,
                verification_request_snippet=getattr(replay, "request_snippet", None),
                verification_response_snippet=getattr(replay, "response_snippet", None),
            )
        ]

    async def _inspect_tokens_and_sessions(
        self,
        kwargs: dict[str, object],
        session_cookies: dict,
    ) -> list[Finding]:
        findings = []
        findings.extend(self._jwt_findings(kwargs, session_cookies))
        findings.extend(self._cookie_attribute_findings(kwargs))
        findings.extend(await self._logout_token_reuse_findings(kwargs, session_cookies))
        return findings

    async def detect(self, urls: list[str], forms: list[object], **kwargs: object) -> list[Finding]:
        findings: list[Finding] = []
        session_cookies = kwargs.get("session_cookies") or {}
        scan_config = kwargs.get("scan_config")
        settings = get_settings()
        scan_mode = scan_config.get_val("scan_mode", getattr(settings, "scan_mode", "verified")) if scan_config else getattr(settings, "scan_mode", "verified")
        verified_mode = scan_mode == "verified"
        is_spa = bool(kwargs.get("is_spa", False))

        # -----------------------------------------------------------------------
        # Form analysis
        # -----------------------------------------------------------------------
        for form in forms:
            raw_inputs  = list(getattr(form, "inputs", []))
            input_names = {i.name.lower() for i in raw_inputs}
            input_types = {getattr(i, "input_type", "text").lower() for i in raw_inputs}
            form_url    = getattr(form, "action", getattr(form, "page_url", ""))
            form_method = getattr(form, "method", "POST").upper()
            has_password = bool(input_names.intersection({"password", "passwd", "pass", "pwd", "passphrase", "secret"})
                                or "password" in input_types)
            has_username = bool(input_names.intersection({"username", "user", "email", "mail", "login",
                                                           "uname", "phone", "mobile", "account"}))
            has_hidden   = "hidden" in input_types

            # 1. Login form discovered → run active auth tests.
            # The passive "Login Form Discovered" finding has been removed: it
            # always emits verified=False/confidence=0 and is dropped by
            # verified-scan-mode filtering, while giving the false impression
            # that brute-force protection was checked. The active probe in
            # _test_active_auth() produces a verified finding only when
            # protection is actually absent, which is the signal that matters.
            if has_username and has_password:
                active_findings = await self._test_active_auth(form_url, form_method, raw_inputs, session_cookies)
                findings.extend(active_findings)

            # 2. Login form submitted over GET
            if has_password and form_method == "GET":
                findings.append(self._finding(
                    vuln_type="Credentials Transmitted via HTTP GET",
                    url=form_url,
                    method=form_method,
                    severity=SeverityLevel.critical,
                    evidence=(
                        "Password field found in a form that submits via GET. "
                        "Credentials will appear in the URL, server logs, browser history, "
                        "and Referer headers - a critical confidentiality failure."
                    ),
                ))

            # 7. Hidden inputs on auth forms → CSRF token presence / absence check
            if (has_username or has_password) and not has_hidden:
                findings.append(self._finding(
                    vuln_type="Authentication Form May Lack CSRF Protection",
                    url=form_url,
                    method=form_method,
                    severity=SeverityLevel.high,
                    category=OwaspCategory.a01,
                    evidence=(
                        "Authentication form has no hidden input fields detected. "
                        "This may indicate missing CSRF token; verify server-side enforcement."
                    ),
                ))

            # 8. Password-change form - requires old password check
            change_hits = input_names.intersection({"current_password", "old_password", "existing_password"})
            new_hits    = input_names.intersection({"new_password", "confirm_password", "password_confirm"})
            if new_hits and not change_hits:
                findings.append(self._finding(
                    vuln_type="Password-Change Form Missing Current Password Verification",
                    url=form_url,
                    method=form_method,
                    severity=SeverityLevel.high,
                    evidence=(
                        "A password-change form was found with new/confirm password fields "
                        "but no current-password field. An attacker with an active session "
                        "can silently change the password (account takeover)."
                    ),
                ))

        findings.extend(await self._test_api_auth_workflows(kwargs, session_cookies))
        findings.extend(await self._inspect_tokens_and_sessions(kwargs, session_cookies))

        # -----------------------------------------------------------------------
        # URL analysis
        # -----------------------------------------------------------------------
        for url in urls:
            parsed      = urlparse(url)
            lowered     = url.lower()
            path_tokens = {seg.lower() for seg in parsed.path.split("/") if seg}
            query_params = parse_qsl(parsed.query, keep_blank_values=True)
            query_keys   = {k.lower() for k, _ in query_params}
            query_values = {v.lower() for _, v in query_params}
            scheme       = parsed.scheme.lower()

            # 1. Password reset endpoint - missing token indicator
            # This is a review hint, not proof of a broken reset flow. In
            # verified mode it is always dropped later, so avoid emitting it.
            if self._path_hits(path_tokens, self.reset_tokens) or self._url_contains(lowered, self.reset_tokens):
                has_token = bool(query_keys.intersection(self._security_control_tokens))
                if not has_token and not verified_mode:
                    findings.append(self._finding(
                        vuln_type="Password Reset Endpoint Without Token Parameter",
                        url=url,
                        severity=SeverityLevel.high,
                        evidence=(
                            "Password-reset endpoint detected with no token/code parameter in URL. "
                            "Verify: reset tokens are unguessable, single-use, short-lived (≤15 min), "
                            "and bound to the requesting user."
                        ),
                    ))
            # 3. Admin / privileged endpoint discovered.
            # URL names alone are not proof of an exposed admin surface. This is
            # especially noisy for SPAs, where client routes often return the
            # same index shell and strict MIME errors for relative assets.
            if (
                not verified_mode
                and not is_spa
                and (self._path_hits(path_tokens, self.admin_tokens) or self._url_contains(lowered, self.admin_tokens))
            ):
                findings.append(self._finding(
                    vuln_type="Admin / Privileged Endpoint Discovered",
                    url=url,
                    severity=SeverityLevel.high,
                    category=OwaspCategory.a01,
                    evidence=(
                        "Administrative or privileged path detected. Verify: endpoint is not "
                        "publicly accessible, requires strong authentication and MFA, and "
                        "enforces IP allowlisting or VPN where appropriate."
                    ),
                ))

            # 5. Sensitive credentials in query string (GET)
            leaked_params = self._sensitive_query_params(query_params, lowered)
            if leaked_params:
                findings.append(self._finding(
                    vuln_type="Sensitive Credential / Token Exposed in URL Query String",
                    url=url,
                    severity=SeverityLevel.critical,
                    evidence=(
                        f"Sensitive parameter(s) {sorted(leaked_params)} found in the URL query "
                        "string. These will appear in server logs, browser history, and Referer "
                        "headers. Credentials/tokens must only be transmitted in POST bodies or headers."
                    ),
                ))

            # 9. Plaintext HTTP on auth endpoint
            # CryptoFailuresDetector emits the site-level structural transport
            # issue that verified mode keeps; this URL-only auth hint is passive
            # duplication and is dropped by verified-mode filtering.
            if scheme == "http" and (
                self._path_hits(path_tokens, self.login_tokens)
                or self._path_hits(path_tokens, self.reset_tokens)
                or self._path_hits(path_tokens, self.admin_tokens)
                or self._path_hits(path_tokens, self.api_auth_tokens)
            ) and not verified_mode:
                findings.append(self._finding(
                    vuln_type="Authentication Endpoint Served Over Plaintext HTTP",
                    url=url,
                    severity=SeverityLevel.critical,
                    evidence=(
                        "Auth-related endpoint is served over HTTP, not HTTPS. "
                        "Credentials are transmitted in cleartext and susceptible to interception."
                    ),
                ))

            # 10. Session / auth token in URL path or query (token fixation / leakage)
            for _, val in query_params:
                v = val.lower()
                # Looks like a JWT (three base64 segments separated by dots)
                if v.count(".") == 2 and len(v) > 40 and all(c in "abcdefghijklmnopqrstuvwxyz0123456789._-+/=" for c in v):
                    findings.append(self._finding(
                        vuln_type="Possible JWT / Session Token Exposed in URL",
                        url=url,
                        severity=SeverityLevel.critical,
                        evidence=(
                            "A query parameter value resembles a JWT or long-form session token. "
                            "Tokens in URLs are logged by proxies, servers, and browsers - "
                            "use Authorization headers or HttpOnly cookies instead."
                        ),
                    ))
                    break
                # Long opaque token (≥32 hex / base64 chars) in auth-related param
                if len(val) >= 32 and query_keys.intersection({"token", "auth", "session", "key", "access_token", "id_token"}):
                    findings.append(self._finding(
                        vuln_type="Session / Auth Token Exposed in URL Query String",
                        url=url,
                        severity=SeverityLevel.high,
                        evidence=(
                            "A long auth-related token value is present in the URL. "
                            "Tokens must not be placed in URLs to avoid log leakage and Referer exposure."
                        ),
                    ))
                    break

            # 11. Default / well-known admin paths
            well_known_admin_paths = (
                "/wp-admin", "/wp-login.php", "/admin", "/administrator",
                "/phpmyadmin", "/pma", "/cpanel", "/plesk", "/webmin",
                "/.env", "/config", "/setup", "/install", "/install.php",
                "/jenkins", "/jira", "/confluence", "/gitlab",
                "/actuator", "/actuator/env", "/actuator/health",
                "/management", "/metrics", "/api/swagger", "/swagger-ui",
                "/graphql", "/graphiql", "/altair",
            )
            for admin_path in well_known_admin_paths:
                if (
                    not verified_mode
                    and not is_spa
                    and (
                        parsed.path.lower().startswith(admin_path)
                        or admin_path.rstrip("/") == parsed.path.lower().rstrip("/")
                    )
                ):
                    findings.append(self._finding(
                        vuln_type="Well-Known Admin / Sensitive Path Discovered",
                        url=url,
                        severity=SeverityLevel.high,
                        evidence=(
                            f"URL matches well-known sensitive path '{admin_path}'. "
                            "Verify this endpoint is not publicly accessible or is "
                            "protected by strong authentication and access controls."
                        ),
                    ))
                    break

            # 12. OAuth / SSO misconfiguration hints
            if any(tok in lowered for tok in ("oauth", "openid", "saml", "sso", "oidc")):
                redirect_uri_vals = [v for k, v in query_params if k.lower() in ("redirect_uri", "return_to", "next", "callback")]
                for rval in redirect_uri_vals:
                    if rval.startswith("http") and not rval.startswith(parsed.scheme + "://" + parsed.netloc):
                        findings.append(self._finding(
                            vuln_type="Open Redirect in OAuth / SSO redirect_uri",
                            url=url,
                            parameter="redirect_uri",
                            severity=SeverityLevel.critical,
                            evidence=(
                                f"OAuth/SSO flow has a redirect_uri '{rval}' pointing to an "
                                "external origin. An unvalidated redirect_uri allows code/token "
                                "interception and account takeover."
                            ),
                        ))

                if "state" not in query_keys and any(tok in lowered for tok in ("oauth", "authorize", "callback")):
                    findings.append(self._finding(
                        vuln_type="OAuth Request Missing 'state' Parameter (CSRF Risk)",
                        url=url,
                        severity=SeverityLevel.high,
                        evidence=(
                            "OAuth authorization request has no 'state' parameter. "
                            "Without state, CSRF attacks can force arbitrary account linking "
                            "or initiate unintended OAuth flows on behalf of the victim."
                        ),
                    ))

        return findings

    # ---------------------------------------------------------------------------
    # Credential / Config Disclosure - derived from observed evidence
    # ---------------------------------------------------------------------------

    _CREDENTIAL_DISCLOSURE_PATTERNS: list[re.Pattern] = [
        re.compile(p, re.IGNORECASE)
        for p in [
            r"password\s*=",
            r"db_password|database_password|db_pass",
        ]
    ]

    def findings_from_observed_evidence(
        self,
        observed_findings: list[Finding],
    ) -> list[Finding]:
        """Derive credential/config disclosure findings from other detectors' evidence snippets.

        When the response body of another detector's confirmed finding (e.g. SQLi, LFI)
        contains database credential or configuration keys leaked in error output, this
        method independently reports it under A07 / Authentication Failures.
        """
        findings: list[Finding] = []
        seen: set[tuple] = set()

        for source in observed_findings or []:
            observed_text = source.verification_response_snippet or ""
            if not observed_text:
                continue

            matched_patterns = [
                p.pattern for p in self._CREDENTIAL_DISCLOSURE_PATTERNS
                if p.search(observed_text)
            ]
            if not matched_patterns:
                continue

            dedup_key = (source.url or "", "Credential / Config Disclosure in Response Body")
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            findings.append(
                Finding(
                    category=OwaspCategory.a07,
                    vuln_type="Credential / Config Disclosure in Response Body",
                    severity=SeverityLevel.high,
                    url=source.url or "",
                    parameter=source.parameter,
                    method=source.method,
                    evidence=(
                        f"Credential or configuration key disclosed in response body: "
                        f"{', '.join(matched_patterns[:2])}. "
                        f"Observed during {source.vuln_type} verification."
                    ),
                    confidence_score=85.0,
                    detection_method="observed_credential_disclosure",
                    detection_evidence={
                        "source_vuln_type": source.vuln_type,
                        "source_detection_method": getattr(source, "detection_method", None),
                        "matched_patterns": matched_patterns,
                    },
                    verified=True,
                    reproducible=getattr(source, "reproducible", False),
                    verification_request_snippet=getattr(source, "verification_request_snippet", None),
                    verification_response_snippet=observed_text or getattr(source, "verification_response_snippet", None),
                )
            )

        return findings
