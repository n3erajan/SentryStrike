import asyncio
import base64
import copy
import json
import logging
import re
import secrets
import statistics
import time
from urllib.parse import parse_qsl, urlencode, urlparse

from app.config import get_settings
from app.core.detectors.base_detector import BaseDetector, Finding
from app.utils.scan_http import build_observed_request_snippet
from shared.models.vulnerability import OwaspCategory, SeverityLevel

logger = logging.getLogger(__name__)

# Sentinel distinguishing "key absent" from "key present with value None".
_MISSING = object()


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
        # A protection control announces itself either as an explicit throttle
        # status (423 Locked / 429 Too Many Requests) or as a *transition* away
        # from the rejection baseline mid-burst (e.g. a 401 that flips to a
        # 302-lockout / 200-challenge, or a 200 login page replaced by an error
        # page). Soft signals (rate-limit/challenge terms) are already screened by
        # _rate_limit_signals_present before this method runs.
        #
        # A UNIFORM non-2xx code is NOT a control — it is the normal rejection
        # baseline. Most correct JSON APIs answer an invalid login with a steady
        # 401/403; the previous "must be 2xx" gate misread that as the server
        # reacting, so those APIs could never be flagged for missing brute-force
        # protection. We therefore key on throttle status + status *stability*,
        # not on the absolute 2xx range.
        statuses = [getattr(r, "status_code", 0) for r in responses]
        if any(code in {423, 429} for code in statuses):
            return False
        if len(set(statuses)) > 1:
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

    async def _test_active_auth(self, form_url: str, method: str, raw_inputs: list, session_cookies: dict, kwargs: dict | None = None) -> list[Finding]:
        findings = []
        kwargs = kwargs or {}
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
            #
            # When the login identifier is an e-mail (the common case for both SPAs
            # and traditional apps), a bare "admin" never authenticates — the
            # candidates must be e-mails on the app's OWN domain. Harvest that
            # domain (and any observed accounts) from what the target itself
            # exposed and synthesise privileged e-mail candidates; this is the same
            # framework-agnostic logic used for JSON API logins, so non-SPA form
            # logins get identical coverage.
            username_is_email = any(
                token in username_param.lower() for token in ("email", "mail")
            ) or bool(self._BARE_EMAIL_RE.match(str(payload.get(username_param, ""))))
            if username_is_email:
                emails, usernames, domains = self._harvest_login_identities(kwargs, session_cookies)
                harvested = self._build_credential_candidates(
                    emails, usernames, domains, email_login=True
                )[: self._MAX_CRED_ATTEMPTS]
                _default_pairs = [
                    # bogus first - establishes the failure baseline
                    (payload[username_param], payload[password_param]),
                    *harvested,
                ]
            else:
                _default_pairs = [
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
                    # 401/403 is the EXPECTED per-attempt rejection of a wrong
                    # credential, NOT a lockout — treating it as one aborts the
                    # sequence after the first failed pair (so default creds are
                    # never reached on any API that rejects with 401). Only a
                    # genuine throttle/lockout (429/423) or a rate-limit message
                    # stops the sequence.
                    if resp_status in {423, 429}:
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

    @staticmethod
    def _get_body_path(body: dict, path: str) -> object:
        """Return the value at a dotted body path, or None if absent."""
        current: object = body
        for part in path.split("."):
            if not isinstance(current, dict):
                return None
            current = current.get(part)
        return current

    @staticmethod
    def _remove_body_path(body: dict, path: str) -> bool:
        """Delete the value at a dotted body path. Returns True if a key was removed."""
        current = body
        parts = path.split(".")
        for part in parts[:-1]:
            next_value = current.get(part)
            if not isinstance(next_value, dict):
                return False
            current = next_value
        return current.pop(parts[-1], _MISSING) is not _MISSING

    def _classify_api_auth_fields(self, body: dict) -> dict[str, str | None]:
        fields: dict[str, str | None] = {
            "username": None,
            "password": None,
            "current_password": None,
            "new_password": None,
            "confirm_password": None,
            "token": None,
            "mfa_code": None,
            "security_answer": None,
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
                "currentpassword", "oldpassword", "existingpassword",
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
            elif fields["security_answer"] is None and normalized in {
                "security_answer", "securityanswer", "secanswer", "secret_answer",
                "recovery_answer", "answer",
            }:
                fields["security_answer"] = path
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
        # The scanner's own winning login recipe: a guaranteed-correct login-flow
        # record (real API URL, method, JSON body, field names) even when the
        # login XHR was never captured as a browser request or mined from JS.
        replay = kwargs.get("auth_replay_state")
        if replay is not None and getattr(replay, "payload", None):
            add(
                str(getattr(replay, "action", "") or getattr(replay, "login_url", "") or ""),
                str(getattr(replay, "method", "POST") or "POST"),
                getattr(replay, "payload", None),
                getattr(replay, "headers", {}) or {},
                "auth_replay",
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

    # ---------------------------------------------------------------------------
    # Default / weak credential probing (JSON API login flows)
    # ---------------------------------------------------------------------------

    # Common privileged / default account local-parts (framework-agnostic). Paired
    # with observed domains for email logins, or used bare for username logins.
    _DEFAULT_LOCALPARTS: tuple[str, ...] = (
        "admin", "administrator", "root", "superadmin", "sysadmin",
        "support", "operator", "manager", "test", "demo", "user", "guest",
    )
    # Common weak/default passwords, ordered by real-world frequency.
    _WEAK_PASSWORDS: tuple[str, ...] = (
        "admin123", "admin", "password", "Password1", "Password123",
        "123456", "12345678", "admin@123", "changeme", "letmein",
        "welcome1", "root", "test", "demo", "qwerty123",
    )
    _BARE_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
    _EMAIL_SCAN_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
    _BARE_USERNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{2,63}$")
    # Upper bound on live login attempts so the probe is bounded regardless of how
    # many candidates the harvest/enrichment produce.
    _MAX_CRED_ATTEMPTS: int = 30

    def _harvest_login_identities(
        self, kwargs: dict[str, object], session_cookies: dict
    ) -> tuple[list[str], list[str], list[str]]:
        """Collect real identities the target itself reveals during the scan.

        Sources (all deterministic, no target hardcoding): the scanner's own
        configured login identity, the username value in the winning login recipe,
        e-mail/subject claims inside observed JWTs, and e-mail-shaped values in
        observed parameters. Returns ``(emails, usernames, domains)``.
        """
        # E-mails/usernames the app itself exposes in RESPONSES ("response" side)
        # vs identities tied to the scanner's OWN account ("account" side). The
        # app's real user/admin domain lives on the response side; the scanner's
        # configured login may be on a wholly unrelated domain (e.g. a personal
        # gmail registered against a corporate app), so response domains must
        # outrank account domains regardless of raw frequency.
        response_emails: list[str] = []
        account_emails: list[str] = []
        usernames: list[str] = []

        def add_identity(value: object, *, from_response: bool) -> None:
            text = str(value or "").strip()
            if not text:
                return
            if self._BARE_EMAIL_RE.match(text):
                bucket = response_emails if from_response else account_emails
                if text.lower() not in {e.lower() for e in (response_emails + account_emails)}:
                    bucket.append(text)
            elif self._BARE_USERNAME_RE.match(text):
                if text.lower() not in {u.lower() for u in usernames}:
                    usernames.append(text)

        # --- account side: the scanner's own identity ---
        # Sourced from the per-scan submitted account (threaded via crawl_context),
        # not the environment. When no account was submitted this is None and only
        # response-observed / replay-payload identities are considered.
        add_identity(kwargs.get("scanner_identity_username"), from_response=False)
        replay = kwargs.get("auth_replay_state")
        if replay is not None:
            for value in (getattr(replay, "payload", {}) or {}).values():
                add_identity(value, from_response=False)
        for item in self._tokens_from_context(kwargs, session_cookies):
            decoded = self._decode_jwt(item["token"])
            if not decoded:
                continue
            _, claims = decoded
            if not isinstance(claims, dict):
                continue
            scopes = [claims]
            data = claims.get("data")
            if isinstance(data, dict):
                scopes.append(data)
            for scope in scopes:
                for key in ("email", "sub", "username", "preferred_username", "user", "upn", "unique_name"):
                    add_identity(scope.get(key), from_response=False)

        # --- response side: e-mails the target exposes in its own data ---
        for parameter in kwargs.get("parameters") or []:
            add_identity(getattr(parameter, "baseline_value", None), from_response=True)
        text_sources: list[str] = [str(kwargs.get("spa_root_html") or "")]
        for request in kwargs.get("requests") or []:
            snippet = getattr(request, "response_snippet", None)
            if snippet:
                text_sources.append(str(snippet))
            post_data = getattr(request, "post_data", None)
            if isinstance(post_data, str):
                text_sources.append(post_data)
        for endpoint in kwargs.get("api_endpoints") or []:
            body = getattr(endpoint, "request_body", None)
            if isinstance(body, str):
                text_sources.append(body)
        for text in text_sources:
            if not text:
                continue
            for match in self._EMAIL_SCAN_RE.findall(text)[:50]:
                add_identity(match, from_response=True)

        def ranked_domains(source_emails: list[str]) -> list[str]:
            counts: dict[str, int] = {}
            for email in source_emails:
                domain = email.split("@", 1)[1].lower()
                if domain:
                    counts[domain] = counts.get(domain, 0) + 1
            return sorted(counts, key=lambda d: counts[d], reverse=True)

        # Response domains first (the app's own), then account domains not already seen.
        domains = ranked_domains(response_emails)
        for domain in ranked_domains(account_emails):
            if domain not in domains:
                domains.append(domain)
        # Observed (response) e-mails are real accounts — prioritise them as
        # verbatim candidates over the scanner's own account identity.
        emails = response_emails + [e for e in account_emails if e not in response_emails]
        return emails, usernames, domains

    def _build_credential_candidates(
        self,
        emails: list[str],
        usernames: list[str],
        domains: list[str],
        email_login: bool,
        extra_users: tuple[str, ...] = (),
        extra_passwords: tuple[str, ...] = (),
    ) -> list[tuple[str, str]]:
        """Cross observed/derived identities with weak passwords into login pairs.

        For an e-mail login, identities are observed e-mails plus common
        privileged local-parts synthesised against the OBSERVED domains — nothing
        target-specific is hardcoded. Ordered most-likely-first; the caller caps
        the total number of live attempts.
        """
        users: list[str] = []

        def add_user(value: str) -> None:
            if value and value not in users:
                users.append(value)

        if email_login:
            # Synthesised privileged accounts first (the common default-account
            # target), then any real observed e-mails (which may also be admin).
            for domain in domains:
                for localpart in self._DEFAULT_LOCALPARTS:
                    add_user(f"{localpart}@{domain}")
            for email in emails:
                add_user(email)
            for extra in extra_users:
                if "@" in extra:
                    add_user(extra)
                else:
                    for domain in domains:
                        add_user(f"{extra}@{domain}")
        else:
            for username in usernames:
                add_user(username)
            for localpart in self._DEFAULT_LOCALPARTS:
                add_user(localpart)
            for extra in extra_users:
                add_user(extra)

        passwords = list(self._WEAK_PASSWORDS)
        for extra in extra_passwords:
            if extra and extra not in passwords:
                passwords.append(extra)

        # Per-user password list: the local-part itself and "<localpart>123" are
        # the two most common default patterns, tried before the generic list.
        per_user: list[tuple[str, list[str]]] = []
        for user in users:
            localpart = user.split("@", 1)[0]
            ordered: list[str] = []
            for password in [localpart, f"{localpart}123", *passwords]:
                if password not in ordered:
                    ordered.append(password)
            per_user.append((user, ordered))

        # Emit breadth-first (password-rank outer, user inner) so the top password
        # is tried against EVERY priority account before moving to the next
        # password — the accepted default pair surfaces well within the attempt cap
        # even when many candidate accounts exist.
        pairs: list[tuple[str, str]] = []
        seen: set[tuple[str, str]] = set()
        max_rank = max((len(pw_list) for _, pw_list in per_user), default=0)
        for rank in range(max_rank):
            for user, pw_list in per_user:
                if rank < len(pw_list):
                    pair = (user, pw_list[rank])
                    if pair not in seen:
                        seen.add(pair)
                        pairs.append(pair)
        return pairs

    def _looks_like_auth_success(self, status: int, body: str, baseline_status: int) -> bool:
        """True when a login response indicates an ACCEPTED credential.

        Zero-FP by construction: a successful login is a 2xx/redirect that either
        carries an auth-token marker OR flips an explicit auth-denial baseline
        (401/403/…) into success. An invalid login (the baseline) satisfies
        neither, so only genuinely accepted credentials qualify.
        """
        if status not in {200, 201, 202, 302, 303}:
            return False
        low = (body or "").lower()
        token_markers = (
            '"token"', '"authentication"', '"access_token"', '"accesstoken"',
            '"id_token"', '"jwt"', '"bearer"', '"sessionid"', '"session_id"',
        )
        has_token = any(marker in low for marker in token_markers) or bool(
            re.search(r"ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.", body or "")
        )
        denied_baseline = baseline_status in {400, 401, 403, 409, 422}
        return has_token or (denied_baseline and status not in {400, 401, 403, 409, 422})

    async def _ai_enrich_credentials(
        self, kwargs: dict[str, object], domains: list[str]
    ) -> tuple[tuple[str, ...], tuple[str, ...]]:
        """Optionally enrich the candidate lists via the AI layer.

        Runs ONLY when ``ai_analysis_enabled`` is set. Any failure (disabled, no
        key, timeout, bad JSON) falls back to empty lists so the deterministic
        harvest remains the base mechanism and no-AI runs are unaffected.
        """
        if not get_settings().ai_analysis_enabled:
            return (), ()
        try:
            from app.analyzers.ai_client import AIClient

            host = urlparse(str(kwargs.get("root_url") or "")).hostname or ""
            technologies = kwargs.get("technologies") or kwargs.get("technology_stack") or []
            tech_names = ", ".join(str(getattr(t, "name", t)) for t in technologies)[:200]
            prompt = (
                "You are assisting an authorised security scan. Given a target web application, "
                "propose likely DEFAULT or WEAK administrative credentials to test against its login. "
                f"Target host: {host or 'unknown'}. Detected technologies: {tech_names or 'unknown'}. "
                "Respond ONLY with JSON of the form "
                '{"usernames": ["..."], "passwords": ["..."]}. '
                "usernames are bare local-parts or full identifiers; keep each list <= 8 items."
            )
            data = await asyncio.wait_for(AIClient().generate_json(prompt), timeout=20.0)
            users = tuple(str(u).strip() for u in (data.get("usernames") or []) if str(u).strip())[:8]
            passwords = tuple(str(p).strip() for p in (data.get("passwords") or []) if str(p).strip())[:8]
            return users, passwords
        except Exception as exc:  # noqa: BLE001 - enrichment is best-effort
            logger.debug("AI credential enrichment skipped: %s", exc)
            return (), ()

    async def _test_api_default_credentials(
        self,
        record: dict,
        kwargs: dict[str, object],
        session_cookies: dict,
    ) -> list[Finding]:
        """Probe a JSON API login flow for accepted default/weak credentials.

        Candidate identities are harvested from what the target reveals (observed
        e-mails/JWT claims/own login domain) and crossed with a common weak-password
        list; when AI analysis is enabled the lists are enriched. Verification is a
        real login: an accepted credential is proven by a 2xx + auth-token response
        that differs from the invalid-credential baseline. Bounded and idempotent.
        """
        from app.core.verification.verification_framework import HttpVerifier

        fields = record["fields"]
        username_path = fields.get("username")
        password_path = fields.get("password")
        if not username_path or not password_path:
            return []
        # Multi-factor / reset / change flows are not plain credential logins.
        if fields.get("mfa_code") or fields.get("new_password") or fields.get("token"):
            return []

        emails, usernames, domains = self._harvest_login_identities(kwargs, session_cookies)
        observed_username = self._get_body_path(record["body"], username_path)
        email_login = (
            "email" in username_path.lower()
            or bool(self._BARE_EMAIL_RE.match(str(observed_username or "")))
            or bool(emails)
        )
        if email_login and not (emails or domains):
            # An e-mail login with no observed domain: we cannot form a valid
            # address without guessing a domain (that would be a blind wordlist).
            return []

        extra_users, extra_passwords = await self._ai_enrich_credentials(kwargs, domains)
        candidates = self._build_credential_candidates(
            emails, usernames, domains, email_login, extra_users, extra_passwords
        )
        if not candidates:
            return []

        verifier = HttpVerifier(cookies=session_cookies)
        verifier.set_request_context(module="auth", parameter=username_path)
        try:
            # Baseline: a clearly-invalid credential. Establishes the failure
            # status/body the accepted-credential check discriminates against.
            baseline_body = copy.deepcopy(record["body"])
            invalid_user = f"sentry_invalid_{int(time.time())}@example.invalid" if email_login else f"sentry_invalid_{int(time.time())}"
            self._set_body_path(baseline_body, username_path, invalid_user)
            self._set_body_path(baseline_body, password_path, "sentry_wrong_password_zzz")
            headers = {**record["headers"], "Content-Type": "application/json"}
            baseline = await verifier.send_request(
                record["url"], record["method"], None, None,
                headers=headers, json_body=baseline_body,
                test_phase="default_creds_baseline", parameter=username_path,
                payload="invalid-baseline",
            )
            baseline_status = getattr(baseline, "status_code", 0)
            # If the invalid credential already "succeeds", the endpoint accepts
            # anything (or is not really a login) — do not manufacture a finding.
            if self._looks_like_auth_success(baseline_status, getattr(baseline, "body", "") or "", -1):
                return []

            for user, password in candidates[: self._MAX_CRED_ATTEMPTS]:
                attempt_body = copy.deepcopy(record["body"])
                self._set_body_path(attempt_body, username_path, user)
                self._set_body_path(attempt_body, password_path, password)
                resp = await verifier.send_request(
                    record["url"], record["method"], None, None,
                    headers=headers, json_body=attempt_body,
                    test_phase="default_credentials_probe", parameter=username_path,
                    payload=f"{user}:{password}",
                )
                status = getattr(resp, "status_code", 0)
                body = getattr(resp, "body", "") or ""
                # A genuine lockout/rate-limit (NOT a plain 401 rejection) means we
                # must stop probing; a 401 is the expected per-attempt failure.
                if status in {423, 429} or self._rate_limit_signals_present([resp]):
                    break
                if self._looks_like_auth_success(status, body, baseline_status):
                    return [
                        self._finding(
                            vuln_type="Default Credentials Accepted",
                            url=record["url"],
                            method=record["method"],
                            parameter=str(username_path),
                            payload=f"{user}:{password}",
                            severity=SeverityLevel.critical,
                            evidence=(
                                f"The login API accepted the weak/default credential pair "
                                f"'{user}' / '{password}'. The invalid-credential baseline returned "
                                f"HTTP {baseline_status}; this pair returned HTTP {status} with an "
                                "authentication token/success response. The identity was derived from "
                                "data the target itself exposed (no target-specific value was hardcoded)."
                            ),
                            verified=True,
                            detection_method="api_default_credentials_probe",
                            confidence_score=95.0,
                            verification_request_snippet=getattr(resp, "request_snippet", None),
                            verification_response_snippet=getattr(resp, "response_snippet", None),
                            detection_evidence={
                                "baseline_status": baseline_status,
                                "accepted_status": status,
                                "source": record["source"],
                                "email_login": email_login,
                            },
                        )
                    ]
            return []
        finally:
            await verifier.close()

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
            # SAFETY: change-password enforcement is now tested exclusively by
            # _test_change_password_current_bypass, which runs against a freshly
            # provisioned DISPOSABLE account. The previous probe here fired the
            # change on the user's REAL scan session, which would actually rotate
            # (and thereby lock out / invalidate) the account under test. Delegated
            # away so we never mutate the real account's password.
            return []
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
                findings.extend(await self._test_api_default_credentials(record, kwargs, session_cookies))
            elif flow_type in {"password_reset", "password_change", "mfa"}:
                findings.extend(
                    await self._test_api_single_request_control(
                        record,
                        session_cookies=session_cookies,
                        auth_headers=auth_headers,
                        flow_type=flow_type,
                    )
                )
            # Weak-recovery is a property of the fields, not the flow label: a reset
            # endpoint that also carries a new-password field is classified as
            # "password_change" above, so run this structural check on every record
            # and let its own field guards scope it to genuine recovery flows.
            findings.extend(self._security_question_recovery_findings(record))
        return findings

    def _security_question_recovery_findings(self, record: dict) -> list[Finding]:
        """Flag a password-reset flow that recovers accounts via a security question.

        Structural weakness (OWASP A07): security questions are low-entropy,
        often answerable from public/social data, and non-revocable. When a reset
        flow sets a new password gated only on a security-answer field — with no
        unguessable, single-use token/OTP/signed challenge — the recovery channel
        is the weakest link. This is a design finding (the fields are observed),
        not an exploit attempt; confidence is moderate and no answer is guessed.
        """
        fields = record["fields"]
        if not fields.get("security_answer"):
            return []
        # Scope to a genuine RECOVERY flow (not registration, which also collects a
        # security answer): either the body sets a new password, or the endpoint is
        # a reset/recovery path. Both are universal recovery signals.
        url_lower = str(record["url"]).lower()
        is_recovery = bool(fields.get("new_password")) or self._url_contains(url_lower, self.reset_tokens)
        if not is_recovery:
            return []
        # A genuine unguessable factor (token/OTP/signed challenge) alongside the
        # security answer is defence-in-depth, not security-question-only recovery.
        if fields.get("token") or fields.get("mfa_code"):
            return []
        # This is a structural finding over an OBSERVED reset request; reconstruct
        # the request snippet from the recorded url/method/headers/body so the
        # report shows the exact request the weakness was found in.
        request_snippet = build_observed_request_snippet(
            url=record["url"],
            method=record["method"],
            headers=record.get("headers"),
            body=record.get("body"),
        )
        return [
            self._finding(
                vuln_type="Password Reset Relies on Security Question (Weak Recovery)",
                url=record["url"],
                method=record["method"],
                parameter=str(fields.get("security_answer")),
                severity=SeverityLevel.medium,
                evidence=(
                    "The password-reset flow sets a new password gated only on a security-answer "
                    "field, with no unguessable token, OTP, or signed challenge. Security questions "
                    "are low-entropy and frequently answerable from public data, making this recovery "
                    "channel a weak link for account takeover."
                ),
                verified=True,
                detection_method="security_question_recovery_pattern",
                confidence_score=65.0,
                verification_request_snippet=request_snippet,
                detection_evidence={
                    "security_answer_field": fields.get("security_answer"),
                    "new_password_field": fields.get("new_password"),
                    "source": record["source"],
                },
            )
        ]

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

    # ---------------------------------------------------------------------------
    # Active JWT forgery
    # ---------------------------------------------------------------------------

    @staticmethod
    def _b64url(raw: bytes) -> str:
        return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")

    # Standard JWT identity claim names (RFC 7519 + common vendor claims). Used to
    # substitute a canary so a reflected forged identity is undeniable proof. Generic
    # — no target-specific claim names.
    _IDENTITY_CLAIM_KEYS = frozenset({
        "email", "mail", "e-mail", "sub", "username", "user", "user_name",
        "preferred_username", "name", "login", "uid", "upn", "unique_name",
        "nameid", "id", "userid", "user_id", "account", "role", "roles",
    })

    def _unsigned_token(self, header: dict, payload: dict, alg: str = "none") -> str:
        payload_segment = self._b64url(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
        header_segment = self._b64url(json.dumps({**header, "alg": alg}, separators=(",", ":")).encode("utf-8"))
        return f"{header_segment}.{payload_segment}."

    def _forge_alg_none(self, header: dict, payload: dict) -> list[tuple[str, str]]:
        """Forge unsigned tokens for the payload across alg=none casing variants.

        A JWT library that honours ``alg:none`` accepts a token with an empty
        signature. Casing variants defeat naive blocklists that only reject the
        exact lowercase string. Returns ``(label, token)`` pairs.
        """
        return [
            (f"alg={variant}", self._unsigned_token(header, payload, variant))
            for variant in ("none", "None", "NONE", "nOnE")
        ]

    def _inject_canary(self, payload: dict, canary: str) -> dict | None:
        """Deep-copy *payload* with a canary substituted into identity claims.

        Returns the mutated payload when at least one identity claim was replaced,
        else ``None``. Reflecting this canary back proves the server both accepted an
        unsigned token AND trusted its (attacker-chosen) identity claims.
        """
        clone = copy.deepcopy(payload)
        count = 0

        def walk(node: object) -> None:
            nonlocal count
            if isinstance(node, dict):
                for key, value in list(node.items()):
                    if isinstance(value, str) and str(key).lower() in self._IDENTITY_CLAIM_KEYS:
                        node[key] = canary
                        count += 1
                    else:
                        walk(value)
            elif isinstance(node, list):
                for value in node:
                    walk(value)

        walk(clone)
        return clone if count else None

    def _forge_key_confusion(self, header: dict, payload: dict, public_key_pem: str) -> str | None:
        """Forge an HS256 token signed with the server's RSA public key as the HMAC secret.

        Algorithm-confusion: a server that verifies with ``jwt.verify(token, publicKey)``
        while allowing symmetric algorithms will validate an HS256 token whose MAC
        key is the (public) PEM it also uses to verify RS256. Generic to any RSA-JWT
        service whose public key is obtainable via standard discovery.
        """
        try:
            import jwt as pyjwt  # PyJWT

            new_header = {key: value for key, value in header.items() if key.lower() != "alg"}
            return pyjwt.encode(
                payload,
                key=public_key_pem,
                algorithm="HS256",
                headers={**new_header, "alg": "HS256"},
            )
        except Exception:
            return None

    @staticmethod
    def _jwks_to_pems(jwks: object) -> list[str]:
        """Convert RSA keys in a JWKS document to PEM public keys (best-effort)."""
        pems: list[str] = []
        keys = jwks.get("keys", []) if isinstance(jwks, dict) else []
        for jwk in keys if isinstance(keys, list) else []:
            if not isinstance(jwk, dict) or jwk.get("kty") != "RSA" or "n" not in jwk or "e" not in jwk:
                continue
            try:
                from cryptography.hazmat.primitives import serialization
                from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers

                def _int(segment: str) -> int:
                    padded = segment + "=" * (-len(segment) % 4)
                    return int.from_bytes(base64.urlsafe_b64decode(padded.encode("ascii")), "big")

                public_key = RSAPublicNumbers(_int(jwk["e"]), _int(jwk["n"])).public_key()
                pem = public_key.public_bytes(
                    serialization.Encoding.PEM,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                ).decode("ascii")
                pems.append(pem)
            except Exception:
                continue
        return pems

    async def _fetch_jwks_pems(self, kwargs: dict[str, object], verifier: object) -> list[str]:
        """Discover RSA public keys via STANDARD JWKS endpoints only (no app paths)."""
        root_url = str(kwargs.get("root_url") or "")
        if not root_url:
            return []
        parsed = urlparse(root_url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        pems: list[str] = []
        for path in ("/.well-known/openid-configuration", "/.well-known/jwks.json"):
            try:
                resp = await verifier.send_request(
                    base + path, "GET", None, None,
                    test_phase="jwt_jwks_discovery", module="auth",
                )
                if not (200 <= getattr(resp, "status_code", 0) < 300):
                    continue
                document = json.loads(getattr(resp, "body", "") or "{}")
            except Exception:
                continue
            jwks = document
            if isinstance(document, dict) and document.get("jwks_uri"):
                try:
                    resp2 = await verifier.send_request(
                        str(document["jwks_uri"]), "GET", None, None,
                        test_phase="jwt_jwks_fetch", module="auth",
                    )
                    jwks = json.loads(getattr(resp2, "body", "") or "{}")
                except Exception:
                    continue
            pems.extend(self._jwks_to_pems(jwks))
        # De-duplicate while preserving order.
        seen: set[str] = set()
        unique: list[str] = []
        for pem in pems:
            if pem not in seen:
                seen.add(pem)
                unique.append(pem)
        return unique

    # Generic REST/English conventions for identity-reflecting endpoints. Used only
    # to RANK candidates so the limited oracle budget is spent on the endpoints most
    # likely to be a forgery oracle — NOT to gate detection (any endpoint that shows
    # an auth differential still qualifies). Contains no target-specific paths.
    _IDENTITY_PATH_TOKENS = (
        "whoami", "userinfo", "me", "self", "current", "profile", "account",
        "session", "identity", "user", "users", "member", "principal", "dashboard",
    )
    # Generic static-asset markers: an asset can never be an auth oracle.
    _STATIC_ASSET_EXTS = frozenset({
        "js", "mjs", "css", "scss", "map", "png", "jpg", "jpeg", "gif", "svg",
        "ico", "webp", "woff", "woff2", "ttf", "eot", "otf",
    })
    _STATIC_ASSET_DIRS = ("/assets/", "/static/", "/i18n/", "/fonts/", "/images/", "/img/")

    @classmethod
    def _is_static_asset(cls, url: str) -> bool:
        path = urlparse(url).path.lower()
        if any(seg in path for seg in cls._STATIC_ASSET_DIRS):
            return True
        last = path.rsplit("/", 1)[-1]
        if "." in last:
            return last.rsplit(".", 1)[-1] in cls._STATIC_ASSET_EXTS
        return False

    def _token_carriers_from_request(self, request: object) -> list[dict]:
        """How a JWT was presented on an observed request (header and/or cookie).

        Returns carrier descriptors ``{loc, name, scheme, token}`` so a forged token
        can later be replayed in the SAME location the application actually reads it
        from. Framework-agnostic: covers ``Authorization: Bearer`` headers and any
        cookie whose value is JWT-shaped (the common SPA pattern).
        """
        carriers: list[dict] = []
        headers = dict(getattr(request, "request_headers", {}) or {})
        bearer = self._extract_bearer(headers)
        if bearer and self._looks_like_jwt(bearer):
            carriers.append({"loc": "header", "name": "Authorization", "scheme": "Bearer ", "token": bearer})

        cookies = dict(getattr(request, "request_cookies", {}) or {})
        if not cookies:
            cookie_header = next((v for k, v in headers.items() if k.lower() == "cookie"), "")
            for part in str(cookie_header).split(";"):
                if "=" in part:
                    name, value = part.split("=", 1)
                    cookies[name.strip()] = value.strip()
        for name, value in cookies.items():
            if self._looks_like_jwt(str(value)):
                carriers.append({"loc": "cookie", "name": str(name), "scheme": "", "token": str(value)})
        return carriers

    def _forgery_oracle_candidates(self, kwargs: dict[str, object]) -> list[dict]:
        """Observed GET endpoints that carried a JWT (header OR cookie), ranked.

        Static assets are dropped (never an auth oracle) and identity-reflecting
        endpoints are ranked first so the budgeted oracle probes land on the URLs
        most likely to expose a signature-verification bypass. The auth differential
        measured later — not this ranking — is what actually qualifies an oracle.
        """
        ranked: list[tuple[int, str, list[dict]]] = []
        seen: set[str] = set()
        for request in kwargs.get("requests") or []:
            if str(getattr(request, "method", "GET") or "GET").upper() != "GET":
                continue
            url = str(getattr(request, "url", "") or "")
            if not url or url in seen:
                continue
            if self._is_static_asset(url):
                continue
            carriers = self._token_carriers_from_request(request)
            if not carriers:
                continue
            seen.add(url)
            path = urlparse(url).path.lower()
            rank = 0 if any(tok in path for tok in self._IDENTITY_PATH_TOKENS) else 1
            ranked.append((rank, url, carriers))
        ranked.sort(key=lambda item: item[0])
        return [{"url": url, "carriers": carriers} for _rank, url, carriers in ranked[:6]]

    @staticmethod
    async def _send_via_carrier(verifier: object, url: str, token: str | None, carrier: dict, *, phase: str) -> object:
        """Send GET *url* presenting *token* (or nothing) in the carrier's location."""
        headers: dict | None = None
        cookies: dict | None = None
        if token is not None:
            if carrier.get("loc") == "cookie":
                cookies = {carrier["name"]: token}
            else:
                headers = {carrier.get("name", "Authorization"): f"{carrier.get('scheme', '')}{token}"}
        return await verifier.send_request(
            url, "GET", None, None,
            headers=headers, cookies=cookies,
            test_phase=phase, module="auth", parameter="jwt",
        )

    @staticmethod
    def _identity_signal_values(payload: object, authed_body: str, noauth_body: str) -> list[str]:
        """Token-derived identity markers reflected ONLY in the authenticated body.

        Walks the JWT payload for scalar leaf values (emails, usernames, numeric ids,
        etc.) and keeps those that appear in the authenticated response but NOT in the
        no-auth response. Such a value is a zero-FP "the server trusted this token's
        claims" signal: its later reappearance under a forged token proves acceptance,
        and its absence from the no-auth baseline rules out coincidental/public echo.
        """
        candidates: list[str] = []

        def walk(node: object) -> None:
            if isinstance(node, dict):
                for value in node.values():
                    walk(value)
            elif isinstance(node, list):
                for value in node:
                    walk(value)
            elif isinstance(node, bool):
                return
            elif isinstance(node, str):
                if len(node) >= 4:
                    candidates.append(node)
            elif isinstance(node, int):
                if node > 999:
                    candidates.append(str(node))

        walk(payload)
        signal: list[str] = []
        for value in candidates:
            if value in authed_body and value not in noauth_body and value not in signal:
                signal.append(value)
        return signal

    async def _establish_forgery_oracle(self, verifier: object, url: str, carriers: list[dict]) -> dict | None:
        """Confirm *url* distinguishes authed from unauthenticated, via ANY carrier.

        For each observed carrier (header / cookie), replays no-token vs the real
        token and looks for an auth differential by EITHER status code (401/403 → 2xx)
        OR body content (token identity claims reflected only when authenticated). The
        first carrier that shows a differential wins; returns the winning carrier plus
        the markers used to judge forgery acceptance. ``None`` when the endpoint is
        public / not a usable oracle. No session cookies are sent, so authentication
        is attributable solely to the presented token.
        """
        for carrier in carriers:
            base_token = carrier.get("token")
            if not base_token or not self._decode_jwt(base_token):
                continue
            no_auth = await self._send_via_carrier(verifier, url, None, carrier, phase="jwt_forgery_noauth")
            real = await self._send_via_carrier(verifier, url, base_token, carrier, phase="jwt_forgery_baseline")
            if getattr(no_auth, "not_tested", False) or getattr(real, "not_tested", False):
                continue

            noauth_status = getattr(no_auth, "status_code", 0)
            real_status = getattr(real, "status_code", 0)
            status_based = noauth_status in (401, 403) and 200 <= real_status < 300

            _header, payload = self._decode_jwt(base_token)
            signal_values = self._identity_signal_values(
                payload, getattr(real, "body", "") or "", getattr(no_auth, "body", "") or ""
            )

            if status_based or signal_values:
                return {
                    "carrier": carrier,
                    "base_token": base_token,
                    "real_status": real_status,
                    "noauth_status": noauth_status,
                    "status_based": status_based,
                    "signal_values": signal_values,
                }
        return None

    @staticmethod
    def _mask_marker(value: str) -> str:
        """Partially mask a reflected identity marker for evidence text."""
        value = str(value)
        if len(value) <= 6:
            return "…"
        return f"{value[:2]}…{value[-2:]}"

    def _judge_forgery(self, resp: object, oracle: dict, canary: str | None) -> dict | None:
        """Decide whether a forged token was accepted. Zero-FP by construction.

        A canary token counts only if the canary reflects (undeniable identity
        injection). An unchanged-payload token counts if it reproduces the authed
        response class: token-derived identity markers that were absent from the
        no-auth baseline reappear, or (for a status-gated oracle) it returns 2xx.
        """
        if getattr(resp, "not_tested", False):
            return None
        status = getattr(resp, "status_code", 0)
        body = getattr(resp, "body", "") or ""
        if canary is not None:
            if canary in body:
                return {"mode": "identity-injection", "markers": [canary], "status": status}
            return None
        hits = [v for v in oracle["signal_values"] if v in body]
        if hits:
            return {"mode": "identity-reflection", "markers": hits, "status": status}
        if oracle["status_based"] and 200 <= status < 300:
            return {"mode": "status-differential", "markers": [], "status": status}
        return None

    async def _active_jwt_forgery_findings(
        self,
        kwargs: dict[str, object],
        session_cookies: dict,
    ) -> list[Finding]:
        """Actively forge the scanner's own JWT and flag only if the forgery is accepted.

        Upgrades passive ``alg=none``/signature notes to a VERIFIED finding: a forged
        token accepted by an endpoint that distinguishes authenticated from anonymous
        access proves signature verification is broken. The oracle differential is
        measured by status code OR response body (identity claim reflection), and the
        forged token is replayed in the SAME carrier (Authorization header or cookie)
        the application actually reads — so the check works for header- and cookie-
        based JWT auth alike. Idempotent GET only; runs solely when an observed
        JWT-carrying GET oracle exists, so it adds near-zero cost otherwise. Session
        cookies are excluded so acceptance is attributable to the forged token alone.
        """
        candidates = self._forgery_oracle_candidates(kwargs)
        if not candidates:
            return []

        from app.core.verification.verification_framework import HttpVerifier

        verifier = HttpVerifier()  # no session cookies: the presented token is the only auth factor
        try:
            for candidate in candidates:
                url = candidate["url"]
                oracle = await self._establish_forgery_oracle(verifier, url, candidate["carriers"])
                if oracle is None:
                    continue

                carrier = oracle["carrier"]
                header, payload = self._decode_jwt(oracle["base_token"])

                # (label, token, canary) — canary None means unchanged payload.
                forged: list[tuple[str, str, str | None]] = [
                    (label, token, None) for label, token in self._forge_alg_none(header, payload)
                ]
                canary = "sentryjwt" + secrets.token_hex(6)
                canary_payload = self._inject_canary(payload, canary)
                if canary_payload is not None:
                    forged.append(("alg=none (identity-forged)", self._unsigned_token(header, canary_payload), canary))
                if str(header.get("alg", "")).upper().startswith(("RS", "ES", "PS")):
                    for pem in await self._fetch_jwks_pems(kwargs, verifier):
                        confused = self._forge_key_confusion(header, payload, pem)
                        if confused:
                            forged.append(("algorithm confusion (RS→HS256)", confused, None))

                for label, token, tok_canary in forged:
                    resp = await self._send_via_carrier(verifier, url, token, carrier, phase="jwt_forgery_attempt")
                    proof = self._judge_forgery(resp, oracle, tok_canary)
                    if proof is None:
                        continue

                    is_none = label.startswith("alg=")
                    carrier_desc = (
                        f"cookie '{carrier['name']}'" if carrier["loc"] == "cookie"
                        else f"'{carrier['name']}' header"
                    )
                    if proof["mode"] == "identity-injection":
                        proof_text = (
                            "the forged token's attacker-chosen identity claim was reflected in the "
                            f"response (marker '{self._mask_marker(proof['markers'][0])}'), proving arbitrary "
                            "identity/role forgery"
                        )
                    elif proof["mode"] == "identity-reflection":
                        proof_text = (
                            "the forged token reproduced the authenticated identity in the response "
                            f"(marker {self._mask_marker(proof['markers'][0])}) that the anonymous baseline did not"
                        )
                    else:
                        proof_text = (
                            f"the no-auth baseline was denied {oracle['noauth_status']} and the forged token "
                            f"returned {proof['status']}"
                        )
                    return [
                        self._finding(
                            vuln_type=(
                                "JWT alg=none Forgery Accepted" if is_none
                                else "JWT Algorithm-Confusion Forgery Accepted"
                            ),
                            url=url,
                            severity=SeverityLevel.critical,
                            evidence=(
                                f"A forged JWT ({label}) built from the scanner's own token, presented via the "
                                f"{carrier_desc}, was accepted by an authentication-gated endpoint: {proof_text}. "
                                "Signature verification is not enforced — any user or role can be impersonated."
                            ),
                            verified=True,
                            detection_method="jwt_active_forgery",
                            confidence_score=95.0,
                            verification_request_snippet=getattr(resp, "request_snippet", None),
                            verification_response_snippet=getattr(resp, "response_snippet", None),
                            detection_evidence={
                                "forgery": label,
                                "proof_mode": proof["mode"],
                                "carrier": f"{carrier['loc']}:{carrier['name']}",
                                "oracle_url": url,
                                "real_status": oracle["real_status"],
                                "noauth_status": oracle["noauth_status"],
                                "forged_status": proof["status"],
                            },
                        )
                    ]
            return []
        finally:
            await verifier.close()

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
                # Derived from an OBSERVED request; reconstruct its snippet so the
                # report shows the exact request whose response set the weak cookie.
                request_snippet = build_observed_request_snippet(
                    url=key[0],
                    method=str(getattr(request, "method", "GET") or "GET"),
                    headers=getattr(request, "request_headers", None),
                    cookies=getattr(request, "request_cookies", None),
                    body=getattr(request, "post_data", None),
                )
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
                        verification_request_snippet=request_snippet,
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

    # ---------------------------------------------------------------------------
    # Change-password: current-password enforcement (safe, disposable-account test)
    # ---------------------------------------------------------------------------

    # Path fragments (separator-stripped) that mark a change-password endpoint, and
    # separator-stripped parameter names for each password field. Generic — no
    # target-specific paths or fields.
    _CHANGE_PW_PATH_TOKENS = (
        "changepassword", "updatepassword", "setpassword",
        "passwordchange", "passwordupdate", "accountpassword",
    )
    _NEW_PW_PARAMS = frozenset({"newpassword", "newpass", "passwordnew", "new"})
    _REPEAT_PW_PARAMS = frozenset({
        "passwordrepeat", "repeatpassword", "confirmpassword", "passwordconfirmation",
        "passwordconfirm", "confirm", "repeat",
    })
    _CURRENT_PW_PARAMS = frozenset({
        "currentpassword", "oldpassword", "existingpassword", "currentpwd", "oldpwd",
        "current", "old", "existing",
    })

    @staticmethod
    def _norm_param(name: object) -> str:
        return re.sub(r"[^a-z0-9]", "", str(name).lower())

    def _classify_pw_params(self, names: list[str]) -> dict:
        found = {"new": None, "repeat": None, "current": None}
        for name in names:
            n = self._norm_param(name)
            if found["new"] is None and n in self._NEW_PW_PARAMS:
                found["new"] = name
            elif found["repeat"] is None and n in self._REPEAT_PW_PARAMS:
                found["repeat"] = name
            elif found["current"] is None and n in self._CURRENT_PW_PARAMS:
                found["current"] = name
        return found

    def _find_change_password_endpoint(self, kwargs: dict[str, object]) -> dict | None:
        """Locate a change-password endpoint (query- or body-parameterised).

        Keyed on a generic path fragment plus a discoverable new-password field, so
        it matches ``GET /rest/user/change-password?current=&new=&repeat=`` and
        ``POST /api/account/change-password {oldPassword,newPassword}`` alike.
        """
        for request in kwargs.get("requests") or []:
            url = str(getattr(request, "url", "") or "")
            if not url:
                continue
            path_norm = re.sub(r"[^a-z0-9]", "", urlparse(url).path.lower())
            if not any(tok in path_norm for tok in self._CHANGE_PW_PATH_TOKENS):
                continue
            method = str(getattr(request, "method", "GET") or "GET").upper()

            query_names = [k for k, _ in parse_qsl(urlparse(url).query, keep_blank_values=True)]
            q_class = self._classify_pw_params(query_names)
            if q_class["new"]:
                return {"url": url.split("?")[0], "method": method, "location": "query", **q_class}

            # Body-parameterised change-password: preserve the observed ENCODING so
            # the probe is replayed the same way the app expects it (JSON vs
            # form-urlencoded), otherwise a correct endpoint would 400 on the wrong
            # content type and the vuln would be missed.
            body = getattr(request, "post_data", None)
            content_type = str(getattr(request, "request_content_type", "") or "").lower()
            body_names: list[str] = []
            encoding = "json"
            if isinstance(body, dict):
                body_names = list(body.keys())
                encoding = "form" if "form-urlencoded" in content_type else "json"
            elif isinstance(body, str) and body.strip():
                parsed = None
                try:
                    parsed = json.loads(body)
                except Exception:
                    parsed = None
                if isinstance(parsed, dict) and "form-urlencoded" not in content_type:
                    body_names = list(parsed.keys())
                    encoding = "json"
                else:
                    body_names = [k for k, _ in parse_qsl(body, keep_blank_values=True)]
                    encoding = "form"
            if "json" in content_type:
                encoding = "json"
            elif "form-urlencoded" in content_type:
                encoding = "form"
            b_class = self._classify_pw_params(body_names)
            if b_class["new"]:
                return {"url": url.split("?")[0], "method": method or "POST", "location": encoding, **b_class}
        return None

    def _build_change_pw_request(self, endpoint: dict, new_pw: str, current_value: str | None):
        """Return (url, method, params, data, json_body) for a change-password attempt.

        Honours the endpoint's observed transport — query string, JSON body, or
        form-urlencoded body — so the probe matches how the server accepts input.
        """
        fields: dict[str, str] = {endpoint["new"]: new_pw}
        if endpoint.get("repeat"):
            fields[endpoint["repeat"]] = new_pw
        if current_value is not None and endpoint.get("current"):
            fields[endpoint["current"]] = current_value
        location = endpoint["location"]
        method = endpoint["method"] or ("GET" if location == "query" else "POST")
        if location == "query":
            return f"{endpoint['url']}?{urlencode(fields)}", method, None, None, None
        if location == "form":
            return endpoint["url"], method, None, fields, None
        return endpoint["url"], method, None, None, fields

    async def _test_change_password_current_bypass(self, kwargs: dict[str, object]) -> list[Finding]:
        """Safely test whether change-password enforces the current password.

        Runs entirely against a freshly provisioned, DISPOSABLE throwaway account —
        never the user's scan session — so a successful password change cannot lock
        anyone out or invalidate the scan. Each variant forward-changes the throwaway
        password (no revert needed, so password-reuse policies are irrelevant), and a
        finding is raised only when a login with the NEW password succeeds, proving
        the change actually took effect without a valid current credential.
        """
        endpoint = self._find_change_password_endpoint(kwargs)
        if endpoint is None:
            return []
        root_url = str(kwargs.get("root_url") or "")
        if not root_url:
            return []

        from app.core.crawler.account_session import account_login_succeeds, provision_disposable_account
        from app.core.verification.verification_framework import HttpVerifier

        account = await provision_disposable_account(root_url)
        if account is None:
            # Provisioning disabled or not possible → cannot test safely → skip.
            return []

        verifier = HttpVerifier(cookies=account.session.cookies, headers=account.session.headers)
        verifier.set_request_context(module="auth", parameter="change-password")
        try:
            # Two safe bypass variants on the throwaway: omit the current-password
            # field, then supply a deliberately wrong one. A correctly-enforcing
            # endpoint rejects both (login with the new password then fails).
            variants: list[tuple[str, str | None]] = [
                ("current-omitted", None),
                ("current-wrong", "sentry_wrong_" + secrets.token_hex(4)),
            ]
            for label, current_value in variants:
                new_pw = "Sn!" + secrets.token_urlsafe(12)
                url, method, params, data, json_body = self._build_change_pw_request(endpoint, new_pw, current_value)
                resp = await verifier.send_request(
                    url, method, params, data, json_body=json_body,
                    test_phase="change_password_current_bypass", parameter="change-password",
                )
                if getattr(resp, "not_tested", False):
                    continue
                if await account_login_succeeds(root_url, account.email, new_pw):
                    how = "omitted" if current_value is None else "set to a wrong value"
                    return [
                        self._finding(
                            vuln_type="Password Change Does Not Require Current Password",
                            url=endpoint["url"],
                            method=method,
                            severity=SeverityLevel.critical,
                            evidence=(
                                "On a throwaway account, the change-password endpoint accepted a new password "
                                f"with the current-password {how}, and the account password was actually changed "
                                "— confirmed by logging in with the new password. The endpoint does not verify the "
                                "current credential, enabling account takeover from any active or CSRF'd session "
                                "(CWE-620). Tested on a disposable identity; no real account was affected."
                            ),
                            verified=True,
                            detection_method="change_password_current_bypass_login_confirmed",
                            confidence_score=95.0,
                            category=OwaspCategory.a07,
                            verification_request_snippet=getattr(resp, "request_snippet", None),
                            verification_response_snippet=getattr(resp, "response_snippet", None),
                            detection_evidence={
                                "bypass_variant": label,
                                "endpoint_location": endpoint["location"],
                                "confirmation": "login_with_new_password_succeeded",
                            },
                        )
                    ]
            return []
        finally:
            await verifier.close()

    async def _inspect_tokens_and_sessions(
        self,
        kwargs: dict[str, object],
        session_cookies: dict,
    ) -> list[Finding]:
        findings = []
        findings.extend(self._jwt_findings(kwargs, session_cookies))
        findings.extend(await self._active_jwt_forgery_findings(kwargs, session_cookies))
        findings.extend(self._cookie_attribute_findings(kwargs))
        findings.extend(await self._logout_token_reuse_findings(kwargs, session_cookies))
        findings.extend(await self._test_change_password_current_bypass(kwargs))
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

            # A form whose action is a client-side (hash) route posts to the SPA
            # shell, not a server endpoint: the "#/login" fragment never leaves the
            # browser, so there is no server-side form handler and no place for a
            # CSRF hidden token to live (SPAs authenticate with bearer tokens the
            # browser does not attach cross-site). Detect this precisely so a normal
            # multi-page-app login form is NOT affected: only skip when the action's
            # real (pre-fragment) path is the app shell ("" or "/") AND it carries a
            # fragment route. "/login" or "/login#anchor" keep a real path → not a
            # shell form → still checked.
            _parsed_action = urlparse(form_url or "")
            posts_to_spa_shell = bool(_parsed_action.fragment) and (_parsed_action.path or "") in ("", "/")

            has_password = bool(input_names.intersection({"password", "passwd", "pass", "pwd", "passphrase", "secret"})
                                or "password" in input_types)
            has_username = bool(input_names.intersection({"username", "user", "email", "mail", "login",
                                                           "uname", "phone", "mobile", "account"}))
            has_hidden   = "hidden" in input_types

            # 1. Login form discovered → run active auth tests.
            if has_username and has_password:
                # A form whose action is a client-side (hash) route posts to the
                # SPA shell, not a login handler — every attempt returns the app
                # index, so active probing there is meaningless and yields a
                # misleading "no brute-force protection" on the shell. For SPAs the
                # REAL JSON login endpoint is exercised by the API auth-workflow
                # path (fed by the winning login recipe), so skip the shell form.
                if "#" in form_url:
                    logger.debug("skipping active auth on client-route form action: %s", form_url)
                else:
                    active_findings = await self._test_active_auth(
                        form_url, form_method, raw_inputs, session_cookies, kwargs
                    )
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

            # 7. Hidden inputs on auth forms → CSRF token presence / absence check.
            # Skip SPA-shell forms (see posts_to_spa_shell): a hash-route action has
            # no server-side form handler, so "no hidden CSRF field" is meaningless
            # (and misleading) there. A normal MPA login form is unaffected.
            #
            # Require an actual credential field (has_password). An identity field
            # alone (email/user) does NOT make a form an authentication form — a
            # contact, feedback, newsletter, data-erasure, or password-reset form
            # all carry `email` without being login forms, and mislabelling them
            # as "Authentication Form ... Lacks CSRF" is a false positive. Real
            # (non-login) CSRF on those endpoints is still covered by the CSRF
            # detector's active token-bypass verification.
            if has_password and not has_hidden and not posts_to_spa_shell:
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

    # SQL-statement keywords used to recognise a reflected query echo (see
    # ``_is_reflected_sql_echo``). Injection detectors surface DB error bodies
    # that echo the application's own query — ``... WHERE email = '<payload>' AND
    # password = '<hash>' ...`` — where ``password =`` is a SQL comparison, not a
    # disclosed credential. Framework-agnostic: SQL keyword syntax is universal.
    _SQL_STATEMENT_RE = re.compile(r"\b(?:select|insert|update|delete)\b", re.IGNORECASE)
    _SQL_PASSWORD_COMPARISON_RE = re.compile(
        r"(?:where\b[^;]{0,300}?)?password\s*=\s*['\"]", re.IGNORECASE | re.DOTALL
    )

    @classmethod
    def _is_reflected_sql_echo(cls, text: str) -> bool:
        """True when a ``password =`` match is part of an echoed SQL statement.

        A DB error that reflects the query (``SELECT ... WHERE ... password =
        '...'``) is not a credential/config disclosure — it is the injected query
        surfaced by the source injection finding, already reported there. Only a
        genuine config-style assignment (``db_password=...`` outside any SQL
        statement) should survive as credential disclosure.
        """
        if not cls._SQL_STATEMENT_RE.search(text):
            return False
        return bool(cls._SQL_PASSWORD_COMPARISON_RE.search(text))

    @classmethod
    def _filter_reflected_credential_matches(
        cls, text: str, matched_patterns: list[str]
    ) -> list[str]:
        if not matched_patterns:
            return matched_patterns
        if not cls._is_reflected_sql_echo(text):
            return matched_patterns
        # Drop the bare ``password =`` comparison echoed from SQL; keep explicit
        # config keys (db_password/database_password/db_pass) which never appear
        # as a SQL comparison operand.
        return [p for p in matched_patterns if p != r"password\s*="]

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
            matched_patterns = self._filter_reflected_credential_matches(
                observed_text, matched_patterns
            )
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
