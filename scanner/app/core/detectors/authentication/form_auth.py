import asyncio
import logging
import statistics

from app.core.detectors.base_detector import Finding
from shared.models.vulnerability import OwaspCategory, SeverityLevel

logger = logging.getLogger("app.core.detectors.auth_detector")


class FormAuthProbeMixin:
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
            #   Default pairs (varied username + password)
            #             → detects Default Credentials Accepted (critical)
            #             → each failed attempt contributes to the lockout counter
            #
            #   Password stuffing (fixed bogus username, varied password)
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
            # Default pairs (varied username). The very first pair uses the
            # known-bogus username so its response becomes the baseline body
            # length / status for success detection.
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

            # Password-stuffing phase: fixed bogus username with varied passwords.
            # These extend the sequential attempt count without re-testing default
            # usernames, covering the pure password-spray / credential-stuffing scenario.
            _stuffing_passwords = [
                "password", "password1", "password123", "123456",
                "letmein", "welcome", "monkey", "dragon",
                "qwerty123", "iloveyou",
            ]
            _stuffing_pairs: list[tuple[str, str]] = [
                (payload[username_param], pw) for pw in _stuffing_passwords
            ]

            _combined_pairs = _default_pairs + _stuffing_pairs
            # Attempts beyond this index use the fixed bogus username (stuffing).
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
