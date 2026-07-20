import json
import re
import secrets
from urllib.parse import parse_qsl, urlencode, urlparse

from app.core.detectors.base_detector import Finding
from app.utils.scan_http import build_observed_request_snippet
from shared.models.vulnerability import OwaspCategory, SeverityLevel


class SessionAuthProbeMixin:
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
