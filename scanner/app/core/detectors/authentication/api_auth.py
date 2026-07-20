import asyncio
import copy
import json
import logging
import re
import time
from urllib.parse import urlparse

from app.config import get_settings
from app.core.detectors.base_detector import Finding
from shared.models.vulnerability import SeverityLevel

logger = logging.getLogger("app.core.detectors.auth_detector")

_MISSING = object()


class AuthApiProbeMixin:
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
                paths.extend(AuthApiProbeMixin._body_paths(value, path))
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
        # The scanner's own winning JSON login recipe can seed API probes even
        # when the login XHR was not captured or mined from JavaScript. HTML-form
        # replays are intentionally excluded: their payload must not be rewritten
        # as JSON and sent to an API-only probe.
        replay = kwargs.get("auth_replay_state")
        if (
            replay is not None
            and getattr(replay, "is_json", False)
            and getattr(replay, "payload", None)
        ):
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
