import asyncio
import json
import logging
import re
from urllib.parse import parse_qsl, unquote, urlparse, urlunparse

from app.core.crawler.api_extractor import ApiExtractor
from app.core.crawler.models import ParameterLocation
from app.core.crawler.spa import SpaFallbackDetector
from app.core.detectors.base_detector import BaseDetector, Finding
from app.core.verification.response_analyzer import ResponseAnalyzer
from app.core.verification.verification_framework import HttpVerifier, URLParameterBuilder
from shared.models.vulnerability import OwaspCategory, SeverityLevel

logger = logging.getLogger(__name__)

_MUTATING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

# Parameter-name tokens (separator-stripped) for change-password forms.
# Shared idea with SessionAuthProbeMixin - keep the sets aligned in spirit, not
# by importing that mixin (csrf must stay usable without the auth package).
_NEW_PASSWORD_PARAMS = frozenset({
    "newpassword", "newpass", "passwordnew", "new",
})
_CONFIRM_PASSWORD_PARAMS = frozenset({
    "passwordrepeat", "repeatpassword", "confirmpassword", "passwordconfirmation",
    "passwordconfirm", "confirm", "repeat", "passwordconf",
})
_CURRENT_PASSWORD_PARAMS = frozenset({
    "currentpassword", "oldpassword", "existingpassword", "currentpwd", "oldpwd",
    "current", "old", "existing", "passwordcurr",
})
# Affirmative that a password-change *handler* ran. Business validation may still
# fail (mismatch / wrong current) - that is enough CSRF proof and must not require
# committing a new password on the scan account.
_CREDENTIAL_ACTION_PROCESSED_RE = re.compile(
    r"\b(?:"
    r"passwords?\s+did\s+not\s+match|"
    r"passwords?\s+do(?:\s+not|n'?t)\s+match|"
    r"password\s+mismatch|"
    r"(?:new\s+)?passwords?\s+(?:do\s+not|dont|don't)\s+match|"
    r"current\s+password\s+(?:is\s+)?(?:incorrect|invalid|wrong)|"
    r"incorrect\s+(?:current\s+)?password|"
    r"password\s+(?:too\s+short|too\s+weak|required|changed|updated)|"
    r"successfully\s+changed"
    r")\b",
    re.I,
)


class _FormInputView:
    """Attribute view of a browser-discovered form input (dict → object)."""

    __slots__ = ("name", "input_type", "value")

    def __init__(self, name: str, input_type: str, value: object) -> None:
        self.name = name
        self.input_type = input_type
        self.value = value


class _FormView:
    """Attribute view of a browser-discovered form so it reads like an HtmlForm."""

    __slots__ = ("action", "page_url", "method", "inputs")

    def __init__(self, action: str, page_url: str, method: str, inputs: list) -> None:
        self.action = action
        self.page_url = page_url
        self.method = method
        self.inputs = inputs


class CSRFDetector(BaseDetector):
    name = "csrf"

    csrf_keywords = {"token", "csrf", "xsrf", "user_token", "session_token"}
    identity_fields = {
        "username", "user", "email", "mail", "login", "uname",
        "phone", "mobile", "account",
    }
    login_secret_fields = {"password", "passwd", "pass", "pwd", "passphrase", "secret"}
    state_changing_actions = {"password", "update", "change", "profile", "user", "admin", "delete", "add", "create", "settings", "save"}
    login_indicators = {
        "login", "signin", "sign-in", "authenticate", "auth", "session",
        "logout", "signout", "sign-out", "logoff",
    }

    @staticmethod
    def _norm_param(name: object) -> str:
        return re.sub(r"[^a-z0-9]", "", str(name or "").lower())

    @classmethod
    def _classify_password_fields(cls, raw_inputs: list) -> dict[str, list[str]]:
        """Split password-related fields into current / new / confirm buckets."""
        found: dict[str, list[str]] = {"current": [], "new": [], "confirm": []}
        password_typed: list[str] = []
        for inp in raw_inputs:
            name = getattr(inp, "name", "") or ""
            if not name:
                continue
            inp_type = (getattr(inp, "input_type", None) or "text").lower()
            norm = cls._norm_param(name)
            if inp_type == "password":
                password_typed.append(name)
            if norm in _CURRENT_PASSWORD_PARAMS:
                found["current"].append(name)
            elif norm in _CONFIRM_PASSWORD_PARAMS:
                found["confirm"].append(name)
            elif norm in _NEW_PASSWORD_PARAMS and norm != "password":
                found["new"].append(name)

        # Fallback: two+ password-typed fields without clear names → new + confirm.
        classified = {n for group in found.values() for n in group}
        leftover = [n for n in password_typed if n not in classified]
        if not found["new"] and leftover:
            found["new"].append(leftover[0])
            leftover = leftover[1:]
        if not found["confirm"] and leftover:
            found["confirm"].append(leftover[0])
        return found

    @classmethod
    def _is_credential_mutating_form(cls, raw_inputs: list) -> bool:
        """True for change-password forms, false for login (identity + password).

        Login forms are already filtered elsewhere; this guards password-change
        CSRF probes so they cannot rewrite the scan account's credentials.
        """
        names = {(getattr(inp, "name", None) or "").lower() for inp in raw_inputs}
        if names.intersection(cls.identity_fields) and names.intersection(cls.login_secret_fields):
            return False
        classified = cls._classify_password_fields(raw_inputs)
        has_password_typed = any(
            (getattr(inp, "input_type", None) or "").lower() == "password"
            or any(tok in (getattr(inp, "name", None) or "").lower() for tok in ("password", "passwd", "pwd"))
            for inp in raw_inputs
        )
        return bool(classified["new"] or classified["confirm"] or classified["current"] or has_password_typed)

    @classmethod
    def _credential_change_action_processed(cls, response: object) -> bool:
        """Handler ran for a password-change request (success or validation failure)."""
        if cls._response_rejected(response):
            return False
        status = int(getattr(response, "status_code", 0) or 0)
        if status not in {200, 201, 202, 204, 302, 303}:
            return False
        body = str(getattr(response, "body", "") or "")
        return bool(_CREDENTIAL_ACTION_PROCESSED_RE.search(body))

    @classmethod
    def _build_csrf_form_payload(cls, raw_inputs: list) -> tuple[dict[str, object], str | None, bool]:
        """Build probe fields for CSRF verification.

        Credential-mutating forms deliberately use non-matching new/confirm values
        (and a wrong current password when present) so a successful CSRF proof
        cannot permanently change the scan account password. Login forms are not
        expected here; callers already filter them.
        """
        credential_mutating = cls._is_credential_mutating_form(raw_inputs)
        classified = cls._classify_password_fields(raw_inputs) if credential_mutating else {
            "current": [], "new": [], "confirm": [],
        }
        csrf_param = None
        inputs_payload: dict[str, object] = {}
        for inp in raw_inputs:
            inp_name = getattr(inp, "name", "") or ""
            inp_type = (getattr(inp, "input_type", None) or "text").lower()
            if not inp_name:
                continue
            if inp_name.lower() in cls.csrf_keywords:
                csrf_param = inp_name
                inputs_payload[inp_name] = str(getattr(inp, "value", "") or "")
                continue
            if credential_mutating and inp_name in classified["confirm"]:
                inputs_payload[inp_name] = "sentry_new_password_b"
            elif credential_mutating and inp_name in classified["current"]:
                inputs_payload[inp_name] = "sentry_wrong_current_password"
            elif credential_mutating and (
                inp_name in classified["new"] or inp_type == "password"
                or any(tok in inp_name.lower() for tok in ("password", "passwd", "pwd"))
            ):
                # New password (or unclassified password-typed field): distinct from confirm.
                inputs_payload[inp_name] = "sentry_new_password_a"
            elif inp_type == "password":
                inputs_payload[inp_name] = "sentry_password123"
            elif inp_type in {"submit", "button", "image"}:
                inputs_payload[inp_name] = getattr(inp, "value", "Submit") or "Submit"
            else:
                inputs_payload[inp_name] = "sentry_test_val"
        return inputs_payload, csrf_param, credential_mutating

    @staticmethod
    def _normalize_form(form: object) -> object:
        """Coerce a browser-discovered form dict into an HtmlForm-like object.

        Static crawler forms (``HtmlForm``/``FormInput``) already expose the
        ``action``/``method``/``inputs`` attributes the detector reads, so they
        pass through untouched. Browser forms arrive as plain dicts.
        """
        if not isinstance(form, dict):
            return form
        action = str(form.get("action") or form.get("page_url") or "")
        page_url = str(form.get("page_url") or "")
        method = str(form.get("method") or "POST")
        inputs: list[object] = []
        for item in form.get("inputs") or []:
            if isinstance(item, dict):
                inputs.append(
                    _FormInputView(
                        name=str(item.get("name", "")),
                        input_type=str(item.get("type") or item.get("input_type") or "text"),
                        value=item.get("value", ""),
                    )
                )
            else:
                inputs.append(item)
        return _FormView(action=action, page_url=page_url, method=method, inputs=inputs)

    def _select_candidate_forms(self, forms: list[object]) -> list[tuple]:
        """Return state-changing, non-login form candidates for CSRF assessment.

        A form is a CSRF candidate when it is state-changing. The signal can
        come from three places:

          1. A mutating method (POST/PUT/PATCH/DELETE).
          2. A state-changing keyword in the URL path (update/change/delete/...).
          3. The form's fields: a password field, or a field the developer
             named like an anti-CSRF token (``token``/``csrf``/``user_token``).
             These mark a protected/mutating action even when the form submits
             via GET and its path carries no keyword.

        GET state-changing forms are actively verified here instead of producing
        a passive hint from the authentication detector.
        """
        form_candidates: list[tuple] = []
        for form in forms:
            form_url = getattr(form, "action", "") or getattr(form, "page_url", "")
            form_method = (getattr(form, "method", "POST") or "POST").upper()
            raw_inputs = list(getattr(form, "inputs", []))
            input_names_lower = {(getattr(inp, "name", None) or "").lower() for inp in raw_inputs}
            input_types_lower = {
                str(getattr(inp, "input_type", "") or "").lower() for inp in raw_inputs
            }

            # Check if form controls state-changing action
            url_path_lower = urlparse(form_url).path.lower()
            is_state_changing = any(kw in url_path_lower for kw in self.state_changing_actions)

            # Password and anti-CSRF fields can reveal mutating intent even when
            # the method and URL do not.
            has_password_field = "password" in input_types_lower or any(
                tok in name for name in input_names_lower
                for tok in ("password", "passwd", "pwd", "passphrase")
            )
            has_token_field = any(kw in name for name in input_names_lower for kw in self.csrf_keywords)
            has_state_changing_field = has_password_field or has_token_field

            # Skip login/auth forms (handled by auth detector)
            if any(tok in url_path_lower for tok in self.login_indicators):
                continue
            if (
                input_names_lower.intersection(self.identity_fields)
                and input_names_lower.intersection(self.login_secret_fields)
            ):
                continue

            # Filter out setup/install/onboarding routes - one-shot operations
            # that do not carry real CSRF risk beyond the initial configuration.
            setup_tokens = {"setup", "install", "wizard", "onboarding"}
            is_setup_route = any(tok in url_path_lower for tok in setup_tokens)

            if form_method in _MUTATING_METHODS or is_state_changing or has_state_changing_field:
                form_candidates.append((form_url, form_method, raw_inputs, is_setup_route))
        return form_candidates

    @staticmethod
    def _bare(url: str) -> str:
        """scheme://netloc/path with query/fragment stripped, for endpoint keys."""
        try:
            parsed = urlparse(url)
            return urlunparse((parsed.scheme, parsed.netloc, parsed.path.rstrip("/") or "/", "", "", "")).lower()
        except Exception:
            return (url or "").split("?")[0].rstrip("/").lower()

    def _mutating_endpoint_keys(self, requests: list, api_endpoints: list) -> set[str]:
        """Bare-URL keys of endpoints confirmed to be real mutating APIs.

        Sourced from observed non-GET XHR/fetch requests and from spec/JS-mined
        API endpoints with a mutating method. A client-side SPA navigation route
        (which returns the HTML shell) is never in this set, so CSRF findings can
        be restricted to genuine state-changing endpoints.
        """
        keys: set[str] = set()
        for observation in requests or []:
            method = (getattr(observation, "method", "GET") or "GET").upper()
            if method in _MUTATING_METHODS:
                keys.add(self._bare(getattr(observation, "url", "")))
        for endpoint in api_endpoints or []:
            method = (getattr(endpoint, "method", "GET") or "GET").upper()
            if method in _MUTATING_METHODS:
                keys.add(self._bare(getattr(endpoint, "url", "")))
        return keys

    def _candidates_from_requests(self, requests: list) -> list[tuple]:
        """Build CSRF candidates from observed mutating XHRs (real API endpoints).

        On a ``<form>``-less SPA these observed non-GET requests are the only
        genuine state-changing surface. Inputs are synthesised from the captured
        body schema so the tamper/Origin-bypass submission carries a realistic
        body. Marked ``is_real_api=True``.
        """
        candidates: list[tuple] = []
        seen: set[tuple[str, str]] = set()
        for observation in requests or []:
            method = (getattr(observation, "method", "GET") or "GET").upper()
            if method not in _MUTATING_METHODS:
                continue
            url = getattr(observation, "url", "")
            if not url:
                continue
            if self._has_unresolved_path_placeholder(url):
                continue
            key = (self._bare(url), method)
            if key in seen:
                continue
            seen.add(key)
            inputs = [
                _FormInputView(name=str(name), input_type="text", value="")
                for name in (getattr(observation, "body_schema", None) or [])
                if name
            ]
            content_type = str(getattr(observation, "request_content_type", "") or "")
            location = (
                ParameterLocation.form
                if "x-www-form-urlencoded" in content_type.lower()
                or "multipart/form-data" in content_type.lower()
                else ParameterLocation.json_body
            )
            candidates.append((url, method, inputs, False, True, location, content_type))
        return candidates

    def _candidates_from_api_endpoints(self, api_endpoints: list) -> list[tuple]:
        """Build CSRF candidates from discovered mutating API schemas/specs."""
        candidates: list[tuple] = []
        seen: set[tuple[str, str]] = set()
        for endpoint in api_endpoints or []:
            method = (getattr(endpoint, "method", "GET") or "GET").upper()
            if method not in _MUTATING_METHODS:
                continue
            if not ApiExtractor.is_api_endpoint(endpoint):
                continue
            content_type, template = ApiExtractor.synthesize_body_schema(
                endpoint,
                allow_generic_body=True,
            )
            if not isinstance(template, dict) or not template:
                continue
            url = str(getattr(endpoint, "url", "") or "")
            if not url:
                continue
            if self._has_unresolved_path_placeholder(url):
                continue
            key = (self._bare(url), method)
            if key in seen:
                continue
            seen.add(key)
            location = (
                ParameterLocation.form
                if "x-www-form-urlencoded" in (content_type or "").lower()
                or "multipart/form-data" in (content_type or "").lower()
                else ParameterLocation.json_body
            )
            inputs = [
                _FormInputView(name=str(name), input_type="text", value=value)
                for name, value in template.items()
                if name
            ]
            candidates.append((url, method, inputs, False, True, location, content_type))
        return candidates

    @staticmethod
    def _has_unresolved_path_placeholder(url: str) -> bool:
        try:
            path = unquote(urlparse(url).path or "")
        except Exception:
            return False
        for segment in path.split("/"):
            if not segment:
                continue
            if segment.startswith("{") and segment.endswith("}"):
                return True
            if segment.startswith("[") and segment.endswith("]"):
                return True
            if segment.startswith("<") and segment.endswith(">"):
                return True
            if segment.startswith(":") and len(segment) > 1:
                return True
        return False

    @staticmethod
    def _response_rejected(response: object) -> bool:
        if int(getattr(response, "status_code", 0) or 0) in {400, 401, 403, 409, 419, 422}:
            return True
        body = str(getattr(response, "body", "") or "").lower()
        return any(
            term in body
            for term in (
                "csrf token", "invalid token", "csrf validation failed",
                "unauthorized request", "token mismatch", "forbidden",
                "access denied", "request verification", "invalid request",
                "security token", "form token",
            )
        )

    @classmethod
    def _response_indicates_processing(cls, response: object) -> bool:
        """Require affirmative mutation evidence; a bare 2xx is never proof."""
        if cls._response_rejected(response):
            return False
        status = int(getattr(response, "status_code", 0) or 0)
        headers = getattr(response, "headers", {}) or {}
        if status in {201, 202, 204}:
            return True
        if status in {302, 303}:
            location = str(headers.get("location") or headers.get("Location") or "").strip()
            return bool(location) and not any(
                token in urlparse(location).path.lower()
                for token in ("login", "signin", "error", "denied", "forbidden")
            )
        if status != 200:
            return False

        body = str(getattr(response, "body", "") or "").strip()
        if not body:
            return False
        try:
            payload = json.loads(body)
        except (TypeError, ValueError, json.JSONDecodeError):
            payload = None

        def _json_success(value: object) -> bool:
            if isinstance(value, dict):
                for key, item in value.items():
                    key_lower = str(key).lower()
                    if key_lower in {"ok", "success", "updated", "saved", "created", "deleted", "changed"} and item is True:
                        return True
                    if key_lower == "status" and str(item).lower() in {"ok", "success", "created", "updated", "saved", "deleted"}:
                        return True
                    if _json_success(item):
                        return True
            elif isinstance(value, list):
                return any(_json_success(item) for item in value)
            return False

        if payload is not None and _json_success(payload):
            return True
        return bool(
            re.search(
                r"\b(?:success(?:ful(?:ly)?)?|updated|saved|deleted|created|changed|completed|processed|uploaded)\b",
                body,
                re.I,
            )
        )

    @classmethod
    async def _responses_equivalent(cls, control: object, probe: object) -> bool:
        """True when the probe is accepted like a known-successful control."""
        if cls._response_rejected(probe):
            return False
        control_status = int(getattr(control, "status_code", 0) or 0)
        probe_status = int(getattr(probe, "status_code", 0) or 0)
        if control_status != probe_status:
            return False
        if control_status in {201, 202, 204}:
            return True
        control_headers = getattr(control, "headers", {}) or {}
        probe_headers = getattr(probe, "headers", {}) or {}
        if control_status in {302, 303}:
            control_location = str(control_headers.get("location") or control_headers.get("Location") or "")
            probe_location = str(probe_headers.get("location") or probe_headers.get("Location") or "")
            return bool(control_location) and control_location == probe_location
        control_body = re.sub(r"\s+", " ", str(getattr(control, "body", "") or "")).strip()
        probe_body = re.sub(r"\s+", " ", str(getattr(probe, "body", "") or "")).strip()
        if not control_body:
            return False
        return await ResponseAnalyzer.calculate_similarity_async(control_body, probe_body) >= 0.90

    # Content types a cross-origin HTML form can natively produce. Anything else
    # (application/json, application/graphql, …) forces a CORS preflight, so a
    # cross-site page cannot silently forge the request.
    _SIMPLE_REQUEST_CONTENT_TYPES = (
        "application/x-www-form-urlencoded",
        "multipart/form-data",
        "text/plain",
    )

    @classmethod
    def _candidate_is_cross_site_forgeable(cls, candidate: tuple) -> bool:
        """True when a browser could emit this request from a cross-site page.

        Static/browser <form> candidates carry no explicit location and default
        to form-encoding - natively forgeable. Observed-XHR and spec candidates
        carry (location, content_type); only a simple (form/text) body is
        forgeable. A JSON/GraphQL body is not, so it can never be classic
        ambient-cookie CSRF regardless of what our same-site client observes.
        """
        location = candidate[5] if len(candidate) > 5 else ParameterLocation.form
        content_type = str(candidate[6] if len(candidate) > 6 else "").lower()
        if location in {ParameterLocation.json_body, ParameterLocation.graphql_variable}:
            return False
        if content_type and not any(
            simple in content_type for simple in cls._SIMPLE_REQUEST_CONTENT_TYPES
        ):
            return False
        return True

    def _candidate_is_auth_endpoint(self, candidate: tuple) -> bool:
        """True when the candidate URL path is an authentication endpoint.

        Login / signin / authenticate / token routes accept anonymous callers by
        design; a forged login is the separate, weaker "login CSRF" class with no
        ambient session to abuse. Structural path match → framework-agnostic.
        """
        try:
            path = urlparse(candidate[0]).path.lower()
        except Exception:
            return False
        return any(tok in path for tok in self.login_indicators)

    def _token_auth_posture(self, form_candidates: list[tuple]) -> list[Finding]:
        """Informational posture note for header/bearer-token apps.

        Ambient-cookie CSRF does not apply when the app authenticates with a
        bearer token (browsers never attach it cross-site), so we never fabricate
        a vulnerability here - only surface an informational note if
        state-changing endpoints exist.
        """
        findings: list[Finding] = []
        seen: set[tuple[str, str]] = set()
        for candidate in form_candidates:
            form_url, method = candidate[0], candidate[1]
            key = (form_url.split("?")[0], method)
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                Finding(
                    category=OwaspCategory.a01,
                    vuln_type="Cross-Site Request Forgery (CSRF)",
                    severity=SeverityLevel.info,
                    url=form_url,
                    parameter="missing_token",
                    method=method,
                    evidence=(
                        "State-changing endpoint on a header/bearer-token application. "
                        "Ambient-cookie CSRF is not applicable because bearer tokens are not "
                        "attached to cross-site requests automatically. Confirm the token is "
                        "never stored in a cookie and that no cookie-based session fallback exists."
                    ),
                    confidence_score=40.0,
                    detection_method="csrf_posture_token_auth",
                    reproducible=False,
                    verified=False,
                )
            )
        return findings

    async def detect(self, urls: list[str], forms: list[object], **kwargs: object) -> list[Finding]:
        findings: list[Finding] = []
        session_cookies = kwargs.get("session_cookies") or {}
        auth_headers = kwargs.get("auth_headers") or {}
        browser_forms = kwargs.get("browser_forms") or []
        requests = kwargs.get("requests") or []
        api_endpoints = kwargs.get("api_endpoints") or []
        is_spa = bool(kwargs.get("is_spa", False))

        # Only genuine mutating APIs (observed non-GET XHR or a spec/JS
        # endpoint with a mutating method) are CSRF-testable. A browser-discovered
        # SPA "form" is an input cluster keyed to a *client-side route* whose
        # ``action`` is the route URL - submitting to it returns the 200 HTML
        # shell for every route, which previously produced blanket false CSRF
        # findings on navigation routes (/register, /search, …).
        mutating_keys = self._mutating_endpoint_keys(requests, api_endpoints)

        def _tag(candidates: list[tuple], real_default: bool) -> list[tuple]:
            tagged: list[tuple] = []
            for form_url, method, raw_inputs, is_setup in candidates:
                is_real_api = real_default or self._bare(form_url) in mutating_keys
                tagged.append((form_url, method, raw_inputs, is_setup, is_real_api))
            return tagged

        # Static crawler forms are real server-rendered endpoints. Browser forms
        # are only real when backed by an observed/spec mutating API.
        static_candidates = _tag(
            self._select_candidate_forms([self._normalize_form(f) for f in forms]), True
        )
        browser_candidates = _tag(
            self._select_candidate_forms([self._normalize_form(f) for f in browser_forms]), False
        )
        request_candidates = self._candidates_from_requests(requests)
        api_candidates = self._candidates_from_api_endpoints(api_endpoints)

        # Dedup by (bare url, method); observed real-API candidates win.
        by_key: dict[tuple[str, str], tuple] = {}
        for candidate in request_candidates + api_candidates + static_candidates + browser_candidates:
            key = (self._bare(candidate[0]), candidate[1])
            existing = by_key.get(key)
            if existing is None or (candidate[4] and not existing[4]):
                by_key[key] = candidate
        form_candidates = list(by_key.values())

        # On an SPA, never test a client-side navigation route: keep only
        # confirmed mutating-API candidates so no finding attaches to a route
        # that merely returns the shell.
        if is_spa:
            form_candidates = [c for c in form_candidates if c[4]]

        # Configure an SPA-shell oracle so a verification response equal to the
        # SPA root shell is treated as "no state change" rather than success.
        spa_detector: SpaFallbackDetector | None = None
        spa_root_html = str(kwargs.get("spa_root_html") or "")
        root_url = str(kwargs.get("root_url") or "")
        if is_spa and spa_root_html:
            spa_detector = SpaFallbackDetector()
            spa_detector.configure_root(root_url, spa_root_html)
            if not spa_detector.root_looks_like_spa():
                spa_detector = None

        # Auth-model-aware branching: cookie-auth keeps the active
        # token-tamper / Origin-bypass verification below; header/bearer-token
        # auth is not exposed to ambient-cookie CSRF, so we only emit an
        # informational posture note and never fabricate a finding.
        if not session_cookies:
            if auth_headers and form_candidates:
                return self._token_auth_posture(form_candidates)
            # No session state and no token auth: cannot verify state changes.
            return []

        # Authed client to perform actions
        verifier = HttpVerifier(cookies=session_cookies)
        verifier.set_request_context(module="csrf")
        semaphore = asyncio.Semaphore(4)

        async def verify_csrf(candidate) -> list[Finding]:
            form_url, method, raw_inputs, is_setup_route, _is_real_api = candidate[:5]
            location = candidate[5] if len(candidate) > 5 else ParameterLocation.form
            content_type = candidate[6] if len(candidate) > 6 else None
            cand_findings = []

            # Identify if a CSRF token parameter exists
            inputs_payload, csrf_param, credential_mutating = self._build_csrf_form_payload(raw_inputs)

            # Setup/reset actions are destructive scanner targets. Their markup may
            # still lack a token, but actively replaying them is not an acceptable
            # way to prove CSRF and can invalidate the rest of the scan.
            if is_setup_route:
                return []

            # A lone new-password field with no confirm/current gate can permanently
            # rewrite the scan account if we submit a matching value. Without a
            # non-committing pair, skip active mutation (same safety bar as the
            # auth detector's disposable-only password-change probe). CSRF on
            # new+confirm forms still runs with mismatched values below.
            if credential_mutating:
                classified = self._classify_password_fields(raw_inputs)
                if classified["new"] and not classified["confirm"] and not classified["current"]:
                    logger.debug(
                        "CSRF: skipping single-field password-change probe on %s "
                        "(would mutate scan credentials)",
                        form_url,
                    )
                    return []

            async with semaphore:
                try:
                    def _request_parts(payload: dict[str, object]) -> tuple:
                        if location in {ParameterLocation.json_body, ParameterLocation.graphql_variable}:
                            return (
                                form_url, None, None, payload,
                                {"Content-Type": content_type or "application/json"},
                            )
                        injected_url, injected_params, injected_data = URLParameterBuilder.inject_parameter(
                            form_url, csrf_param or "dummy", "tampered", method
                        )
                        if method in _MUTATING_METHODS:
                            injected_data = payload
                        else:
                            injected_params = payload
                        return injected_url, injected_params, injected_data, None, None

                    def _action_accepted(response: object) -> bool:
                        if self._response_indicates_processing(response):
                            return True
                        # Password-change handlers often return a validation error
                        # (mismatch / wrong current) instead of a success word -
                        # that still proves the forged request reached app logic.
                        return credential_mutating and self._credential_change_action_processed(response)

                    control_response = None
                    if csrf_param:
                        csrf_value = str(inputs_payload.get(csrf_param) or "")
                        if not csrf_value:
                            # A token name without its observed value cannot form a
                            # valid control. Treat it as unverified structure, not an
                            # exploitable bypass.
                            return []
                        control_url, control_params, control_data, control_json, control_headers = _request_parts(inputs_payload)
                        control_response = await verifier.send_request(
                            control_url,
                            method,
                            control_params,
                            control_data,
                            headers=control_headers,
                            json_body=control_json,
                            test_phase="valid_token_control",
                        )
                        if not _action_accepted(control_response):
                            return []

                    test_payload = inputs_payload.copy()
                    if csrf_param:
                        test_payload[csrf_param] = "invalid_token_xyz"
                    injected_url, injected_params, injected_data, json_body, request_headers = _request_parts(test_payload)
                    bypass_headers = {
                        **(request_headers or {}),
                        "Origin": "https://evil.example",
                        "Referer": "https://evil.example/malicious",
                    }
                    bypass_response = await verifier.send_request(
                        injected_url,
                        method,
                        injected_params,
                        injected_data,
                        headers=bypass_headers,
                        json_body=json_body,
                        test_phase="origin_token_bypass" if csrf_param else "origin_missing_token",
                    )

                    if control_response is not None:
                        accepted = await self._responses_equivalent(control_response, bypass_response)
                    else:
                        accepted = _action_accepted(bypass_response)
                    if not accepted:
                        return []

                    response_to_check = bypass_response

                    # An SPA returns the 200 HTML shell for any client-side
                    # route, so "200 + no error string" is not evidence of a state
                    # change. If the response is the SPA shell, no mutation
                    # occurred - never emit a finding.
                    if spa_detector is not None:
                        shell = spa_detector.detect(
                            injected_url,
                            response_to_check.status_code,
                            response_to_check.headers.get("content-type", ""),
                            response_to_check.body or "",
                            allow_file_like_path=True,
                        )
                        if shell.is_fallback:
                            logger.debug(
                                "CSRF: ignoring SPA shell response for %s (%s, similarity=%.3f)",
                                form_url, shell.reason, shell.similarity,
                            )
                            return []

                    evidence_msg = "Foreign-Origin submission produced affirmative state-change evidence without a CSRF token."
                    if csrf_param:
                        evidence_msg = (
                            f"A valid-token control processed successfully, and the same action with tampered "
                            f"CSRF token '{csrf_param}' and foreign Origin/Referer was accepted equivalently."
                        )

                    samesite_attr = None
                    cookie_responses = [bypass_response]
                    if control_response is not None:
                        cookie_responses.append(control_response)
                    for resp in cookie_responses:
                        set_cookie_headers = [v for k, v in resp.headers.items() if k.lower() == "set-cookie"]
                        for header in set_cookie_headers:
                            cookie_parts = [p.strip().lower() for p in header.split(";")]
                            cookie_name = cookie_parts[0].split("=")[0] if "=" in cookie_parts[0] else ""
                            if cookie_name in session_cookies or any(tok in cookie_name for tok in ["session", "token", "sess"]):
                                for part in cookie_parts:
                                    if part.startswith("samesite"):
                                        samesite_attr = part.split("=", 1)[1] if "=" in part else "strict"

                    severity = SeverityLevel.high
                    if samesite_attr == "strict":
                        severity = SeverityLevel.low
                        evidence_msg += " SameSite=Strict provides substantial browser-side mitigation."
                    elif samesite_attr == "lax":
                        severity = SeverityLevel.medium
                        evidence_msg += " SameSite=Lax mitigates some cross-site submission paths."

                    cand_findings.append(
                        Finding(
                            category=OwaspCategory.a01,
                            vuln_type="Cross-Site Request Forgery (CSRF)",
                            severity=severity,
                            url=form_url,
                            parameter=csrf_param or "missing_token",
                            method=method,
                            evidence=evidence_msg,
                            confidence_score=95.0 if csrf_param else 90.0,
                            detection_method="token_bypass" if csrf_param else "missing_token_state_change",
                            reproducible=True,
                            verified=True,
                            verification_request_snippet=response_to_check.request_snippet,
                            verification_response_snippet=response_to_check.response_snippet,
                        )
                    )
                except Exception as e:
                    logger.error("CSRF verification failed for %s: %s", form_url, e)
            return cand_findings

        # Framework-agnostic CSRF preconditions, applied uniformly to every
        # candidate source (static form, SPA form, observed XHR, spec endpoint)
        # before any active verification. Classic ambient-cookie CSRF is only
        # possible when a browser will actually emit the state-changing request
        # cross-site, so we require BOTH:
        #   1. A cross-site-forgeable body. Only "simple" request bodies
        #      (application/x-www-form-urlencoded, multipart/form-data,
        #      text/plain, or empty) can be produced by a cross-origin HTML form.
        #      A JSON or GraphQL body cannot - an attacker page can't set that
        #      Content-Type on a form, and a cross-site fetch() of it triggers a
        #      CORS preflight the target must approve. Such endpoints are NOT
        #      forgeable, so replaying them from our own same-site client and
        #      seeing 200 is not evidence of CSRF.
        #   2. A non-authentication endpoint. Login / signin / authenticate /
        #      token routes are meant to accept anonymous, session-less callers;
        #      "login CSRF" is a separate, far weaker class with no ambient
        #      session to abuse.
        # This is what turns "our client replayed it and got 200" into a real
        # cross-site claim, and it generalises to any framework - no app-specific
        # paths or content types are hard-coded.
        verifiable_candidates = [
            c
            for c in form_candidates
            if self._candidate_is_cross_site_forgeable(c)
            and not self._candidate_is_auth_endpoint(c)
        ]

        tasks = [verify_csrf(c) for c in verifiable_candidates]
        results = await asyncio.gather(*tasks)
        for res in results:
            findings.extend(res)

        await verifier.close()
        return findings
