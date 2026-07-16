import asyncio
import logging
from urllib.parse import parse_qsl, unquote, urlparse, urlunparse

from app.core.crawler.api_extractor import ApiExtractor
from app.core.crawler.models import ParameterLocation
from app.core.crawler.spa import SpaFallbackDetector
from app.core.detectors.base_detector import BaseDetector, Finding
from app.core.verification.verification_framework import HttpVerifier, URLParameterBuilder
from shared.models.vulnerability import OwaspCategory, SeverityLevel

logger = logging.getLogger(__name__)

_MUTATING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


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
    state_changing_actions = {"password", "update", "change", "profile", "user", "admin", "delete", "add", "create", "settings", "save"}
    login_indicators = {"login", "signin", "sign-in", "authenticate", "auth", "session"}

    @staticmethod
    def _normalize_form(form: object) -> object:
        """Coerce a browser-discovered form dict into an HtmlForm-like object.

        Static crawler forms (``HtmlForm``/``FormInput``) already expose the
        ``action``/``method``/``inputs`` attributes the detector reads, so they
        pass through untouched. Browser forms (Task 2) arrive as plain dicts.
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
        """Return state-changing, non-login form candidates for CSRF assessment."""
        form_candidates: list[tuple] = []
        for form in forms:
            form_url = getattr(form, "action", "") or getattr(form, "page_url", "")
            form_method = (getattr(form, "method", "POST") or "POST").upper()
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
        to form-encoding — natively forgeable. Observed-XHR and spec candidates
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
        a vulnerability here — only surface an informational note if
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

        # P0-4: only genuine mutating APIs (observed non-GET XHR or a spec/JS
        # endpoint with a mutating method) are CSRF-testable. A browser-discovered
        # SPA "form" is an input cluster keyed to a *client-side route* whose
        # ``action`` is the route URL — submitting to it returns the 200 HTML
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

        # Auth-model-aware branching (Task 8): cookie-auth keeps the active
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
                    
                    json_body = None
                    request_headers = None
                    if location in {ParameterLocation.json_body, ParameterLocation.graphql_variable}:
                        injected_url = form_url
                        injected_params = None
                        injected_data = None
                        json_body = test_payload
                        request_headers = {"Content-Type": content_type or "application/json"}
                    else:
                        # Submit the form
                        injected_url, injected_params, injected_data = URLParameterBuilder.inject_parameter(
                            form_url, csrf_param or "dummy", "tampered", method
                        )

                        # Overwrite injected data with complete form payload
                        if method in {"POST", "PUT", "PATCH", "DELETE"}:
                            injected_data = test_payload
                        else:
                            injected_params = test_payload

                    response = await verifier.send_request(
                        injected_url,
                        method,
                        injected_params,
                        injected_data,
                        headers=request_headers,
                        json_body=json_body,
                        test_phase="token_tamper",
                    )

                    # Phase 3: Add optional Origin/Referer bypass test
                    bypass_headers = {
                        "Origin": "https://evil.example",
                        "Referer": "https://evil.example/malicious"
                    }
                    # Send bypass request if the original request succeeded (to minimize requests), 
                    # but we can also just send it and check its success.
                    bypass_headers = {**(request_headers or {}), **bypass_headers}
                    bypass_response = await verifier.send_request(
                        injected_url,
                        method,
                        injected_params,
                        injected_data,
                        headers=bypass_headers,
                        json_body=json_body,
                        test_phase="origin_bypass",
                    )

                    # Criteria for CSRF vulnerability:
                    # 1. HTTP 200 or 302 redirect (success indicator)
                    # 2. Response body doesn't contain a clear CSRF/token validation error
                    response_to_check = bypass_response if bypass_response.status_code in [200, 302, 303] else response

                    # P0-4: an SPA returns the 200 HTML shell for any client-side
                    # route, so "200 + no error string" is not evidence of a state
                    # change. If the response is the SPA shell, no mutation
                    # occurred — never emit a finding.
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
                                    category=OwaspCategory.a01,
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

        # Framework-agnostic CSRF preconditions, applied uniformly to every
        # candidate source (static form, SPA form, observed XHR, spec endpoint)
        # before any active verification. Classic ambient-cookie CSRF is only
        # possible when a browser will actually emit the state-changing request
        # cross-site, so we require BOTH:
        #   1. A cross-site-forgeable body. Only "simple" request bodies
        #      (application/x-www-form-urlencoded, multipart/form-data,
        #      text/plain, or empty) can be produced by a cross-origin HTML form.
        #      A JSON or GraphQL body cannot — an attacker page can't set that
        #      Content-Type on a form, and a cross-site fetch() of it triggers a
        #      CORS preflight the target must approve. Such endpoints are NOT
        #      forgeable, so replaying them from our own same-site client and
        #      seeing 200 is not evidence of CSRF.
        #   2. A non-authentication endpoint. Login / signin / authenticate /
        #      token routes are meant to accept anonymous, session-less callers;
        #      "login CSRF" is a separate, far weaker class with no ambient
        #      session to abuse.
        # This is what turns "our client replayed it and got 200" into a real
        # cross-site claim, and it generalises to any framework — no app-specific
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
