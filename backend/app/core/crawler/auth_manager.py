from __future__ import annotations

import json
import logging
import re
import secrets
from dataclasses import dataclass, field
from enum import Enum
from typing import Any
from urllib.parse import urlparse

import httpx
from bs4 import BeautifulSoup

from app.core.crawler.api_extractor import ApiExtractor
from app.core.crawler.models import ApiEndpoint
from app.core.crawler.spa import (
    SpaFallbackDetector,
    install_resource_blocking,
    settle_page,
)
from app.core.crawler.url_parser import normalize_url, same_domain

logger = logging.getLogger(__name__)


def redact_secret(value: str | None) -> str:
    if not value:
        return ""
    if len(value) <= 12:
        return "***"
    return f"{value[:6]}...{value[-4:]} len={len(value)}"


async def _merge_session_storage(storage_state: Any, page: Any) -> Any:
    """Merge the live page's sessionStorage into a Playwright ``storage_state``.

    Playwright's ``context.storage_state()`` captures cookies + localStorage but
    NOT sessionStorage, so session-scoped values an SPA keeps there (cart/basket
    id, CSRF token, wizard progress) are lost when the blob is replayed into a
    fresh crawl context — and the flows that need them (e.g. an add-to-basket
    POST attaching a sessionStorage id) can never fire. This reads the page's
    sessionStorage and attaches it, per origin, so the crawler's restore path
    (``browser_engine._session_storage_init_script``) has data to re-seed. Purely
    generic: no key is inspected or special-cased. Best-effort — any failure
    leaves ``storage_state`` unchanged."""
    if not isinstance(storage_state, dict):
        return storage_state
    try:
        raw = await page.evaluate("() => JSON.stringify(sessionStorage)")
        data = json.loads(raw or "{}")
    except Exception:
        return storage_state
    if not isinstance(data, dict) or not data:
        return storage_state
    entries = [{"name": str(k), "value": str(v)} for k, v in data.items()]
    try:
        origin = await page.evaluate("() => location.origin")
    except Exception:
        origin = None
    origins = storage_state.setdefault("origins", [])
    target = None
    if origin:
        for o in origins:
            if isinstance(o, dict) and o.get("origin") == origin:
                target = o
                break
    if target is None:
        target = {"origin": origin} if origin else {}
        origins.append(target)
    target["sessionStorage"] = entries
    return storage_state


class AuthStrategy(str, Enum):
    redirect = "redirect"
    html_form = "html_form"
    js_api = "js_api"
    browser_spa = "browser_spa"
    brute_force = "brute_force"


class AuthVerificationState(str, Enum):
    unauthenticated = "unauthenticated"
    attempted = "attempted"
    authenticated_unverified = "authenticated_unverified"
    authenticated_verified = "authenticated_verified"
    expired = "expired"


@dataclass
class AuthReplayState:
    login_url: str
    action: str
    method: str
    payload: dict[str, str]
    is_json: bool = False
    headers: dict[str, str] = field(default_factory=dict)
    metadata: dict[str, str] = field(default_factory=dict)


@dataclass
class AuthResult:
    cookies: dict[str, str] = field(default_factory=dict)
    bearer_token: str | None = None
    strategy: AuthStrategy | None = None
    replay_state: AuthReplayState | None = None
    authenticated: bool = False
    is_spa: bool = False
    state: AuthVerificationState = AuthVerificationState.unauthenticated
    verification_evidence: str = ""
    storage_state: dict | None = None
    # Populated only for self-provisioned throwaway accounts, so callers that need
    # to re-authenticate the account later (e.g. to confirm a password change) know
    # the credentials that were used. Never set for the user's real scan session.
    account_email: str | None = None
    account_password: str | None = None


@dataclass
class AuthFlowCandidate:
    url: str
    method: str = "POST"
    fields: dict[str, str] = field(default_factory=dict)
    flow_type: str = "form"
    evidence: str = ""


@dataclass
class AuthState:
    cookies: dict[str, str] = field(default_factory=dict)
    bearer_tokens: list[str] = field(default_factory=list)
    csrf_tokens: dict[str, str] = field(default_factory=dict)
    flow: AuthFlowCandidate | None = None


class ModernAuthManager:
    """Authentication discovery helpers for traditional and SPA applications."""

    LOGIN_HINTS = ("login", "signin", "sign-in", "auth", "session", "oauth", "token")
    TOKEN_RE = re.compile(r"""(?P<name>csrf|xsrf|token|jwt|access_token|id_token)["'\s:=]+(?P<value>[A-Za-z0-9._\-+/=]{12,})""", re.I)

    @classmethod
    def discover_flows(cls, page_url: str, html: str, api_endpoints: list[ApiEndpoint] | None = None) -> list[AuthFlowCandidate]:
        flows: list[AuthFlowCandidate] = []
        soup = BeautifulSoup(html, "html.parser")

        for form in soup.find_all("form"):
            text = " ".join([form.get("id", ""), form.get("class", [""])[0] if form.get("class") else "", form.get_text(" ", strip=True)]).lower()
            has_password = bool(form.find("input", attrs={"type": re.compile("^password$", re.I)}))
            if not has_password and not any(hint in text for hint in cls.LOGIN_HINTS):
                continue

            action = normalize_url(page_url, form.get("action", page_url))
            fields: dict[str, str] = {}
            for inp in form.find_all(["input", "textarea", "select"]):
                name = inp.get("name")
                if name:
                    fields[name] = inp.get("value", "")
            flows.append(
                AuthFlowCandidate(
                    url=action,
                    method=form.get("method", "POST").upper(),
                    fields=fields,
                    flow_type="form",
                    evidence="password/login form",
                )
            )

        for endpoint in api_endpoints or []:
            lowered = endpoint.url.lower()
            if any(hint in lowered for hint in cls.LOGIN_HINTS):
                flows.append(
                    AuthFlowCandidate(
                        url=endpoint.url,
                        method=endpoint.method,
                        flow_type="api",
                        evidence=endpoint.evidence or "auth-like API endpoint",
                    )
                )
        return flows

    @classmethod
    def extract_tokens(cls, html_or_script: str) -> dict[str, str]:
        tokens: dict[str, str] = {}
        for match in cls.TOKEN_RE.finditer(html_or_script):
            tokens[match.group("name").lower()] = match.group("value")
        return tokens

    @staticmethod
    def snapshot_cookies(cookies: httpx.Cookies) -> dict[str, str]:
        return {cookie.name: cookie.value for cookie in cookies.jar}

    @classmethod
    def auth_endpoints_from_javascript(cls, base_url: str, script_text: str) -> list[ApiEndpoint]:
        _, endpoints = ApiExtractor.extract_from_javascript(base_url, script_text)
        return [endpoint for endpoint in endpoints if any(hint in endpoint.url.lower() for hint in cls.LOGIN_HINTS)]


class SmartAuthenticator:
    """Cascading multi-strategy authentication manager for traditional and SPA sites."""

    def __init__(self, settings: Any) -> None:
        self.settings = settings
        self._discovered_storage_keys: set[str] = set()

    async def authenticate(
        self, client: httpx.AsyncClient, root_url: str, username: str, password: str
    ) -> AuthResult:
        logger.info("[auth] Starting smart authentication cascade for %s", root_url)
        is_spa = await self._detect_spa(client, root_url)

        # Strategy 1: Redirect Detection
        result = await self._try_redirect_login(client, root_url, username, password)
        if result and result.authenticated:
            result.is_spa = is_spa
            logger.info("[auth] Strategy 1 (Redirect Detection) succeeded")
            if is_spa and not result.storage_state:
                result.storage_state = await self._capture_browser_storage_state(
                    root_url, result.cookies, result.bearer_token
                )
            return result

        # Strategy 2: HTML Form Extraction
        result = await self._try_html_form_login(client, root_url, username, password)
        if result and result.authenticated:
            result.is_spa = is_spa
            logger.info("[auth] Strategy 2 (HTML Form Extraction) succeeded")
            if is_spa and not result.storage_state:
                result.storage_state = await self._capture_browser_storage_state(
                    root_url, result.cookies, result.bearer_token
                )
            return result

        # Strategy 3: JS API Discovery + Param Extraction
        result = await self._try_js_api_login(client, root_url, username, password)
        if result and result.authenticated:
            result.is_spa = is_spa
            logger.info("[auth] Strategy 3 (JS API Discovery) succeeded")
            if is_spa and not result.storage_state:
                result.storage_state = await self._capture_browser_storage_state(
                    root_url, result.cookies, result.bearer_token
                )
            return result

        # Strategy 4: Playwright Browser Login
        result = await self._try_browser_spa_login(client, root_url, username, password)
        if result and result.authenticated:
            result.is_spa = True
            logger.info("[auth] Strategy 4 (Playwright Browser Login) succeeded")
            return result

        # Strategy 5: Brute-Force Endpoints
        result = await self._try_brute_force_login(client, root_url, username, password)
        if result and result.authenticated:
            result.is_spa = is_spa
            logger.info("[auth] Strategy 5 (Brute-Force Endpoints) succeeded")
            if is_spa and not result.storage_state:
                result.storage_state = await self._capture_browser_storage_state(
                    root_url, result.cookies, result.bearer_token
                )
            return result

        logger.warning("[auth] All authentication strategies failed")
        return AuthResult(authenticated=False, is_spa=is_spa)

    @staticmethod
    def _substitute_replay_credentials(
        payload: dict[str, str],
        prior_username: str | None,
        prior_password: str | None,
        username: str,
        password: str,
    ) -> dict[str, str]:
        """Return a copy of ``payload`` with the prior account's credentials
        swapped for a new account's.

        Prefer exact value replacement when the primary credentials are known,
        then fall back to credential-field names. The fallback is important for
        recipes captured from browser/forms where the stored body can contain
        placeholders/defaults instead of the literal first-account secret.
        """
        new_payload: dict[str, str] = {}
        for key, value in payload.items():
            key_lower = str(key).lower()
            if prior_username and value == prior_username:
                new_payload[key] = username
            elif prior_password and value == prior_password:
                new_payload[key] = password
            elif any(token in key_lower for token in ("email", "username", "user", "login")):
                new_payload[key] = username
            elif any(token in key_lower for token in ("password", "passwd", "pass")):
                new_payload[key] = password
            else:
                new_payload[key] = value
        return new_payload

    async def authenticate_with_replay(
        self,
        client: httpx.AsyncClient,
        replay_state: AuthReplayState,
        username: str,
        password: str,
        *,
        prior_username: str | None = None,
        prior_password: str | None = None,
    ) -> AuthResult:
        """Log a *different* account in by replaying the winning login recipe.

        Reuses the exact endpoint/method/body that already authenticated the main
        account (``replay_state``), swapping in this account's credentials, so the
        second/admin login skips the full strategy cascade (which otherwise
        restarts from Strategy 1 for every account). Returns an unauthenticated
        result on any failure so the caller can fall back to the cascade.
        """
        payload = self._substitute_replay_credentials(
            replay_state.payload, prior_username, prior_password, username, password
        )
        logger.info(
            "[auth] Replaying winning login recipe (%s %s) for a secondary account",
            replay_state.method, replay_state.action,
        )
        try:
            if replay_state.login_url:
                await client.get(replay_state.login_url, follow_redirects=True)
            if replay_state.headers:
                client.headers.update(replay_state.headers)
            if replay_state.method.upper() == "BROWSER":
                return await self._authenticate_browser_replay(
                    client,
                    replay_state,
                    username,
                    password,
                )
            if replay_state.method.upper() == "POST":
                if replay_state.is_json:
                    resp = await client.post(replay_state.action, json=payload, follow_redirects=True)
                else:
                    resp = await client.post(replay_state.action, data=payload, follow_redirects=True)
            else:
                resp = await client.get(replay_state.action, params=payload, follow_redirects=True)
            result = await self._verify_auth(client, resp)
            if result.authenticated:
                result.replay_state = AuthReplayState(
                    login_url=replay_state.login_url,
                    action=replay_state.action,
                    method=replay_state.method,
                    payload=payload,
                    is_json=replay_state.is_json,
                    headers=dict(replay_state.headers),
                )
            return result
        except Exception as exc:
            logger.warning("[auth] Login-recipe replay failed for secondary account: %s", exc)
            return AuthResult(authenticated=False)

    async def _authenticate_browser_replay(
        self,
        client: httpx.AsyncClient,
        replay_state: AuthReplayState,
        username: str,
        password: str,
    ) -> AuthResult:
        try:
            from playwright.async_api import async_playwright
        except Exception as exc:
            logger.warning("[auth] Playwright unavailable for browser replay: %s", exc)
            return AuthResult(authenticated=False)

        username_selector = replay_state.payload.get("username_selector") or "input[type='text']"
        password_selector = replay_state.payload.get("password_selector") or "input[type='password']"
        submit_selector = replay_state.payload.get("submit_selector")
        try:
            async with async_playwright() as pw:
                browser = await pw.chromium.launch(headless=True)
                context = await browser.new_context()
                if getattr(self.settings, "crawl_browser_block_resources", True):
                    await install_resource_blocking(context)
                page = await context.new_page()
                await page.goto(
                    replay_state.action or replay_state.login_url,
                    wait_until="domcontentloaded",
                    timeout=8000,
                )
                await settle_page(page)
                await page.fill(username_selector, username)
                await page.fill(password_selector, password)
                # Bounded click with an Enter fallback: a disabled reactive-form
                # submit button would otherwise block on Playwright's 30s
                # actionability wait. Pressing Enter submits via keydown regardless
                # of button state.
                submitted_click = False
                if submit_selector:
                    try:
                        await page.click(submit_selector, timeout=3000)
                        submitted_click = True
                    except Exception as exc:
                        logger.debug("[auth] replay submit click failed (%s); using Enter", exc)
                if not submitted_click:
                    await page.press(password_selector, "Enter")
                await settle_page(page)
                cookies = await context.cookies()
                cookies_dict = {c["name"]: c["value"] for c in cookies}
                storage_state = None
                try:
                    storage_state = await context.storage_state()
                except Exception:
                    pass
                storage_state = await _merge_session_storage(storage_state, page)
                bearer_token = None
                try:
                    local_storage = await page.evaluate("() => JSON.stringify(localStorage)")
                    for key, value in json.loads(local_storage or "{}").items():
                        if any(hint in str(key).lower() for hint in ("token", "jwt", "auth", "session", "id_token", "access_token")):
                            if isinstance(value, str) and (value.startswith("Bearer ") or len(value.split(".")) == 3 or len(value) > 30):
                                bearer_token = value.replace("Bearer ", "").strip()
                                break
                except Exception:
                    pass
                await context.close()
                await browser.close()

                client.cookies.update(cookies_dict)
                if bearer_token:
                    client.headers["Authorization"] = f"Bearer {bearer_token}"
                result = await self._verify_auth(client)
                if result.authenticated:
                    result.strategy = AuthStrategy.browser_spa
                    result.cookies = cookies_dict
                    result.bearer_token = bearer_token
                    result.storage_state = storage_state
                    result.replay_state = AuthReplayState(
                        login_url=replay_state.login_url,
                        action=replay_state.action,
                        method="BROWSER",
                        payload=dict(replay_state.payload),
                        is_json=False,
                        headers=dict(replay_state.headers),
                    )
                return result
        except Exception as exc:
            logger.warning("[auth] Browser login replay failed: %s", exc)
            return AuthResult(authenticated=False)

    async def _detect_spa(self, client: httpx.AsyncClient, root_url: str) -> bool:
        try:
            response = await client.get(root_url, follow_redirects=True)
            if response.status_code != 200 or "text/html" not in response.headers.get("content-type", "").lower():
                return False
            is_spa = SpaFallbackDetector.looks_like_spa_shell(str(response.url), response.text)
            if is_spa:
                logger.info("[auth] Root page appears to be an SPA shell")
            return is_spa
        except Exception as exc:
            logger.debug("[auth] SPA detection failed: %s", exc)
            return False

    async def _try_redirect_login(
        self, client: httpx.AsyncClient, root_url: str, username: str, password: str
    ) -> AuthResult | None:
        logger.info("[auth] Trying Strategy 1: Redirect Detection")
        try:
            resp = await client.get(root_url, follow_redirects=True)
            if resp.status_code == 200:
                final_url = str(resp.url)
                is_login_page = any(hint in final_url.lower() for hint in ("login", "signin", "auth", "session"))
                has_password_field = "type=\"password\"" in resp.text.lower() or "type='password'" in resp.text.lower() or "<input" in resp.text.lower() and "password" in resp.text.lower()

                if is_login_page or has_password_field:
                    logger.info("[auth] Redirected to potential login page: %s", final_url)
                    result = await self._parse_and_submit_form(client, final_url, resp.text, username, password)
                    if result and result.authenticated:
                        result.strategy = AuthStrategy.redirect
                        return result
        except Exception as e:
            logger.warning("[auth] Strategy 1 failed: %s", e)
        return None

    async def _try_html_form_login(
        self, client: httpx.AsyncClient, root_url: str, username: str, password: str
    ) -> AuthResult | None:
        logger.info("[auth] Trying Strategy 2: HTML Form Extraction")
        login_paths = ["/login", "/signin", "/auth", "/session/new", "/login.php", "/login.html", "/"]
        configured_login_url = getattr(self.settings, "authentication_login_url", None)
        if configured_login_url:
            login_paths.insert(0, str(configured_login_url))
        for path in login_paths:
            url = path if str(path).startswith(("http://", "https://")) else normalize_url(root_url, path)
            try:
                resp = await client.get(url, follow_redirects=True)
                if resp.status_code == 200:
                    result = await self._parse_and_submit_form(client, str(resp.url), resp.text, username, password)
                    if result and result.authenticated:
                        result.strategy = AuthStrategy.html_form
                        return result
            except Exception as e:
                logger.debug("[auth] Strategy 2 path %s failed: %s", url, e)
        return None

    async def _parse_and_submit_form(
        self, client: httpx.AsyncClient, page_url: str, html: str, username: str, password: str
    ) -> AuthResult | None:
        soup = BeautifulSoup(self._normalize_malformed_forms(html), "html.parser")
        forms = soup.find_all("form")
        if not forms:
            return None

        for form in forms:
            has_password = bool(form.find("input", attrs={"type": re.compile("^password$", re.I)}))
            form_text = " ".join([
                form.get("id", ""),
                form.get("class", [""])[0] if form.get("class") else "",
                form.get_text(" ", strip=True)
            ]).lower()

            login_hints = ("login", "signin", "sign-in", "auth", "session", "oauth", "token", "usr", "pwd", "email")
            if not has_password and not any(hint in form_text for hint in login_hints):
                continue

            action = normalize_url(page_url, form.get("action", ""))
            method = form.get("method", "POST").upper()
            payload = {}

            for inp in form.find_all(["input", "select", "textarea"]):
                name = inp.get("name")
                if not name:
                    continue
                val = inp.get("value", "")
                inp_type = inp.get("type", "text").lower()
                autocomplete = inp.get("autocomplete", "").lower()
                placeholder = inp.get("placeholder", "").lower()

                field_classification = self._classify_field_name_and_attrs(name, inp_type, autocomplete, placeholder)
                if field_classification == "username":
                    payload[name] = username
                elif field_classification == "password":
                    payload[name] = password
                elif inp_type == "hidden":
                    payload[name] = val
                elif inp_type in ["submit", "button"] and "submit" in name.lower():
                    payload[name] = val or "Submit"

            # Fallback if no matching fields mapped
            if not any(v in payload.values() for v in (username, password)):
                username_field_found = False
                for inp in form.find_all("input"):
                    name = inp.get("name")
                    if not name:
                        continue
                    inp_type = inp.get("type", "text").lower()
                    if inp_type == "password":
                        payload[name] = password
                    elif inp_type in ("text", "email") and not username_field_found:
                        payload[name] = username
                        username_field_found = True

            try:
                if method == "POST":
                    resp = await client.post(action, data=payload, follow_redirects=True)
                else:
                    resp = await client.get(action, params=payload, follow_redirects=True)

                auth_result = await self._verify_auth(client, resp)
                if auth_result.authenticated:
                    auth_result.replay_state = AuthReplayState(
                        login_url=page_url,
                        action=action,
                        method=method,
                        payload=payload,
                        is_json=False
                    )
                    return auth_result
            except Exception as e:
                logger.warning("[auth] Failed form submission to %s: %s", action, e)

        return None

    @staticmethod
    def _normalize_malformed_forms(html: str) -> str:
        return re.sub(r"<form\b([^>]*?)/>", r"<form\1>", html, flags=re.I)

    def _classify_field_name_and_attrs(
        self, name: str, inp_type: str = "", autocomplete: str = "", placeholder: str = ""
    ) -> str | None:
        name_lower = name.lower()
        inp_type_lower = inp_type.lower()
        autocomplete_lower = autocomplete.lower()
        placeholder_lower = placeholder.lower()

        if inp_type_lower == "password" or autocomplete_lower in ("current-password", "new-password", "password"):
            return "password"
        if inp_type_lower == "email" or autocomplete_lower in ("username", "email"):
            return "username"

        for hint in ("password", "pass", "passwd", "pwd", "secret", "credential", "psw"):
            if hint in name_lower or hint in placeholder_lower:
                return "password"

        for hint in ("email", "username", "user", "login", "account", "uname", "identifier", "mail", "usr"):
            if hint in name_lower or hint in placeholder_lower:
                return "username"

        return None

    async def _try_js_api_login(
        self, client: httpx.AsyncClient, root_url: str, username: str, password: str
    ) -> AuthResult | None:
        logger.info("[auth] Trying Strategy 3: JS API Discovery + Param Extraction")
        try:
            root_resp = await client.get(root_url)
            if root_resp.status_code != 200:
                return None

            soup = BeautifulSoup(root_resp.text, "html.parser")
            script_urls: list[str] = []
            for script in soup.find_all("script"):
                src = script.get("src")
                if src:
                    normalized = normalize_url(root_url, src)
                    if same_domain(root_url, normalized):
                        script_urls.append(normalized)

            if not script_urls:
                logger.debug("[auth] No same-domain scripts found in root HTML")
                return None

            auth_endpoints: list[ApiEndpoint] = []
            script_contents: dict[str, str] = {}
            for script_url in script_urls:
                try:
                    resp = await client.get(script_url)
                    if resp.status_code == 200:
                        script_contents[script_url] = resp.text
                        keys = ApiExtractor.extract_storage_keys(resp.text)
                        if keys:
                            self._discovered_storage_keys.update(keys)
                            logger.info("[auth] Discovered storage keys in JS asset %s: %s", script_url, keys)
                        routes, endpoints = ApiExtractor.extract_from_javascript(root_url, resp.text)
                        for ep in endpoints:
                            login_hints = ("login", "signin", "sign-in", "auth", "session", "oauth", "token")
                            if any(hint in ep.url.lower() for hint in login_hints):
                                auth_endpoints.append(ep)
                except Exception as e:
                    logger.debug("[auth] Failed to fetch or parse script %s: %s", script_url, e)

            if not auth_endpoints:
                logger.info("[auth] No auth endpoints found in JavaScript assets")
                return None

            auth_endpoints = self._rank_auth_endpoints(auth_endpoints, script_contents)
            for ep in auth_endpoints:
                logger.info("[auth] Discovered auth endpoint: %s %s", ep.method, ep.url)
                params = []
                for script_url, script_text in script_contents.items():
                    path = urlparse(ep.url).path
                    if path in script_text or ep.url in script_text:
                        params = self._extract_js_body_params(script_text, path or ep.url)
                        if params:
                            logger.info("[auth] Extracted parameter names for endpoint %s: %s", ep.url, params)
                            break

                payload = self._map_credentials_to_params(params, username, password)

                try:
                    logger.info("[auth] Submitting credentials to JS API: POST %s with payload keys %s", ep.url, list(payload.keys()))
                    resp = await client.post(ep.url, json=payload, headers={"Content-Type": "application/json"}, follow_redirects=True)

                    auth_result = await self._verify_auth(client, resp)
                    if auth_result.authenticated:
                        auth_result.strategy = AuthStrategy.js_api
                        auth_result.replay_state = AuthReplayState(
                            login_url=root_url,
                            action=ep.url,
                            method="POST",
                            payload=payload,
                            is_json=True,
                            headers={"Content-Type": "application/json"}
                        )
                        return auth_result
                except Exception as e:
                    logger.warning("[auth] JS API submission failed to %s: %s", ep.url, e)
        except Exception as e:
            logger.warning("[auth] Strategy 3 failed: %s", e)
        return None

    def _rank_auth_endpoints(
        self, endpoints: list[ApiEndpoint], script_contents: dict[str, str] | None = None
    ) -> list[ApiEndpoint]:
        scored: list[tuple[int, int, ApiEndpoint]] = []
        seen: set[tuple[str, str]] = set()
        script_values = list((script_contents or {}).values())

        for index, endpoint in enumerate(endpoints):
            key = (endpoint.url, endpoint.method.upper())
            if key in seen:
                continue
            seen.add(key)

            parsed = urlparse(endpoint.url)
            path = parsed.path.lower()
            score = 0

            if any(prefix in path for prefix in ("/rest/", "/api/", "/graphql", "/gql", "/rpc", "/trpc")):
                score += 100
            if any(auth_path in path for auth_path in ("/user/login", "/auth/login", "/login", "/signin", "/session")):
                score += 40
            if endpoint.method.upper() == "POST":
                score += 25
            if path in {"/login", "/signin", "/auth"}:
                score -= 75
            if any(marker in (endpoint.evidence or "").lower() for marker in ("fetch", "xhr", "graphql")):
                score += 15

            for script_text in script_values:
                if path and path in script_text:
                    params = self._extract_js_body_params(script_text, path)
                    if {"email", "username", "user", "login"}.intersection({param.lower() for param in params}):
                        score += 25
                    if any("pass" in param.lower() or "pwd" in param.lower() for param in params):
                        score += 25
                    break

            scored.append((-score, index, endpoint))

        return [endpoint for _, _, endpoint in sorted(scored)]

    def _extract_js_body_params(self, script_text: str, endpoint_path: str) -> list[str]:
        idx = script_text.find(endpoint_path)
        if idx == -1:
            parts = [p for p in endpoint_path.split("/") if p]
            if len(parts) >= 2:
                subpath = "/".join(parts[-2:])
                idx = script_text.find(subpath)

        if idx == -1:
            return []

        start_win = max(0, idx - 800)
        end_win = min(len(script_text), idx + 1200)
        window = script_text[start_win:end_win]

        pattern = re.compile(r"""\b([a-zA-Z_][a-zA-Z0-9_$]{1,29})\s*:|["']([a-zA-Z0-9_$-]{2,30})["']\s*:""")
        keys = []
        for match in pattern.finditer(window):
            key = match.group(1) or match.group(2)
            if key and key not in keys:
                keys.append(key)

        return keys

    def _map_credentials_to_params(self, param_names: list[str], username: str, password: str) -> dict[str, str]:
        payload = {}
        username_key = None
        password_key = None

        for name in param_names:
            classification = self._classify_field_name_and_attrs(name)
            if classification == "username" and not username_key:
                username_key = name
            elif classification == "password" and not password_key:
                password_key = name

        if not username_key:
            username_key = next((name for name in param_names if "user" in name.lower() or "mail" in name.lower()), "email")
        if not password_key:
            password_key = next((name for name in param_names if "pass" in name.lower() or "pwd" in name.lower()), "password")

        payload[username_key] = username
        payload[password_key] = password
        return payload

    async def _try_browser_spa_login(
        self, client: httpx.AsyncClient, root_url: str, username: str, password: str
    ) -> AuthResult | None:
        logger.info("[auth] Trying Strategy 4: Playwright Browser Login")
        try:
            from playwright.async_api import async_playwright
        except Exception as exc:
            logger.warning("[auth] Playwright is unavailable; skipping browser SPA login: %s", exc)
            return None

        try:
            async with async_playwright() as pw:
                browser = await pw.chromium.launch(headless=True)
                context = await browser.new_context()
                if getattr(self.settings, "crawl_browser_block_resources", True):
                    await install_resource_blocking(context)
                page = await context.new_page()

                logger.info("[auth] Browser launched, navigating to %s", root_url)
                await page.goto(root_url, wait_until="domcontentloaded", timeout=8000)
                await settle_page(page)

                # Dismiss blocking overlays (cookie consent, Material CDK backdrops,
                # welcome modals) before searching for form inputs. Without this,
                # Angular Material overlays intercept pointer events and the password
                # field is never found, causing Strategy 4 to bail prematurely.
                try:
                    await page.keyboard.press("Escape")
                    await page.wait_for_timeout(400)
                except Exception:
                    pass
                for _dismiss_sel in [
                    "button:has-text('Got it')", "button:has-text('Accept')",
                    "button:has-text('Accept All')", "button:has-text('OK')",
                    "button:has-text('Dismiss')", "button:has-text('Close')",
                    "button:has-text('Agree')", "[aria-label='Close']",
                    ".cdk-overlay-backdrop", ".mat-dialog-container button",
                ]:
                    try:
                        _loc = page.locator(_dismiss_sel)
                        if await _loc.count() > 0 and await _loc.first.is_visible():
                            await _loc.first.click(force=True, timeout=800)
                            await page.wait_for_timeout(300)
                            break
                    except Exception:
                        pass

                login_btn_selectors = [
                    "a[href*='login']", "a[href*='signin']", "a[href*='sign-in']",
                    "button:has-text('login')", "button:has-text('log in')",
                    "button:has-text('signin')", "button:has-text('sign in')",
                    "a:has-text('login')", "a:has-text('log in')",
                    "a:has-text('signin')", "a:has-text('sign in')"
                ]

                if await page.locator("input[type='password']").count() == 0:
                    for selector in login_btn_selectors:
                        try:
                            loc = page.locator(selector)
                            if await loc.count() > 0:
                                for i in range(await loc.count()):
                                    el = loc.nth(i)
                                    if await el.is_visible():
                                        logger.info("[auth] Clicking login element: %s", selector)
                                        await el.click()
                                        await settle_page(page)
                                        break
                                if await page.locator("input[type='password']").count() > 0:
                                    break
                        except Exception as e:
                            logger.debug("[auth] Failed to click selector %s: %s", selector, e)

                # Wait up to 3 s for the password field to appear after navigation
                # and any overlay dismissal; SPAs may lazy-render the login form.
                try:
                    await page.wait_for_selector("input[type='password']", timeout=3000)
                except Exception:
                    pass

                # If password input is not present, try direct navigation to common client-side login routes
                if await page.locator("input[type='password']").count() == 0:
                    parsed_root = urlparse(root_url)
                    base_origin = f"{parsed_root.scheme}://{parsed_root.netloc}"
                    login_paths = ["/login", "/#/login", "/signin", "/#/signin", "/sign-in", "/#/sign-in", "/auth/login", "/#/auth/login"]
                    for path in login_paths:
                        target_login_url = base_origin + path
                        try:
                            logger.info("[auth] Trying direct navigation to SPA login route: %s", target_login_url)
                            await page.goto(target_login_url, wait_until="domcontentloaded", timeout=8000)
                            await settle_page(page)
                            if await page.locator("input[type='password']").count() > 0:
                                logger.info("[auth] Found password input after direct navigation to %s", target_login_url)
                                break
                        except Exception as e:
                            logger.debug("[auth] Failed to navigate to %s: %s", target_login_url, e)

                browser_login_url = page.url

                password_inputs = page.locator("input[type='password']")
                if await password_inputs.count() == 0:
                    logger.warning("[auth] No password input found in DOM after navigation/clicks/routing")
                    await context.close()
                    await browser.close()
                    return None

                inputs = page.locator("input")
                username_selector = None
                password_selector = "input[type='password']"

                for i in range(await inputs.count()):
                    inp = inputs.nth(i)
                    if not await inp.is_visible():
                        continue

                    inp_type = await inp.get_attribute("type") or "text"
                    inp_name = await inp.get_attribute("name") or ""
                    inp_id = await inp.get_attribute("id") or ""
                    inp_placeholder = await inp.get_attribute("placeholder") or ""
                    inp_autocomplete = await inp.get_attribute("autocomplete") or ""

                    classification = self._classify_field_name_and_attrs(
                        inp_name + " " + inp_id, inp_type, inp_autocomplete, inp_placeholder
                    )

                    if classification == "username" and not username_selector:
                        if inp_name:
                            username_selector = f"input[name='{inp_name}']"
                        elif inp_id:
                            username_selector = f"input[id='{inp_id}']"
                        elif inp_type == "email":
                            username_selector = "input[type='email']"
                        else:
                            username_selector = "input[type='text']"

                if not username_selector:
                    for i in range(await inputs.count()):
                        inp = inputs.nth(i)
                        if not await inp.is_visible():
                            continue
                        inp_type = await inp.get_attribute("type") or "text"
                        if inp_type in ("text", "email"):
                            inp_name = await inp.get_attribute("name") or ""
                            inp_id = await inp.get_attribute("id") or ""
                            if inp_name:
                                username_selector = f"input[name='{inp_name}']"
                            elif inp_id:
                                username_selector = f"input[id='{inp_id}']"
                            break

                if not username_selector:
                    username_selector = "input[type='text']"

                logger.info("[auth] Filling credentials: username via '%s', password via '%s'", username_selector, password_selector)
                await page.fill(username_selector, username)
                await page.fill(password_selector, password)

                submit_selectors = [
                    "button[type='submit']", "input[type='submit']",
                    "button:has-text('login')", "button:has-text('log in')",
                    "button:has-text('signin')", "button:has-text('sign in')",
                    "button:has-text('submit')", "a:has-text('login')",
                    "a:has-text('log in')", "a:has-text('signin')", "a:has-text('sign in')"
                ]

                clicked = False
                clicked_selector = None
                for sel in submit_selectors:
                    try:
                        loc = page.locator(sel)
                        if await loc.count() > 0:
                            for i in range(await loc.count()):
                                el = loc.nth(i)
                                # Skip hidden or still-disabled controls fast. A
                                # reactive-form submit button (Angular/React/Vue)
                                # stays ``[disabled]`` until the framework marks the
                                # form valid; clicking it would block on Playwright's
                                # 30s actionability wait, then throw — two such
                                # buttons burned ~60s per login. Skipping lets the
                                # Enter fallback (which submits via keydown
                                # regardless of button state) fire immediately.
                                if not await el.is_visible():
                                    continue
                                if not await el.is_enabled():
                                    logger.info(
                                        "[auth] Submit button disabled, skipping: %s", sel
                                    )
                                    continue
                                logger.info("[auth] Clicking submit button: %s", sel)
                                # Bounded timeout: never spend the default 30s on a
                                # single control that turns non-actionable.
                                await el.click(timeout=3000)
                                clicked = True
                                clicked_selector = sel
                                break
                            if clicked:
                                break
                    except Exception as e:
                        logger.debug("[auth] Failed to click submit selector %s: %s", sel, e)

                if not clicked:
                    logger.info("[auth] Pressing Enter on password input as fallback")
                    await page.press(password_selector, "Enter")

                await settle_page(page)

                cookies = await context.cookies()
                cookies_dict = {c["name"]: c["value"] for c in cookies}

                # Capture the entire authenticated session (cookies + per-origin
                # localStorage/sessionStorage) so downstream browser contexts render as
                # the logged-in user regardless of where the app stores its token.
                # Generic: never inspect or special-case any key name here.
                storage_state = None
                try:
                    storage_state = await context.storage_state()
                except Exception as e:
                    logger.debug("[auth] Failed to capture storage_state: %s", e)
                storage_state = await _merge_session_storage(storage_state, page)

                local_storage = await page.evaluate("() => JSON.stringify(localStorage)")
                bearer_token = None
                if local_storage:
                    try:
                        ls_dict = json.loads(local_storage)
                        # First: try matching any of the discovered storage keys from JS!
                        for k in self._discovered_storage_keys:
                            if k in ls_dict:
                                v = ls_dict[k]
                                token_val = None
                                if isinstance(v, str):
                                    token_val = v
                                elif isinstance(v, dict):
                                    for subkey, subval in v.items():
                                        if any(hint in subkey.lower() for hint in ("token", "jwt", "access", "bearer", "session")):
                                            if isinstance(subval, str):
                                                token_val = subval
                                                break
                                if token_val:
                                    bearer_token = token_val.replace("Bearer ", "").strip()
                                    logger.info("[auth] Found bearer token via discovered JS key '%s'", k)
                                    break
                        
                        # Fallback to the existing generic check if not found:
                        if not bearer_token:
                            for k, v in ls_dict.items():
                                if any(hint in k.lower() for hint in ("token", "jwt", "auth", "session", "id_token", "access_token")):
                                    if isinstance(v, str) and (v.startswith("Bearer ") or len(v.split(".")) == 3 or len(v) > 30):
                                        bearer_token = v.replace("Bearer ", "").strip()
                                        logger.info("[auth] Found bearer token in localStorage key '%s'", k)
                                        break
                    except Exception as e:
                        logger.debug("[auth] Failed to parse localStorage: %s", e)

                client.cookies.update(cookies_dict)
                if bearer_token:
                    client.headers["Authorization"] = f"Bearer {bearer_token}"

                auth_result = await self._verify_auth(client)
                if auth_result.authenticated:
                    auth_result.strategy = AuthStrategy.browser_spa
                    auth_result.cookies = cookies_dict
                    auth_result.bearer_token = bearer_token
                    auth_result.storage_state = storage_state
                    auth_result.replay_state = AuthReplayState(
                        login_url=root_url,
                        action=browser_login_url,
                        method="BROWSER",
                        payload={
                            "username_selector": username_selector,
                            "password_selector": password_selector,
                            "submit_selector": clicked_selector or "",
                        },
                        is_json=False,
                    )
                    logger.info("[auth] Strategy 4 succeeded!")
                    await context.close()
                    await browser.close()
                    return auth_result

                await context.close()
                await browser.close()
        except Exception as e:
            logger.warning("[auth] Strategy 4 failed: %s", e)
        return None

    async def _try_brute_force_login(
        self, client: httpx.AsyncClient, root_url: str, username: str, password: str
    ) -> AuthResult | None:
        logger.info("[auth] Trying Strategy 5: Brute-Force Endpoints")
        common_api_paths = [
            "/api/login",
            "/api/auth/login",
            "/rest/user/login",
            "/api/v1/auth/login",
            "/auth/login",
            "/login",
            "/api/signin",
            "/api/auth/signin"
        ]
        payload_templates = [
            {"email": username, "password": password},
            {"username": username, "password": password},
            {"user": username, "pass": password},
            {"login": username, "password": password}
        ]
        for path in common_api_paths:
            url = normalize_url(root_url, path)
            for payload in payload_templates:
                try:
                    logger.debug("[auth] Brute-forcing JS API POST %s with keys %s", url, list(payload.keys()))
                    resp = await client.post(url, json=payload, headers={"Content-Type": "application/json"}, follow_redirects=True)
                    auth_result = await self._verify_auth(client, resp)
                    if auth_result.authenticated:
                        auth_result.strategy = AuthStrategy.brute_force
                        auth_result.replay_state = AuthReplayState(
                            login_url=root_url,
                            action=url,
                            method="POST",
                            payload=payload,
                            is_json=True,
                            headers={"Content-Type": "application/json"}
                        )
                        return auth_result
                except Exception as e:
                    logger.debug("[auth] Brute force to %s failed: %s", url, e)
        return None

    async def _verify_auth(self, client: httpx.AsyncClient, response: httpx.Response | None = None) -> AuthResult:
        cookies = ModernAuthManager.snapshot_cookies(client.cookies)

        bearer_token = None
        verification_evidence = ""
        auth_header = client.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            bearer_token = auth_header.replace("Bearer ", "").strip()
            verification_evidence = "authorization header present"

        if response is not None:
            if response.status_code in (200, 201, 204, 302):
                try:
                    data = response.json()

                    def search_token(d):
                        if isinstance(d, dict):
                            for k, v in d.items():
                                if any(t in k.lower() for t in ("token", "jwt", "access", "bearer", "sessionid", "sid")):
                                    if isinstance(v, str) and len(v) > 15:
                                        return v
                                res = search_token(v)
                                if res:
                                    return res
                        elif isinstance(d, list):
                            for item in d:
                                res = search_token(item)
                                if res:
                                    return res
                        return None

                    found_token = search_token(data)
                    if found_token:
                        bearer_token = found_token
                        verification_evidence = "token-bearing login response"
                        logger.info("[auth] Extracted token from login response: %s", redact_secret(bearer_token))
                except Exception:
                    pass

                if not bearer_token:
                    tokens = ModernAuthManager.extract_tokens(response.text)
                    if tokens:
                        bearer_token = next(iter(tokens.values()))
                        verification_evidence = "token pattern in response text"
                        logger.info("[auth] Extracted token pattern from response text: %s", redact_secret(bearer_token))

        state = AuthVerificationState.unauthenticated

        if response is not None:
            if response.status_code in (401, 403):
                state = AuthVerificationState.unauthenticated
            else:
                body_lower = response.text.lower()
                invalid_hints = self._configured_failure_hints()
                if any(hint in body_lower for hint in invalid_hints):
                    state = AuthVerificationState.unauthenticated
                elif bearer_token:
                    state = AuthVerificationState.authenticated_verified
                elif self._response_has_auth_success_marker(response):
                    state = AuthVerificationState.authenticated_verified
                    verification_evidence = verification_evidence or "post-login success marker"
                elif cookies:
                    state = AuthVerificationState.authenticated_unverified
                    verification_evidence = "cookies present but no protected-resource proof"
        elif bearer_token:
            state = AuthVerificationState.authenticated_verified
        elif cookies:
            state = AuthVerificationState.authenticated_unverified
            verification_evidence = "cookies present but no response proof"

        validation = await self._verify_configured_protected_target(client)
        if validation:
            state = AuthVerificationState.authenticated_verified
            verification_evidence = validation

        authenticated = state in {
            AuthVerificationState.authenticated_unverified,
            AuthVerificationState.authenticated_verified,
        }

        return AuthResult(
            cookies=cookies,
            bearer_token=bearer_token,
            authenticated=authenticated,
            state=state,
            verification_evidence=verification_evidence,
        )

    def _configured_failure_hints(self) -> tuple[str, ...]:
        configured = getattr(self.settings, "authentication_failure_text", None)
        hints = [
            "invalid credentials",
            "invalid email",
            "invalid username",
            "login failed",
            "unauthorized",
            "incorrect password",
            "bad credentials",
            "authentication failed",
        ]
        if configured:
            hints.append(str(configured).lower())
        return tuple(hints)

    def _response_has_auth_success_marker(self, response: httpx.Response) -> bool:
        body_lower = response.text.lower()
        success_text = getattr(self.settings, "authentication_success_text", None)
        if success_text and str(success_text).lower() in body_lower:
            return True

        success_regex = getattr(self.settings, "authentication_success_regex", None)
        if success_regex:
            try:
                if re.search(str(success_regex), response.text, re.I):
                    return True
            except re.error:
                logger.warning("[auth] Ignoring invalid authentication_success_regex")

        if getattr(self.settings, "authentication_failure_regex", None):
            try:
                if re.search(str(self.settings.authentication_failure_regex), response.text, re.I):
                    return False
            except re.error:
                logger.warning("[auth] Ignoring invalid authentication_failure_regex")

        success_hints = (
            "logout",
            "log out",
            "sign out",
            "dashboard",
            "profile",
            "my account",
            "account settings",
            "welcome",
        )
        return any(hint in body_lower for hint in success_hints)

    async def _verify_configured_protected_target(self, client: httpx.AsyncClient) -> str:
        protected_url = (
            getattr(self.settings, "authentication_validation_url", None)
            or getattr(self.settings, "authentication_success_url", None)
        )
        if not protected_url:
            return ""
        try:
            resp = await client.get(str(protected_url), follow_redirects=True)
        except Exception as exc:
            logger.debug("[auth] Protected target validation failed: %s", exc)
            return ""
        if resp.status_code in (401, 403):
            return ""
        if getattr(self.settings, "authentication_failure_regex", None):
            try:
                if re.search(str(self.settings.authentication_failure_regex), resp.text, re.I):
                    return ""
            except re.error:
                logger.warning("[auth] Ignoring invalid authentication_failure_regex")
        if self._response_has_auth_success_marker(resp):
            return f"protected validation target succeeded: {protected_url}"
        if 200 <= resp.status_code < 300:
            return f"protected validation target returned HTTP {resp.status_code}: {protected_url}"
        return ""

    # ------------------------------------------------------------------
    # Secondary identity provisioning (for differential IDOR/BOLA)
    # ------------------------------------------------------------------

    # Common registration endpoints tried when no register form is discovered.
    _REGISTER_API_PATHS = (
        "/api/register", "/api/auth/register", "/api/signup", "/api/auth/signup",
        "/rest/user", "/api/users", "/api/v1/auth/register", "/register", "/signup",
    )

    @staticmethod
    def _throwaway_credentials() -> tuple[str, str]:
        """Generate a unique throwaway email + strong password."""
        token = secrets.token_hex(8)
        return f"sentry_secondary_{token}@sentrystrike.invalid", f"Sn!{secrets.token_urlsafe(12)}"

    async def acquire_secondary_identity(
        self, client: httpx.AsyncClient, root_url: str
    ) -> AuthResult | None:
        """Provision a throwaway second identity for cross-identity IDOR checks.

        Attempts, in order, to register a fresh user (discovered HTML register
        form, then common register API paths) and log it in via the existing
        authentication cascade. Returns an authenticated :class:`AuthResult`
        with the secondary session's cookies/bearer token, or ``None`` when a
        second identity cannot be provisioned. Never raises — provisioning is
        strictly best-effort and the caller degrades gracefully.
        """
        username, password = self._throwaway_credentials()
        logger.info("[auth] Attempting to provision secondary identity on %s", root_url)

        registered = await self._register_secondary(client, root_url, username, password)
        if not registered:
            logger.info("[auth] Secondary identity registration not possible; skipping")
            return None

        # A registration flow often returns a session directly; verify first.
        verified = await self._verify_auth(client)
        if verified.authenticated:
            logger.info("[auth] Secondary identity active from registration response")
            verified.account_email = username
            verified.account_password = password
            return verified

        # Otherwise log the new user in via the normal cascade.
        result = await self.authenticate(client, root_url, username, password)
        if result and result.authenticated:
            logger.info("[auth] Secondary identity logged in via cascade")
            result.account_email = username
            result.account_password = password
            return result
        logger.info("[auth] Secondary identity registered but login failed")
        return None

    async def _register_secondary(
        self, client: httpx.AsyncClient, root_url: str, username: str, password: str
    ) -> bool:
        """Best-effort registration of a throwaway account. Returns success."""
        # 1) Discovered HTML register form.
        try:
            resp = await client.get(root_url, follow_redirects=True)
            if resp.status_code == 200 and "text/html" in resp.headers.get("content-type", "").lower():
                if await self._submit_register_form(client, str(resp.url), resp.text, username, password):
                    return True
        except Exception as exc:
            logger.debug("[auth] Secondary register form discovery failed: %s", exc)

        # 2) Common register API endpoints with credential-shaped JSON bodies.
        payload_templates = (
            {"email": username, "password": password},
            {"email": username, "password": password, "passwordRepeat": password},
            {"username": username, "password": password},
            {"user": username, "pass": password},
        )
        for path in self._REGISTER_API_PATHS:
            url = normalize_url(root_url, path)
            for payload in payload_templates:
                try:
                    resp = await client.post(
                        url, json=payload, headers={"Content-Type": "application/json"}, follow_redirects=True
                    )
                except Exception as exc:
                    logger.debug("[auth] Secondary register POST %s failed: %s", url, exc)
                    continue
                if resp.status_code in (200, 201):
                    logger.info("[auth] Secondary account registered via %s", url)
                    return True
                # A 409/400 "already exists" means the endpoint works; retry a
                # fresh credential set is unnecessary since ours is random.
        return False

    async def _submit_register_form(
        self, client: httpx.AsyncClient, page_url: str, html: str, username: str, password: str
    ) -> bool:
        """Submit an HTML registration form if the page exposes one."""
        soup = BeautifulSoup(self._normalize_malformed_forms(html), "html.parser")
        for form in soup.find_all("form"):
            has_password = bool(form.find("input", attrs={"type": re.compile("^password$", re.I)}))
            form_text = " ".join(
                [
                    form.get("id", ""),
                    form.get("class", [""])[0] if form.get("class") else "",
                    form.get_text(" ", strip=True),
                ]
            ).lower()
            register_hints = ("register", "signup", "sign up", "create account", "join")
            if not has_password or not any(hint in form_text for hint in register_hints):
                continue

            action = normalize_url(page_url, form.get("action", ""))
            method = form.get("method", "POST").upper()
            payload: dict[str, str] = {}
            for inp in form.find_all(["input", "select", "textarea"]):
                name = inp.get("name")
                if not name:
                    continue
                inp_type = inp.get("type", "text").lower()
                classification = self._classify_field_name_and_attrs(
                    name, inp_type, inp.get("autocomplete", ""), inp.get("placeholder", "")
                )
                if classification == "username":
                    payload[name] = username
                elif classification == "password":
                    payload[name] = password
                elif inp_type == "hidden":
                    payload[name] = inp.get("value", "")
            if password not in payload.values():
                continue
            try:
                if method == "POST":
                    resp = await client.post(action, data=payload, follow_redirects=True)
                else:
                    resp = await client.get(action, params=payload, follow_redirects=True)
            except Exception as exc:
                logger.debug("[auth] Secondary register form submit to %s failed: %s", action, exc)
                continue
            if resp.status_code in (200, 201, 302):
                logger.info("[auth] Secondary account registered via HTML form %s", action)
                return True
        return False

    async def _capture_browser_storage_state(
        self, root_url: str, cookies: dict[str, str], bearer_token: str | None
    ) -> dict | None:
        """Launch a temporary browser context, seed it with cookies/bearer_token, and capture storage_state."""
        try:
            from playwright.async_api import async_playwright
        except Exception:
            return None

        try:
            async with async_playwright() as pw:
                browser = await pw.chromium.launch(headless=True)
                context = await browser.new_context()
                if getattr(self.settings, "crawl_browser_block_resources", True):
                    await install_resource_blocking(context)

                # Seed cookies if any
                if cookies:
                    parsed = urlparse(root_url)
                    domain = parsed.netloc.split(":")[0]
                    path = parsed.path or "/"
                    cookies_list = []
                    for name, value in cookies.items():
                        cookies_list.append(
                            {
                                "name": name,
                                "value": value,
                                "domain": domain,
                                "path": path,
                            }
                        )
                    await context.add_cookies(cookies_list)

                page = await context.new_page()
                await page.goto(root_url, wait_until="commit")

                # Seed bearer token in localStorage if present
                if bearer_token:
                    token_keys = {"token", "access_token", "jwt", "auth_token", "authToken", "sentrystrike_token"}
                    if self._discovered_storage_keys:
                        token_keys.update(self._discovered_storage_keys)

                    user_keys = [k for k in self._discovered_storage_keys if "user" in k.lower()]
                    
                    keys_to_set = list(token_keys)
                    await page.evaluate("""(args) => {
                        const { token, keys, userKeys } = args;
                        for (const key of keys) {
                            localStorage.setItem(key, token);
                            localStorage.setItem(key, "Bearer " + token);
                        }
                        for (const ukey of userKeys) {
                            try {
                                const existing = localStorage.getItem(ukey);
                                if (existing) {
                                    const parsed = JSON.parse(existing);
                                    if (typeof parsed === 'object') {
                                        parsed.token = token;
                                        parsed.access_token = token;
                                        localStorage.setItem(ukey, JSON.stringify(parsed));
                                        continue;
                                    }
                                }
                            } catch (e) {}
                            localStorage.setItem(ukey, JSON.stringify({ token: token, access_token: token, email: "scanner@example.com" }));
                        }
                    }""", {"token": bearer_token, "keys": keys_to_set, "userKeys": user_keys})

                await page.wait_for_timeout(500)
                storage_state = await context.storage_state()
                storage_state = await _merge_session_storage(storage_state, page)
                await context.close()
                await browser.close()
                return storage_state
        except Exception as e:
            logger.debug("[auth] Failed to capture backup browser storage state: %s", e)
            return None

