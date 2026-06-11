from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any
from urllib.parse import urlparse

import httpx
from bs4 import BeautifulSoup

from app.core.crawler.api_extractor import ApiExtractor
from app.core.crawler.models import ApiEndpoint
from app.core.crawler.spa import SpaFallbackDetector
from app.core.crawler.url_parser import normalize_url, same_domain

logger = logging.getLogger(__name__)


class AuthStrategy(str, Enum):
    redirect = "redirect"
    html_form = "html_form"
    js_api = "js_api"
    browser_spa = "browser_spa"
    brute_force = "brute_force"


@dataclass
class AuthReplayState:
    login_url: str
    action: str
    method: str
    payload: dict[str, str]
    is_json: bool = False
    headers: dict[str, str] = field(default_factory=dict)


@dataclass
class AuthResult:
    cookies: dict[str, str] = field(default_factory=dict)
    bearer_token: str | None = None
    strategy: AuthStrategy | None = None
    replay_state: AuthReplayState | None = None
    authenticated: bool = False
    is_spa: bool = False


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
            return result

        # Strategy 2: HTML Form Extraction
        result = await self._try_html_form_login(client, root_url, username, password)
        if result and result.authenticated:
            result.is_spa = is_spa
            logger.info("[auth] Strategy 2 (HTML Form Extraction) succeeded")
            return result

        # Strategy 3: JS API Discovery + Param Extraction
        result = await self._try_js_api_login(client, root_url, username, password)
        if result and result.authenticated:
            result.is_spa = is_spa
            logger.info("[auth] Strategy 3 (JS API Discovery) succeeded")
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
            return result

        logger.warning("[auth] All authentication strategies failed")
        return AuthResult(authenticated=False, is_spa=is_spa)

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
        for path in login_paths:
            url = normalize_url(root_url, path)
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
                        routes, endpoints = ApiExtractor.extract_from_javascript(script_url, resp.text)
                        for ep in endpoints:
                            login_hints = ("login", "signin", "sign-in", "auth", "session", "oauth", "token")
                            if any(hint in ep.url.lower() for hint in login_hints):
                                auth_endpoints.append(ep)
                except Exception as e:
                    logger.debug("[auth] Failed to fetch or parse script %s: %s", script_url, e)

            if not auth_endpoints:
                logger.info("[auth] No auth endpoints found in JavaScript assets")
                return None

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
                page = await context.new_page()

                logger.info("[auth] Browser launched, navigating to %s", root_url)
                await page.goto(root_url, wait_until="networkidle", timeout=15000)

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
                                        await page.wait_for_load_state("networkidle", timeout=5000)
                                        break
                                if await page.locator("input[type='password']").count() > 0:
                                    break
                        except Exception as e:
                            logger.debug("[auth] Failed to click selector %s: %s", selector, e)

                password_inputs = page.locator("input[type='password']")
                if await password_inputs.count() == 0:
                    logger.warning("[auth] No password input found in DOM after navigation/clicks")
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
                for sel in submit_selectors:
                    try:
                        loc = page.locator(sel)
                        if await loc.count() > 0:
                            for i in range(await loc.count()):
                                el = loc.nth(i)
                                if await el.is_visible():
                                    logger.info("[auth] Clicking submit button: %s", sel)
                                    await el.click()
                                    clicked = True
                                    break
                            if clicked:
                                break
                    except Exception as e:
                        logger.debug("[auth] Failed to click submit selector %s: %s", sel, e)

                if not clicked:
                    logger.info("[auth] Pressing Enter on password input as fallback")
                    await page.press(password_selector, "Enter")

                await page.wait_for_load_state("networkidle", timeout=5000)

                cookies = await context.cookies()
                cookies_dict = {c["name"]: c["value"] for c in cookies}

                local_storage = await page.evaluate("() => JSON.stringify(localStorage)")
                bearer_token = None
                if local_storage:
                    try:
                        ls_dict = json.loads(local_storage)
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
                    auth_result.replay_state = None
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
        auth_header = client.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            bearer_token = auth_header.replace("Bearer ", "").strip()

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
                        logger.info("[auth] Extracted token from login response: %s", bearer_token)
                except Exception:
                    pass

                if not bearer_token:
                    tokens = ModernAuthManager.extract_tokens(response.text)
                    if tokens:
                        bearer_token = next(iter(tokens.values()))
                        logger.info("[auth] Extracted token pattern from response text: %s", bearer_token)

        authenticated = bool(cookies or bearer_token)

        if response is not None:
            if response.status_code in (401, 403):
                authenticated = False
            else:
                body_lower = response.text.lower()
                invalid_hints = ("invalid credentials", "invalid email", "invalid username", "login failed", "unauthorized", "incorrect password")
                if any(hint in body_lower for hint in invalid_hints):
                    authenticated = False

        return AuthResult(
            cookies=cookies,
            bearer_token=bearer_token,
            authenticated=authenticated
        )
