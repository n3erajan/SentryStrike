from __future__ import annotations

import json
import logging
import re
from typing import Any
from urllib.parse import parse_qs, urljoin, urlparse

from app.config import get_settings
from app.core.crawler.api_extractor import ApiExtractor
from app.core.crawler.models import ApiEndpoint, CrawlState, RequestObservation, RouteCandidate, RouteSource

logger = logging.getLogger(__name__)


DESTRUCTIVE_LABEL_RE = re.compile(
    r"\b(delete|remove|destroy|purchase|checkout|pay|confirm|transfer|withdraw|subscribe|unsubscribe)\b",
    re.I,
)
COOKIE_BANNER_LABEL_RE = re.compile(r"\b(accept|agree|allow|ok|got it|continue|close|dismiss)\b", re.I)
SAFE_SUBMIT_LABEL_RE = re.compile(
    r"\b(login|log in|sign in|register|sign up|submit|send|save|search|reset|upload|continue|next)\b",
    re.I,
)
INTERACTIVE_SELECTOR = (
    "a[href], button, [role=button], input[type=submit], input[type=button], "
    "input[type=checkbox], input[type=radio], [tabindex]:not([tabindex='-1'])"
)
SAFE_FIELD_VALUES = {
    "email": "scanner@example.com",
    "search": "test",
    "q": "test",
    "query": "test",
    "name": "Scanner Test",
    "message": "Scanner test message",
    "comment": "Scanner test comment",
    "quantity": "1",
    "qty": "1",
    "id": "1",
    "url": "https://example.com/",
    "file": "sample.txt",
    "filename": "sample.txt",
}
VOLATILE_REQUEST_HEADERS = {
    "accept-encoding",
    "connection",
    "content-length",
    "host",
    "proxy-authorization",
    "proxy-connection",
    "sec-ch-ua",
    "sec-ch-ua-mobile",
    "sec-ch-ua-platform",
    "sec-fetch-dest",
    "sec-fetch-mode",
    "sec-fetch-site",
    "sec-fetch-user",
    "te",
    "upgrade-insecure-requests",
}


class BrowserDiscoveryEngine:
    """Optional Playwright-backed crawler for SPAs.

    The engine is deliberately isolated so the HTTP crawler remains usable when
    browser binaries are unavailable. It records runtime navigation and network
    activity that static crawling cannot see.
    """

    def __init__(self, max_interactions: int = 25) -> None:
        self.max_interactions = max_interactions
        self.settings = get_settings()

    @staticmethod
    async def check_readiness() -> tuple[bool, str | None]:
        try:
            from playwright.async_api import async_playwright
        except Exception as exc:
            return False, f"Playwright import failed: {exc}"

        try:
            async with async_playwright() as pw:
                browser = await pw.chromium.launch(headless=True)
                await browser.close()
        except Exception as exc:
            return False, f"Playwright browser launch failed: {exc}"
        return True, None

    async def crawl(
        self,
        root_url: str,
        auth_cookies: dict[str, str] | None = None,
        auth_headers: dict[str, str] | None = None,
        routes: list[str] | None = None,
    ) -> CrawlState:
        try:
            from playwright.async_api import async_playwright
        except Exception as exc:
            logger.warning("Playwright is unavailable; skipping browser discovery: %s", exc)
            return CrawlState(browser_available=False, browser_error=f"Playwright import failed: {exc}")

        state = CrawlState(browser_available=True)
        observed_by_key: dict[tuple[str, str, str], RequestObservation] = {}

        async with async_playwright() as pw:
            try:
                browser = await pw.chromium.launch(headless=True)
            except Exception as exc:
                logger.warning("Playwright browser launch failed; skipping browser discovery: %s", exc)
                return CrawlState(browser_available=False, browser_error=f"Playwright browser launch failed: {exc}")

            context = await browser.new_context()

            if auth_cookies:
                parsed = urlparse(root_url)
                domain = parsed.netloc.split(":")[0]
                path = parsed.path or "/"
                cookies_list = []
                for name, value in auth_cookies.items():
                    cookies_list.append(
                        {
                            "name": name,
                            "value": value,
                            "domain": domain,
                            "path": path,
                        }
                    )
                await context.add_cookies(cookies_list)

            if auth_headers:
                await context.set_extra_http_headers(auth_headers)

            page = await context.new_page()

            async def on_request(request):
                if request.resource_type in {"xhr", "fetch", "websocket"}:
                    observed_by_key[self._observation_key(request.url, request.method, request.post_data)] = (
                        await self._build_request_observation(request)
                    )

            async def on_response(response):
                request = response.request
                if request.resource_type not in {"xhr", "fetch", "websocket"}:
                    return
                observation_key = self._observation_key(request.url, request.method, request.post_data)
                observed = observed_by_key.get(observation_key) or await self._build_request_observation(request)
                headers = dict(response.headers)
                observed.response_status = response.status
                observed.response_headers = headers
                observed.response_content_type = headers.get("content-type")
                observed.redirect_chain = self._redirect_chain(request)
                try:
                    observed.response_snippet = (await response.text())[:1000]
                except Exception:
                    observed.response_snippet = None
                observed_by_key[observation_key] = observed

            page.on("request", on_request)
            page.on("response", on_response)

            try:
                for target_url in self._browser_targets(root_url, routes or []):
                    try:
                        await page.goto(target_url, wait_until="domcontentloaded", timeout=15000)
                        await self._settle(page)
                        state.add_route(
                            RouteCandidate(
                                url=page.url,
                                source=RouteSource.browser,
                                priority=75,
                                evidence="browser_navigation",
                            )
                        )
                        workflow_stats = await self._exercise_page(page)
                        state.workflow_states_visited += workflow_stats.get("states", 0)
                        state.browser_forms_discovered += workflow_stats.get("forms", 0)
                        state.file_inputs_discovered += workflow_stats.get("file_inputs", 0)
                    except Exception as exc:
                        logger.warning("browser discovery failed for %s: %s", target_url, exc)
            finally:
                for observation in self._dedupe_observations(observed_by_key.values()):
                    state.requests.append(observation)
                    endpoint = ApiEndpoint(
                        url=observation.url,
                        method=observation.method,
                        source=RouteSource.browser,
                        content_type=observation.request_content_type,
                        request_body=observation.post_data,
                        body_schema=list(observation.body_schema),
                        multipart_fields=list(observation.multipart_fields),
                        replayable=observation.replayable,
                        headers=observation.request_headers,
                        evidence=f"{observation.resource_type}:{observation.response_status or 'unknown'}",
                    )
                    state.add_api_endpoint(endpoint)
                    for parameter in ApiExtractor.parameters_from_endpoint(endpoint):
                        parameter.source = "browser_request"
                        parameter.context["replayable"] = observation.replayable
                        parameter.context["cookies"] = dict(observation.request_cookies)
                        state.add_parameter(parameter)
                await context.close()
                await browser.close()
        return state

    @staticmethod
    def _observation_key(url: str, method: str, post_data: Any = None) -> tuple[str, str, str]:
        return (method.upper(), url, str(post_data or ""))

    async def _exercise_page(self, page: Any) -> dict[str, int]:
        seen_states: set[str] = set()
        attempted_controls: set[str] = set()
        forms_seen = 0
        file_inputs_seen = 0

        await self._dismiss_common_dialogs(page)
        for _ in range(self.max_interactions):
            state_signature = await self._ui_state_signature(page)
            if state_signature not in seen_states:
                seen_states.add(state_signature)

            forms_seen = max(forms_seen, await self._count_locator(page, "form"))
            file_inputs_seen = max(file_inputs_seen, await self._count_locator(page, "input[type=file]"))
            await self._prepare_interactive_inputs(page)

            element, control_key = await self._next_interaction(page, attempted_controls)
            if element is None or control_key is None:
                break
            attempted_controls.add(control_key)

            try:
                await element.click(timeout=1200)
                await self._wait_after_interaction(page)
                await self._dismiss_common_dialogs(page)
            except Exception:
                continue

        return {
            "states": len(seen_states),
            "forms": forms_seen,
            "file_inputs": file_inputs_seen,
        }

    async def _prepare_interactive_inputs(self, page: Any) -> None:
        await self._fill_safe_fields(page)
        await self._select_safe_options(page)
        await self._fill_file_inputs(page)

    async def _fill_safe_fields(self, page: Any) -> None:
        input_selector = "input:not([type=hidden]):not([type=file])"
        if not self.settings.authentication_password:
            input_selector = "input:not([type=hidden]):not([type=password]):not([type=file])"
        fields = page.locator(
            f"{input_selector}, textarea, [contenteditable=true]"
        )
        count = min(await fields.count(), self.max_interactions)
        for index in range(count):
            try:
                field = fields.nth(index)
                if not await field.is_visible():
                    continue
                await field.fill(await self._value_for_field(field), timeout=1000)
                if await self._looks_like_search(field):
                    await field.press("Enter", timeout=1000)
                    await self._settle(page)
            except Exception:
                continue

    async def _select_safe_options(self, page: Any) -> None:
        selects = page.locator("select")
        count = min(await selects.count(), self.max_interactions)
        for index in range(count):
            try:
                select = selects.nth(index)
                if not await select.is_visible():
                    continue
                options = select.locator("option")
                option_count = await options.count()
                for option_index in range(option_count):
                    option = options.nth(option_index)
                    value = await option.get_attribute("value")
                    disabled = await option.get_attribute("disabled")
                    if disabled is not None:
                        continue
                    if value:
                        await select.select_option(value, timeout=1000)
                        break
            except Exception:
                continue

    async def _fill_file_inputs(self, page: Any) -> None:
        file_inputs = page.locator("input[type=file]")
        count = min(await file_inputs.count(), self.max_interactions)
        for index in range(count):
            try:
                field = file_inputs.nth(index)
                multiple = await field.get_attribute("multiple")
                files = self._benign_upload_files()
                await field.set_input_files(files if multiple is not None else files[0], timeout=1000)
            except Exception:
                continue

    def _benign_upload_files(self) -> list[dict[str, Any]]:
        return [
            {
                "name": "sentry-upload.txt",
                "mimeType": "text/plain",
                "buffer": b"SENTRY_UPLOAD_TEST_CANARY",
            },
            {
                "name": "sentry-upload.json",
                "mimeType": "application/json",
                "buffer": b'{"canary":"SENTRY_UPLOAD_TEST_CANARY"}',
            },
            {
                "name": "sentry-upload.png",
                "mimeType": "image/png",
                "buffer": b"\x89PNG\r\n\x1a\n",
            },
        ]

    async def _next_interaction(self, page: Any, attempted: set[str]) -> tuple[Any | None, str | None]:
        controls = page.locator(INTERACTIVE_SELECTOR)
        count = min(await controls.count(), self.max_interactions * 2)
        fallback: tuple[Any | None, str | None] = (None, None)
        for index in range(count):
            try:
                element = controls.nth(index)
                if not await element.is_visible():
                    continue
                label = await self._control_label(element)
                control_key = await self._control_key(element, index, label)
                if control_key in attempted:
                    continue
                if self._is_destructive_control(label):
                    continue
                if self._is_submit_like_control(label):
                    return element, control_key
                if fallback == (None, None):
                    fallback = (element, control_key)
            except Exception:
                continue
        return fallback

    async def _control_label(self, element: Any) -> str:
        return " ".join(
            part
            for part in [
                await self._safe_inner_text(element),
                await element.get_attribute("aria-label") or "",
                await element.get_attribute("title") or "",
                await element.get_attribute("name") or "",
                await element.get_attribute("id") or "",
                await element.get_attribute("type") or "",
                await element.get_attribute("value") or "",
                await element.get_attribute("href") or "",
            ]
            if part
        )

    async def _control_key(self, element: Any, index: int, label: str) -> str:
        attrs = [
            await element.get_attribute("href") or "",
            await element.get_attribute("name") or "",
            await element.get_attribute("id") or "",
            await element.get_attribute("type") or "",
            label,
        ]
        return f"{index}:{'|'.join(attrs).strip().lower()}"

    def _is_destructive_control(self, label: str) -> bool:
        if self.settings.scan_mode.lower() == "aggressive":
            return False
        return bool(DESTRUCTIVE_LABEL_RE.search(label or ""))

    @staticmethod
    def _is_submit_like_control(label: str) -> bool:
        return bool(SAFE_SUBMIT_LABEL_RE.search(label or ""))

    async def _dismiss_common_dialogs(self, page: Any) -> None:
        controls = page.locator("button, [role=button], input[type=button]")
        count = min(await controls.count(), 10)
        for index in range(count):
            try:
                element = controls.nth(index)
                if not await element.is_visible():
                    continue
                label = await self._control_label(element)
                if COOKIE_BANNER_LABEL_RE.search(label) and not DESTRUCTIVE_LABEL_RE.search(label):
                    await element.click(timeout=750)
                    await self._wait_after_interaction(page)
            except Exception:
                continue

    async def _ui_state_signature(self, page: Any) -> str:
        try:
            route = page.url
        except Exception:
            route = ""
        try:
            dom_signature = await page.evaluate(
                """() => {
                    const visible = (el) => {
                        const style = window.getComputedStyle(el);
                        const rect = el.getBoundingClientRect();
                        return style && style.visibility !== 'hidden' && style.display !== 'none' && rect.width > 0 && rect.height > 0;
                    };
                    const controls = [...document.querySelectorAll('form,input,textarea,select,button,a[href],[role=button]')]
                        .filter(visible)
                        .slice(0, 80)
                        .map((el) => [
                            el.tagName.toLowerCase(),
                            el.getAttribute('type') || '',
                            el.getAttribute('name') || '',
                            el.getAttribute('id') || '',
                            el.getAttribute('href') || '',
                            (el.innerText || el.value || '').trim().slice(0, 40)
                        ].join(':'));
                    return controls.join('|');
                }"""
            )
        except Exception:
            dom_signature = ""
        return f"{route}|{dom_signature}"[:2000]

    async def _count_locator(self, page: Any, selector: str) -> int:
        try:
            return await page.locator(selector).count()
        except Exception:
            return 0

    async def _wait_after_interaction(self, page: Any) -> None:
        await self._settle(page)

    async def _settle(self, page: Any) -> None:
        """Bounded settle for SPAs whose network never goes idle.

        ``networkidle`` never fires on apps with persistent connections or
        polling (e.g. Angular apps with a service worker), so we wait for the
        DOM to be ready with a short cap and fall back to a fixed pause.
        """
        try:
            await page.wait_for_load_state("domcontentloaded", timeout=1500)
        except Exception:
            pass
        try:
            await page.wait_for_timeout(400)
        except Exception:
            pass

    async def _value_for_field(self, field: Any) -> str:
        attrs = await self._field_attrs(field)
        joined = " ".join(attrs).lower()
        if "password" in joined and self.settings.authentication_password:
            return self.settings.authentication_password
        if self.settings.authentication_username and any(
            token in joined for token in ("email", "username", "user", "login", "account")
        ):
            return self.settings.authentication_username
        for token, value in SAFE_FIELD_VALUES.items():
            if token in joined:
                return value
        return "test"

    async def _looks_like_search(self, field: Any) -> bool:
        joined = " ".join(await self._field_attrs(field)).lower()
        return any(token in joined for token in ("search", "q", "query"))

    async def _field_attrs(self, field: Any) -> list[str]:
        return [
            await field.get_attribute("name") or "",
            await field.get_attribute("id") or "",
            await field.get_attribute("placeholder") or "",
            await field.get_attribute("type") or "",
            await field.get_attribute("aria-label") or "",
        ]

    async def _safe_inner_text(self, element: Any) -> str:
        try:
            return await element.inner_text(timeout=250)
        except Exception:
            return ""

    def _browser_targets(self, root_url: str, routes: list[str]) -> list[str]:
        root_origin = self._origin(root_url)
        targets = [root_url]
        seen = {self._normalize_for_seen(root_url)}
        for route in routes:
            absolute = urljoin(root_url, route)
            if self._origin(absolute) != root_origin:
                continue
            key = self._normalize_for_seen(absolute)
            if key in seen:
                continue
            seen.add(key)
            targets.append(absolute)
            if len(targets) >= self.max_interactions + 1:
                break
        return targets

    def _dedupe_observations(self, observations: Any) -> list[RequestObservation]:
        deduped: dict[tuple[str, str, str | None, tuple[str, ...]], RequestObservation] = {}
        for observation in observations:
            content_type = (
                observation.request_content_type
                or (observation.request_headers or {}).get("content-type")
                or observation.response_content_type
            )
            key = (
                observation.method.upper(),
                self._template_url(observation.url),
                content_type,
                tuple(sorted(observation.body_schema or self._body_schema(observation.post_data))),
            )
            existing = deduped.get(key)
            if existing is None or (existing.response_status is None and observation.response_status is not None):
                deduped[key] = observation
        return list(deduped.values())

    async def _build_request_observation(self, request: Any) -> RequestObservation:
        headers = await self._request_headers(request)
        normalized_headers = self._normalize_request_headers(headers)
        content_type = self._header_value(normalized_headers, "content-type")
        cookies = self._parse_cookie_header(self._header_value(normalized_headers, "cookie") or "")
        post_data = request.post_data
        body_kind, body_schema, multipart_fields = self._request_body_metadata(post_data, content_type)
        replayable = self._is_replayable(request.method, post_data, content_type, body_schema, multipart_fields)
        return RequestObservation(
            url=request.url,
            method=request.method,
            resource_type=request.resource_type,
            request_headers=normalized_headers,
            request_cookies=cookies,
            request_content_type=content_type,
            post_data=post_data,
            body_kind=body_kind,
            body_schema=body_schema,
            multipart_fields=multipart_fields,
            replayable=replayable,
        )

    async def _request_headers(self, request: Any) -> dict[str, str]:
        try:
            return dict(await request.all_headers())
        except Exception:
            return dict(getattr(request, "headers", {}) or {})

    def _normalize_request_headers(self, headers: dict[str, str]) -> dict[str, str]:
        normalized: dict[str, str] = {}
        for name, value in (headers or {}).items():
            lowered = str(name).lower()
            if lowered in VOLATILE_REQUEST_HEADERS:
                continue
            if value is None:
                continue
            normalized[lowered] = str(value)
        return normalized

    @staticmethod
    def _header_value(headers: dict[str, str], name: str) -> str | None:
        lowered = name.lower()
        for header_name, value in (headers or {}).items():
            if header_name.lower() == lowered:
                return value
        return None

    @staticmethod
    def _parse_cookie_header(cookie_header: str) -> dict[str, str]:
        cookies: dict[str, str] = {}
        for part in cookie_header.split(";"):
            if "=" not in part:
                continue
            name, value = part.split("=", 1)
            name = name.strip()
            if name:
                cookies[name] = value.strip()
        return cookies

    def _request_body_metadata(
        self,
        body: Any,
        content_type: str | None,
    ) -> tuple[str | None, list[str], list[dict[str, Any]]]:
        if isinstance(body, bytes):
            body = body.decode("utf-8", "ignore")
        if not isinstance(body, str) or not body.strip():
            return None, [], []

        lowered = (content_type or "").lower()
        if "json" in lowered:
            return "json", sorted(self._body_schema(body)), []
        if "application/x-www-form-urlencoded" in lowered:
            names = sorted(name for name in parse_qs(body, keep_blank_values=True) if name)
            return "form", names, [{"name": name, "type": "text"} for name in names]
        if "multipart/form-data" in lowered:
            fields = self._multipart_field_metadata(body)
            return "multipart", sorted(field["name"] for field in fields if field.get("name")), fields
        return None, [], []

    def _multipart_field_metadata(self, body: str) -> list[dict[str, Any]]:
        fields: list[dict[str, Any]] = []
        seen: set[str] = set()
        for match in re.finditer(
            r'Content-Disposition:\s*form-data;\s*name="(?P<name>[^"]+)"(?P<rest>[^\r\n]*)',
            body,
            re.I,
        ):
            name = match.group("name")
            if not name or name in seen:
                continue
            seen.add(name)
            rest = match.group("rest") or ""
            filename_match = re.search(r'filename="(?P<filename>[^"]*)"', rest, re.I)
            fields.append(
                {
                    "name": name,
                    "type": "file" if filename_match else "text",
                    "filename": filename_match.group("filename") if filename_match else None,
                }
            )
        return fields

    @staticmethod
    def _is_replayable(
        method: str,
        body: Any,
        content_type: str | None,
        body_schema: list[str],
        multipart_fields: list[dict[str, Any]],
    ) -> bool:
        method = method.upper()
        if method in {"GET", "HEAD", "OPTIONS"}:
            return True
        if not body:
            return False
        lowered = (content_type or "").lower()
        if "json" in lowered:
            return bool(body_schema)
        if "application/x-www-form-urlencoded" in lowered:
            return bool(body_schema)
        if "multipart/form-data" in lowered:
            return bool(multipart_fields)
        return False

    def _template_url(self, url: str) -> str:
        parsed = urlparse(url)
        path = re.sub(r"/(?:[0-9]+|[0-9a-f]{8,}(?:-[0-9a-f]{4,})*)", "/{id}", parsed.path, flags=re.I)
        query_names = sorted(part.split("=", 1)[0] for part in parsed.query.split("&") if part)
        query_suffix = f"?{'&'.join(query_names)}" if query_names else ""
        return f"{parsed.scheme}://{parsed.netloc}{path}{query_suffix}"

    def _body_schema(self, body: Any) -> set[str]:
        if not isinstance(body, str) or not body.strip():
            return set()
        try:
            parsed = json.loads(body)
        except Exception:
            return set()
        schema: set[str] = set()

        def walk(value: Any, prefix: str = "") -> None:
            if isinstance(value, dict):
                for key, child in value.items():
                    path = f"{prefix}.{key}" if prefix else key
                    schema.add(path)
                    walk(child, path)
            elif isinstance(value, list):
                for item in value[:1]:
                    walk(item, f"{prefix}[]")

        walk(parsed)
        return schema

    def _redirect_chain(self, request: Any) -> list[str]:
        chain: list[str] = []
        current = getattr(request, "redirected_from", None)
        if callable(current):
            current = current()
        while current is not None:
            url = getattr(current, "url", None)
            if url:
                chain.insert(0, url)
            current = getattr(current, "redirected_from", None)
            if callable(current):
                current = current()
        return chain

    def _origin(self, url: str) -> str:
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}".lower()

    def _normalize_for_seen(self, url: str) -> str:
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}".rstrip("/").lower()
