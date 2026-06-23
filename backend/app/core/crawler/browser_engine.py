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
                        await page.goto(target_url, wait_until="networkidle", timeout=15000)
                        state.add_route(
                            RouteCandidate(
                                url=page.url,
                                source=RouteSource.browser,
                                priority=75,
                                evidence="browser_navigation",
                            )
                        )
                        await self._exercise_page(page)
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

    async def _exercise_page(self, page: Any) -> None:
        await self._fill_safe_fields(page)
        locators = page.locator("a[href], button, [role=button], input[type=submit], button[type=submit]")
        count = min(await locators.count(), self.max_interactions)
        for index in range(count):
            try:
                element = locators.nth(index)
                if not await element.is_visible():
                    continue
                label = " ".join(
                    part
                    for part in [
                        await self._safe_inner_text(element),
                        await element.get_attribute("aria-label") or "",
                        await element.get_attribute("title") or "",
                    ]
                    if part
                )
                if DESTRUCTIVE_LABEL_RE.search(label):
                    continue
                await element.click(timeout=1000)
                await page.wait_for_load_state("networkidle", timeout=3000)
            except Exception:
                continue

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
                    await page.wait_for_load_state("networkidle", timeout=3000)
            except Exception:
                continue

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
