from __future__ import annotations

import logging
from typing import Any

from app.core.crawler.models import ApiEndpoint, CrawlState, RequestObservation, RouteSource

logger = logging.getLogger(__name__)


class BrowserDiscoveryEngine:
    """Optional Playwright-backed crawler for SPAs.

    The engine is deliberately isolated so the HTTP crawler remains usable when
    browser binaries are unavailable. It records runtime navigation and network
    activity that static crawling cannot see.
    """

    def __init__(self, max_interactions: int = 25) -> None:
        self.max_interactions = max_interactions

    async def crawl(
        self,
        root_url: str,
        auth_cookies: dict[str, str] | None = None,
        auth_headers: dict[str, str] | None = None,
    ) -> CrawlState:
        try:
            from playwright.async_api import async_playwright
        except Exception as exc:
            logger.warning("Playwright is unavailable; skipping browser discovery: %s", exc)
            return CrawlState()

        state = CrawlState()
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=True)
            context = await browser.new_context()

            if auth_cookies:
                from urllib.parse import urlparse
                parsed = urlparse(root_url)
                domain = parsed.netloc.split(":")[0]
                path = parsed.path or "/"
                cookies_list = []
                for name, value in auth_cookies.items():
                    cookies_list.append({
                        "name": name,
                        "value": value,
                        "domain": domain,
                        "path": path,
                    })
                await context.add_cookies(cookies_list)

            if auth_headers:
                await context.set_extra_http_headers(auth_headers)

            page = await context.new_page()

            async def on_request(request):
                if request.resource_type in {"xhr", "fetch", "websocket"}:
                    state.requests.append(
                        RequestObservation(
                            url=request.url,
                            method=request.method,
                            resource_type=request.resource_type,
                            request_headers=dict(request.headers),
                            post_data=request.post_data,
                        )
                    )
                    state.add_api_endpoint(
                        ApiEndpoint(
                            url=request.url,
                            method=request.method,
                            source=RouteSource.browser,
                            request_body=request.post_data,
                            headers=dict(request.headers),
                            evidence=request.resource_type,
                        )
                    )

            page.on("request", on_request)
            try:
                await page.goto(root_url, wait_until="networkidle", timeout=15000)
                await self._exercise_page(page)
            except Exception as exc:
                logger.warning("browser discovery failed for %s: %s", root_url, exc)
            finally:
                await context.close()
                await browser.close()
        return state

    async def _exercise_page(self, page: Any) -> None:
        locators = page.locator("a[href], button, [role=button], input[type=submit]")
        count = min(await locators.count(), self.max_interactions)
        for index in range(count):
            try:
                element = locators.nth(index)
                if await element.is_visible():
                    await element.click(timeout=1000)
                    await page.wait_for_load_state("networkidle", timeout=3000)
            except Exception:
                continue
