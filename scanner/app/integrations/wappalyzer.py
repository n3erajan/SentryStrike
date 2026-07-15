"""Technology fingerprinting for the scanned target.

Replaces the previous header-only stub with a robust, Wappalyzer-schema engine
(:mod:`app.integrations.wappalyzer_engine`) fed from two evidence sources:

1. **Passive** — response headers, cookies, HTML, ``<script src>`` and ``<meta>``
   tags the crawler already captured (``crawl_result.requests`` /
   ``spa_root_html``). Zero extra requests in the common path.
2. **Runtime** — an optional Playwright ``page.evaluate`` pass that reads the
   ``js`` window properties and ``dom`` selectors the fingerprints reference.
   This is what identifies modern SPAs (e.g. Angular via ``[ng-version]``) that
   emit no ``Server`` / ``X-Powered-By`` header.

Output is ``list[TechnologyComponent]`` — unchanged, so CVE enrichment
(:meth:`app.integrations.cve_database.CveDatabaseService.enrich_components`) is
untouched.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from bs4 import BeautifulSoup

from app.config import get_settings
from app.integrations import wappalyzer_engine as engine
from shared.models.vulnerability import TechnologyComponent
from app.utils.scan_http import create_scan_client

logger = logging.getLogger(__name__)

try:  # Playwright is optional; the passive path works without it.
    from playwright.async_api import async_playwright

    PLAYWRIGHT_AVAILABLE = True
except ImportError:  # pragma: no cover
    async_playwright = None
    PLAYWRIGHT_AVAILABLE = False


class TechnologyDetector:
    def __init__(self) -> None:
        self.settings = get_settings()

    async def detect(
        self,
        url: str,
        *,
        crawl_result: Any | None = None,
        browser_available: bool = False,
        storage_state: dict | None = None,
        session_cookies: dict | None = None,
    ) -> list[TechnologyComponent]:
        """Fingerprint the target's technology stack.

        Backward-compatible: ``detect(url)`` alone still works (single-fetch
        fallback). When ``crawl_result`` is supplied, evidence is reused from the
        crawl; when ``browser_available`` and Playwright are present, a runtime
        JS/DOM pass is added.
        """
        evidence = await self._gather_evidence(url, crawl_result)

        if browser_available and PLAYWRIGHT_AVAILABLE:
            try:
                await self._augment_with_runtime(url, evidence, storage_state, session_cookies)
            except Exception as exc:  # never let the browser pass break detection
                logger.debug("Technology runtime pass failed for %s: %s", url, exc)

        try:
            components = engine.match(evidence)
        except Exception as exc:
            logger.warning("Fingerprint matching failed for %s: %s", url, exc)
            return []

        results = [
            TechnologyComponent(name=c.name, version=c.version, category=c.category)
            for c in components
        ]
        logger.debug("Technology detection for %s: %d component(s)", url, len(results))
        return results

    # ------------------------------------------------------------------ #
    # Passive evidence
    # ------------------------------------------------------------------ #

    async def _gather_evidence(self, url: str, crawl_result: Any | None) -> engine.Evidence:
        headers: dict[str, str] = {}
        cookies: dict[str, str] = {}
        html_parts: list[str] = []

        if crawl_result is not None:
            # Root HTML captured by the browser engine.
            root_html = getattr(crawl_result, "spa_root_html", "") or ""
            if root_html:
                html_parts.append(root_html)

            # Per-request observations: headers, cookies, response snippets.
            for obs in getattr(crawl_result, "requests", []) or []:
                for hname, hval in (getattr(obs, "response_headers", {}) or {}).items():
                    key = hname.lower()
                    # Keep the first value per header (usually the root doc's).
                    headers.setdefault(key, str(hval))
                for cname, cval in (getattr(obs, "request_cookies", {}) or {}).items():
                    cookies.setdefault(cname, str(cval))
                snippet = getattr(obs, "response_snippet", "") or ""
                # Only HTML-ish snippets contribute to html/script/meta matching.
                if snippet and "<" in snippet and ">" in snippet:
                    html_parts.append(snippet)

        # Fallback / supplement: one fetch of the root document.
        if not headers and not html_parts:
            try:
                async with create_scan_client(timeout=self.settings.request_timeout_seconds) as client:
                    resp = await client.get(url)
                headers = {k.lower(): v for k, v in resp.headers.items()}
                for cname, cval in resp.cookies.items():
                    cookies.setdefault(cname, cval)
                html_parts.append(resp.text)
            except Exception as exc:
                logger.debug("Technology fallback fetch failed for %s: %s", url, exc)

        html = "\n".join(html_parts)
        script_src, meta = self._parse_html(html)

        return engine.Evidence(
            headers=headers,
            cookies=cookies,
            html=html,
            script_src=script_src,
            meta=meta,
            url=url,
        )

    @staticmethod
    def _parse_html(html: str) -> tuple[list[str], dict[str, str]]:
        script_src: list[str] = []
        meta: dict[str, str] = {}
        if not html:
            return script_src, meta
        try:
            soup = BeautifulSoup(html, "html.parser")
        except Exception:
            return script_src, meta
        for script in soup.find_all("script"):
            src = script.get("src")
            if src:
                script_src.append(src)
        for tag in soup.find_all("meta"):
            name = tag.get("name") or tag.get("property")
            content = tag.get("content")
            if name and content:
                meta[name.lower()] = content
        return script_src, meta

    # ------------------------------------------------------------------ #
    # Runtime (Playwright) evidence — js / dom fingerprints
    # ------------------------------------------------------------------ #

    async def _augment_with_runtime(
        self,
        url: str,
        evidence: engine.Evidence,
        storage_state: dict | None,
        session_cookies: dict | None,
    ) -> None:
        js_paths, dom_selectors = engine.runtime_probes()
        if not js_paths and not dom_selectors:
            return

        timeout = min(20.0, max(5.0, self.settings.request_timeout_seconds * 1.5))
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context(
                ignore_https_errors=True,
                user_agent="SentryStrikeScanner/1.0",
                storage_state=storage_state if storage_state else None,
            )
            try:
                page = await context.new_page()
                try:
                    await page.goto(url, wait_until="networkidle", timeout=int(timeout * 1000))
                except Exception:
                    # networkidle can time out on chatty SPAs; a domcontentloaded
                    # render is still enough for js/dom fingerprints.
                    await page.goto(url, wait_until="domcontentloaded", timeout=int(timeout * 1000))
                await asyncio.sleep(0.4)

                js_values = await self._probe_js(page, js_paths)
                dom_values = await self._probe_dom(page, dom_selectors)
                evidence.js.update(js_values)
                evidence.dom.update(dom_values)
            finally:
                await context.close()
                await browser.close()

    @staticmethod
    async def _probe_js(page: Any, js_paths: list[str]) -> dict[str, str]:
        """Read each dotted window.<path>, returning present values as strings."""
        script = """
        (paths) => {
          const out = {};
          for (const path of paths) {
            try {
              let cur = window;
              for (const part of path.split('.')) {
                if (cur == null) { cur = undefined; break; }
                cur = cur[part];
              }
              if (cur !== undefined && cur !== null) {
                out[path] = (typeof cur === 'object' || typeof cur === 'function')
                  ? '' : String(cur);
              }
            } catch (e) { /* ignore inaccessible props */ }
          }
          return out;
        }
        """
        try:
            return await page.evaluate(script, js_paths)
        except Exception:
            return {}

    @staticmethod
    async def _probe_dom(page: Any, selectors: list[str]) -> dict[str, dict]:
        """For each CSS selector, report existence + attributes + text of the first node."""
        script = """
        (selectors) => {
          const out = {};
          for (const sel of selectors) {
            let el;
            try { el = document.querySelector(sel); } catch (e) { continue; }
            if (!el) continue;
            const attrs = {};
            for (const a of el.attributes) attrs[a.name.toLowerCase()] = a.value;
            out[sel] = {
              exists: true,
              text: (el.textContent || '').slice(0, 200),
              attributes: attrs,
            };
          }
          return out;
        }
        """
        try:
            return await page.evaluate(script, selectors)
        except Exception:
            return {}
