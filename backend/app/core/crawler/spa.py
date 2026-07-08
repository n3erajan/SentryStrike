from __future__ import annotations

import asyncio
import hashlib
import logging
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


async def settle_page(
    page: Any,
    *,
    inflight: dict[str, int] | None = None,
    quiet_ms: float = 500.0,
    cap_ms: float = 4000.0,
) -> None:
    """domcontentloaded + inflight-drain settle. ``networkidle``-free.

    ``networkidle`` never fires on apps with persistent sockets/polling/analytics,
    so instead of waiting for a load state that never arrives we watch an in-flight
    request counter and return once it stays at zero for ``quiet_ms`` or ``cap_ms``
    elapses — whichever comes first.

    Two modes:

    - ``inflight`` provided (the crawl engine): use the caller's persistent
      counter — already wired to the page's request/requestfinished/requestfailed
      events for the whole route sequence — and attach no listeners here.
    - ``inflight`` omitted (the auth manager): attach a temporary counter for the
      duration of this call and detach it before returning, so repeated calls on
      the same page never accumulate handlers.

    Shared by the crawl engine and the auth manager so there is exactly one
    settle implementation.
    """
    owns_counter = inflight is None
    if owns_counter:
        inflight = {"count": 0}

        def _inc(_request: Any) -> None:
            inflight["count"] += 1

        def _dec(_request: Any) -> None:
            inflight["count"] = max(0, inflight["count"] - 1)

        listeners = (("request", _inc), ("requestfinished", _dec), ("requestfailed", _dec))
        for event, handler in listeners:
            try:
                page.on(event, handler)
            except Exception:
                pass

    try:
        loop = asyncio.get_running_loop()
        start = loop.time()
        quiet_start: float | None = None
        while True:
            now = loop.time()
            if (now - start) * 1000.0 >= cap_ms:
                break
            if inflight.get("count", 0) <= 0:
                if quiet_start is None:
                    quiet_start = now
                elif (now - quiet_start) * 1000.0 >= quiet_ms:
                    break
            else:
                quiet_start = None
            await asyncio.sleep(0.05)
        try:
            await asyncio.wait_for(page.wait_for_load_state("domcontentloaded"), timeout=1.0)
        except Exception:
            pass
    finally:
        if owns_counter:
            for event, handler in listeners:
                try:
                    page.remove_listener(event, handler)
                except Exception:
                    pass


# Resource types that never carry app data an XHR depends on. Blocking these
# speeds up settle on every navigation without breaking SPA data loads.
BLOCKED_RESOURCE_TYPES = frozenset({"image", "media", "font", "stylesheet"})

# Known third-party analytics/tracker/monitoring hosts. Matched by substring
# against the request URL. Blocking these avoids burning the settle budget on
# beacons that are irrelevant to the scan. Same-origin traffic is never matched
# here (the caller only blocks by resource type or tracker host, never by
# same-origin script/xhr/fetch/document).
BLOCKED_HOST_SUBSTRINGS = (
    "google-analytics.com",
    "googletagmanager.com",
    "doubleclick.net",
    "google-analytics",
    "googletagmanager",
    "doubleclick",
    "facebook.net",
    "facebook.com/tr",
    "connect.facebook",
    "hotjar.com",
    "hotjar",
    "segment.io",
    "segment.com",
    "mixpanel.com",
    "mixpanel",
    "sentry.io",
    "bugsnag.com",
    "fullstory.com",
    "amplitude.com",
    "intercom.io",
    "clarity.ms",
    "newrelic.com",
    "nr-data.net",
    "optimizely.com",
    "cdn.heapanalytics.com",
)


def _is_tracker(url: str) -> bool:
    lowered = url.lower()
    return any(host in lowered for host in BLOCKED_HOST_SUBSTRINGS)


async def install_resource_blocking(context: Any) -> None:
    """Abort non-essential resource loads on ``context`` for a faster settle.

    Blocks by resource type (image/media/font/stylesheet) and known-tracker host
    only. Never aborts ``script``/``xhr``/``fetch``/``document`` — those can drive
    SPA data loads, so blocking them would break discovery. Best-effort: any error
    installing the route is swallowed so resource blocking never fails a crawl.
    """
    async def _route(route: Any) -> None:
        try:
            request = route.request
            if request.resource_type in BLOCKED_RESOURCE_TYPES or _is_tracker(request.url):
                await route.abort()
            else:
                await route.continue_()
        except Exception:
            # A doomed route (target already closed, etc.) must not raise into
            # the crawl. Try to let it through, then give up silently.
            try:
                await route.continue_()
            except Exception:
                pass

    try:
        await context.route("**/*", _route)
    except Exception as exc:
        logger.debug("failed to install resource blocking: %s", exc)


@dataclass
class SpaFallbackSignal:
    is_fallback: bool
    reason: str = ""
    similarity: float = 0.0


class SpaFallbackDetector:
    """Detect unknown client-side routes that all return the same SPA shell."""

    def __init__(self, root_html: str | None = None, root_url: str | None = None) -> None:
        self.root_url = root_url
        self.root_html = root_html or ""
        self.root_fingerprint = self.fingerprint(root_html or "") if root_html else ""
        self.root_title = self._title(root_html or "") if root_html else ""
        self.root_tokens = self._tokens_from_fingerprint_source(root_html or "") if root_html else set()

    def configure_root(self, root_url: str, html: str) -> None:
        self.root_url = root_url
        self.root_html = html
        self.root_fingerprint = self.fingerprint(html)
        self.root_title = self._title(html)
        self.root_tokens = self._tokens_from_fingerprint_source(html)

    def root_looks_like_spa(self) -> bool:
        return self.looks_like_spa_shell(self.root_url or "", self.root_html, self.root_tokens)

    def detect(
        self,
        url: str,
        status_code: int,
        content_type: str,
        html: str,
        *,
        allow_file_like_path: bool = False,
    ) -> SpaFallbackSignal:
        if status_code != 200 or "text/html" not in content_type.lower():
            return SpaFallbackSignal(False)
        if not self.root_fingerprint or not html:
            return SpaFallbackSignal(False)

        parsed = urlparse(url)
        if pathlib_suffix(parsed.path) and not allow_file_like_path:
            return SpaFallbackSignal(False)

        candidate_fingerprint = self.fingerprint(html)
        if candidate_fingerprint == self.root_fingerprint:
            return SpaFallbackSignal(True, "html shell fingerprint matched root", 1.0)

        similarity = self._similarity(self.root_tokens, self._tokens_from_fingerprint_source(html))
        if similarity >= 0.98 and self.root_title and self.root_title == self._title(html):
            return SpaFallbackSignal(True, "html shell is effectively identical to root", similarity)
        return SpaFallbackSignal(False, similarity=similarity)

    @staticmethod
    def fingerprint(html: str) -> str:
        normalized = re.sub(r">\s+<", "><", html)
        normalized = re.sub(r"\s+", " ", normalized)
        normalized = re.sub(r"<script\b[^>]*>.*?</script>", "<script></script>", normalized, flags=re.I | re.S)
        normalized = re.sub(r"<style\b[^>]*>.*?</style>", "<style></style>", normalized, flags=re.I | re.S)
        normalized = re.sub(r"\b(?:nonce|integrity|crossorigin)=(['\"]).*?\1", "", normalized, flags=re.I)
        return hashlib.sha256(normalized.strip().encode("utf-8", "ignore")).hexdigest()

    @staticmethod
    def _title(html: str) -> str:
        match = re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.S)
        return re.sub(r"\s+", " ", match.group(1)).strip().lower() if match else ""

    @staticmethod
    def _tokens_from_fingerprint_source(html: str) -> set[str]:
        return set(re.findall(r"[A-Za-z0-9_/-]{3,}", html.lower()))

    @staticmethod
    def _similarity(a: set[str], b: set[str]) -> float:
        if not a and not b:
            return 1.0
        if not a or not b:
            return 0.0
        return len(a & b) / len(a | b)

    @classmethod
    def looks_like_spa_shell(cls, url: str, html: str, tokens: set[str] | None = None) -> bool:
        source = html.lower()
        token_set = tokens if tokens is not None else cls._tokens_from_fingerprint_source(html)
        marker_patterns = (
            r"<(?:app-root|app|router-outlet)\b",
            r"<div[^>]+id=(['\"])(?:root|app|__next|__nuxt|svelte)\1",
            r"\b(?:ng-version|data-reactroot|data-server-rendered)\b",
            r"\b(?:main|app|runtime|polyfills|vendor|bundle|chunk)[.-][a-z0-9._-]+\.js\b",
            r"\b(?:react|reactdom|angular|vue|webpack|vite|next/static|nuxt)\b",
        )
        if any(re.search(pattern, source, re.I) for pattern in marker_patterns):
            return True
        if any(token in token_set for token in {"app-root", "router-outlet", "__next", "__nuxt", "webpack", "vite"}):
            return True
        parsed = urlparse(url)
        return parsed.path in ("", "/") and "<script" in source and len(token_set) <= 80 and "<form" not in source


def pathlib_suffix(path: str) -> str:
    last = path.rsplit("/", 1)[-1]
    return "." in last and last.rsplit(".", 1)[-1].lower()
