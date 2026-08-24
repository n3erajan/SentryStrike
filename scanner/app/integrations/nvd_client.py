"""Client for the NIST National Vulnerability Database (NVD) API.

Queries are made by **CPE applicability**, not by description keyword. NVD's
``keywordSearch`` parameter is a full-text search over CVE prose, which fails in
both directions:

* False positives on loose versions. ``keywordSearch="WordPress 7.1"`` returns 84
  results, none of which are WordPress core - the top five are CVEs for the
  wp-google-maps and wp-live-chat-support *plugins*, matched because their
  descriptions read "before 7.1.03 for WordPress". WordPress 7.1 is the current
  release and has no applicable CVEs at all.
* Silent false negatives on precise versions. ``"Express 4.18.2"``,
  ``"Nginx 1.24.0"`` and ``"Node.js 18.16.0"`` each return *zero* results,
  because NVD descriptions rarely spell out a full patch version - so a
  vulnerable component was reported as clean.

``virtualMatchString=cpe:2.3:a:f5:nginx:1.24.0`` instead asks NVD to match the
version against each CVE's declared applicability ranges, which returns exactly
the two CVEs that cover nginx 1.24.0. Every result is then re-verified locally by
:mod:`app.integrations.cpe_match` before it is reported.
"""

import asyncio
import logging
import time
from collections import deque
from datetime import datetime, timedelta, timezone

import httpx

from app.config import get_settings
from app.integrations.cpe_match import any_config_applies, cpe_product
from app.integrations.vuln_lookup import VulnLookup

logger = logging.getLogger(__name__)

SOURCE = "nvd-cpe"

# NVD's published request ceilings per rolling 30-second window.
_UNKEYED_BUDGET = 5
_KEYED_BUDGET = 50
_WINDOW_SECONDS = 30.0

# CVSS metric blocks in preference order (newest scoring system first).
_METRIC_KEYS = ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2")


class _RateLimiter:
    """Bound calls to ``max_calls`` per rolling ``window_seconds``.

    Without a key NVD allows only 5 requests per 30 seconds and answers 403/429
    beyond that. The old client had no limiter and swallowed the resulting errors
    as empty results, so a scan with more than five versioned components silently
    reported the tail of its stack as vulnerability-free.
    """

    def __init__(self, max_calls: int, window_seconds: float = _WINDOW_SECONDS) -> None:
        self.max_calls = max(1, max_calls)
        self.window_seconds = window_seconds
        self.min_interval = 0.0
        self._calls: deque[float] = deque()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            while True:
                now = time.monotonic()
                while self._calls and now - self._calls[0] >= self.window_seconds:
                    self._calls.popleft()
                if len(self._calls) < self.max_calls:
                    self._calls.append(now)
                    return
                wait = self.window_seconds - (now - self._calls[0])
                await asyncio.sleep(max(wait, self.min_interval or 0.01))


class NvdClient:
    """Look up CVEs applicable to a specific component version via CPE matching.

    Successful lookups are cached in memory per (name, version, cpe) for the
    configured TTL. Failures are deliberately *not* cached: caching a transient
    rate-limit response would suppress a real component for a whole TTL.
    """

    def __init__(self, *, transport: httpx.BaseTransport | None = None) -> None:
        self.settings = get_settings()
        self._transport = transport
        self._cache: dict[str, tuple[datetime, VulnLookup]] = {}
        self.page_size = 200
        self.rate_limiter = _RateLimiter(self._request_budget())

    def _request_budget(self) -> int:
        return _KEYED_BUDGET if self.settings.nvd_api_key else _UNKEYED_BUDGET

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #

    async def lookup(
        self, component_name: str, version: str | None, cpe: str | None
    ) -> VulnLookup:
        """Return the CVEs applicable to ``component_name`` at ``version``.

        Both a version and a CPE are required. Without a version there is nothing
        to match ranges against; without a CPE there is no product identity, and
        guessing one from the display name is how "PHP" ends up carrying TYPO3's
        CVEs. Either gap yields ``not_assessed`` rather than a misleading ``[]``.
        """
        if not version or not version.strip():
            return VulnLookup.not_assessed(
                f"no version detected for {component_name}; CVE applicability "
                "cannot be determined without one"
            )
        identity = cpe_product(cpe or "")
        if not identity:
            return VulnLookup.not_assessed(
                f"no CPE mapping for {component_name}; cannot match CVEs by product identity"
            )

        version = version.strip()
        vendor, product = identity
        key = f"{vendor}:{product}:{version}"
        now = datetime.now(timezone.utc)
        cached = self._cache.get(key)
        if cached and now - cached[0] < timedelta(seconds=self.settings.cve_cache_ttl_seconds):
            return cached[1]

        try:
            raw = await self._fetch_all(vendor, product, version)
        except httpx.HTTPStatusError as exc:
            reason = f"NVD returned HTTP {exc.response.status_code} for {vendor}:{product}"
            logger.warning("%s", reason)
            return VulnLookup.failed(SOURCE, reason)
        except Exception as exc:
            reason = f"NVD request failed for {vendor}:{product}: {exc}"
            logger.warning("%s", reason)
            return VulnLookup.failed(SOURCE, reason)

        cves = [
            self._parse_item(item)
            for item in raw
            if any_config_applies(
                version, vendor, product, item.get("cve", {}).get("configurations", [])
            )
        ]
        dropped = len(raw) - len(cves)
        if dropped:
            logger.debug(
                "NVD %s:%s %s - dropped %d/%d result(s) not applicable to this version",
                vendor, product, version, dropped, len(raw),
            )
        result = VulnLookup.assessed(SOURCE, cves)
        self._cache[key] = (now, result)
        return result

    # ------------------------------------------------------------------ #
    # HTTP
    # ------------------------------------------------------------------ #

    async def _fetch_all(self, vendor: str, product: str, version: str) -> list[dict]:
        """Page through every result for this CPE instead of truncating.

        The old client passed ``resultsPerPage=5`` and kept whatever NVD happened
        to return first - which is roughly CVE-ID order, so the five *oldest*
        matches won and anything recent was discarded unseen.
        """
        match_string = f"cpe:2.3:a:{vendor}:{product}:{version}"
        collected: list[dict] = []
        start_index = 0
        while True:
            payload = await self._get(
                {
                    "virtualMatchString": match_string,
                    "resultsPerPage": self.page_size,
                    "startIndex": start_index,
                }
            )
            page = payload.get("vulnerabilities", []) or []
            collected.extend(page)
            total = int(payload.get("totalResults", len(collected)) or 0)
            start_index += self.page_size
            if not page or start_index >= total:
                return collected

    async def _get(self, params: dict) -> dict:
        headers = {}
        if self.settings.nvd_api_key:
            headers["apiKey"] = self.settings.nvd_api_key
        await self.rate_limiter.acquire()
        async with httpx.AsyncClient(timeout=30.0, transport=self._transport) as client:
            resp = await client.get(self.settings.nvd_api_url, params=params, headers=headers)
            resp.raise_for_status()
            return resp.json()

    # ------------------------------------------------------------------ #
    # Parsing
    # ------------------------------------------------------------------ #

    def _parse_item(self, item: dict) -> dict:
        cve = item.get("cve", {})
        description = ""
        for d in cve.get("descriptions", []) or []:
            if d.get("lang") == "en":
                description = d.get("value", "")
                break
        return {
            "cve_id": cve.get("id", "UNKNOWN"),
            "summary": description,
            "severity_score": self._base_score(cve.get("metrics", {}) or {}),
            "published": cve.get("published"),
            "references": [
                r.get("url") for r in (cve.get("references", []) or []) if r.get("url")
            ][:5],
        }

    @staticmethod
    def _base_score(metrics: dict) -> float | None:
        """Read the base score from the newest CVSS block the CVE carries."""
        for key in _METRIC_KEYS:
            entries = metrics.get(key) or []
            if entries:
                data = entries[0].get("cvssData", {}) or {}
                score = data.get("baseScore")
                if score is not None:
                    return float(score)
        return None
