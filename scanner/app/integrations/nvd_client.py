import logging
import re
from datetime import datetime, timedelta, timezone

import httpx

from app.config import get_settings

logger = logging.getLogger(__name__)


class NvdClient:
    def __init__(self) -> None:
        self.settings = get_settings()
        self._cache: dict[str, tuple[datetime, list[dict]]] = {}

    @staticmethod
    def _base_version(version: str | None) -> str | None:
        """Strip distro/packaging suffixes to yield the upstream version.
        E.g. "5.3.2-1ubuntu4.30" -> "5.3.2", "2.4.6-6.el7" -> "2.4.6".
        """
        if not version:
            return None
        # Match a leading semver (e.g. 5.3.2, 2.4.6, 10.0.1) or major.minor (e.g. 3.1)
        m = re.match(r"\d+(?:\.\d+){1,2}", version)
        return m.group(0) if m else version

    async def _search_nvd(self, query: str) -> list[dict]:
        headers = {}
        if self.settings.nvd_api_key:
            headers["apiKey"] = self.settings.nvd_api_key
        params = {"keywordSearch": query, "resultsPerPage": 5}
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(self.settings.nvd_api_url, params=params, headers=headers)
            resp.raise_for_status()
        return resp.json().get("vulnerabilities", [])

    async def lookup_cves(self, component_name: str, version: str | None = None) -> list[dict]:
        key = f"{component_name.lower()}:{version or ''}"
        now = datetime.now(timezone.utc)
        cached = self._cache.get(key)
        if cached and now - cached[0] < timedelta(seconds=self.settings.cve_cache_ttl_seconds):
            return cached[1]

        base_ver = self._base_version(version)
        queries = [f"{component_name} {version}".strip()]
        if base_ver and base_ver != version:
            queries.append(f"{component_name} {base_ver}")

        result: list[dict] = []
        for query in queries:
            try:
                vulns = await self._search_nvd(query)
                result = [self._parse_item(v) for v in vulns]
                if result:
                    break
            except Exception as exc:
                logger.warning("NVD lookup failed for query '%s': %s", query, exc)

        self._cache[key] = (now, result)
        return result

    def _parse_item(self, item: dict) -> dict:
        cve = item.get("cve", {})
        cve_id = cve.get("id", "UNKNOWN")
        description = ""
        for d in cve.get("descriptions", []):
            if d.get("lang") == "en":
                description = d.get("value", "")
                break
        severity = None
        metrics = cve.get("metrics", {})
        cvss_v31 = metrics.get("cvssMetricV31") or []
        if cvss_v31:
            severity = cvss_v31[0].get("cvssData", {}).get("baseScore")
        return {"cve_id": cve_id, "summary": description, "severity_score": severity}
