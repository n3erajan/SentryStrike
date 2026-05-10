import logging
from datetime import datetime, timedelta, timezone

import httpx

from app.config import get_settings

logger = logging.getLogger(__name__)


class NvdClient:
    def __init__(self) -> None:
        self.settings = get_settings()
        self._cache: dict[str, tuple[datetime, list[dict]]] = {}

    async def lookup_cves(self, component_name: str, version: str | None = None) -> list[dict]:
        key = f"{component_name.lower()}:{version or ''}"
        now = datetime.now(timezone.utc)
        cached = self._cache.get(key)
        if cached and now - cached[0] < timedelta(seconds=self.settings.cve_cache_ttl_seconds):
            return cached[1]

        params = {"keywordSearch": f"{component_name} {version or ''}".strip(), "resultsPerPage": 5}
        headers = {}
        if self.settings.nvd_api_key:
            headers["apiKey"] = self.settings.nvd_api_key

        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(self.settings.nvd_api_url, params=params, headers=headers)
                resp.raise_for_status()
            vulns = resp.json().get("vulnerabilities", [])
            result = [self._parse_item(v) for v in vulns]
            self._cache[key] = (now, result)
            return result
        except Exception as exc:
            logger.warning("NVD lookup failed for %s: %s", key, exc)
            return []

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
