"""Client for the OSV.dev vulnerability database.

OSV is the right source for anything published to a package ecosystem. It
aggregates GitHub Security Advisories, PyPA, RustSec, Go's vuln DB and others,
and - crucially - resolves version ranges using each ecosystem's own version
semantics rather than a text match. It is keyless and unmetered.

Where NVD's ``keywordSearch="Express 4.18.2"`` returned zero results, OSV returns
the two advisories that actually apply: CVE-2024-43796 (XSS via
``response.redirect()``) and CVE-2024-29041 (open redirect on malformed URLs).
"""

import logging
from datetime import datetime, timedelta, timezone

import httpx

from app.config import get_settings
from app.integrations.cvss import base_score_from_vector
from app.integrations.vuln_lookup import VulnLookup

logger = logging.getLogger(__name__)

SOURCE = "osv"

# CVSS vector types we can convert to a numeric base score, newest first.
_SCORABLE_TYPES = ("CVSS_V3",)


class OsvClient:
    """Resolve advisories for one ecosystem package at one version."""

    def __init__(self, *, transport: httpx.BaseTransport | None = None) -> None:
        self.settings = get_settings()
        self._transport = transport
        self._cache: dict[str, tuple[datetime, VulnLookup]] = {}

    async def lookup(
        self, component_name: str, version: str | None, ecosystem: str, package: str
    ) -> VulnLookup:
        """Return advisories affecting ``package``@``version`` in ``ecosystem``."""
        if not version or not version.strip():
            return VulnLookup.not_assessed(
                f"no version detected for {component_name}; OSV resolves advisories "
                "by exact version and cannot match without one"
            )

        version = version.strip()
        key = f"{ecosystem}:{package}:{version}"
        now = datetime.now(timezone.utc)
        cached = self._cache.get(key)
        if cached and now - cached[0] < timedelta(seconds=self.settings.cve_cache_ttl_seconds):
            return cached[1]

        try:
            payload = await self._query(ecosystem, package, version)
        except httpx.HTTPStatusError as exc:
            reason = f"OSV returned HTTP {exc.response.status_code} for {package}@{version}"
            logger.warning("%s", reason)
            return VulnLookup.failed(SOURCE, reason)
        except Exception as exc:
            reason = f"OSV request failed for {package}@{version}: {exc}"
            logger.warning("%s", reason)
            return VulnLookup.failed(SOURCE, reason)

        cves = [
            self._parse_vuln(v)
            for v in (payload.get("vulns", []) or [])
            # A withdrawn advisory has been retracted; reporting it is a false positive.
            if not v.get("withdrawn")
        ]
        result = VulnLookup.assessed(SOURCE, cves)
        self._cache[key] = (now, result)
        return result

    async def _query(self, ecosystem: str, package: str, version: str) -> dict:
        body = {"package": {"name": package, "ecosystem": ecosystem}, "version": version}
        async with httpx.AsyncClient(timeout=30.0, transport=self._transport) as client:
            resp = await client.post(self.settings.osv_api_url, json=body)
            resp.raise_for_status()
            return resp.json()

    @staticmethod
    def _parse_vuln(vuln: dict) -> dict:
        # Prefer the CVE alias: the report, the CVE cache and the KEV/EPSS
        # overlays are all keyed on CVE IDs. An advisory with no CVE assigned
        # keeps its OSV id, since it is still a real vulnerability.
        aliases = vuln.get("aliases", []) or []
        cve_id = next((a for a in aliases if a.startswith("CVE-")), vuln.get("id", "UNKNOWN"))

        score = None
        for entry in vuln.get("severity", []) or []:
            if entry.get("type") in _SCORABLE_TYPES:
                score = base_score_from_vector(entry.get("score"))
                if score is not None:
                    break

        return {
            "cve_id": cve_id,
            "osv_id": vuln.get("id"),
            "summary": vuln.get("summary") or vuln.get("details", "")[:300],
            "severity_score": score,
            # Carried so a v4-only advisory still conveys severity without a
            # fabricated number standing in for the missing score.
            "severity_label": (vuln.get("database_specific") or {}).get("severity"),
            "published": vuln.get("published"),
            "references": [
                r.get("url") for r in (vuln.get("references", []) or []) if r.get("url")
            ][:5],
        }
