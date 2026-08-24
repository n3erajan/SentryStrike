"""Client for the Wordfence Intelligence v3 vulnerability data feed.

WordPress core is indexed by NVD under ``cpe:2.3:a:wordpress:wordpress``, but its
plugin and theme ecosystem - where nearly all real WordPress risk lives - is
covered late and incompletely. That mismatch is what produced the original false
positives: a keyword search for WordPress core surfaced CVEs belonging to the
wp-google-maps and wp-live-chat-support plugins.

Shape and auth follow Wordfence's published v3 documentation. The endpoint takes
no parameters and returns the entire feed as a UUID-keyed object, so it is fetched
once per TTL and indexed by ``(type, slug)``. Authentication is
``Authorization: Bearer <key>``; v1 and v2 of this feed were switched off on
2026-03-09 and now answer HTTP 410.

Without ``WORDFENCE_API_KEY`` this client reports every plugin and theme as
*unassessed*. That is deliberate - claiming a plugin is clean when nothing was
queried is the failure mode being fixed.
"""

import logging
import time

import httpx

from app.config import get_settings
from app.integrations.cpe_match import compare_versions
from app.integrations.vuln_lookup import VulnLookup

logger = logging.getLogger(__name__)

SOURCE = "wordfence"

# The feed uses "*" for an unbounded end of a version range.
_UNBOUNDED = ("*", "", None)


class WordfenceClient:
    """Resolve WordPress plugin/theme vulnerabilities from the Wordfence feed."""

    def __init__(self, *, transport: httpx.BaseTransport | None = None) -> None:
        self.settings = get_settings()
        self._transport = transport
        self._api_key_override: str | None = None
        self._feed: dict[tuple[str, str], list[tuple[dict, dict]]] | None = None
        self._fetched_at: float = 0.0

    @property
    def api_key(self) -> str | None:
        if self._api_key_override is not None:
            return self._api_key_override
        return self.settings.wordfence_api_key

    @property
    def enabled(self) -> bool:
        return bool(self.api_key)

    async def lookup(
        self, component_name: str, version: str | None, software_type: str, slug: str | None
    ) -> VulnLookup:
        """Return vulnerabilities affecting ``slug``@``version``.

        ``software_type`` is ``"plugin"``, ``"theme"`` or ``"core"``, matching the
        feed's own ``software[].type`` values.
        """
        if not self.enabled:
            return VulnLookup.not_assessed(
                f"{component_name} is a WordPress {software_type}, which NVD covers "
                "poorly; set WORDFENCE_API_KEY to assess it against the Wordfence "
                "Intelligence feed"
            )
        if not version or not version.strip():
            return VulnLookup.not_assessed(
                f"no version detected for {component_name}; affected-version ranges "
                "cannot be matched without one"
            )
        if not slug:
            return VulnLookup.not_assessed(
                f"no plugin/theme slug resolved for {component_name}; the feed is "
                "keyed on slug and a display name cannot be substituted for one"
            )

        try:
            index = await self._load_feed()
        except httpx.HTTPStatusError as exc:
            reason = f"Wordfence returned HTTP {exc.response.status_code} for the feed"
            logger.warning("%s", reason)
            return VulnLookup.failed(SOURCE, reason)
        except Exception as exc:
            reason = f"Wordfence feed fetch failed: {exc}"
            logger.warning("%s", reason)
            return VulnLookup.failed(SOURCE, reason)

        version = version.strip()
        cves = [
            self._parse_record(record, entry)
            for record, entry in index.get((software_type.lower(), slug.lower()), [])
            if not record.get("informational")
            and self._version_affected(version, entry.get("affected_versions", {}))
        ]
        return VulnLookup.assessed(SOURCE, cves)

    # ------------------------------------------------------------------ #
    # Feed
    # ------------------------------------------------------------------ #

    async def _load_feed(self) -> dict[tuple[str, str], list[tuple[dict, dict]]]:
        ttl = self.settings.threat_intel_cache_ttl_seconds
        if self._feed is not None and time.monotonic() - self._fetched_at < ttl:
            return self._feed

        headers = {"Authorization": f"Bearer {self.api_key}"}
        async with httpx.AsyncClient(timeout=120.0, transport=self._transport) as client:
            resp = await client.get(self.settings.wordfence_api_url, headers=headers)
            resp.raise_for_status()
            payload = resp.json()

        # The endpoint accepts no parameters and returns everything, so index the
        # whole feed by (type, slug) once instead of re-scanning per component.
        index: dict[tuple[str, str], list[tuple[dict, dict]]] = {}
        for record in (payload or {}).values():
            if not isinstance(record, dict):
                continue
            for entry in record.get("software", []) or []:
                slug = (entry.get("slug") or "").lower()
                sw_type = (entry.get("type") or "").lower()
                if slug and sw_type:
                    index.setdefault((sw_type, slug), []).append((record, entry))
        self._feed = index
        self._fetched_at = time.monotonic()
        logger.debug("Wordfence feed loaded: %d (type, slug) keys", len(index))
        return index

    # ------------------------------------------------------------------ #
    # Version ranges
    # ------------------------------------------------------------------ #

    @staticmethod
    def _version_affected(version: str, affected_versions: dict) -> bool:
        """Does ``version`` fall inside any of this entry's affected ranges?

        Unlike NVD's un-versioned legacy CPEs, a ``*`` bound here is an explicit
        editorial statement ("every version up to X"), so it is honoured as an
        open end rather than rejected as missing data.
        """
        for rng in (affected_versions or {}).values():
            if not isinstance(rng, dict):
                continue
            start, end = rng.get("from_version"), rng.get("to_version")
            if start not in _UNBOUNDED:
                cmp = compare_versions(version, start)
                if cmp < 0 or (cmp == 0 and not rng.get("from_inclusive", True)):
                    continue
            if end not in _UNBOUNDED:
                cmp = compare_versions(version, end)
                if cmp > 0 or (cmp == 0 and not rng.get("to_inclusive", True)):
                    continue
            return True
        return False

    # ------------------------------------------------------------------ #
    # Parsing
    # ------------------------------------------------------------------ #

    @staticmethod
    def _parse_record(record: dict, entry: dict) -> dict:
        cvss = record.get("cvss") or {}
        cve = (record.get("cve") or "").strip()
        return {
            # Some records are disclosed before a CVE is assigned; keep them
            # identifiable rather than dropping a real vulnerability.
            "cve_id": cve or f"WORDFENCE-{record.get('id')}",
            "summary": record.get("title") or record.get("description", "")[:300],
            "severity_score": cvss.get("score"),
            "severity_label": cvss.get("rating"),
            "published": record.get("published"),
            "remediation": entry.get("remediation"),
            "patched_versions": entry.get("patched_versions") or [],
            "references": (record.get("references") or [])[:5],
        }
