"""Exploitation-in-the-wild overlays: CISA KEV and FIRST's EPSS.

CPE and OSV matching settle *which* CVEs apply to a component. These two feeds
settle which of them matter most, so findings can be ranked instead of truncated -
the old client kept whatever five results NVD returned first, which was roughly
CVE-ID order, so the oldest matches always won.

* **KEV** - CISA's Known Exploited Vulnerabilities catalogue: CVEs with confirmed
  active exploitation. Membership is a strong signal to patch now.
* **EPSS** - FIRST's Exploit Prediction Scoring System: the probability a CVE will
  be exploited in the next 30 days. Usefully orthogonal to CVSS, which measures
  impact if exploited, not likelihood.

Both are keyless, and both are advisory: if either feed is unavailable the
enrichment continues without it rather than failing the scan.
"""

import logging
import time

import httpx

from app.config import get_settings

logger = logging.getLogger(__name__)


class ThreatIntel:
    """Fetch and cache the KEV catalogue and EPSS scores."""

    def __init__(self, *, transport: httpx.BaseTransport | None = None) -> None:
        self.settings = get_settings()
        self._transport = transport
        self._kev: set[str] | None = None
        self._kev_fetched_at: float = 0.0
        # The EPSS API caps query-string length, so long CVE lists are chunked.
        self.epss_batch_size = 100

    # ------------------------------------------------------------------ #
    # KEV
    # ------------------------------------------------------------------ #

    async def known_exploited(self, cve_ids: list[str]) -> list[str]:
        """Return the subset of ``cve_ids`` present in CISA's KEV catalogue."""
        if not cve_ids:
            return []
        catalog = await self._kev_catalog()
        if not catalog:
            return []
        return [c for c in cve_ids if c in catalog]

    async def _kev_catalog(self) -> set[str]:
        ttl = self.settings.threat_intel_cache_ttl_seconds
        if self._kev is not None and time.monotonic() - self._kev_fetched_at < ttl:
            return self._kev
        try:
            async with httpx.AsyncClient(timeout=60.0, transport=self._transport) as client:
                resp = await client.get(self.settings.kev_feed_url)
                resp.raise_for_status()
                payload = resp.json()
        except Exception as exc:
            logger.warning("KEV catalogue fetch failed: %s", exc)
            # Cache the miss briefly so a broken feed does not add a 60s timeout
            # to every component in the stack.
            self._kev = set()
            self._kev_fetched_at = time.monotonic()
            return self._kev
        self._kev = {
            v["cveID"] for v in payload.get("vulnerabilities", []) or [] if v.get("cveID")
        }
        self._kev_fetched_at = time.monotonic()
        logger.debug("KEV catalogue loaded: %d entries", len(self._kev))
        return self._kev

    # ------------------------------------------------------------------ #
    # EPSS
    # ------------------------------------------------------------------ #

    async def exploit_probability(self, cve_ids: list[str]) -> dict[str, float]:
        """Return ``{cve_id: epss_probability}`` for the CVEs EPSS scores.

        CVEs EPSS has no score for are *absent* from the result rather than
        present with 0.0, which would read as "certainly not exploited".
        """
        ids = [c for c in cve_ids if c.startswith("CVE-")]
        if not ids:
            return {}

        scores: dict[str, float] = {}
        try:
            async with httpx.AsyncClient(timeout=30.0, transport=self._transport) as client:
                for start in range(0, len(ids), self.epss_batch_size):
                    batch = ids[start : start + self.epss_batch_size]
                    resp = await client.get(
                        self.settings.epss_api_url, params={"cve": ",".join(batch)}
                    )
                    resp.raise_for_status()
                    for row in resp.json().get("data", []) or []:
                        cve, epss = row.get("cve"), row.get("epss")
                        if cve and epss is not None:
                            scores[cve] = float(epss)
        except Exception as exc:
            logger.warning("EPSS lookup failed: %s", exc)
            return scores
        return scores
