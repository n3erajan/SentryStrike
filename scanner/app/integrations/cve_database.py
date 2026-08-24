"""Route each detected component to the vulnerability source that covers it.

No single database covers a whole web stack, and the cost of pretending otherwise
is a report full of other software's CVEs. The production report that prompted
this rewrite attributed three WordPress *plugin* CVEs to WordPress core, TYPO3's
CVE-2021-41113 to PHP, and the H2O web server's CVE-2021-43848 to "HTTP/3" -
every one of them because a single ``keywordSearch`` was doing all the work.

Routing:

* ecosystem package (Express, Django, Laravel, jQuery) -> :mod:`osv_client`
* WordPress plugin / theme -> :mod:`wordfence_client`
* server, language, CMS core (Nginx, PHP, WordPress) -> :mod:`nvd_client` by CPE
* anything else -> ``not_assessed``

Two rules hold across all of them. A component with no version is never queried,
because there is nothing to match version ranges against. And a component nothing
could assess is marked ``not_assessed`` rather than left with an empty CVE list
that reads as "clean".
"""

import logging

from app.integrations.nvd_client import NvdClient
from app.integrations.osv_client import OsvClient
from app.integrations.package_identity import osv_package
from app.integrations.threat_intel import ThreatIntel
from app.integrations.vuln_lookup import VulnLookup
from app.integrations.wappalyzer_engine import cpe_for
from app.integrations.wordfence_client import WordfenceClient
from shared.models.cve import CveRecord
from shared.models.vulnerability import TechnologyComponent

logger = logging.getLogger(__name__)

# Fingerprint-DB categories that identify WordPress extensions. The Wordfence
# feed types them "plugin" / "theme".
_WP_PLUGIN_CATEGORIES = {"wordpress plugins", "wordpress plugin"}
_WP_THEME_CATEGORIES = {"wordpress themes", "wordpress theme"}


class CveDatabaseService:
    """Enrich detected technology components with vulnerabilities that apply."""

    def __init__(self) -> None:
        self.nvd_client = NvdClient()
        self.osv_client = OsvClient()
        self.wordfence_client = WordfenceClient()
        self.threat_intel = ThreatIntel()

    async def enrich_components(
        self, components: list[TechnologyComponent]
    ) -> list[TechnologyComponent]:
        """Look up vulnerabilities per component and persist newly seen CVEs."""
        for component in components:
            try:
                lookup = await self._lookup(component)
            except Exception as exc:
                logger.warning(
                    "CVE lookup raised for %s %s: %s", component.name, component.version or "", exc
                )
                lookup = VulnLookup.failed(
                    "unknown", f"lookup raised for {component.name}: {exc}"
                )

            component.cves = lookup.cve_ids
            component.cve_scores = lookup.scores
            component.cve_assessment = lookup.status
            component.cve_assessment_reason = lookup.reason
            component.cve_source = lookup.source

            await self._attach_threat_intel(component)
            await self._persist(component, lookup)

        assessed = sum(1 for c in components if c.cve_assessment == "assessed")
        skipped = sum(1 for c in components if c.cve_assessment == "not_assessed")
        failed = sum(1 for c in components if c.cve_assessment == "failed")
        if components:
            logger.info(
                "CVE enrichment: %d assessed, %d not assessed, %d failed",
                assessed, skipped, failed,
            )
        return components

    # ------------------------------------------------------------------ #
    # Routing
    # ------------------------------------------------------------------ #

    async def _lookup(self, component: TechnologyComponent) -> VulnLookup:
        name, version = component.name, component.version
        category = (component.category or "").lower()

        # Every source needs a version; refusing here keeps the reason uniform
        # rather than depending on which source happened to be picked.
        if not version or not version.strip():
            return VulnLookup.not_assessed(
                f"no version detected for {name}; CVE applicability cannot be "
                "determined without one"
            )

        if category in _WP_PLUGIN_CATEGORIES:
            return await self.wordfence_client.lookup(name, version, "plugin", component.slug)
        if category in _WP_THEME_CATEGORIES:
            return await self.wordfence_client.lookup(name, version, "theme", component.slug)

        # Prefer OSV for anything published to a package ecosystem: it resolves
        # ranges with the ecosystem's own version semantics and lands advisories
        # well before NVD assigns CPEs to them.
        package = osv_package(name)
        if package:
            ecosystem, package_name = package
            return await self.osv_client.lookup(name, version, ecosystem, package_name)

        cpe = cpe_for(name)
        if cpe:
            return await self.nvd_client.lookup(name, version, cpe)

        return VulnLookup.not_assessed(
            f"{name} maps to no CPE and no ecosystem package; no vulnerability "
            "source can be queried for it by identity"
        )

    # ------------------------------------------------------------------ #
    # Overlays + persistence
    # ------------------------------------------------------------------ #

    async def _attach_threat_intel(self, component: TechnologyComponent) -> None:
        """Attach KEV membership and EPSS scores, best-effort.

        Both feeds are advisory ranking signals. Losing them must not turn an
        otherwise good assessment into a failure.
        """
        cve_ids = [c for c in component.cves if c.startswith("CVE-")]
        if not cve_ids:
            return
        try:
            component.cve_kev = await self.threat_intel.known_exploited(cve_ids)
        except Exception as exc:
            logger.debug("KEV overlay failed for %s: %s", component.name, exc)
        try:
            component.cve_epss = await self.threat_intel.exploit_probability(cve_ids)
        except Exception as exc:
            logger.debug("EPSS overlay failed for %s: %s", component.name, exc)

    async def _persist(self, component: TechnologyComponent, lookup: VulnLookup) -> None:
        """Cache newly seen CVE records for reuse across scans."""
        for item in lookup.cves:
            cve_id = item.get("cve_id")
            if not cve_id:
                continue
            try:
                if await CveRecord.find_one(CveRecord.cve_id == cve_id):
                    continue
                await CveRecord(
                    cve_id=cve_id,
                    component_name=component.name,
                    component_version=component.version,
                    severity_score=item.get("severity_score"),
                    summary=item.get("summary"),
                    references=item.get("references") or [],
                ).insert()
            except Exception as exc:
                logger.warning("Failed to cache CVE %s: %s", cve_id, exc)
