import logging

from app.integrations.nvd_client import NvdClient
from shared.models.cve import CveRecord
from shared.models.vulnerability import TechnologyComponent

logger = logging.getLogger(__name__)


class CveDatabaseService:
    def __init__(self) -> None:
        self.nvd_client = NvdClient()

    async def enrich_components(self, components: list[TechnologyComponent]) -> list[TechnologyComponent]:
        enriched: list[TechnologyComponent] = []
        for component in components:
            try:
                cves = await self.nvd_client.lookup_cves(component.name, component.version)
            except Exception as exc:
                logger.warning(
                    "CVE lookup failed for component %s %s: %s",
                    component.name,
                    component.version or "",
                    exc,
                )
                cves = []
            cve_ids = [item.get("cve_id", "") for item in cves if item.get("cve_id")]
            component.cves = cve_ids
            component.cve_scores = {
                item["cve_id"]: item["severity_score"]
                for item in cves
                if item.get("cve_id") and item.get("severity_score") is not None
            }
            enriched.append(component)

            for c in cves:
                if not c.get("cve_id"):
                    continue
                try:
                    exists = await CveRecord.find_one(CveRecord.cve_id == c["cve_id"])
                    if exists:
                        continue
                    await CveRecord(
                        cve_id=c["cve_id"],
                        component_name=component.name,
                        component_version=component.version,
                        severity_score=c.get("severity_score"),
                        summary=c.get("summary"),
                    ).insert()
                except Exception as exc:
                    logger.warning("Failed to cache CVE %s: %s", c["cve_id"], exc)

        return enriched
