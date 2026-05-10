from app.integrations.nvd_client import NvdClient
from app.models.cve import CveRecord
from app.models.vulnerability import TechnologyComponent


class CveDatabaseService:
    def __init__(self) -> None:
        self.nvd_client = NvdClient()

    async def enrich_components(self, components: list[TechnologyComponent]) -> list[TechnologyComponent]:
        enriched: list[TechnologyComponent] = []
        for component in components:
            cves = await self.nvd_client.lookup_cves(component.name, component.version)
            cve_ids = [item.get("cve_id", "") for item in cves if item.get("cve_id")]
            component.cves = cve_ids
            enriched.append(component)

            for c in cves:
                if not c.get("cve_id"):
                    continue
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

        return enriched
