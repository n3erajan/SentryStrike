from datetime import datetime, timezone

from beanie import PydanticObjectId

from app.models.scan import CrawlMode, Scan, ScanStatus


class ScanRepository:
    async def create(self, target_url: str, crawl_mode: CrawlMode = CrawlMode.full) -> Scan:
        scan = Scan(target_url=target_url, crawl_mode=crawl_mode, status=ScanStatus.queued)
        await scan.insert()
        return scan

    async def get_by_id(self, scan_id: str) -> Scan | None:
        try:
            oid = PydanticObjectId(scan_id)
        except Exception:
            return None
        return await Scan.get(oid)

    async def list(self, skip: int = 0, limit: int = 20) -> list[Scan]:
        return await Scan.find_all().sort(-Scan.created_at).skip(skip).limit(limit).to_list()

    async def delete(self, scan_id: str) -> bool:
        scan = await self.get_by_id(scan_id)
        if not scan:
            return False
        await scan.delete()
        return True

    async def update_status(
        self,
        scan: Scan,
        status: ScanStatus,
        progress: int | None = None,
        error_message: str | None = None,
    ) -> Scan:
        scan.status = status
        if progress is not None:
            scan.progress = progress
        if status == ScanStatus.running and scan.started_at is None:
            scan.started_at = datetime.now(timezone.utc)
        if status in {ScanStatus.completed, ScanStatus.failed, ScanStatus.cancelled}:
            scan.completed_at = datetime.now(timezone.utc)
        if error_message:
            scan.error_message = error_message
        scan.updated_at = datetime.now(timezone.utc)
        await scan.save()
        return scan
