from datetime import datetime, timezone

from beanie import PydanticObjectId

from app.models.scan import CrawlMode, Scan, ScanPhase, ScanStatus


class ScanRepository:
    async def create(
        self,
        target_url: str,
        *,
        owner_user_id: str,
        owner_email: str,
        authorization_confirmed: bool,
        authorization_text: str | None = None,
        crawl_mode: CrawlMode = CrawlMode.full,
    ) -> Scan:
        now = datetime.now(timezone.utc)
        scan = Scan(
            target_url=target_url,
            owner_user_id=owner_user_id,
            owner_email=owner_email,
            crawl_mode=crawl_mode,
            status=ScanStatus.queued,
            authorization_confirmed=authorization_confirmed,
            authorization_text=authorization_text,
            authorization_confirmed_at=now if authorization_confirmed else None,
        )
        await scan.insert()
        return scan

    async def get_by_id(self, scan_id: str) -> Scan | None:
        try:
            oid = PydanticObjectId(scan_id)
        except Exception:
            return None
        return await Scan.get(oid)

    async def get_owned_by_id(self, scan_id: str, owner_user_id: str) -> Scan | None:
        scan = await self.get_by_id(scan_id)
        if scan is None or scan.owner_user_id != owner_user_id:
            return None
        return scan

    async def list(self, skip: int = 0, limit: int = 20, owner_user_id: str | None = None) -> list[Scan]:
        query = Scan.find(Scan.owner_user_id == owner_user_id) if owner_user_id else Scan.find_all()
        return await query.sort(-Scan.created_at).skip(skip).limit(limit).to_list()

    async def delete(self, scan_id: str) -> bool:
        scan = await self.get_by_id(scan_id)
        if not scan:
            return False
        await scan.delete()
        return True

    async def delete_owned(self, scan_id: str, owner_user_id: str) -> bool:
        scan = await self.get_owned_by_id(scan_id, owner_user_id)
        if not scan:
            return False
        await scan.delete()
        return True

    async def update_status(
        self,
        scan: Scan,
        status: ScanStatus,
        progress: int | None = None,
        current_phase: ScanPhase | None = None,
        phase_message: str | None = None,
        error_message: str | None = None,
    ) -> Scan:
        scan.status = status
        if progress is not None:
            scan.progress = progress
        if current_phase is not None:
            scan.current_phase = current_phase
        if phase_message is not None:
            scan.phase_message = phase_message
        if status == ScanStatus.running and scan.started_at is None:
            scan.started_at = datetime.now(timezone.utc)
        if status in {ScanStatus.completed, ScanStatus.failed, ScanStatus.cancelled}:
            scan.completed_at = datetime.now(timezone.utc)
        if error_message:
            scan.error_message = error_message
        scan.updated_at = datetime.now(timezone.utc)
        await scan.save()
        return scan
