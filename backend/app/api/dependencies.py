from collections.abc import AsyncGenerator

from fastapi import Depends, HTTPException, status

from app.database.repositories.scan_repository import ScanRepository

scan_repository = ScanRepository()


def get_scan_repository() -> ScanRepository:
    return scan_repository


def ensure_scan_exists(scan_id: str, repo: ScanRepository = Depends(get_scan_repository)):
    async def _inner() -> object:
        scan = await repo.get_by_id(scan_id)
        if not scan:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
        return scan

    return _inner


def json_response(data: object = None, message: str = "ok", success: bool = True) -> dict:
    return {"success": success, "message": message, "data": data}
