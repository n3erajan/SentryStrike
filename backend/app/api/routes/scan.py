from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.api.dependencies import get_scan_repository, json_response
from app.core.scanner import ScanOrchestrator
from app.database.repositories.scan_repository import ScanRepository
from app.schemas.scan_schema import CreateScanRequest

router = APIRouter(prefix="/scans", tags=["scans"])

orchestrator: ScanOrchestrator | None = None


def set_orchestrator(instance: ScanOrchestrator) -> None:
    global orchestrator
    orchestrator = instance


@router.post("", status_code=status.HTTP_202_ACCEPTED)
async def create_scan(
    payload: CreateScanRequest,
    repo: ScanRepository = Depends(get_scan_repository),
) -> dict:
    scan = await repo.create(str(payload.target_url), crawl_mode=payload.crawl_mode)
    if orchestrator is None:
        raise HTTPException(status_code=500, detail="Scanner orchestrator not initialized")
    await orchestrator.queue_scan(str(scan.id))
    return json_response({"scan_id": str(scan.id), "status": scan.status, "progress": scan.progress}, "scan queued")


@router.get("")
async def list_scans(
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=20, ge=1, le=100),
    repo: ScanRepository = Depends(get_scan_repository),
) -> dict:
    scans = await repo.list(skip=skip, limit=limit)
    payload = [
        {
            "id": str(scan.id),
            "target_url": scan.target_url,
            "crawl_mode": scan.crawl_mode,
            "status": scan.status,
            "progress": scan.progress,
            "created_at": scan.created_at,
            "updated_at": scan.updated_at,
        }
        for scan in scans
    ]
    return json_response({"items": payload, "total": len(payload)})


@router.get("/{scan_id}")
async def get_scan_details(scan_id: str, repo: ScanRepository = Depends(get_scan_repository)) -> dict:
    scan = await repo.get_by_id(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    data = scan.model_dump()
    data["id"] = str(scan.id)
    return json_response(data)


@router.get("/{scan_id}/status")
async def get_scan_status(scan_id: str, repo: ScanRepository = Depends(get_scan_repository)) -> dict:
    scan = await repo.get_by_id(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return json_response({"id": str(scan.id), "status": scan.status, "progress": scan.progress, "error": scan.error_message})


@router.delete("/{scan_id}", status_code=status.HTTP_200_OK)
async def delete_scan(scan_id: str, repo: ScanRepository = Depends(get_scan_repository)) -> dict:
    deleted = await repo.delete(scan_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Scan not found")
    return json_response({"deleted": True})


@router.post("/{scan_id}/cancel", status_code=status.HTTP_200_OK)
async def cancel_scan(scan_id: str, repo: ScanRepository = Depends(get_scan_repository)) -> dict:
    scan = await repo.get_by_id(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if orchestrator is None:
        raise HTTPException(status_code=500, detail="Scanner orchestrator not initialized")
    cancelled = await orchestrator.cancel_scan(scan_id)
    return json_response({"cancelled": cancelled})
