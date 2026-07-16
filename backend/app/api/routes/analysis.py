from fastapi import APIRouter, Depends, HTTPException

from app.api.dependencies import get_current_user, get_scan_repository, json_response
from shared.database.repositories.scan_repository import ScanRepository
from shared.models.user import User

router = APIRouter(prefix="/analysis", tags=["analysis"])


@router.get("/scans/{scan_id}/vulnerabilities")
async def list_vulnerabilities(
    scan_id: str,
    severity: str | None = None,
    category: str | None = None,
    repo: ScanRepository = Depends(get_scan_repository),
    current_user: User = Depends(get_current_user),
) -> dict:
    scan = await repo.get_owned_by_id(scan_id, str(current_user.id))
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    vulns = scan.vulnerabilities
    if severity:
        vulns = [v for v in vulns if v.severity.value.lower() == severity.lower()]
    if category:
        vulns = [v for v in vulns if v.category.value.lower().startswith(category.lower())]

    return json_response({"total": len(vulns), "items": [v.model_dump() for v in vulns]})


@router.get("/scans/{scan_id}/vulnerabilities/{vulnerability_id}")
async def get_vulnerability_details(
    scan_id: str,
    vulnerability_id: str,
    repo: ScanRepository = Depends(get_scan_repository),
    current_user: User = Depends(get_current_user),
) -> dict:
    scan = await repo.get_owned_by_id(scan_id, str(current_user.id))
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    for vuln in scan.vulnerabilities:
        if vuln.id == vulnerability_id:
            return json_response(vuln.model_dump())
    raise HTTPException(status_code=404, detail="Vulnerability not found")



