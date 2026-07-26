from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.api.dependencies import (
    get_application_repository,
    get_current_user,
    get_scan_repository,
    json_response,
    require_role,
)
from app.schemas.application_schema import (
    ApplicationResponse,
    CreateApplicationRequest,
    UpdateApplicationRequest,
)
from shared.database.repositories.application_repository import ApplicationRepository
from shared.database.repositories.scan_repository import ScanRepository
from shared.models.application import Application
from shared.models.user import User, UserRole

router = APIRouter(prefix="/applications", tags=["applications"])

# Roles that may create, update, or delete applications (all non-viewers).
APP_ACTOR_ROLES = (UserRole.owner, UserRole.admin, UserRole.analyst, UserRole.developer)


def _application_response(app: Application) -> dict:
    """Project an Application document to its API representation."""
    return ApplicationResponse(
        id=str(app.id),
        name=app.name,
        target_url=app.target_url,
        org_id=app.org_id,
        default_scan_config=app.default_scan_config,
        created_at=app.created_at,
        updated_at=app.updated_at,
    ).model_dump(mode="json")


@router.post("", status_code=status.HTTP_201_CREATED)
async def create_application(
    payload: CreateApplicationRequest,
    apps: ApplicationRepository = Depends(get_application_repository),
    current_user: User = Depends(require_role(*APP_ACTOR_ROLES)),
) -> dict:
    """Create a new web application target for the caller's organization."""
    config_dict = payload.default_scan_config.model_dump(mode="json", exclude_none=True)
    app = await apps.create(
        name=payload.name,
        target_url=str(payload.target_url),
        org_id=current_user.org_id,
        default_scan_config=config_dict,
    )
    return json_response(_application_response(app), "application created")


@router.get("")
async def list_applications(
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=20, ge=1, le=100),
    apps: ApplicationRepository = Depends(get_application_repository),
    current_user: User = Depends(get_current_user),
) -> dict:
    """List applications for the caller's organization."""
    app_list = await apps.list_in_org(current_user.org_id, skip=skip, limit=limit)
    total = await apps.count_in_org(current_user.org_id)
    payload = [_application_response(app) for app in app_list]
    return json_response({"items": payload, "total": total})


@router.get("/{app_id}")
async def get_application(
    app_id: str,
    apps: ApplicationRepository = Depends(get_application_repository),
    current_user: User = Depends(get_current_user),
) -> dict:
    """Get an application by ID within the caller's organization."""
    app = await apps.get_in_org(app_id, current_user.org_id)
    if app is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Application not found")
    return json_response(_application_response(app))


@router.put("/{app_id}")
async def update_application(
    app_id: str,
    payload: UpdateApplicationRequest,
    apps: ApplicationRepository = Depends(get_application_repository),
    current_user: User = Depends(require_role(*APP_ACTOR_ROLES)),
) -> dict:
    """Update an existing application within the caller's organization."""
    config_dict = (
        payload.default_scan_config.model_dump(mode="json", exclude_none=True)
        if payload.default_scan_config is not None
        else None
    )
    app = await apps.update_in_org(
        app_id,
        current_user.org_id,
        name=payload.name,
        target_url=str(payload.target_url) if payload.target_url else None,
        default_scan_config=config_dict,
    )
    if app is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Application not found")
    return json_response(_application_response(app), "application updated")


@router.delete("/{app_id}")
async def delete_application(
    app_id: str,
    apps: ApplicationRepository = Depends(get_application_repository),
    current_user: User = Depends(require_role(*APP_ACTOR_ROLES)),
) -> dict:
    """Delete an application within the caller's organization."""
    deleted = await apps.delete_in_org(app_id, current_user.org_id)
    if not deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Application not found")
    return json_response({"deleted": True}, "application deleted")


@router.get("/{app_id}/scans")
async def list_application_scans(
    app_id: str,
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=20, ge=1, le=100),
    apps: ApplicationRepository = Depends(get_application_repository),
    scans: ScanRepository = Depends(get_scan_repository),
    current_user: User = Depends(get_current_user),
) -> dict:
    """List historical scan reports for a specific application."""
    app = await apps.get_in_org(app_id, current_user.org_id)
    if app is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Application not found")

    scan_list = await scans.list_by_target_url(
        org_id=current_user.org_id,
        target_url=app.target_url,
        skip=skip,
        limit=limit,
    )
    payload = [
        {
            "id": str(scan.id),
            "target_url": scan.target_url,
            "crawl_mode": scan.crawl_mode,
            "status": scan.status,
            "progress": scan.progress,
            "current_phase": scan.current_phase,
            "phase_message": scan.phase_message,
            "overall_risk_score": scan.overall_risk_score,
            "overall_risk_level": scan.overall_risk_level,
            "created_at": scan.created_at,
            "completed_at": scan.completed_at,
        }
        for scan in scan_list
    ]
    return json_response({"items": payload, "total": len(payload)})
