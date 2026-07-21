from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.api.dependencies import get_current_user, get_scan_repository, json_response, require_role
from shared.database.repositories.scan_repository import ScanRepository
from shared.models.scan import ScanAuthAccount, ScanAuthRole, ScanPhase, ScanStatus
from shared.models.user import User, UserRole
from shared.scan_queue import ScanJob, ScanQueue, ScanQueueError
from shared.schemas.scan_schema import CreateScanRequest, ScanCredentials

router = APIRouter(prefix="/scans", tags=["scans"])

# Everyone except a viewer may launch or cancel scans.
SCAN_ACTOR_ROLES = (UserRole.owner, UserRole.admin, UserRole.analyst, UserRole.developer)

# Module-level scan queue reference, wired at startup via set_scan_queue().
# A global is used because FastAPI lifespan context cannot be passed directly
# into route functions without per-request lookups.
scan_queue: ScanQueue | None = None


def set_scan_queue(instance: ScanQueue) -> None:
    """Wire the scan queue instance for use by route handlers.

    Called once during application startup in the lifespan hook.
    """
    global scan_queue
    scan_queue = instance


def _auth_accounts_from_payload(credentials: ScanCredentials | None) -> list[ScanAuthAccount]:
    """Convert optional ScanCredentials into a flat list of ScanAuthAccount DTOs.

    Each populated credential slot (main, second, admin) becomes a single
    ScanAuthAccount tagged with its role, ready for the Redis job payload.
    Unpopulated slots are omitted rather than sent as null-bearing entries.
    """
    if credentials is None:
        return []
    accounts: list[ScanAuthAccount] = []
    for role, cred in (
        (ScanAuthRole.main, credentials.main),
        (ScanAuthRole.second, credentials.second),
        (ScanAuthRole.admin, credentials.admin),
    ):
        if cred is None or not cred.is_populated:
            continue
        accounts.append(
            ScanAuthAccount(
                role=role,
                username=cred.username,
                password=cred.password,
                cookie=cred.cookie,
                header=cred.header,
            )
        )
    return accounts


def _scan_summary(scan) -> dict:
    """Project a Scan document to its list-view representation."""
    return {
        "id": str(scan.id),
        "target_url": scan.target_url,
        "owner_user_id": scan.owner_user_id,
        "owner_email": scan.owner_email,
        "crawl_mode": scan.crawl_mode,
        "status": scan.status,
        "progress": scan.progress,
        "current_phase": scan.current_phase,
        "phase_message": scan.phase_message,
        "authorization_confirmed": scan.authorization_confirmed,
        "authorization_confirmed_at": scan.authorization_confirmed_at,
        "created_at": scan.created_at,
        "updated_at": scan.updated_at,
    }


@router.post("", status_code=status.HTTP_202_ACCEPTED)
async def create_scan(
    payload: CreateScanRequest,
    repo: ScanRepository = Depends(get_scan_repository),
    current_user: User = Depends(require_role(*SCAN_ACTOR_ROLES)),
) -> dict:
    """Submit a new scan target and enqueue the job for processing.

    Credentials are serialized into the Redis job as plaintext and removed
    atomically when a worker claims the job. MongoDB persists only role names.
    """
    auth_accounts = _auth_accounts_from_payload(payload.credentials)
    scan = await repo.create(
        str(payload.target_url),
        org_id=current_user.org_id,
        owner_user_id=str(current_user.id),
        owner_email=current_user.email,
        authorization_confirmed=payload.authorization_confirmed,
        crawl_mode=payload.crawl_mode,
        auth_roles_provided=[account.role for account in auth_accounts],
    )
    if scan_queue is None:
        raise HTTPException(status_code=500, detail="Scan queue not initialized")
    try:
        await scan_queue.enqueue(
            ScanJob(
                scan_id=str(scan.id),
                auth_accounts=auth_accounts,
                scan_config=payload.config,
            )
        )
    except ScanQueueError as exc:
        await repo.update_status(
            scan,
            ScanStatus.failed,
            progress=scan.progress,
            current_phase=ScanPhase.failed,
            phase_message="Scan queue unavailable",
            error_message="Scan queue unavailable",
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Scan queue unavailable",
        ) from exc
    return json_response(
        {
            "scan_id": str(scan.id),
            "status": scan.status,
            "progress": scan.progress,
            "current_phase": scan.current_phase,
            "phase_message": scan.phase_message,
            "owner_user_id": scan.owner_user_id,
            "authorization_confirmed": scan.authorization_confirmed,
            "authorization_confirmed_at": scan.authorization_confirmed_at,
        },
        "scan queued",
    )


@router.get("")
async def list_scans(
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=20, ge=1, le=100),
    repo: ScanRepository = Depends(get_scan_repository),
    current_user: User = Depends(get_current_user),
) -> dict:
    """Return a paginated list of scans for the caller's organization.

    All org members share one view, so scans are scoped by ``org_id`` rather
    than by the individual submitter.
    """
    scans = await repo.list(skip=skip, limit=limit, org_id=current_user.org_id)
    # Flip any scan whose worker died (running in DB, no live lease) to failed so
    # the list never shows a permanently "running" zombie. Best-effort: a Redis
    # outage leaves the scan untouched rather than falsely failing it.
    if scan_queue is not None:
        scans = [await repo.reconcile_if_orphaned(scan, scan_queue) for scan in scans]
    payload = [_scan_summary(scan) for scan in scans]
    return json_response({"items": payload, "total": len(payload)})


@router.get("/{scan_id}")
async def get_scan_details(
    scan_id: str,
    repo: ScanRepository = Depends(get_scan_repository),
    current_user: User = Depends(get_current_user),
) -> dict:
    """Return full scan details including all vulnerabilities and metadata."""
    scan = await repo.get_in_org(scan_id, current_user.org_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    scan = await repo.reconcile_if_orphaned(scan, scan_queue)
    data = scan.model_dump()
    data["id"] = str(scan.id)
    # Defensive: credentials are never persisted, but strip any legacy field.
    data.pop("auth_accounts", None)
    return json_response(data)


@router.get("/{scan_id}/status")
async def get_scan_status(
    scan_id: str,
    repo: ScanRepository = Depends(get_scan_repository),
    current_user: User = Depends(get_current_user),

) -> dict:
    scan = await repo.get_in_org(scan_id, current_user.org_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    scan = await repo.reconcile_if_orphaned(scan, scan_queue)
    return json_response({
        "id": str(scan.id),
        "status": scan.status,
        "progress": scan.progress,
        "current_phase": scan.current_phase,
        "phase_message": scan.phase_message,
        "started_at": scan.started_at,
        "eta_seconds": scan.eta_seconds,
        "error": scan.error_message,
        "updated_at": scan.updated_at,
    })


@router.post("/{scan_id}/cancel", status_code=status.HTTP_200_OK)
async def cancel_scan(
    scan_id: str,
    repo: ScanRepository = Depends(get_scan_repository),
    current_user: User = Depends(require_role(*SCAN_ACTOR_ROLES)),
) -> dict:
    """Request cancellation of a running or queued scan.

    Any non-viewer member of the scan's org may cancel it (not just the
    submitter); the canceller is recorded on the scan.
    """
    scan = await repo.get_in_org(scan_id, current_user.org_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    # A scan whose worker died is not really running: cancelling it should
    # resolve the UI immediately rather than set a cancel key nobody reads.
    if scan_queue is not None:
        scan = await repo.reconcile_if_orphaned(scan, scan_queue)
    if scan.status in {ScanStatus.completed, ScanStatus.failed, ScanStatus.cancelled}:
        return json_response({"cancelled": False})
    if scan_queue is None:
        raise HTTPException(status_code=500, detail="Scan queue not initialized")
    try:
        await scan_queue.request_cancel(scan_id)
    except ScanQueueError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Scan queue unavailable",
        ) from exc

    scan.cancelled_by_user_id = str(current_user.id)
    scan.cancelled_by_email = current_user.email
    if scan.status == ScanStatus.queued:
        await repo.update_status(
            scan,
            ScanStatus.cancelled,
            progress=scan.progress,
            current_phase=ScanPhase.cancelled,
            phase_message="Scan cancelled by user",
        )
    else:
        # Running scan: the worker will transition status on the cancel signal;
        # persist the canceller attribution now.
        await scan.save()
    return json_response({"cancelled": True})
