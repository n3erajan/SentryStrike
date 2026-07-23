from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.api.dependencies import (
    get_audit_repository,
    get_current_user,
    get_notification_repository,
    get_scan_repository,
    json_response,
    require_role,
)
from shared.database.repositories.audit_repository import AuditRepository
from shared.database.repositories.scan_repository import ScanRepository
from shared.database.repositories.notification_repository import NotificationRepository
from shared.models.notification import NotificationType
from shared.models.audit import AuditAction
from shared.models.scan import ScanPhase, ScanStatus
from shared.models.user import User, UserRole
from shared.scan_queue import ScanJob, ScanQueue, ScanQueueError
from shared.schemas.scan_schema import CreateScanRequest, scan_auth_accounts_from_credentials

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


def _scan_summary(scan) -> dict:
    """Project a Scan document to its list-view representation."""
    return {
        "id": str(scan.id),
        "target_url": scan.target_url,
        "submitted_by_user_id": scan.submitted_by_user_id,
        "submitted_by_full_name": scan.submitted_by_full_name,
        "submitted_by_email": scan.submitted_by_email,
        "crawl_mode": scan.crawl_mode,
        "status": scan.status,
        "progress": scan.progress,
        "current_phase": scan.current_phase,
        "phase_message": scan.phase_message,
        "analysis": getattr(scan, "analysis", None),
        "authorization_confirmed": scan.authorization_confirmed,
        "authorization_confirmed_at": scan.authorization_confirmed_at,
        "risk_score": scan.overall_risk_score,
        "risk_level": scan.overall_risk_level,
        "total_findings": scan.statistics.total_vulnerabilities,
        "severity_breakdown": scan.statistics.severity_breakdown.model_dump(mode="json"),
        "total_urls_crawled": scan.statistics.total_urls_crawled,
        "started_at": scan.started_at,
        "completed_at": scan.completed_at,
        "site_title": scan.site_title or "",
        "created_at": scan.created_at,
        "updated_at": scan.updated_at,
    }


async def _reconcile_and_notify(
    scan,
    repo: ScanRepository,
    notifications: NotificationRepository,
):
    previous_status = scan.status
    scan = await repo.reconcile_if_orphaned(scan, scan_queue)
    if previous_status != ScanStatus.failed and scan.status == ScanStatus.failed:
        await notifications.create(
            org_id=scan.org_id,
            recipient_user_id=scan.submitted_by_user_id,
            type=NotificationType.scan_failed,
            title="Scan failed",
            message=f"The scan of {scan.target_url} failed.",
            resource_type="scan",
            resource_id=str(scan.id),
            metadata={"status": ScanStatus.failed.value, "target_url": scan.target_url},
            dedupe_key=f"scan-terminal:{scan.org_id}:{scan.id}:failed",
        )
    return scan


@router.post("", status_code=status.HTTP_202_ACCEPTED)
async def create_scan(
    payload: CreateScanRequest,
    repo: ScanRepository = Depends(get_scan_repository),
    notifications: NotificationRepository = Depends(get_notification_repository),
    audit: AuditRepository = Depends(get_audit_repository),
    current_user: User = Depends(require_role(*SCAN_ACTOR_ROLES)),
) -> dict:
    """Submit a new scan target and enqueue the job for processing.

    Credentials are serialized into the Redis job as plaintext and removed
    atomically when a worker claims the job. MongoDB persists only role names.
    """
    auth_accounts = scan_auth_accounts_from_credentials(payload.credentials)
    scan = await repo.create(
        str(payload.target_url),
        org_id=current_user.org_id,
        submitted_by_user_id=str(current_user.id),
        submitted_by_full_name=current_user.full_name,
        submitted_by_email=current_user.email,
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
        await notifications.create(
            org_id=current_user.org_id,
            recipient_user_id=str(current_user.id),
            type=NotificationType.scan_failed,
            title="Scan failed",
            message=f"The scan of {scan.target_url} could not be queued.",
            resource_type="scan",
            resource_id=str(scan.id),
            metadata={"status": ScanStatus.failed.value, "target_url": scan.target_url},
            dedupe_key=f"scan-terminal:{current_user.org_id}:{scan.id}:failed",
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Scan queue unavailable",
        ) from exc
    await audit.record(
        org_id=current_user.org_id,
        action=AuditAction.scan_created,
        actor_user_id=str(current_user.id),
        actor_email=current_user.email,
        target_type="scan",
        target_id=str(scan.id),
        metadata={"target_url": scan.target_url, "crawl_mode": scan.crawl_mode.value},
    )
    return json_response(
        {
            "scan_id": str(scan.id),
            "status": scan.status,
            "progress": scan.progress,
            "current_phase": scan.current_phase,
            "phase_message": scan.phase_message,
            "submitted_by_user_id": scan.submitted_by_user_id,
            "submitted_by_full_name": scan.submitted_by_full_name,
            "submitted_by_email": scan.submitted_by_email,
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
    notifications: NotificationRepository = Depends(get_notification_repository),
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
        scans = [await _reconcile_and_notify(scan, repo, notifications) for scan in scans]
    payload = [_scan_summary(scan) for scan in scans]
    return json_response({"items": payload, "total": len(payload)})


@router.get("/{scan_id}")
async def get_scan_details(
    scan_id: str,
    repo: ScanRepository = Depends(get_scan_repository),
    notifications: NotificationRepository = Depends(get_notification_repository),
    current_user: User = Depends(get_current_user),
) -> dict:
    """Return full scan details including all vulnerabilities and metadata."""
    scan = await repo.get_in_org(scan_id, current_user.org_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    scan = await _reconcile_and_notify(scan, repo, notifications)
    data = scan.model_dump()
    data["id"] = str(scan.id)
    # Defensive: credentials are never persisted, but strip any legacy field.
    data.pop("auth_accounts", None)
    return json_response(data)


@router.get("/{scan_id}/status")
async def get_scan_status(
    scan_id: str,
    repo: ScanRepository = Depends(get_scan_repository),
    notifications: NotificationRepository = Depends(get_notification_repository),
    current_user: User = Depends(get_current_user),

) -> dict:
    scan = await repo.get_in_org(scan_id, current_user.org_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    scan = await _reconcile_and_notify(scan, repo, notifications)
    return json_response({
        "id": str(scan.id),
        "status": scan.status,
        "progress": scan.progress,
        "current_phase": scan.current_phase,
        "phase_message": scan.phase_message,
        "started_at": scan.started_at,
        "eta_seconds": scan.eta_seconds,
        "error": scan.error_message,
        "analysis": getattr(scan, "analysis", None),
        "updated_at": scan.updated_at,
    })


@router.post("/{scan_id}/cancel", status_code=status.HTTP_200_OK)
async def cancel_scan(
    scan_id: str,
    repo: ScanRepository = Depends(get_scan_repository),
    notifications: NotificationRepository = Depends(get_notification_repository),
    audit: AuditRepository = Depends(get_audit_repository),
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
        scan = await _reconcile_and_notify(scan, repo, notifications)
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
        await notifications.create(
            org_id=current_user.org_id,
            recipient_user_id=scan.submitted_by_user_id,
            type=NotificationType.scan_cancelled,
            title="Scan cancelled",
            message=f"The scan of {scan.target_url} was cancelled.",
            resource_type="scan",
            resource_id=scan_id,
            metadata={"status": ScanStatus.cancelled.value, "target_url": scan.target_url},
            dedupe_key=f"scan-terminal:{current_user.org_id}:{scan_id}:cancelled",
        )
    else:
        # Running scan: the worker will transition status on the cancel signal;
        # persist the canceller attribution now.
        await scan.save()
    await audit.record(
        org_id=current_user.org_id,
        action=AuditAction.scan_cancelled,
        actor_user_id=str(current_user.id),
        actor_email=current_user.email,
        target_type="scan",
        target_id=scan_id,
        metadata={"target_url": scan.target_url},
    )
    return json_response({"cancelled": True})
