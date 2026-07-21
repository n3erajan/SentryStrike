from fastapi import APIRouter, Depends, HTTPException, status

from app.api.dependencies import (
    get_audit_repository,
    get_current_user,
    get_member_repository,
    get_notification_repository,
    get_reverification_repository,
    get_scan_repository,
    json_response,
    require_role,
)
from shared.database.repositories.audit_repository import AuditRepository
from shared.database.repositories.member_repository import MemberRepository
from shared.database.repositories.notification_repository import NotificationRepository
from shared.database.repositories.reverification_repository import ReverificationRepository
from shared.database.repositories.scan_repository import ScanRepository
from shared.models.audit import AuditAction
from shared.models.notification import NotificationType
from shared.models.reverification import ReverificationJob
from shared.models.user import User, UserRole
from shared.models.vulnerability import FindingComment, RemediationStatus, Vulnerability
from shared.scan_queue import ScanJob, ScanJobKind, ScanQueueError
from shared.schemas.scan_schema import scan_auth_accounts_from_credentials
from app.api.routes import scan as scan_routes
from app.schemas.finding_schema import (
    AssignFindingRequest,
    CommentRequest,
    RemediationRequest,
    ReverificationRequest,
)

router = APIRouter(prefix="/analysis", tags=["analysis"])

# Triagers own the workflow decisions: who works a finding and whether a claimed
# fix is accepted. Contributors (triagers + developers) may discuss and advance a
# fix up to "pending verification". Viewers are read-only throughout.
FINDING_TRIAGE_ROLES = (UserRole.owner, UserRole.admin, UserRole.analyst)
FINDING_CONTRIBUTOR_ROLES = (UserRole.owner, UserRole.admin, UserRole.analyst, UserRole.developer)
# Terminal remediation states are a triager-only decision (a developer cannot
# sign off their own fix or accept the risk); everything up to and including
# "fixed_pending_verification" is open to any contributor.
TRIAGER_ONLY_REMEDIATION = {RemediationStatus.verified_fixed, RemediationStatus.wont_fix}


def _find_vulnerability(scan, vulnerability_id: str) -> Vulnerability | None:
    """Return the embedded finding with the given id, or None."""
    for vuln in scan.vulnerabilities:
        if vuln.id == vulnerability_id:
            return vuln
    return None


def _reverification_response(job: ReverificationJob) -> dict:
    data = job.model_dump(mode="json")
    data["id"] = str(job.id)
    return data


@router.get("/scans/{scan_id}/vulnerabilities")
async def list_vulnerabilities(
    scan_id: str,
    severity: str | None = None,
    category: str | None = None,
    repo: ScanRepository = Depends(get_scan_repository),
    current_user: User = Depends(get_current_user),
) -> dict:
    """Return vulnerabilities for a given scan, optionally filtered by severity or category."""
    scan = await repo.get_in_org(scan_id, current_user.org_id)
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
    """Return the full detail for a specific vulnerability within a scan."""
    scan = await repo.get_in_org(scan_id, current_user.org_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    vuln = _find_vulnerability(scan, vulnerability_id)
    if vuln is None:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    return json_response(vuln.model_dump())


async def _load_scan_and_finding(repo: ScanRepository, scan_id: str, vulnerability_id: str, org_id: str):
    """Fetch an org-scoped scan and one of its findings, raising 404 on either miss.

    Collapsing both lookups here keeps the mutation handlers below to their
    role-and-workflow logic. Cross-org access is indistinguishable from a
    missing scan (see ``get_in_org``).
    """
    scan = await repo.get_in_org(scan_id, org_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    vuln = _find_vulnerability(scan, vulnerability_id)
    if vuln is None:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    return scan, vuln


@router.put("/scans/{scan_id}/vulnerabilities/{vulnerability_id}/assignment")
async def assign_finding(
    scan_id: str,
    vulnerability_id: str,
    payload: AssignFindingRequest,
    repo: ScanRepository = Depends(get_scan_repository),
    members: MemberRepository = Depends(get_member_repository),
    notifications: NotificationRepository = Depends(get_notification_repository),
    current_user: User = Depends(require_role(*FINDING_TRIAGE_ROLES)),
) -> dict:
    """Assign a finding to a member of the caller's org, or unassign it (null).

    Triagers (owner/admin/analyst) hand out work; the assignee must belong to
    the same organization, so no cross-tenant reference can be planted.
    """
    scan, vuln = await _load_scan_and_finding(repo, scan_id, vulnerability_id, current_user.org_id)

    if payload.assignee_user_id is None:
        vuln.assignee_user_id = None
        vuln.assignee_email = None
    else:
        assignee = await members.get_in_org(payload.assignee_user_id, current_user.org_id)
        if assignee is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Assignee is not a member of this workspace")
        vuln.assignee_user_id = str(assignee.id)
        vuln.assignee_email = assignee.email

    await scan.save()
    if vuln.assignee_user_id is not None:
        await notifications.create(
            org_id=current_user.org_id,
            recipient_user_id=vuln.assignee_user_id,
            type=NotificationType.finding_assigned,
            title="Finding assigned",
            message=f"{vuln.vuln_type} was assigned to you.",
            resource_type="finding",
            resource_id=vuln.id,
            metadata={"scan_id": scan_id},
            dedupe_key=(
                f"finding-assigned:{current_user.org_id}:{scan_id}:"
                f"{vuln.id}:{vuln.assignee_user_id}"
            ),
        )
    return json_response(vuln.model_dump(), "assignment updated")


@router.post("/scans/{scan_id}/vulnerabilities/{vulnerability_id}/comments", status_code=status.HTTP_201_CREATED)
async def add_finding_comment(
    scan_id: str,
    vulnerability_id: str,
    payload: CommentRequest,
    repo: ScanRepository = Depends(get_scan_repository),
    notifications: NotificationRepository = Depends(get_notification_repository),
    current_user: User = Depends(require_role(*FINDING_CONTRIBUTOR_ROLES)),
) -> dict:
    """Append a team comment to a finding. Any contributor (non-viewer) may comment."""
    scan, vuln = await _load_scan_and_finding(repo, scan_id, vulnerability_id, current_user.org_id)

    comment = FindingComment(
        author_user_id=str(current_user.id),
        author_email=current_user.email,
        body=payload.body,
    )
    vuln.comments.append(comment)
    await scan.save()
    recipients = {
        recipient
        for recipient in (vuln.assignee_user_id, getattr(scan, "submitted_by_user_id", None))
        if recipient and recipient != str(current_user.id)
    }
    for recipient in recipients:
        await notifications.create(
            org_id=current_user.org_id,
            recipient_user_id=recipient,
            type=NotificationType.finding_commented,
            title="New finding comment",
            message=f"{current_user.email} commented on {vuln.vuln_type}.",
            resource_type="finding",
            resource_id=vuln.id,
            metadata={"scan_id": scan_id, "comment_id": comment.id},
            dedupe_key=f"finding-comment:{current_user.org_id}:{comment.id}:{recipient}",
        )
    return json_response(comment.model_dump(mode="json"), "comment added")


@router.put("/scans/{scan_id}/vulnerabilities/{vulnerability_id}/remediation")
async def update_finding_remediation(
    scan_id: str,
    vulnerability_id: str,
    payload: RemediationRequest,
    repo: ScanRepository = Depends(get_scan_repository),
    notifications: NotificationRepository = Depends(get_notification_repository),
    current_user: User = Depends(require_role(*FINDING_CONTRIBUTOR_ROLES)),
) -> dict:
    """Advance a finding's remediation state.

    Any contributor may move a finding through the working states up to
    ``fixed_pending_verification``; only a triager may confirm ``verified_fixed``
    or formally accept the risk with ``wont_fix``.
    """
    scan, vuln = await _load_scan_and_finding(repo, scan_id, vulnerability_id, current_user.org_id)

    if (
        payload.remediation_status in TRIAGER_ONLY_REMEDIATION
        and current_user.role not in FINDING_TRIAGE_ROLES
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only an owner, admin, or analyst may confirm or waive a fix.",
        )

    vuln.remediation_status = payload.remediation_status
    await scan.save()
    recipients = {
        recipient
        for recipient in (vuln.assignee_user_id, getattr(scan, "submitted_by_user_id", None))
        if recipient and recipient != str(current_user.id)
    }
    for recipient in recipients:
        await notifications.create(
            org_id=current_user.org_id,
            recipient_user_id=recipient,
            type=NotificationType.remediation_status_changed,
            title="Remediation status changed",
            message=(
                f"{vuln.vuln_type} moved to {payload.remediation_status.value.replace('_', ' ')}."
            ),
            resource_type="finding",
            resource_id=vuln.id,
            metadata={"scan_id": scan_id, "status": payload.remediation_status.value},
            dedupe_key=(
                f"remediation:{current_user.org_id}:{scan_id}:{vuln.id}:"
                f"{payload.remediation_status.value}:{recipient}"
            ),
        )
    return json_response(vuln.model_dump(), "remediation status updated")


@router.post(
    "/scans/{scan_id}/vulnerabilities/{vulnerability_id}/reverify",
    status_code=status.HTTP_202_ACCEPTED,
)
async def create_finding_reverification(
    scan_id: str,
    vulnerability_id: str,
    payload: ReverificationRequest,
    scans: ScanRepository = Depends(get_scan_repository),
    reverifications: ReverificationRepository = Depends(get_reverification_repository),
    audit: AuditRepository = Depends(get_audit_repository),
    current_user: User = Depends(require_role(*FINDING_TRIAGE_ROLES)),
) -> dict:
    """Queue a focused replay of one finding's captured verification request."""
    _, vulnerability = await _load_scan_and_finding(
        scans, scan_id, vulnerability_id, current_user.org_id
    )
    if vulnerability.verification_target is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="This finding does not contain a replayable verification target.",
        )
    auth_accounts = scan_auth_accounts_from_credentials(payload.credentials)
    job = await reverifications.create(
        org_id=current_user.org_id,
        scan_id=scan_id,
        vulnerability_id=vulnerability_id,
        requested_by_user_id=str(current_user.id),
        requested_by_email=current_user.email,
        target=vulnerability.verification_target,
        auth_roles_provided=[account.role for account in auth_accounts],
    )
    attached = await scans.attach_reverification_job(
        scan_id=scan_id,
        org_id=current_user.org_id,
        vulnerability_id=vulnerability_id,
        job_id=str(job.id),
    )
    if not attached:
        await reverifications.fail(job, "Finding changed before the job could be attached")
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="The finding changed before re-verification could be queued.",
        )
    if scan_routes.scan_queue is None:
        await reverifications.fail(job, "Scan queue not initialized")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Re-verification queue unavailable",
        )
    try:
        await scan_routes.scan_queue.enqueue(
            ScanJob(
                kind=ScanJobKind.finding_reverification,
                scan_id=scan_id,
                reverification_job_id=str(job.id),
                auth_accounts=auth_accounts,
            )
        )
    except ScanQueueError as exc:
        await reverifications.fail(job, "Re-verification queue unavailable")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Re-verification queue unavailable",
        ) from exc
    await audit.record(
        org_id=current_user.org_id,
        action=AuditAction.finding_reverification_created,
        actor_user_id=str(current_user.id),
        actor_email=current_user.email,
        target_type="reverification",
        target_id=str(job.id),
        metadata={"scan_id": scan_id, "vulnerability_id": vulnerability_id},
    )
    return json_response(_reverification_response(job), "re-verification queued")


@router.get("/scans/{scan_id}/vulnerabilities/{vulnerability_id}/reverifications")
async def list_finding_reverifications(
    scan_id: str,
    vulnerability_id: str,
    scans: ScanRepository = Depends(get_scan_repository),
    reverifications: ReverificationRepository = Depends(get_reverification_repository),
    current_user: User = Depends(get_current_user),
) -> dict:
    await _load_scan_and_finding(scans, scan_id, vulnerability_id, current_user.org_id)
    jobs = await reverifications.list_for_finding(
        org_id=current_user.org_id,
        scan_id=scan_id,
        vulnerability_id=vulnerability_id,
    )
    return json_response(
        {"items": [_reverification_response(job) for job in jobs], "total": len(jobs)}
    )


@router.get(
    "/scans/{scan_id}/vulnerabilities/{vulnerability_id}/reverifications/{job_id}"
)
async def get_finding_reverification(
    scan_id: str,
    vulnerability_id: str,
    job_id: str,
    scans: ScanRepository = Depends(get_scan_repository),
    reverifications: ReverificationRepository = Depends(get_reverification_repository),
    current_user: User = Depends(get_current_user),
) -> dict:
    await _load_scan_and_finding(scans, scan_id, vulnerability_id, current_user.org_id)
    job = await reverifications.get_in_org(job_id, current_user.org_id)
    if job is None or job.scan_id != scan_id or job.vulnerability_id != vulnerability_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Re-verification job not found",
        )
    return json_response(_reverification_response(job))



