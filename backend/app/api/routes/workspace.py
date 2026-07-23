from datetime import timezone

from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.api.dependencies import (
    get_audit_repository,
    get_current_user,
    get_invite_service,
    get_member_repository,
    get_notification_repository,
    get_organization_repository,
    json_response,
    require_role,
)
from app.core.email import get_email_backend, render_workspace_invite_email
from app.core.invites import InviteError, InviteService, build_invite_link
from shared.database.repositories.audit_repository import AuditRepository
from shared.database.repositories.member_repository import MemberRepository
from shared.database.repositories.notification_repository import NotificationRepository
from shared.database.repositories.organization_repository import OrganizationRepository
from shared.models.audit import AuditAction
from shared.models.invite import Invite, InviteEmailStatus
from shared.models.notification import NotificationType
from shared.models.user import User, UserRole
from app.schemas.workspace_schema import (
    ChangeRoleRequest,
    DefaultConfigRequest,
    InviteMemberRequest,
    InviteResponse,
    MemberResponse,
    RetentionRequest,
)

router = APIRouter(prefix="/workspace", tags=["workspace"])

# Endpoints that mutate the workspace (invite, remove, role change, settings)
# are limited to the owner and admins. Read endpoints admit any member.
WORKSPACE_ADMIN_ROLES = (UserRole.owner, UserRole.admin)


def _member_response(user: User) -> dict:
    """Project a User document to its workspace member representation."""
    return MemberResponse(
        id=str(user.id),
        full_name=user.full_name,
        email=user.email,
        role=user.role.value,
        is_active=user.is_active,
        created_at=user.created_at,
    ).model_dump(mode="json")


def _invite_response(invite: Invite) -> dict:
    """Project an Invite document to its workspace pending-invite representation."""
    return InviteResponse(
        id=str(invite.id),
        email=invite.email,
        role=invite.role.value,
        state=invite.state.value,
        expires_at=invite.expires_at,
        created_at=invite.created_at,
        invited_by_user_id=invite.invited_by_user_id,
        email_delivery_status=invite.email_delivery_status.value,
        email_delivery_backend=invite.email_delivery_backend,
        email_delivery_attempted_at=invite.email_delivery_attempted_at,
        email_delivery_error=invite.email_delivery_error,
    ).model_dump(mode="json")


# --------------------------------------------------------------------------- #
# Members
# --------------------------------------------------------------------------- #


@router.get("/members")
async def list_members(
    members: MemberRepository = Depends(get_member_repository),
    orgs: OrganizationRepository = Depends(get_organization_repository),
    invites: InviteService = Depends(get_invite_service),
    current_user: User = Depends(get_current_user),
) -> dict:
    """List every member of the caller's organization. Any member may read."""
    await invites.expire_pending_member_invites(current_user.org_id)
    users = await members.list_in_org(current_user.org_id)
    org = await orgs.get_by_id(current_user.org_id)
    return json_response(
        {
            "items": [_member_response(u) for u in users],
            "total": len(users),
            "member_limit": getattr(org, "member_limit", None),
            "occupied_seats": getattr(org, "occupied_seats", None),
        }
    )


@router.delete("/members/{user_id}")
async def remove_member(
    user_id: str,
    members: MemberRepository = Depends(get_member_repository),
    orgs: OrganizationRepository = Depends(get_organization_repository),
    audit: AuditRepository = Depends(get_audit_repository),
    current_user: User = Depends(require_role(*WORKSPACE_ADMIN_ROLES)),
) -> dict:
    """Remove a member: a hard delete of their account and all their sessions.

    Guards (all must hold): the caller is owner/admin (enforced by the
    dependency), the target is in the same org, the target is not the owner,
    and the target is not the caller. Irreversible and confirmed by the client.
    """
    if user_id == str(current_user.id):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="You cannot remove yourself.")
    target = await members.get_in_org(user_id, current_user.org_id)
    if target is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Member not found")
    if target.role == UserRole.owner:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="The owner cannot be removed.")
    removed_email = target.email
    removed_role = target.role.value
    await members.delete_member(target)
    await orgs.release_member_seat(current_user.org_id)
    await audit.record(
        org_id=current_user.org_id,
        action=AuditAction.member_removed,
        actor_user_id=str(current_user.id),
        actor_email=current_user.email,
        target_type="user",
        target_id=user_id,
        metadata={"email": removed_email, "role": removed_role},
    )
    return json_response({"removed": True}, "member removed")


@router.patch("/members/{user_id}/role")
async def change_member_role(
    user_id: str,
    payload: ChangeRoleRequest,
    members: MemberRepository = Depends(get_member_repository),
    notifications: NotificationRepository = Depends(get_notification_repository),
    audit: AuditRepository = Depends(get_audit_repository),
    current_user: User = Depends(require_role(*WORKSPACE_ADMIN_ROLES)),
) -> dict:
    """Change a member's role. Cannot target the owner, self, or grant ownership.

    The assignable-role validation lives on the request schema; ownership is
    fixed at onboarding and is never granted or transferred through the API.
    """
    if user_id == str(current_user.id):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="You cannot change your own role.")
    target = await members.get_in_org(user_id, current_user.org_id)
    if target is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Member not found")
    if target.role == UserRole.owner:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="The owner's role cannot be changed.")
    previous_role = target.role.value
    await members.set_role(target, payload.role)
    await notifications.create(
        org_id=current_user.org_id,
        recipient_user_id=user_id,
        type=NotificationType.member_role_changed,
        title="Workspace role changed",
        message=f"Your workspace role changed from {previous_role} to {payload.role.value}.",
        resource_type="member",
        resource_id=user_id,
        metadata={"from": previous_role, "to": payload.role.value},
        dedupe_key=(
            f"member-role:{current_user.org_id}:{user_id}:"
            f"{previous_role}:{payload.role.value}"
        ),
    )
    await audit.record(
        org_id=current_user.org_id,
        action=AuditAction.member_role_changed,
        actor_user_id=str(current_user.id),
        actor_email=current_user.email,
        target_type="user",
        target_id=user_id,
        metadata={"email": target.email, "from": previous_role, "to": payload.role.value},
    )
    return json_response(_member_response(target), "role updated")


# --------------------------------------------------------------------------- #
# Invites
# --------------------------------------------------------------------------- #


@router.get("/invites")
async def list_invites(
    orgs: OrganizationRepository = Depends(get_organization_repository),
    invite_service: InviteService = Depends(get_invite_service),
    current_user: User = Depends(require_role(*WORKSPACE_ADMIN_ROLES)),
) -> dict:
    """List pending invites for the caller's organization. Owner/admin only."""
    await invite_service.expire_pending_member_invites(current_user.org_id)
    invites = await orgs.list_pending_invites(current_user.org_id)
    return json_response({"items": [_invite_response(i) for i in invites], "total": len(invites)})


@router.post("/invites", status_code=status.HTTP_201_CREATED)
async def invite_member(
    payload: InviteMemberRequest,
    orgs: OrganizationRepository = Depends(get_organization_repository),
    invites: InviteService = Depends(get_invite_service),
    audit: AuditRepository = Depends(get_audit_repository),
    current_user: User = Depends(require_role(*WORKSPACE_ADMIN_ROLES)),
) -> dict:
    """Invite an email into the caller's org with a pinned role. Owner/admin only.

    The invite is bound to the caller's ``org_id``; the role is validated by the
    request schema (an owner invite is never issuable here). The signup link is
    emailed and echoed to the operator when no public hostname is configured.
    """
    org = await orgs.get_by_id(current_user.org_id)
    org_name = org.name if org is not None else None
    try:
        token, invite = await invites.create_invite(
            email=payload.email,
            role=payload.role,
            org_id=current_user.org_id,
            org_name=org_name,
            invited_by_user_id=str(current_user.id),
        )
    except InviteError as exc:
        headers = None
        retry_after = getattr(exc, "retry_after", None)
        if retry_after is not None:
            headers = {"Retry-After": str(retry_after)}
        raise HTTPException(
            status_code=exc.status_code, detail=exc.message, headers=headers
        ) from exc

    link = build_invite_link(token)
    subject, body_text, body_html = render_workspace_invite_email(
        org_name=org_name,
        role=payload.role.value,
        link=link,
        token=token,
    )
    backend = get_email_backend()
    try:
        backend.send(
            to=payload.email,
            subject=subject,
            body_text=body_text,
            body_html=body_html,
        )
    except Exception as exc:  # noqa: BLE001 — compensate the persisted invite and seat
        await invites.record_email_delivery(
            invite,
            status=InviteEmailStatus.failed,
            backend=backend.name,
            error=f"{type(exc).__name__}: {exc}",
        )
        await invites.cancel(invite)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Invitation email could not be delivered; no invitation was created.",
        ) from exc
    await invites.record_email_delivery(
        invite,
        status=InviteEmailStatus.smtp_accepted,
        backend=backend.name,
    )
    await audit.record(
        org_id=current_user.org_id,
        action=AuditAction.invite_created,
        actor_user_id=str(current_user.id),
        actor_email=current_user.email,
        target_type="invite",
        target_id=str(invite.id),
        metadata={"email": payload.email, "role": payload.role.value},
    )
    return json_response(_invite_response(invite), "invite email accepted by SMTP server")


@router.post("/invites/{invite_id}/cancel")
async def cancel_invite(
    invite_id: str,
    orgs: OrganizationRepository = Depends(get_organization_repository),
    invites: InviteService = Depends(get_invite_service),
    audit: AuditRepository = Depends(get_audit_repository),
    current_user: User = Depends(require_role(*WORKSPACE_ADMIN_ROLES)),
) -> dict:
    """Invalidate a pending invite so its token no longer accepts. Owner/admin only."""
    invite = await orgs.get_invite_in_org(invite_id, current_user.org_id)
    if invite is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Invite not found")
    invite = await invites.cancel(invite)
    await audit.record(
        org_id=current_user.org_id,
        action=AuditAction.invite_cancelled,
        actor_user_id=str(current_user.id),
        actor_email=current_user.email,
        target_type="invite",
        target_id=invite_id,
        metadata={"email": invite.email, "role": invite.role.value},
    )
    return json_response(_invite_response(invite), "invite cancelled")


@router.get("")
async def get_workspace(
    orgs: OrganizationRepository = Depends(get_organization_repository),
    current_user: User = Depends(get_current_user),
) -> dict:
    """Return the current workspace's metadata and settings."""
    org = await orgs.get_by_id(current_user.org_id)
    if org is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Workspace not found")
    return json_response({
        "id": str(org.id),
        "name": org.name,
        "member_limit": org.member_limit,
        "occupied_seats": org.occupied_seats,
        "retention_days": org.retention_days,
        "created_at": org.created_at,
    })


@router.get("/audit-log")
async def list_audit_log(
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=200),
    audit: AuditRepository = Depends(get_audit_repository),
    current_user: User = Depends(require_role(*WORKSPACE_ADMIN_ROLES)),
) -> dict:
    """Return the org's audit-log entries, newest first. Owner/admin only."""
    entries = await audit.list_in_org(current_user.org_id, skip=skip, limit=limit)
    items = [
        {
            "id": str(entry.id),
            "action": entry.action.value,
            "actor_user_id": entry.actor_user_id,
            "actor_email": entry.actor_email,
            "target_type": entry.target_type,
            "target_id": entry.target_id,
            "metadata": entry.metadata,
            "created_at": (
                entry.created_at.replace(tzinfo=timezone.utc).isoformat()
                if entry.created_at and entry.created_at.tzinfo is None
                else entry.created_at.isoformat() if entry.created_at else None
            ),
        }
        for entry in entries
    ]
    return json_response({"items": items, "total": len(items)})


# --------------------------------------------------------------------------- #
# Settings — default scan config & retention
# --------------------------------------------------------------------------- #


@router.get("/default-config")
async def get_default_config(
    orgs: OrganizationRepository = Depends(get_organization_repository),
    current_user: User = Depends(get_current_user),
) -> dict:
    """Return the workspace's stored default scan config blob. Any member may read.

    The frontend fetches this to pre-fill the create-scan form; there is no
    server-side merge — the submitter sends a fully resolved config.
    """
    org = await orgs.get_by_id(current_user.org_id)
    if org is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Organization not found")
    return json_response({"config": org.default_scan_config})


@router.put("/default-config")
async def set_default_config(
    payload: DefaultConfigRequest,
    orgs: OrganizationRepository = Depends(get_organization_repository),
    current_user: User = Depends(require_role(*WORKSPACE_ADMIN_ROLES)),
) -> dict:
    """Replace the workspace's default scan config blob. Owner/admin only."""
    org = await orgs.get_by_id(current_user.org_id)
    if org is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Organization not found")
    org = await orgs.set_default_scan_config(
        org, payload.config.model_dump(mode="json", exclude_none=True)
    )
    return json_response({"config": org.default_scan_config}, "default config updated")


@router.get("/retention")
async def get_retention(
    orgs: OrganizationRepository = Depends(get_organization_repository),
    current_user: User = Depends(get_current_user),
) -> dict:
    """Return the workspace's scan-data retention window in days. Any member may read."""
    org = await orgs.get_by_id(current_user.org_id)
    if org is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Organization not found")
    return json_response({"retention_days": org.retention_days})


@router.put("/retention")
async def set_retention(
    payload: RetentionRequest,
    orgs: OrganizationRepository = Depends(get_organization_repository),
    current_user: User = Depends(require_role(*WORKSPACE_ADMIN_ROLES)),
) -> dict:
    """Update the retention window, enforcing the compliance floor. Owner/admin only.

    The repository clamps the value to at least ``MIN_RETENTION_DAYS``, so a
    request below the floor is silently raised to it rather than rejected.
    """
    org = await orgs.get_by_id(current_user.org_id)
    if org is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Organization not found")
    org = await orgs.set_retention_days(org, payload.retention_days)
    return json_response({"retention_days": org.retention_days}, "retention updated")
