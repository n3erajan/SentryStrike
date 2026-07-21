from fastapi import APIRouter, Depends, HTTPException, status

from app.api.dependencies import (
    get_current_user,
    get_invite_service,
    get_member_repository,
    get_organization_repository,
    json_response,
    require_role,
)
from app.core.email import get_email_backend
from app.core.invites import InviteError, InviteService, build_invite_link
from shared.database.repositories.member_repository import MemberRepository
from shared.database.repositories.organization_repository import OrganizationRepository
from shared.models.invite import Invite
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
    ).model_dump(mode="json")


def _render_member_invite_email(org_name: str | None, role: UserRole, link: str | None, token: str) -> tuple[str, str]:
    """Return (subject, body) for a member invitation email."""
    workspace = org_name or "your team's"
    subject = f"You're invited to join the {org_name} workspace on SentryStrike" if org_name else (
        "You're invited to join a workspace on SentryStrike"
    )
    where = link or f"your SentryStrike signup page with this invite token:\n\n    {token}"
    body = (
        f"Hello,\n\n"
        f"You've been invited to join the {workspace} workspace on SentryStrike "
        f"as a {role.value}.\n\n"
        f"To accept, complete registration here:\n\n    {where}\n\n"
        f"This link is single-use and will expire. If you weren't expecting this, "
        f"you can ignore this email.\n"
    )
    return subject, body


# --------------------------------------------------------------------------- #
# Members
# --------------------------------------------------------------------------- #


@router.get("/members")
async def list_members(
    members: MemberRepository = Depends(get_member_repository),
    current_user: User = Depends(get_current_user),
) -> dict:
    """List every member of the caller's organization. Any member may read."""
    users = await members.list_in_org(current_user.org_id)
    return json_response({"items": [_member_response(u) for u in users], "total": len(users)})


@router.delete("/members/{user_id}")
async def remove_member(
    user_id: str,
    members: MemberRepository = Depends(get_member_repository),
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
    await members.delete_member(target)
    return json_response({"removed": True}, "member removed")


@router.patch("/members/{user_id}/role")
async def change_member_role(
    user_id: str,
    payload: ChangeRoleRequest,
    members: MemberRepository = Depends(get_member_repository),
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
    await members.set_role(target, payload.role)
    return json_response(_member_response(target), "role updated")


# --------------------------------------------------------------------------- #
# Invites
# --------------------------------------------------------------------------- #


@router.get("/invites")
async def list_invites(
    orgs: OrganizationRepository = Depends(get_organization_repository),
    current_user: User = Depends(require_role(*WORKSPACE_ADMIN_ROLES)),
) -> dict:
    """List pending invites for the caller's organization. Owner/admin only."""
    invites = await orgs.list_pending_invites(current_user.org_id)
    return json_response({"items": [_invite_response(i) for i in invites], "total": len(invites)})


@router.post("/invites", status_code=status.HTTP_201_CREATED)
async def invite_member(
    payload: InviteMemberRequest,
    orgs: OrganizationRepository = Depends(get_organization_repository),
    invites: InviteService = Depends(get_invite_service),
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
        raise HTTPException(status_code=exc.status_code, detail=exc.message) from exc

    link = build_invite_link(token)
    subject, body = _render_member_invite_email(org_name, payload.role, link, token)
    try:
        get_email_backend().send(to=payload.email, subject=subject, body_text=body)
    except Exception:  # noqa: BLE001 — delivery failure must not void a created invite
        pass
    return json_response(_invite_response(invite), "invite sent")


@router.post("/invites/{invite_id}/cancel")
async def cancel_invite(
    invite_id: str,
    orgs: OrganizationRepository = Depends(get_organization_repository),
    invites: InviteService = Depends(get_invite_service),
    current_user: User = Depends(require_role(*WORKSPACE_ADMIN_ROLES)),
) -> dict:
    """Invalidate a pending invite so its token no longer accepts. Owner/admin only."""
    invite = await orgs.get_invite_in_org(invite_id, current_user.org_id)
    if invite is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Invite not found")
    invite = await invites.cancel(invite)
    return json_response(_invite_response(invite), "invite cancelled")


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
    org = await orgs.set_default_scan_config(org, payload.config)
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
