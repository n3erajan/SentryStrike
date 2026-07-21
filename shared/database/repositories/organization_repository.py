from datetime import datetime, timezone

from beanie import PydanticObjectId

from shared.models.invite import Invite, InviteState
from shared.models.organization import MIN_RETENTION_DAYS, Organization


class OrganizationRepository:
    """Persistence for workspace organizations and their pending invites."""

    async def get_by_id(self, org_id: str) -> Organization | None:
        """Fetch an organization by string id, returning None for malformed ids."""
        try:
            oid = PydanticObjectId(org_id)
        except Exception:
            return None
        return await Organization.get(oid)

    async def set_default_scan_config(self, org: Organization, config: dict) -> Organization:
        """Replace the stored default scan config blob."""
        org.default_scan_config = config
        org.updated_at = datetime.now(timezone.utc)
        await org.save()
        return org

    async def set_retention_days(self, org: Organization, days: int) -> Organization:
        """Update retention, enforcing the compliance floor of ``MIN_RETENTION_DAYS``."""
        org.retention_days = max(MIN_RETENTION_DAYS, days)
        org.updated_at = datetime.now(timezone.utc)
        await org.save()
        return org

    async def list_pending_invites(self, org_id: str) -> list[Invite]:
        """List pending invites for an org, newest first."""
        return (
            await Invite.find(Invite.org_id == org_id, Invite.state == InviteState.pending)
            .sort(-Invite.created_at)
            .to_list()
        )

    async def get_invite_in_org(self, invite_id: str, org_id: str) -> Invite | None:
        """Fetch an invite only if it belongs to the given organization."""
        try:
            oid = PydanticObjectId(invite_id)
        except Exception:
            return None
        invite = await Invite.get(oid)
        if invite is None or invite.org_id != org_id:
            return None
        return invite
