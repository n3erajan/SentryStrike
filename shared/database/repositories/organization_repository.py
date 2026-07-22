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

    async def list_all(self) -> list[Organization]:
        """List every organization (used by the retention purge to sweep each tenant)."""
        return await Organization.find_all().to_list()

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

    async def reserve_member_seat(self, org_id: str) -> bool:
        """Atomically reserve a seat when the workspace still has capacity."""
        try:
            oid = PydanticObjectId(org_id)
        except Exception:
            return False
        result = await Organization.get_motor_collection().update_one(
            {
                "_id": oid,
                "$expr": {"$lt": ["$occupied_seats", "$member_limit"]},
            },
            {"$inc": {"occupied_seats": 1}, "$set": {"updated_at": datetime.now(timezone.utc)}},
        )
        return result.modified_count == 1

    async def release_member_seat(self, org_id: str) -> bool:
        """Release one non-owner seat without allowing the counter below one."""
        try:
            oid = PydanticObjectId(org_id)
        except Exception:
            return False
        result = await Organization.get_motor_collection().update_one(
            {"_id": oid, "occupied_seats": {"$gt": 1}},
            {"$inc": {"occupied_seats": -1}, "$set": {"updated_at": datetime.now(timezone.utc)}},
        )
        return result.modified_count == 1

    async def set_member_limit(self, org_id: str, limit: int) -> Organization | None:
        """Set a vendor-controlled seat limit unless it is below occupied seats."""
        try:
            oid = PydanticObjectId(org_id)
        except Exception:
            return None
        result = await Organization.get_motor_collection().update_one(
            {"_id": oid, "occupied_seats": {"$lte": limit}},
            {"$set": {"member_limit": limit, "updated_at": datetime.now(timezone.utc)}},
        )
        if result.matched_count != 1:
            return None
        return await Organization.get(oid)

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
        return await Invite.find_one(Invite.id == oid, Invite.org_id == org_id)
