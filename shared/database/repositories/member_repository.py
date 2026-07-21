from beanie import PydanticObjectId

from shared.models.user import User, UserRole, UserSession


class MemberRepository:
    """Org-scoped persistence for member accounts.

    All queries are scoped by ``org_id`` so a caller can only ever reach members
    of their own workspace. Removal is a hard delete of the account plus all of
    its sessions (a member's only exit is owner/admin-initiated removal).
    """

    async def get_in_org(self, user_id: str, org_id: str) -> User | None:
        """Fetch a user only if they belong to the given organization."""
        try:
            oid = PydanticObjectId(user_id)
        except Exception:
            return None
        return await User.find_one(User.id == oid, User.org_id == org_id)

    async def list_in_org(self, org_id: str) -> list[User]:
        """List all members of an organization, newest first."""
        return await User.find(User.org_id == org_id).sort(-User.created_at).to_list()

    async def set_role(self, user: User, role: UserRole) -> User:
        """Update a member's role."""
        user.role = role
        await user.save()
        return user

    async def delete_member(self, user: User) -> None:
        """Hard-delete a member account and revoke every session it holds."""
        await UserSession.find(UserSession.user_id == str(user.id)).delete()
        await user.delete()
