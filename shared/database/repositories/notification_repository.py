from datetime import datetime, timezone

from beanie import PydanticObjectId
from pymongo.errors import DuplicateKeyError

from shared.models.notification import Notification, NotificationType


class NotificationRepository:
    """User-and-workspace-scoped persistence for durable notifications."""

    async def create(
        self,
        *,
        org_id: str,
        recipient_user_id: str,
        type: NotificationType,
        title: str,
        message: str,
        dedupe_key: str,
        resource_type: str | None = None,
        resource_id: str | None = None,
        metadata: dict | None = None,
    ) -> Notification:
        notification = Notification(
            org_id=org_id,
            recipient_user_id=recipient_user_id,
            type=type,
            title=title,
            message=message,
            resource_type=resource_type,
            resource_id=resource_id,
            metadata=metadata or {},
            dedupe_key=dedupe_key,
        )
        try:
            await notification.insert()
            return notification
        except DuplicateKeyError:
            existing = await Notification.find_one(
                Notification.dedupe_key == dedupe_key,
                Notification.org_id == org_id,
                Notification.recipient_user_id == recipient_user_id,
            )
            if existing is None:
                raise
            return existing

    async def list_for_user(
        self,
        *,
        org_id: str,
        recipient_user_id: str,
        skip: int = 0,
        limit: int = 50,
        unread_only: bool = False,
    ) -> list[Notification]:
        filters = [
            Notification.org_id == org_id,
            Notification.recipient_user_id == recipient_user_id,
        ]
        if unread_only:
            filters.append(Notification.read_at == None)  # noqa: E711 - ODM expression
        return (
            await Notification.find(*filters)
            .sort(-Notification.created_at)
            .skip(skip)
            .limit(limit)
            .to_list()
        )

    async def unread_count(self, *, org_id: str, recipient_user_id: str) -> int:
        return await Notification.find(
            Notification.org_id == org_id,
            Notification.recipient_user_id == recipient_user_id,
            Notification.read_at == None,  # noqa: E711 - ODM expression
        ).count()

    async def mark_read(
        self, notification_id: str, *, org_id: str, recipient_user_id: str
    ) -> Notification | None:
        try:
            oid = PydanticObjectId(notification_id)
        except Exception:
            return None
        notification = await Notification.find_one(
            Notification.id == oid,
            Notification.org_id == org_id,
            Notification.recipient_user_id == recipient_user_id,
        )
        if notification is None:
            return None
        if notification.read_at is None:
            notification.read_at = datetime.now(timezone.utc)
            await notification.save()
        return notification

    async def mark_all_read(self, *, org_id: str, recipient_user_id: str) -> int:
        result = await Notification.get_motor_collection().update_many(
            {
                "org_id": org_id,
                "recipient_user_id": recipient_user_id,
                "read_at": None,
            },
            {"$set": {"read_at": datetime.now(timezone.utc)}},
        )
        return result.modified_count
