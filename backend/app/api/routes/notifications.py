from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.api.dependencies import get_current_user, get_notification_repository, json_response
from shared.database.repositories.notification_repository import NotificationRepository
from shared.models.notification import Notification
from shared.models.user import User


router = APIRouter(prefix="/notifications", tags=["notifications"])


def _notification_response(notification: Notification) -> dict:
    data = notification.model_dump(mode="json")
    data["id"] = str(notification.id)
    return data


@router.get("")
async def list_notifications(
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=200),
    unread_only: bool = False,
    repo: NotificationRepository = Depends(get_notification_repository),
    current_user: User = Depends(get_current_user),
) -> dict:
    items = await repo.list_for_user(
        org_id=current_user.org_id,
        recipient_user_id=str(current_user.id),
        skip=skip,
        limit=limit,
        unread_only=unread_only,
    )
    return json_response(
        {"items": [_notification_response(item) for item in items], "total": len(items)}
    )


@router.get("/unread-count")
async def unread_notification_count(
    repo: NotificationRepository = Depends(get_notification_repository),
    current_user: User = Depends(get_current_user),
) -> dict:
    count = await repo.unread_count(
        org_id=current_user.org_id, recipient_user_id=str(current_user.id)
    )
    return json_response({"count": count})


@router.patch("/{notification_id}/read")
async def mark_notification_read(
    notification_id: str,
    repo: NotificationRepository = Depends(get_notification_repository),
    current_user: User = Depends(get_current_user),
) -> dict:
    notification = await repo.mark_read(
        notification_id,
        org_id=current_user.org_id,
        recipient_user_id=str(current_user.id),
    )
    if notification is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Notification not found")
    return json_response(_notification_response(notification), "notification marked read")


@router.post("/read-all")
async def mark_all_notifications_read(
    repo: NotificationRepository = Depends(get_notification_repository),
    current_user: User = Depends(get_current_user),
) -> dict:
    updated = await repo.mark_all_read(
        org_id=current_user.org_id, recipient_user_id=str(current_user.id)
    )
    return json_response({"updated": updated}, "notifications marked read")
