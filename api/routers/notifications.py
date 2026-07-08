"""notifications.py router — /api/notifications/*"""

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from auth import CurrentUser
from database import get_db
from notifications import list_notifications, mark_notification_read, mark_all_read
from schemas import NotificationOut, PaginatedNotifications

router = APIRouter(prefix='/api/notifications', tags=['notifications'])


@router.get('', response_model=PaginatedNotifications)
async def get_notifications(
    current_user: CurrentUser,
    db: AsyncSession = Depends(get_db),
    unread_only: bool = False,
    limit: int = 50,
    offset: int = 0,
):
    """List notifications for the current user."""
    items, total, unread = await list_notifications(
        db, current_user.id, unread_only=unread_only, limit=limit, offset=offset
    )
    return PaginatedNotifications(
        items=[NotificationOut.model_validate(n) for n in items],
        total=total,
        unread=unread,
    )


@router.post('/{notif_id}/read')
async def read_notification(
    notif_id: int,
    current_user: CurrentUser,
    db: AsyncSession = Depends(get_db),
):
    """Mark a single notification as read."""
    ok = await mark_notification_read(db, notif_id, current_user.id)
    return {'success': ok}


@router.post('/read-all')
async def read_all_notifications(
    current_user: CurrentUser,
    db: AsyncSession = Depends(get_db),
):
    """Mark all notifications as read."""
    count = await mark_all_read(db, current_user.id)
    return {'success': True, 'marked_read': count}
