"""
notifications.py — In-app notification service.

Provides functions to create, mark-read, and list notifications.
Designed to be called from routers and Celery tasks.
"""

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from models import Notification


async def create_notification(
    db: AsyncSession,
    user_id: int,
    event_type: str,
    title: str,
    message: str,
    link: str | None = None,
) -> Notification:
    """Create a notification for a specific user."""
    n = Notification(
        user_id=user_id,
        event_type=event_type,
        title=title,
        message=message,
        link=link,
        is_read=False,
    )
    db.add(n)
    await db.flush()
    return n


async def mark_notification_read(
    db: AsyncSession,
    notification_id: int,
    user_id: int,
) -> bool:
    """Mark a notification as read. Returns True if the notification existed
    and belonged to the user."""
    result = await db.execute(
        update(Notification)
        .where(Notification.id == notification_id, Notification.user_id == user_id)
        .values(is_read=True)
    )
    return result.rowcount > 0


async def mark_all_read(db: AsyncSession, user_id: int) -> int:
    """Mark all unread notifications for a user as read. Returns count."""
    result = await db.execute(
        update(Notification)
        .where(Notification.user_id == user_id, Notification.is_read.is_(False))
        .values(is_read=True)
    )
    return result.rowcount


async def list_notifications(
    db: AsyncSession,
    user_id: int,
    unread_only: bool = False,
    limit: int = 50,
    offset: int = 0,
) -> tuple[list[Notification], int, int]:
    """Return notifications for a user plus total and unread counts.

    Returns: (items, total, unread_count)
    """
    # Total count
    total_q = select(func.count(Notification.id)).where(Notification.user_id == user_id)
    if unread_only:
        total_q = total_q.where(Notification.is_read.is_(False))
    total = (await db.execute(total_q)).scalar_one()

    # Unread count (always needed for the bell badge)
    unread = (await db.execute(
        select(func.count(Notification.id))
        .where(Notification.user_id == user_id, Notification.is_read.is_(False))
    )).scalar_one()

    # Items
    items_q = (
        select(Notification)
        .where(Notification.user_id == user_id)
        .order_by(Notification.created_at.desc())
        .limit(limit)
        .offset(offset)
    )
    if unread_only:
        items_q = items_q.where(Notification.is_read.is_(False))

    items = (await db.execute(items_q)).scalars().all()
    return list(items), total, unread
