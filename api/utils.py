"""
utils.py — Shared helpers used across multiple routers.

Centralises logic that was previously duplicated in auth.py, engagements.py,
and admin.py routers.
"""

from fastapi import Request
from sqlalchemy.ext.asyncio import AsyncSession

from models import AuditLog


def get_client_ip(request: Request) -> str | None:
    """Extract the real client IP, honouring X-Forwarded-For from nginx."""
    forwarded = request.headers.get('X-Forwarded-For', '').split(',')[0].strip()
    return forwarded or (request.client.host if request.client else None)


def add_audit_log(
    db: AsyncSession,
    *,
    action: str,
    user_id: int | None = None,
    username: str | None = None,
    target_type: str | None = None,
    target_id: int | None = None,
    target_name: str | None = None,
    detail: dict | None = None,
    ip_address: str | None = None,
) -> None:
    """Append an AuditLog entry to the current session (no flush/commit)."""
    db.add(AuditLog(
        user_id=user_id,
        username=username or 'system',
        action=action,
        target_type=target_type,
        target_id=target_id,
        target_name=target_name,
        detail=detail,
        ip_address=ip_address,
    ))
