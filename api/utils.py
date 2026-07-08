"""
utils.py — Shared helpers used across multiple routers.

Centralises logic that was previously duplicated in auth.py, engagements.py,
and admin.py routers.
"""

import ipaddress

from fastapi import Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from config import settings
from models import AuditLog, Engagement, EngagementMember


def _parse_networks(cidrs: list[str]) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    nets = []
    for c in cidrs:
        try:
            nets.append(ipaddress.ip_network(c, strict=False))
        except ValueError:
            continue  # malformed entry in config — skip rather than 500
    return nets


def _ip_in_any(ip_str: str, networks: list) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return any(ip in net for net in networks)


def get_client_ip(request: Request) -> str | None:
    """
    Extract the real client IP for audit logging.

    X-Forwarded-For is attacker-controlled unless the request actually came
    through a proxy you run — anyone can set that header on a direct
    request. This only trusts it when the immediate TCP peer
    (request.client.host) matches settings.trusted_proxies_list; otherwise
    the header is ignored outright and the raw connection IP is used. With
    trusted_proxies unset (the default), X-Forwarded-For is never trusted.

    When trusted, walks the comma-separated chain from the right (the hop
    closest to this server) rather than taking the left-most entry — a
    proxy that appends without replacing lets a client prepend arbitrary
    values to the left, so the left-most entry is exactly as spoofable as
    the header's absence.
    """
    peer = request.client.host if request.client else None
    trusted_nets = _parse_networks(settings.trusted_proxies_list)

    if not trusted_nets or not peer or not _ip_in_any(peer, trusted_nets):
        return peer

    hops = [h.strip() for h in request.headers.get('X-Forwarded-For', '').split(',') if h.strip()]
    for hop in reversed(hops):
        if not _ip_in_any(hop, trusted_nets):
            return hop
    return peer  # every hop was itself a trusted proxy — nothing more specific to report


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


async def user_has_engagement_access(db: AsyncSession, engagement_id: int, current_user) -> bool:
    """
    True if current_user can access the given engagement: they're an Admin,
    the creator, or a member (see models.py::EngagementMember).

    Shared by engagements.py::_get_engagement_or_403 and findings.py's
    per-finding/per-scan endpoints — findings/scans don't have their own
    ownership, they inherit it from the engagement they belong to, so both
    routers need exactly the same answer to "does this user have standing
    on this engagement". Before this existed, findings.py's per-ID
    endpoints (get_finding, update_finding, bulk_update_findings,
    scan_status, scan_stream) had no ownership check at all — any
    authenticated user could read or modify any finding by ID regardless
    of which engagement it belonged to.
    """
    if current_user.role == 'Admin':
        return True
    owned = (await db.execute(
        select(Engagement.id).where(
            Engagement.id == engagement_id,
            Engagement.created_by == current_user.id,
        )
    )).scalar_one_or_none()
    if owned:
        return True
    is_member = (await db.execute(
        select(EngagementMember.id).where(
            EngagementMember.engagement_id == engagement_id,
            EngagementMember.user_id == current_user.id,
        )
    )).scalar_one_or_none()
    return is_member is not None


def accessible_engagement_filter(current_user):
    """
    SQLAlchemy boolean condition restricting a query to engagements
    current_user owns or is a member of. Returns None for Admin — callers
    should skip the .where() entirely in that case rather than adding a
    filter that happens to match everything, which is both slower and
    easy to accidentally get wrong.

    This is the query-level equivalent of user_has_engagement_access
    (which answers "can they access *this one* engagement" — this answers
    "which engagements can they access" for list/aggregate queries).
    Currently used by dashboard.py's trend endpoint; list_engagements,
    findings.py's _base_q, and search.py each still carry their own
    hand-written version of this same ownership-or-membership condition
    predating this helper — worth unifying if this logic needs to change
    again, but not touched here to avoid re-testing already-shipped,
    already-covered call sites without a concrete need to change them.
    """
    if current_user.role == 'Admin':
        return None
    member_eng_ids = select(EngagementMember.engagement_id).where(
        EngagementMember.user_id == current_user.id
    )
    return (
        (Engagement.created_by == current_user.id) |
        (Engagement.id.in_(member_eng_ids))
    )
