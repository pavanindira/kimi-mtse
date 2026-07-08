"""engagements.py router — /api/engagements/*"""

import hashlib
import os
import re
import secrets
import subprocess
import time
from datetime import datetime, timedelta, timezone

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse, Response
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from auth import AdminUser, AnalystUser, CurrentUser
from database import get_db
from crypto_utils import encrypt_secret
from models import (Engagement, EngagementMember, Finding,
                    MAX_DELIVERIES_PER_ENGAGEMENT, ReportTemplate, Scan,
                    ScheduledScan, User, WebhookDelivery)
from schemas import (EngagementCreate, EngagementDetail, EngagementMemberCreate,
                     EngagementMemberOut, EngagementOut, EngagementUpdate,
                     FindingDelta, FindingOut, ReportTemplateOut, ScanCreate,
                     ScanOut, ScheduledScanCreate, ScheduledScanOut,
                     ScheduledScanUpdate, SeveritySummary, WebhookDeliveryOut,
                     WebhookSecretOut)
from tasks import (celery, run_cloud_scan, run_infra_scan, run_mobile_scan,
                   run_sast_scan, run_web_scan)
from utils import add_audit_log, get_client_ip, user_has_engagement_access
from webhooks import serialize_payload, sign_payload


def _gen_webhook_secret() -> str:
    """64 hex chars (32 random bytes) — used as the HMAC-SHA256 signing key
    for webhook payload delivery. See tasks.py::_dispatch_webhook."""
    return secrets.token_hex(32)

router = APIRouter(prefix='/api/engagements', tags=['engagements'])

TASK_MAP = {
    'web':    run_web_scan,
    'sast':   run_sast_scan,
    'infra':  run_infra_scan,
    'cloud':  run_cloud_scan,
    'mobile': run_mobile_scan,
}


def _target_in_scope(target: str, scope_lines: list[str]) -> bool:
    """
    Return True if target matches at least one entry in the scope list.

    Scope entries can be:
      - CIDR notation:    10.0.0.0/8, 192.168.1.0/24
      - Hostname glob:    *.example.com, app.example.com
      - URL prefix:       https://app.example.com, https://api.example.com/v2/
    """
    import ipaddress as _ip
    from urllib.parse import urlparse as _up

    parsed    = _up(target)
    host_part = parsed.hostname or target.split('/')[0].split(':')[0]

    for entry in scope_lines:
        entry = entry.strip()
        if not entry:
            continue
        # CIDR check
        try:
            network = _ip.ip_network(entry, strict=False)
            try:
                addr = _ip.ip_address(host_part)
                if addr in network:
                    return True
                continue
            except ValueError:
                pass  # host is not a bare IP
        except ValueError:
            pass

        # URL prefix check
        if entry.startswith(('http://', 'https://')):
            if target.startswith(entry):
                return True
            continue

        # Hostname / wildcard glob check
        import fnmatch
        if fnmatch.fnmatch(host_part, entry):
            return True

    return False


async def _get_engagement_or_403(
    eng_id: int,
    current_user,
    db: AsyncSession,
) -> Engagement:
    """
    Fetch an engagement by id.  Raises 404 if it does not exist.
    Raises 403 if the caller is not Admin, did not create the engagement,
    and is not a member of it (see EngagementMember in models.py).

    Using 403 (not 404) for access violations is intentional — returning
    404 would reveal whether the engagement exists to a user who has no right
    to see it.  We reveal a 403 so the caller knows the ID is valid but they
    lack access, which is the appropriate signal for a UI to show.

    Membership grants the same per-engagement access as ownership, but not
    additional global permissions — a Viewer member still can't hit an
    AnalystUser-gated endpoint (PATCH/DELETE), since that dependency
    rejects them before this function is even called. This function only
    answers "does this specific user have any standing on this specific
    engagement", not "what are they allowed to do here".

    The actual access check (owner/admin/member) lives in
    utils.py::user_has_engagement_access, shared with findings.py — a
    finding or scan doesn't have its own ownership, it inherits the
    engagement's, so both routers need identical answers here.
    """
    eng = (await db.execute(
        select(Engagement).where(Engagement.id == eng_id)
    )).scalar_one_or_none()
    if not eng:
        raise HTTPException(status_code=404, detail='Engagement not found')
    if not await user_has_engagement_access(db, eng_id, current_user):
        raise HTTPException(
            status_code=403,
            detail='You do not have access to this engagement',
        )
    return eng


def _require_owner_or_admin(eng: Engagement, current_user) -> None:
    """
    Membership management is deliberately narrower than general engagement
    access — any member can read/write the engagement itself, but only the
    owner or an Admin can decide who else gets that access. Without this, a
    member could add arbitrary other people to an engagement they don't own.
    """
    if current_user.role != 'Admin' and eng.created_by != current_user.id:
        raise HTTPException(
            status_code=403,
            detail='Only the engagement owner or an Admin can manage members',
        )



async def _severity_summary(db: AsyncSession, engagement_id: int) -> SeveritySummary:
    rows = (await db.execute(
        select(Finding.severity, func.count(Finding.id))
        .join(Scan, Finding.scan_id_fk == Scan.id)
        .where(Scan.engagement_id == engagement_id,
               Finding.status.in_(['Open', 'Confirmed']))
        .group_by(Finding.severity)
    )).all()
    d = {r[0]: r[1] for r in rows}
    return SeveritySummary(
        Critical=d.get('Critical', 0), High=d.get('High', 0),
        Medium=d.get('Medium', 0),     Low=d.get('Low', 0),
        Info=d.get('Info', 0),
    )


# ── List ──────────────────────────────────────────────────────────────────────

@router.get('', response_model=list[EngagementOut])
async def list_engagements(
    current_user: CurrentUser,
    db: AsyncSession = Depends(get_db),
    status: str | None = None,
):
    """
    Admins see all engagements.
    Analysts and Viewers see engagements they created or are a member of.
    """
    q = select(Engagement).order_by(Engagement.updated_at.desc())
    if current_user.role != 'Admin':
        member_eng_ids = select(EngagementMember.engagement_id).where(
            EngagementMember.user_id == current_user.id
        )
        q = q.where(
            (Engagement.created_by == current_user.id) |
            (Engagement.id.in_(member_eng_ids))
        )
    if status:
        q = q.where(Engagement.status == status)
    result = await db.execute(q)
    return result.scalars().all()


# ── Create ────────────────────────────────────────────────────────────────────

@router.post('', response_model=EngagementOut, status_code=status.HTTP_201_CREATED)
async def create_engagement(
    body:         EngagementCreate,
    current_user: AnalystUser,
    request:      Request,
    db:           AsyncSession = Depends(get_db),
):
    eng = Engagement(
        name=body.name, client_name=body.client_name,
        description=body.description, created_by=current_user.id,
        scope=body.scope or None,
        webhook_url=body.webhook_url,
        webhook_secret=_gen_webhook_secret() if body.webhook_url else None,
        started_at=datetime.now(timezone.utc),
    )
    db.add(eng)
    await db.flush()
    add_audit_log(db, action='engagement.created',
                  user_id=current_user.id, username=current_user.username,
                  target_type='engagement', target_id=eng.id, target_name=eng.name,
                  detail={'client': eng.client_name},
                  ip_address=get_client_ip(request))
    return eng


# ── Report templates (for the per-engagement picker) ────────────────────────
# Deliberately separate from admin.py's /api/admin/report-templates, which is
# Admin-only (manages logos, sets the global default). Any Analyst/Admin who
# can edit an engagement needs to be able to see the template list to assign
# one — ReportTemplateOut exposes nothing sensitive (id/name/is_default/
# has_logo/created_at), so Analyst access here is fine.
#
# Registered ahead of GET /{eng_id} — Starlette matches path segments before
# FastAPI validates the {eng_id}: int converter, so a static route earlier in
# the file always wins over a parameterized one at the same depth.
@router.get('/report-templates', response_model=list[ReportTemplateOut])
async def list_report_templates_for_engagements(
    current_user: AnalystUser,
    db:           AsyncSession = Depends(get_db),
):
    rows = (await db.execute(select(ReportTemplate))).scalars().all()
    return [ReportTemplateOut.from_orm_obj(r) for r in rows]


# ── Get ───────────────────────────────────────────────────────────────────────

@router.get('/{eng_id}', response_model=EngagementDetail)
async def get_engagement(
    eng_id:       int,
    current_user: CurrentUser,
    db:           AsyncSession = Depends(get_db),
):
    eng = await _get_engagement_or_403(eng_id, current_user, db)

    summary    = await _severity_summary(db, eng_id)
    scan_count = (await db.execute(
        select(func.count(Scan.id)).where(Scan.engagement_id == eng_id)
    )).scalar_one()
    finding_count = (await db.execute(
        select(func.count(Finding.id))
        .join(Scan, Finding.scan_id_fk == Scan.id)
        .where(Scan.engagement_id == eng_id,
               Finding.status.in_(['Open', 'Confirmed']))
    )).scalar_one()

    detail = EngagementDetail.model_validate(eng)
    detail.severity_summary = summary
    detail.scan_count        = scan_count
    detail.finding_count     = finding_count
    return detail


# ── Scans ─────────────────────────────────────────────────────────────────────

@router.get('/{eng_id}/scans', response_model=list[ScanOut])
async def list_scans(
    eng_id:       int,
    current_user: CurrentUser,
    db:           AsyncSession = Depends(get_db),
):
    await _get_engagement_or_403(eng_id, current_user, db)
    result = await db.execute(
        select(Scan).where(Scan.engagement_id == eng_id)
        .order_by(Scan.created_at.desc())
    )
    scans = result.scalars().all()
    if not scans:
        return []

    # Single bulk COUNT query — avoids N+1, far cheaper than a column_property
    # correlated subquery which requires undefer() on every async ORM query.
    scan_ids  = [s.id for s in scans]
    count_rows = (await db.execute(
        select(Finding.scan_id_fk, func.count(Finding.id))
        .where(Finding.scan_id_fk.in_(scan_ids))
        .group_by(Finding.scan_id_fk)
    )).all()
    count_map = {row[0]: row[1] for row in count_rows}

    out = []
    for s in scans:
        so = ScanOut.model_validate(s)
        so.finding_count = count_map.get(s.id, 0)
        out.append(so)
    return out


@router.post('/{eng_id}/scans', response_model=ScanOut,
             status_code=status.HTTP_201_CREATED)
async def start_scan(
    eng_id:       int,
    body:         ScanCreate,
    current_user: AnalystUser,
    request:      Request,
    db:           AsyncSession = Depends(get_db),
):
    # Verify engagement exists and caller has access
    eng = await _get_engagement_or_403(eng_id, current_user, db)

    # ── Scope check ───────────────────────────────────────────────────────────
    # Warn (don't block) if the target appears to fall outside the declared
    # engagement scope.  This is advisory — the analyst may be scanning a
    # support system for the same client — but it surfaces accidental mistakes.
    scope_warning: str | None = None
    if eng.scope:
        scope_lines = [s.strip() for s in eng.scope.splitlines() if s.strip()]
        in_scope = _target_in_scope(body.target, scope_lines)
        if not in_scope:
            scope_warning = (
                f'WARNING: Target "{body.target}" does not match any declared '
                f'scope entry for this engagement. '
                f'Proceed only if this is intentional.'
            )

    clean   = re.sub(r'[^\w.-]', '_', body.target)[:60]
    ts      = datetime.now().strftime('%Y%m%d_%H%M%S')
    folder  = f'{body.scan_type}_{clean}_{ts}'
    scan_id = os.urandom(8).hex()

    options = {
        'auth_header':    body.auth_header,
        'proxy':          body.proxy,
        'enable_katana':  body.enable_katana,
        'enable_sqlmap':  body.enable_sqlmap,
        'enable_stealth': body.enable_stealth,
    }
    # git_token is intentionally excluded from `options` so it is never
    # written to the DB. It is passed directly to the Celery task, where
    # it lives only in the worker's memory for the duration of the clone,
    # and in the Redis result backend until result_expires (24h). For higher
    # sensitivity, consider a short-lived secrets store (Vault, AWS SSM).
    task_options = {**options, 'git_token': body.git_token or ''}

    scan = Scan(
        scan_id=scan_id, engagement_id=eng_id,
        scan_type=body.scan_type, target=body.target,
        folder_name=folder, status='Queued',
        options=options, created_by=current_user.id,
    )
    db.add(scan)
    await db.flush()

    task_fn = TASK_MAP.get(body.scan_type)
    if task_fn:
        task = task_fn.delay(scan_id, body.target, folder, task_options)
        scan.celery_task_id = task.id

    add_audit_log(db, action='scan.started',
                  user_id=current_user.id, username=current_user.username,
                  target_type='scan', target_id=scan.id, target_name=body.target,
                  detail={'scan_type': body.scan_type, 'scan_id': scan_id},
                  ip_address=get_client_ip(request))
    out = ScanOut.model_validate(scan)
    if scope_warning:
        # model_dump(mode='json') converts datetime fields to ISO strings
        return JSONResponse(
            status_code=201,
            content={**out.model_dump(mode='json'), 'scope_warning': scope_warning},
        )
    return out


# ── Scheduled scans ───────────────────────────────────────────────────────────
# Recurring dispatch happens in tasks.py::run_scheduled_scans, a periodic
# Celery Beat task (see celery.conf.beat_schedule there) — these endpoints
# only manage the ScheduledScan config rows.

@router.get('/{eng_id}/scheduled-scans', response_model=list[ScheduledScanOut])
async def list_scheduled_scans(
    eng_id:       int,
    current_user: AnalystUser,
    db:           AsyncSession = Depends(get_db),
):
    eng = await _get_engagement_or_403(eng_id, current_user, db)
    rows = (await db.execute(
        select(ScheduledScan).where(ScheduledScan.engagement_id == eng.id)
        .order_by(ScheduledScan.created_at.desc())
    )).scalars().all()
    return [ScheduledScanOut.from_orm_obj(r) for r in rows]


@router.post('/{eng_id}/scheduled-scans', response_model=ScheduledScanOut,
            status_code=status.HTTP_201_CREATED)
async def create_scheduled_scan(
    eng_id:       int,
    body:         ScheduledScanCreate,
    request:      Request,
    current_user: AnalystUser,
    db:           AsyncSession = Depends(get_db),
):
    """
    Create a recurring scan. Target/scan_type validation (SSRF blocklist,
    per-type format) is inherited from ScanCreate and runs once here — the
    periodic dispatch task trusts an already-validated target on every
    future run, same as a one-off scan isn't re-validated at execution time.

    The scope-mismatch check is advisory here too, same as start_scan, but
    only surfaced at creation — nobody's watching a 3am scheduled run to see
    a warning, so it wouldn't help there, only at setup time.
    """
    eng = await _get_engagement_or_403(eng_id, current_user, db)

    scope_warning: str | None = None
    if eng.scope:
        scope_lines = [s.strip() for s in eng.scope.splitlines() if s.strip()]
        if not _target_in_scope(body.target, scope_lines):
            scope_warning = (
                f'WARNING: Target "{body.target}" does not match any declared '
                f'scope entry for this engagement. Proceed only if this is intentional.'
            )

    now = datetime.now(timezone.utc)
    next_run = now if body.run_immediately else now + timedelta(hours=body.interval_hours)

    sched = ScheduledScan(
        engagement_id=eng_id, scan_type=body.scan_type, target=body.target,
        interval_hours=body.interval_hours, enabled=True,
        options={
            'auth_header':    body.auth_header,
            'proxy':          body.proxy,
            'enable_katana':  body.enable_katana,
            'enable_sqlmap':  body.enable_sqlmap,
            'enable_stealth': body.enable_stealth,
        },
        git_token_encrypted=encrypt_secret(body.git_token) if body.git_token else None,
        next_run_at=next_run, created_by=current_user.id,
    )
    db.add(sched)
    await db.flush()

    add_audit_log(db, action='scheduled_scan.created',
                  user_id=current_user.id, username=current_user.username,
                  target_type='scheduled_scan', target_id=sched.id, target_name=body.target,
                  detail={'scan_type': body.scan_type, 'interval_hours': body.interval_hours},
                  ip_address=get_client_ip(request))

    out = ScheduledScanOut.from_orm_obj(sched)
    if scope_warning:
        return JSONResponse(
            status_code=201,
            content={**out.model_dump(mode='json'), 'scope_warning': scope_warning},
        )
    return out


@router.patch('/{eng_id}/scheduled-scans/{sched_id}', response_model=ScheduledScanOut)
async def update_scheduled_scan(
    eng_id:       int,
    sched_id:     int,
    body:         ScheduledScanUpdate,
    request:      Request,
    current_user: AnalystUser,
    db:           AsyncSession = Depends(get_db),
):
    """Pause/resume (enabled) or change the interval. Target/scan_type are
    immutable here — see ScheduledScanUpdate's docstring for why."""
    eng = await _get_engagement_or_403(eng_id, current_user, db)
    sched = (await db.execute(
        select(ScheduledScan).where(ScheduledScan.id == sched_id,
                                    ScheduledScan.engagement_id == eng.id)
    )).scalar_one_or_none()
    if not sched:
        raise HTTPException(status_code=404, detail='Scheduled scan not found')

    changed: dict = {}
    if body.enabled is not None:
        changed['enabled'] = body.enabled
    if body.interval_hours is not None:
        changed['interval_hours'] = body.interval_hours
        # Re-anchor next_run_at to the new interval from now, rather than
        # leaving a next_run_at computed under the old interval — changing
        # "every 24h" to "every 1h" should take effect soon, not after
        # whatever was left of the old 24h window.
        changed['next_run_at'] = datetime.now(timezone.utc) + timedelta(hours=body.interval_hours)

    if not changed:
        return ScheduledScanOut.from_orm_obj(sched)

    for field, value in changed.items():
        setattr(sched, field, value)

    add_audit_log(db, action='scheduled_scan.updated',
                  user_id=current_user.id, username=current_user.username,
                  target_type='scheduled_scan', target_id=sched.id, target_name=sched.target,
                  detail={k: v for k, v in changed.items() if k != 'next_run_at'},
                  ip_address=get_client_ip(request))

    await db.flush()
    return ScheduledScanOut.from_orm_obj(sched)


@router.delete('/{eng_id}/scheduled-scans/{sched_id}', status_code=status.HTTP_204_NO_CONTENT)
async def delete_scheduled_scan(
    eng_id:       int,
    sched_id:     int,
    request:      Request,
    current_user: AnalystUser,
    db:           AsyncSession = Depends(get_db),
):
    eng = await _get_engagement_or_403(eng_id, current_user, db)
    sched = (await db.execute(
        select(ScheduledScan).where(ScheduledScan.id == sched_id,
                                    ScheduledScan.engagement_id == eng.id)
    )).scalar_one_or_none()
    if not sched:
        raise HTTPException(status_code=404, detail='Scheduled scan not found')

    add_audit_log(db, action='scheduled_scan.deleted',
                  user_id=current_user.id, username=current_user.username,
                  target_type='scheduled_scan', target_id=sched.id, target_name=sched.target,
                  ip_address=get_client_ip(request))
    await db.delete(sched)


# ── Engagement members ────────────────────────────────────────────────────────
# Additional users granted access to this engagement beyond its creator.
# See models.py::EngagementMember and _require_owner_or_admin above for the
# access-control design.

@router.get('/{eng_id}/members', response_model=list[EngagementMemberOut])
async def list_engagement_members(
    eng_id:       int,
    current_user: CurrentUser,
    db:           AsyncSession = Depends(get_db),
):
    """Any member/owner/admin can see who else has access — visibility into
    who can see an engagement is not itself sensitive the way granting
    access is (that's gated separately, see add/remove below)."""
    eng = await _get_engagement_or_403(eng_id, current_user, db)
    rows = (await db.execute(
        select(EngagementMember, User.username, User.role)
        .join(User, User.id == EngagementMember.user_id)
        .where(EngagementMember.engagement_id == eng.id)
        .order_by(EngagementMember.created_at)
    )).all()
    return [
        EngagementMemberOut(id=m.id, user_id=m.user_id, username=username,
                            role=role, added_at=m.created_at)
        for m, username, role in rows
    ]


@router.post('/{eng_id}/members', response_model=EngagementMemberOut,
            status_code=status.HTTP_201_CREATED)
async def add_engagement_member(
    eng_id:       int,
    body:         EngagementMemberCreate,
    request:      Request,
    current_user: AnalystUser,
    db:           AsyncSession = Depends(get_db),
):
    eng = await _get_engagement_or_403(eng_id, current_user, db)
    _require_owner_or_admin(eng, current_user)

    user = (await db.execute(
        select(User).where(User.username == body.username)
    )).scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail='User not found')
    if user.id == eng.created_by:
        raise HTTPException(status_code=400,
                            detail='This user already owns the engagement')

    existing = (await db.execute(
        select(EngagementMember).where(
            EngagementMember.engagement_id == eng.id,
            EngagementMember.user_id == user.id,
        )
    )).scalar_one_or_none()
    if existing:
        raise HTTPException(status_code=409, detail='User is already a member')

    member = EngagementMember(engagement_id=eng.id, user_id=user.id,
                              added_by=current_user.id)
    db.add(member)
    await db.flush()

    add_audit_log(db, action='engagement.member_added',
                  user_id=current_user.id, username=current_user.username,
                  target_type='engagement', target_id=eng.id, target_name=eng.name,
                  detail={'added_username': user.username}, ip_address=get_client_ip(request))

    return EngagementMemberOut(id=member.id, user_id=user.id, username=user.username,
                               role=user.role, added_at=member.created_at)


@router.delete('/{eng_id}/members/{user_id}', status_code=status.HTTP_204_NO_CONTENT)
async def remove_engagement_member(
    eng_id:       int,
    user_id:      int,
    request:      Request,
    current_user: AnalystUser,
    db:           AsyncSession = Depends(get_db),
):
    eng = await _get_engagement_or_403(eng_id, current_user, db)
    _require_owner_or_admin(eng, current_user)

    member = (await db.execute(
        select(EngagementMember).where(
            EngagementMember.engagement_id == eng.id,
            EngagementMember.user_id == user_id,
        )
    )).scalar_one_or_none()
    if not member:
        raise HTTPException(status_code=404, detail='Member not found')

    removed_user = (await db.execute(
        select(User.username).where(User.id == user_id)
    )).scalar_one_or_none()

    add_audit_log(db, action='engagement.member_removed',
                  user_id=current_user.id, username=current_user.username,
                  target_type='engagement', target_id=eng.id, target_name=eng.name,
                  detail={'removed_username': removed_user}, ip_address=get_client_ip(request))
    await db.delete(member)


# ── Report ────────────────────────────────────────────────────────────────────

@router.get('/{eng_id}/report')
async def export_report(
    eng_id:       int,
    current_user: AnalystUser,
    request:      Request,
    db:           AsyncSession = Depends(get_db),
):
    from report import render_engagement_report_async
    eng = await _get_engagement_or_403(eng_id, current_user, db)

    pdf_bytes = await render_engagement_report_async(eng, db)
    client    = eng.client_name.replace(' ', '_')
    name      = eng.name.replace(' ', '_')
    filename  = f'{client}_{name}_report.pdf'

    add_audit_log(db, action='report.exported',
                  user_id=current_user.id, username=current_user.username,
                  target_type='engagement', target_id=eng.id, target_name=eng.name,
                  ip_address=get_client_ip(request))
    return Response(
        content=pdf_bytes,
        media_type='application/pdf',
        headers={'Content-Disposition': f'attachment; filename="{filename}"'},
    )


# ── Update engagement ─────────────────────────────────────────────────────────

@router.patch('/{eng_id}', response_model=EngagementOut)
async def update_engagement(
    eng_id:       int,
    body:         EngagementUpdate,
    request:      Request,
    current_user: AnalystUser,
    db:           AsyncSession = Depends(get_db),
):
    """Partially update an engagement's name, client, description, or status."""
    eng = await _get_engagement_or_403(eng_id, current_user, db)

    changed: dict = {}
    if body.name               is not None: changed['name']               = body.name
    if body.client_name        is not None: changed['client_name']        = body.client_name
    if body.description        is not None: changed['description']        = body.description
    if body.status             is not None: changed['status']             = body.status
    if body.scope              is not None: changed['scope']              = body.scope or None
    # report_template_id needs to distinguish "field omitted" (leave as-is)
    # from "field explicitly sent as null" (clear override, fall back to the
    # global default template) — unlike scope/webhook_url there's no falsy
    # sentinel available on an int|None field, so this checks
    # model_fields_set instead of `is not None`.
    if 'report_template_id' in body.model_fields_set:
        changed['report_template_id'] = body.report_template_id
    if body.webhook_url        is not None: changed['webhook_url']        = body.webhook_url or None

    # Generate a signing secret the first time a webhook is configured.
    # Deliberately does not regenerate on every URL edit — swapping the URL
    # shouldn't silently invalidate a receiver's stored verification key;
    # use the explicit rotate endpoint for that. Clearing the URL leaves the
    # secret in place too, so re-adding a webhook later doesn't need every
    # downstream verifier reconfigured.
    if changed.get('webhook_url') and not eng.webhook_secret:
        changed['webhook_secret'] = _gen_webhook_secret()

    if not changed:
        return eng  # no-op — return current state

    for field, value in changed.items():
        setattr(eng, field, value)
    eng.updated_at = datetime.now(timezone.utc)

    # Redact the secret itself — `changed` is logged verbatim as audit detail
    # and audit logs are readable by any Admin; recording that a secret was
    # (re)generated is useful, the value itself is not something that
    # belongs in an audit trail.
    audit_detail = {**changed}
    if 'webhook_secret' in audit_detail:
        audit_detail['webhook_secret'] = '<generated>'

    add_audit_log(db, action='engagement.updated',
                  user_id=current_user.id, username=current_user.username,
                  target_type='engagement', target_id=eng.id, target_name=eng.name,
                  detail=audit_detail, ip_address=get_client_ip(request))
    return eng


# ── Webhook signing secret ───────────────────────────────────────────────────
# Kept off EngagementOut on purpose (see WebhookSecretOut docstring) — these
# are the only two places the plaintext secret is ever returned.

@router.get('/{eng_id}/webhook-secret', response_model=WebhookSecretOut)
async def get_webhook_secret(
    eng_id:       int,
    current_user: AnalystUser,
    db:           AsyncSession = Depends(get_db),
):
    """Reveal the current signing secret, e.g. to paste into a receiver's
    verification config. Same owner-or-admin rule as the rest of the engagement."""
    eng = await _get_engagement_or_403(eng_id, current_user, db)
    if not eng.webhook_secret:
        raise HTTPException(
            status_code=404,
            detail='No webhook secret — set a webhook_url first to generate one',
        )
    return WebhookSecretOut(webhook_secret=eng.webhook_secret)


@router.post('/{eng_id}/webhook-secret/rotate', response_model=WebhookSecretOut)
async def rotate_webhook_secret(
    eng_id:       int,
    request:      Request,
    current_user: AnalystUser,
    db:           AsyncSession = Depends(get_db),
):
    """
    Generate a new signing secret, invalidating the old one immediately.
    Use when a secret may have leaked, or as routine rotation hygiene.
    The receiver's stored verification key must be updated to match, or
    every subsequent delivery will fail signature verification on their end.
    """
    eng = await _get_engagement_or_403(eng_id, current_user, db)
    eng.webhook_secret = _gen_webhook_secret()
    eng.updated_at     = datetime.now(timezone.utc)
    add_audit_log(db, action='engagement.webhook_secret_rotated',
                  user_id=current_user.id, username=current_user.username,
                  target_type='engagement', target_id=eng.id, target_name=eng.name,
                  ip_address=get_client_ip(request))
    await db.flush()
    return WebhookSecretOut(webhook_secret=eng.webhook_secret)


# ── Webhook delivery history ─────────────────────────────────────────────────

@router.get('/{eng_id}/webhook-deliveries', response_model=list[WebhookDeliveryOut])
async def list_webhook_deliveries(
    eng_id:       int,
    current_user: AnalystUser,
    db:           AsyncSession = Depends(get_db),
):
    """
    Recent webhook delivery attempts — both real scan.completed dispatches
    and on-demand webhook.test pings — most recent first. Capped at
    MAX_DELIVERIES_PER_ENGAGEMENT rows (see models.py); this is diagnostic
    history for the Settings tab, not an audit trail.
    """
    eng = await _get_engagement_or_403(eng_id, current_user, db)
    rows = (await db.execute(
        select(WebhookDelivery)
        .where(WebhookDelivery.engagement_id == eng.id)
        .order_by(WebhookDelivery.created_at.desc())
        .limit(MAX_DELIVERIES_PER_ENGAGEMENT)
    )).scalars().all()
    return rows


@router.post('/{eng_id}/webhook-test', response_model=WebhookDeliveryOut)
async def test_webhook(
    eng_id:       int,
    current_user: AnalystUser,
    db:           AsyncSession = Depends(get_db),
):
    """
    Send a one-off test payload to the configured webhook_url immediately,
    so whoever's setting this up can verify their receiver works without
    waiting for a real scan to finish. Recorded to webhook_deliveries like
    any other dispatch (event='webhook.test', scan_id=None), signed the
    same way via webhooks.sign_payload — see that module's docstring for
    why the signing logic is shared with tasks.py rather than reimplemented
    here.

    Uses httpx (async) rather than the `requests` library tasks.py uses —
    this runs in the FastAPI event loop, where a blocking call would stall
    other requests being served concurrently; tasks.py runs in a separate
    sync Celery worker process where that concern doesn't apply.
    """
    eng = await _get_engagement_or_403(eng_id, current_user, db)
    if not eng.webhook_url:
        raise HTTPException(status_code=400, detail='No webhook_url configured')

    payload = {
        'event':         'webhook.test',
        'engagement_id': eng.id,
        'message':       'This is a test delivery from MSTE — no scan was actually run.',
        'sent_at':       datetime.now(timezone.utc).isoformat(),
    }
    raw_body = serialize_payload(payload)
    headers  = {'Content-Type': 'application/json'}
    if eng.webhook_secret:
        headers.update(sign_payload(eng.webhook_secret, raw_body))

    success, status_code, error, response_snippet = False, None, None, None
    start = time.monotonic()
    try:
        async with httpx.AsyncClient(timeout=5, follow_redirects=False) as client:
            resp = await client.post(eng.webhook_url, content=raw_body, headers=headers)
        status_code      = resp.status_code
        success          = 200 <= resp.status_code < 300
        response_snippet = resp.text[:500] if resp.text else None
    except Exception as exc:
        error = str(exc)[:2000]
    duration_ms = int((time.monotonic() - start) * 1000)

    delivery = WebhookDelivery(
        engagement_id=eng.id, scan_id=None, event='webhook.test',
        url=eng.webhook_url, success=success, status_code=status_code,
        error=error, response_snippet=response_snippet, duration_ms=duration_ms,
    )
    db.add(delivery)

    # Same prune-on-insert policy as tasks.py::_dispatch_webhook.
    old_ids = (await db.execute(
        select(WebhookDelivery.id)
        .where(WebhookDelivery.engagement_id == eng.id)
        .order_by(WebhookDelivery.created_at.desc())
        .offset(MAX_DELIVERIES_PER_ENGAGEMENT)
    )).scalars().all()
    if old_ids:
        await db.execute(
            WebhookDelivery.__table__.delete().where(WebhookDelivery.id.in_(old_ids))
        )

    await db.flush()
    return delivery


# ── Delete engagement ─────────────────────────────────────────────────────────

@router.delete('/{eng_id}', status_code=status.HTTP_204_NO_CONTENT)
async def delete_engagement(
    eng_id:       int,
    request:      Request,
    current_user: AdminUser,
    db:           AsyncSession = Depends(get_db),
):
    """
    Permanently delete an engagement and all associated scans and findings.
    Admin only.  This operation is irreversible — consider archiving instead
    (PATCH status=Archived) for audit-trail preservation.
    """
    # Admin-only route, but we still use the helper to get a clean 404 vs 403
    eng = await _get_engagement_or_403(eng_id, current_user, db)

    add_audit_log(db, action='engagement.deleted',
                  user_id=current_user.id, username=current_user.username,
                  target_type='engagement', target_id=eng.id, target_name=eng.name,
                  ip_address=get_client_ip(request))

    await db.delete(eng)
    # cascade handles scans + findings via FK ON DELETE CASCADE in models


# ── Cancel scan ───────────────────────────────────────────────────────────────

def _container_suffix(folder_name: str) -> str:
    """Replicate scan.sh CNAME_SUFFIX: sha256(folder_name)[:12]."""
    return hashlib.sha256(folder_name.encode()).hexdigest()[:12]


_CANCELLABLE = frozenset({'Queued', 'Running'})
_WEB_TOOLS   = ('nuclei', 'ffuf', 'katana', 'sqlmap', 'testssl')
_INFRA_TOOLS = ('nmap',)
_SAST_TOOLS  = ('semgrep', 'trivy', 'gitleaks', 'hadolint')


@router.delete('/{eng_id}/scans/{scan_id}',
               status_code=status.HTTP_200_OK)
async def cancel_scan(
    eng_id:       int,
    scan_id:      str,
    request:      Request,
    current_user: AnalystUser,
    db:           AsyncSession = Depends(get_db),
):
    """
    Cancel a Queued or Running scan.

    Steps:
    1. Revoke the Celery task (SIGTERM → worker stops launching new sub-steps).
    2. Kill any Docker containers that scan.sh already started for this scan.
    3. Mark the scan as Cancelled in the DB.

    Containers are identified by the deterministic naming scheme used in
    scan.sh: mste_{tool}_{sha256(folder_name)[:12]}.
    """
    scan = (await db.execute(
        select(Scan).where(
            Scan.scan_id      == scan_id,
            Scan.engagement_id == eng_id,
        )
    )).scalar_one_or_none()

    if not scan:
        raise HTTPException(status_code=404, detail='Scan not found')

    if scan.status not in _CANCELLABLE:
        raise HTTPException(
            status_code=409,
            detail=f'Cannot cancel a scan with status "{scan.status}". '
                   f'Only Queued or Running scans can be cancelled.',
        )

    # ── 1. Revoke the Celery task ─────────────────────────────────────────────
    if scan.celery_task_id:
        try:
            celery.control.revoke(scan.celery_task_id, terminate=True, signal='SIGTERM')
        except Exception as exc:
            # Non-fatal — the task may have already finished or the broker
            # may be temporarily unreachable. Log and continue so the
            # containers still get killed and the DB state is updated.
            import logging
            logging.getLogger(__name__).warning(
                'revoke(%s) failed: %s', scan.celery_task_id, exc
            )

    # ── 2. Kill Docker containers ─────────────────────────────────────────────
    suffix = _container_suffix(scan.folder_name)
    tool_names: tuple[str, ...]
    if scan.scan_type == 'web':
        tool_names = _WEB_TOOLS
    elif scan.scan_type == 'infra':
        tool_names = _INFRA_TOOLS
    elif scan.scan_type == 'sast':
        tool_names = _SAST_TOOLS
    else:
        tool_names = ()

    killed: list[str] = []
    for tool in tool_names:
        cname = f'mste_{tool}_{suffix}'
        try:
            result = subprocess.run(
                ['docker', 'rm', '-f', cname],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode == 0:
                killed.append(cname)
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass  # docker not available in test env — skip silently

    # ── 3. Update DB status ───────────────────────────────────────────────────
    scan.status       = 'Cancelled'
    scan.completed_at = datetime.now(timezone.utc)

    add_audit_log(db, action='scan.cancelled',
                  user_id=current_user.id, username=current_user.username,
                  target_type='scan', target_id=scan.id, target_name=scan.target,
                  detail={'scan_id': scan_id, 'containers_killed': killed},
                  ip_address=get_client_ip(request))

    return {
        'scan_id':           scan_id,
        'status':            'Cancelled',
        'containers_killed': killed,
    }


# ── Finding delta (re-test diff) ──────────────────────────────────────────────

@router.get('/{eng_id}/delta', response_model=FindingDelta)
async def finding_delta(
    eng_id:          int,
    current_user:    CurrentUser,
    db:              AsyncSession = Depends(get_db),
    since_scan_id:   str | None = None,
):
    """
    Return a diff of findings between a baseline scan and the latest scan.

    If `since_scan_id` is provided it is used as the baseline; otherwise the
    second-most-recent completed scan is used (i.e. previous run vs latest).

    Bucketed by dedup_hash so findings are matched by content, not by DB id:

    - new       — dedup_hash present in latest but not in baseline (new risk)
    - recurring — dedup_hash in both baseline and latest (not fixed)
    - resolved  — dedup_hash in baseline but absent from latest (fixed / gone)
    """
    await _get_engagement_or_403(eng_id, current_user, db)

    # ── Fetch all completed scans for this engagement (oldest → newest) ───────
    scans = (await db.execute(
        select(Scan)
        .where(
            Scan.engagement_id == eng_id,
            Scan.status        == 'Completed',
        )
        .order_by(Scan.completed_at.asc())
    )).scalars().all()

    if len(scans) < 2 and since_scan_id is None:
        raise HTTPException(
            status_code=409,
            detail='At least two completed scans are required to compute a delta. '
                   'Run a re-test scan first, or supply since_scan_id explicitly.',
        )

    # ── Resolve baseline and current scans ────────────────────────────────────
    current_scan = scans[-1]

    if since_scan_id:
        baseline_scan = next(
            (s for s in scans if s.scan_id == since_scan_id), None
        )
        if not baseline_scan:
            raise HTTPException(
                status_code=404,
                detail=f'Baseline scan "{since_scan_id}" not found or not completed.',
            )
        if baseline_scan.id == current_scan.id:
            raise HTTPException(
                status_code=409,
                detail='Baseline and current scan are the same. '
                       'Provide the scan_id of an earlier scan.',
            )
    else:
        baseline_scan = scans[-2]

    # ── Fetch findings for both scans in two queries ──────────────────────────
    async def _findings_by_scan(scan_db_id: int) -> list[Finding]:
        rows = (await db.execute(
            select(Finding).where(Finding.scan_id_fk == scan_db_id)
        )).scalars().all()
        return rows

    baseline_findings = await _findings_by_scan(baseline_scan.id)
    current_findings  = await _findings_by_scan(current_scan.id)

    # Build hash → Finding maps (most recent occurrence wins for recurring)
    baseline_hashes: dict[str, Finding] = {
        f.dedup_hash: f for f in baseline_findings if f.dedup_hash
    }
    current_hashes: dict[str, Finding] = {
        f.dedup_hash: f for f in current_findings if f.dedup_hash
    }

    new_findings       = [f for h, f in current_hashes.items() if h not in baseline_hashes]
    recurring_findings = [f for h, f in current_hashes.items() if h in baseline_hashes]
    resolved_findings  = [f for h, f in baseline_hashes.items() if h not in current_hashes]

    # Sort each bucket by severity (Critical first) then CVSS descending
    _sev_order = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3, 'Info': 4}

    def _sort_key(f: Finding) -> tuple:
        return (_sev_order.get(f.severity, 9), -(f.cvss_score or 0))

    new_findings.sort(key=_sort_key)
    recurring_findings.sort(key=_sort_key)
    resolved_findings.sort(key=_sort_key)

    return FindingDelta(
        baseline_scan_id = baseline_scan.scan_id,
        current_scan_id  = current_scan.scan_id,
        new              = [FindingOut.model_validate(f) for f in new_findings],
        recurring        = [FindingOut.model_validate(f) for f in recurring_findings],
        resolved         = [FindingOut.model_validate(f) for f in resolved_findings],
        new_count        = len(new_findings),
        recurring_count  = len(recurring_findings),
        resolved_count   = len(resolved_findings),
    )
