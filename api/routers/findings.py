"""findings.py router — /api/findings/* and /api/scans/<id>/stream"""

import asyncio
import json
from datetime import datetime, timezone

import redis.asyncio as aioredis
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import StreamingResponse
from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from auth import AnalystUser, CurrentUser
from utils import add_audit_log, get_client_ip, user_has_engagement_access
from config import settings
from database import get_db, AsyncSessionLocal
from models import Engagement, EngagementMember, Finding, Scan
from schemas import (BulkStatusUpdate, EvidenceOut, FindingDetail, FindingOut,
                     FindingNotesUpdate, FindingStatusUpdate,
                     ManualFindingCreate, PaginatedFindings)
router = APIRouter(tags=['findings'])


async def _get_finding_scan_and_check_access(
    db: AsyncSession, finding: Finding, current_user,
) -> Scan | None:
    """
    Resolve a finding's parent Scan (if any) and verify current_user has
    access to the engagement it belongs to. Raises 403 if not.

    Shared by every per-finding endpoint below — get_finding, update_finding,
    update_finding_notes, and the finding_ids collected in
    bulk_update_findings all need the identical check, and before this
    helper existed several of them didn't have it at all (see
    utils.py::user_has_engagement_access's docstring for the history).

    Returns None (rather than raising) for a finding with no scan_id_fk
    (manually-created findings may lack one) — callers that need the scan
    for other reasons should check for that themselves; callers that only
    care about access can treat None as "nothing to check against" and rely
    on Admin-only manual-finding creation paths elsewhere already being
    gated correctly.
    """
    if not finding.scan_id_fk:
        return None
    scan = (await db.execute(
        select(Scan).where(Scan.id == finding.scan_id_fk)
    )).scalar_one_or_none()
    if scan and not await user_has_engagement_access(db, scan.engagement_id, current_user):
        raise HTTPException(status_code=403,
                            detail='You do not have access to this finding')
    return scan


# ── List findings ─────────────────────────────────────────────────────────────

@router.get('/api/findings', response_model=PaginatedFindings)
async def list_findings(
    current_user:  CurrentUser,
    db:            AsyncSession = Depends(get_db),
    severity:      str | None = None,
    status:        str | None = None,
    tool:          str | None = None,
    scan_id:       str | None = None,
    engagement_id: int | None = None,
    limit:         int = 200,
    offset:        int = 0,
):
    """
    Return a paginated list of findings with total count.

    Response shape:
        { total, items, limit, offset, pages }

    All filters are applied to both the COUNT and the item query so the
    frontend can render accurate page controls without a second request.
    """
    clamped_limit = min(max(limit, 1), 500)

    # ── Build base filter query ───────────────────────────────────────────────
    # Always join through Scan so ownership scoping can be applied uniformly.
    def _base_q():
        q = select(Finding).join(Scan, Finding.scan_id_fk == Scan.id)
        if current_user.role != 'Admin':
            member_eng_ids = select(EngagementMember.engagement_id).where(
                EngagementMember.user_id == current_user.id
            )
            q = q.join(Engagement, Scan.engagement_id == Engagement.id).where(
                (Engagement.created_by == current_user.id) |
                (Engagement.id.in_(member_eng_ids))
            )
        if severity:      q = q.where(Finding.severity    == severity)
        if status:        q = q.where(Finding.status      == status)
        if tool:          q = q.where(Finding.tool        == tool)
        if engagement_id: q = q.where(Scan.engagement_id  == engagement_id)
        return q

    # Resolve scan_id string → PK once, shared by both queries
    scan_pk: int | None = None
    if scan_id:
        row = (await db.execute(
            select(Scan.id).where(Scan.scan_id == scan_id)
        )).scalar_one_or_none()
        scan_pk = row

    # ── COUNT query (same filters, no limit/offset) ───────────────────────────
    count_q = select(func.count()).select_from(_base_q().subquery())
    if scan_pk:
        count_q = select(func.count()).select_from(
            _base_q().where(Finding.scan_id_fk == scan_pk).subquery()
        )
    total = (await db.execute(count_q)).scalar_one()

    # ── Items query ───────────────────────────────────────────────────────────
    items_q = _base_q()
    if scan_pk:
        items_q = items_q.where(Finding.scan_id_fk == scan_pk)
    items_q = (
        items_q
        .order_by(Finding.cvss_score.desc().nulls_last(), Finding.last_seen.desc())
        .limit(clamped_limit)
        .offset(offset)
    )
    items = (await db.execute(items_q)).scalars().all()

    pages = max(1, -(-total // clamped_limit))  # ceiling division

    return PaginatedFindings(
        total=total,
        items=items,
        limit=clamped_limit,
        offset=offset,
        pages=pages,
    )


# ── Get finding detail ────────────────────────────────────────────────────────

@router.get('/api/findings/{finding_id}', response_model=FindingDetail)
async def get_finding(
    finding_id:   int,
    current_user: CurrentUser,
    db:           AsyncSession = Depends(get_db),
):
    from sqlalchemy.orm import selectinload
    from models import Evidence

    result = await db.execute(
        select(Finding)
        .where(Finding.id == finding_id)
        .options(selectinload(Finding.evidence))
    )
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail='Finding not found')

    scan = await _get_finding_scan_and_check_access(db, finding, current_user)

    # Build the base finding fields from FindingOut first,
    # then extend with evidence and scan context.
    # We can't use FindingDetail.model_validate directly because the
    # SQLAlchemy ClassVar `evidence` relationship isn't a mapped column —
    # Pydantic sees it as None when auto-validating from the ORM object.
    base   = FindingOut.model_validate(finding)
    raw_ev = list(finding.evidence) if finding.evidence else []

    out = FindingDetail(
        **base.model_dump(),
        evidence=[EvidenceOut.model_validate(ev) for ev in raw_ev],
    )

    if scan:
        out.scan_id       = scan.scan_id
        out.engagement_id = scan.engagement_id

    return out


# ── Update finding status ─────────────────────────────────────────────────────

@router.patch('/api/findings/{finding_id}', response_model=FindingOut)
async def update_finding(
    finding_id:   int,
    body:         FindingStatusUpdate,
    current_user: AnalystUser,
    request:      Request,
    db:           AsyncSession = Depends(get_db),
):
    """Update a finding's status and/or analyst notes."""
    result = await db.execute(
        select(Finding).where(Finding.id == finding_id)
    )
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail='Finding not found')
    await _get_finding_scan_and_check_access(db, finding, current_user)

    old_status     = finding.status
    finding.status = body.status
    if body.notes is not None:
        finding.analyst_notes = body.notes
    finding.last_seen = datetime.now(timezone.utc)

    add_audit_log(db, action='finding.status_changed',
                  user_id=current_user.id, username=current_user.username,
                  target_type='finding', target_id=finding.id,
                  target_name=finding.vulnerability_name,
                  detail={'old': old_status, 'new': body.status},
                  ip_address=get_client_ip(request))
    return finding


@router.patch('/api/findings/{finding_id}/notes', response_model=FindingOut)
async def update_finding_notes(
    finding_id:   int,
    body:         FindingNotesUpdate,
    current_user: AnalystUser,
    request:      Request,
    db:           AsyncSession = Depends(get_db),
):
    """
    Update analyst notes on a finding without changing its status.

    Notes support markdown. Use for confirming exploitability, recording
    false-positive rationale, or linking remediation tickets.
    """
    result = await db.execute(
        select(Finding).where(Finding.id == finding_id)
    )
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail='Finding not found')
    await _get_finding_scan_and_check_access(db, finding, current_user)

    finding.analyst_notes = body.notes
    finding.last_seen     = datetime.now(timezone.utc)

    add_audit_log(db, action='finding.notes_updated',
                  user_id=current_user.id, username=current_user.username,
                  target_type='finding', target_id=finding.id,
                  target_name=finding.vulnerability_name,
                  ip_address=get_client_ip(request))
    return finding


@router.post('/api/scans/{scan_id}/findings',
             response_model=FindingOut,
             status_code=201)
async def create_manual_finding(
    scan_id:      str,
    body:         ManualFindingCreate,
    current_user: AnalystUser,
    request:      Request,
    db:           AsyncSession = Depends(get_db),
):
    """
    Create a manual finding for a scan.

    Used when a pentester discovers a vulnerability that automated tools
    missed — business logic flaws, chained exploits, multi-step attacks, etc.
    Manual findings are marked tool='Manual', start with status='Confirmed',
    and appear in all reports, delta views, and filtered lists.
    """
    import hashlib
    scan = (await db.execute(
        select(Scan).where(Scan.scan_id == scan_id)
    )).scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail='Scan not found')
    if not await user_has_engagement_access(db, scan.engagement_id, current_user):
        raise HTTPException(status_code=403,
                            detail='You do not have access to this scan')

    dedup_hash = hashlib.sha256(
        f"Manual:{body.vulnerability_name}:{body.location or ''}".encode()
    ).hexdigest()

    finding = Finding(
        scan_id_fk         = scan.id,
        tool               = 'Manual',
        vulnerability_name = body.vulnerability_name,
        severity           = body.severity,
        status             = 'Confirmed',
        cvss_score         = body.cvss_score,
        cve_id             = body.cve_id,
        cwe_id             = body.cwe_id,
        target_url         = body.target_url,
        host               = body.host,
        port               = body.port,
        file_path          = body.file_path,
        line_number        = body.line_number,
        description        = body.description,
        remediation        = body.remediation,
        analyst_notes      = body.analyst_notes,
        dedup_hash         = dedup_hash,
        first_seen         = datetime.now(timezone.utc),
        last_seen          = datetime.now(timezone.utc),
    )
    db.add(finding)
    await db.flush()

    add_audit_log(db, action='finding.created_manual',
                  user_id=current_user.id, username=current_user.username,
                  target_type='finding', target_id=finding.id,
                  target_name=finding.vulnerability_name,
                  detail={'scan_id': scan_id, 'severity': body.severity},
                  ip_address=get_client_ip(request))
    return finding


# ── Bulk status updateate ────────────────────────────────────────────────────────

@router.post('/api/findings/bulk-status')
async def bulk_update_findings(
    body:         BulkStatusUpdate,
    current_user: AnalystUser,
    request:      Request,
    db:           AsyncSession = Depends(get_db),
):
    """
    Previously updated by raw `Finding.id IN (...)` with no ownership check
    at all — any Analyst could mass-update any finding across the entire
    deployment by passing arbitrary IDs, regardless of which engagement it
    belonged to. Now scoped to findings whose scan's engagement the caller
    owns, is a member of, or (for Admin) unconditionally. `updated` in the
    response reflects rows actually matched, not len(finding_ids) — a
    request naming some inaccessible IDs now silently updates only the
    accessible subset rather than either updating everything or failing
    the whole batch.
    """
    vals: dict = {'status': body.status, 'last_seen': datetime.now(timezone.utc)}
    if body.notes:
        vals['analyst_notes'] = body.notes

    q = update(Finding).where(Finding.id.in_(body.finding_ids))
    if current_user.role != 'Admin':
        member_eng_ids = select(EngagementMember.engagement_id).where(
            EngagementMember.user_id == current_user.id
        )
        accessible_scan_ids = (
            select(Scan.id)
            .join(Engagement, Scan.engagement_id == Engagement.id)
            .where(
                (Engagement.created_by == current_user.id) |
                (Engagement.id.in_(member_eng_ids))
            )
        )
        q = q.where(Finding.scan_id_fk.in_(accessible_scan_ids))
    q = q.values(**vals)

    result = await db.execute(q)
    updated_count = result.rowcount

    add_audit_log(db, action='finding.bulk_status_changed',
                  user_id=current_user.id, username=current_user.username,
                  detail={'ids': body.finding_ids, 'new_status': body.status,
                          'count': updated_count, 'notes': body.notes or None},
                  ip_address=get_client_ip(request))
    return {'success': True, 'updated': updated_count,
            'status': body.status}


# ── Scan status ───────────────────────────────────────────────────────────────

@router.get('/api/scans/{scan_id}/status')
async def scan_status(
    scan_id:      str,
    current_user: CurrentUser,
    db:           AsyncSession = Depends(get_db),
):
    scan = (await db.execute(
        select(Scan).where(Scan.scan_id == scan_id)
    )).scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail='Scan not found')
    if not await user_has_engagement_access(db, scan.engagement_id, current_user):
        raise HTTPException(status_code=403,
                            detail='You do not have access to this scan')

    count = (await db.execute(
        select(func.count(Finding.id)).where(Finding.scan_id_fk == scan.id)
    )).scalar_one()
    return {
        'scan_id':  scan_id,
        'status':   scan.status,
        'findings': count,
    }


# ── SSE progress stream ───────────────────────────────────────────────────────

# Terminal scan statuses — when any of these are published on the status
# channel the SSE generator closes the stream.
_TERMINAL_STATUSES = frozenset({'Completed', 'Failed', 'Cancelled'})

# Maximum time (seconds) the SSE stream runs without receiving any message
# before sending a heartbeat.  Also acts as a safety net: if the status
# notification is lost the stream re-checks the DB on every heartbeat.
_HEARTBEAT_INTERVAL = 15.0

# Hard ceiling on stream duration to prevent leaked connections from scans
# stuck in Running state without ever publishing a status update.
_STREAM_MAX_SECONDS = 7200  # 2 hours


@router.get('/api/scans/{scan_id}/stream')
async def scan_stream(
    scan_id:      str,
    current_user: CurrentUser,
    db:           AsyncSession = Depends(get_db),
):
    """
    Server-Sent Events stream for real-time scan progress.

    Architecture after this change
    ──────────────────────────────
    Before: the SSE loop opened a new DB session every 15 seconds to poll
            scan.status — with 10 concurrent streams that was ~40 idle DB
            sessions cycling constantly.

    After:  _update_scan_status() publishes the new status to a dedicated
            Redis channel (scan:{id}:status) immediately after the DB commit.
            The SSE generator subscribes to both:
              • scan:{id}:progress  — log lines from the worker
              • scan:{id}:status    — terminal status signal from the worker

            DB is only consulted twice per stream lifetime:
              1. Initial existence + already-done check (before subscribing).
              2. Safety-net DB re-check on each heartbeat (handles the rare
                 case where the Redis publish was dropped).

    Protocol
    ────────
        data: <JSON ProgressEvent>   — log line from the worker
        event: status                — non-terminal status change
        event: end / data: <status>  — scan completed / failed / cancelled
        : heartbeat                  — keepalive, fires if no message for 15s
    """
    scan = (await db.execute(
        select(Scan).where(Scan.scan_id == scan_id)
    )).scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail='Scan not found')
    if not await user_has_engagement_access(db, scan.engagement_id, current_user):
        raise HTTPException(status_code=403,
                            detail='You do not have access to this scan')

    async def event_generator():
        redis  = aioredis.from_url(settings.redis_url, decode_responses=True)
        pubsub = redis.pubsub()
        loop   = asyncio.get_event_loop()
        deadline = loop.time() + _STREAM_MAX_SECONDS

        try:
            # ── 1. Replay buffered log for late subscribers / page refresh ────
            buffered = await redis.lrange(f'scan:{scan_id}:log', 0, -1)
            for item in buffered:
                yield f'data: {item}\n\n'

            # ── 2. Early-exit if scan already finished ────────────────────────
            async with AsyncSessionLocal() as check_db:
                current = (await check_db.execute(
                    select(Scan).where(Scan.scan_id == scan_id)
                )).scalar_one_or_none()
            if current and current.status in _TERMINAL_STATUSES:
                yield f'event: end\ndata: {current.status}\n\n'
                return

            # ── 3. Subscribe to both channels in one pubsub connection ────────
            # progress channel: log lines published by publish_progress()
            # status channel:   terminal signals published by _update_scan_status()
            await pubsub.subscribe(
                f'scan:{scan_id}:progress',
                f'scan:{scan_id}:status',
            )

            # ── 4. Event loop — DB only touched on heartbeat safety-net ───────
            while True:
                if loop.time() > deadline:
                    yield f'event: end\ndata: Timeout\n\n'
                    break

                try:
                    message = await asyncio.wait_for(
                        pubsub.get_message(ignore_subscribe_messages=True),
                        timeout=_HEARTBEAT_INTERVAL,
                    )
                except asyncio.TimeoutError:
                    message = None

                if message and message.get('type') == 'message':
                    channel = message.get('channel', '')
                    data    = message['data']

                    if channel.endswith(':status'):
                        # Worker published a status change
                        if data in _TERMINAL_STATUSES:
                            yield f'event: end\ndata: {data}\n\n'
                            break
                        else:
                            # Non-terminal status update (e.g. Queued→Running)
                            yield f'event: status\ndata: {data}\n\n'
                    else:
                        # Progress log line
                        yield f'data: {data}\n\n'

                else:
                    # Heartbeat — also acts as safety-net for lost publishes
                    yield ': heartbeat\n\n'

                    # Rare fallback: only DB query inside the hot loop.
                    # Fires at most once per _HEARTBEAT_INTERVAL (15s).
                    async with AsyncSessionLocal() as poll_db:
                        updated = (await poll_db.execute(
                            select(Scan).where(Scan.scan_id == scan_id)
                        )).scalar_one_or_none()
                    if updated and updated.status in _TERMINAL_STATUSES:
                        yield f'event: end\ndata: {updated.status}\n\n'
                        break

        finally:
            try:
                await pubsub.unsubscribe()
                await pubsub.aclose()
                await redis.aclose()
            except Exception:
                pass

    return StreamingResponse(
        event_generator(),
        media_type='text/event-stream',
        headers={
            'X-Accel-Buffering': 'no',
            'Cache-Control':     'no-cache',
            'Connection':        'keep-alive',
        },
    )
