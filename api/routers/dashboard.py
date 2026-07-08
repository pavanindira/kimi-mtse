"""dashboard.py router — /api/dashboard/*"""

from collections import defaultdict
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from auth import CurrentUser
from database import get_db
from models import Engagement, Finding, Scan
from schemas import (DashboardTrends, FindingsTrendPoint, ScansTrendPoint,
                     SeveritySummary)
from utils import accessible_engagement_filter

router = APIRouter(prefix='/api/dashboard', tags=['dashboard'])

# Findings in either of these statuses are treated as "resolved" for the
# avg_days_to_resolve approximation — see DashboardTrends' docstring for
# why this is an approximation rather than a precise measurement.
_TERMINAL_STATUSES = ('Fixed', 'False Positive')

_SEVERITIES = ('Critical', 'High', 'Medium', 'Low', 'Info')


def _week_start(dt: datetime) -> str:
    """Monday of dt's week, as an ISO date string — the trend bucket key."""
    monday = dt.date() - timedelta(days=dt.weekday())
    return monday.isoformat()


@router.get('/trends', response_model=DashboardTrends)
async def get_dashboard_trends(
    current_user: CurrentUser,
    db:           AsyncSession = Depends(get_db),
    days:         int = 90,
):
    """
    Time-series data for the dashboard: findings discovered per week (by
    severity), scans run per week (completed/failed), the current
    open-severity snapshot, and an approximate average time-to-resolve.

    Scoped to engagements current_user can access, same as everywhere else
    (see utils.py::accessible_engagement_filter).

    Bucketing is done in Python, not SQL (no date_trunc/strftime in the
    query) — this needs to behave identically against SQLite (used by the
    test suite) and Postgres (production), and date-truncation functions
    aren't portable between the two. Fine at the volumes a single
    deployment's findings/scans reach over a 90-365 day window; if that
    changes, move to a materialized rollup table rather than widening this
    per-request query further.
    """
    days  = max(7, min(days, 365))
    since = datetime.now(timezone.utc) - timedelta(days=days)
    eng_filter = accessible_engagement_filter(current_user)

    # ── Findings discovered per week, by severity ────────────────────────────
    fq = (
        select(Finding.first_seen, Finding.severity)
        .join(Scan, Finding.scan_id_fk == Scan.id)
        .where(Finding.first_seen >= since)
    )
    if eng_filter is not None:
        fq = fq.join(Engagement, Scan.engagement_id == Engagement.id).where(eng_filter)
    finding_rows = (await db.execute(fq)).all()

    findings_buckets: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for first_seen, severity in finding_rows:
        if first_seen is None:
            continue
        findings_buckets[_week_start(first_seen)][severity] += 1

    findings_by_week = [
        FindingsTrendPoint(
            week_start=week,
            **{sev: counts.get(sev, 0) for sev in _SEVERITIES},
        )
        for week, counts in sorted(findings_buckets.items())
    ]

    # ── Scans run per week ────────────────────────────────────────────────────
    sq = select(Scan.created_at, Scan.status).where(Scan.created_at >= since)
    if eng_filter is not None:
        sq = sq.join(Engagement, Scan.engagement_id == Engagement.id).where(eng_filter)
    scan_rows = (await db.execute(sq)).all()

    scans_buckets: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for created_at, scan_status in scan_rows:
        if created_at is None:
            continue
        wk = _week_start(created_at)
        scans_buckets[wk]['total'] += 1
        if scan_status == 'Completed':
            scans_buckets[wk]['completed'] += 1
        elif scan_status == 'Failed':
            scans_buckets[wk]['failed'] += 1

    scans_by_week = [
        ScansTrendPoint(week_start=week, total=counts['total'],
                        completed=counts['completed'], failed=counts['failed'])
        for week, counts in sorted(scans_buckets.items())
    ]

    # ── Current open-severity snapshot (not time-bucketed — "as of now") ────
    snap_q = (
        select(Finding.severity, func.count(Finding.id))
        .join(Scan, Finding.scan_id_fk == Scan.id)
        .where(Finding.status.in_(['Open', 'Confirmed']))
        .group_by(Finding.severity)
    )
    if eng_filter is not None:
        snap_q = snap_q.join(Engagement, Scan.engagement_id == Engagement.id).where(eng_filter)
    snap_rows = (await db.execute(snap_q)).all()
    snap_d = {row[0]: row[1] for row in snap_rows}
    open_severity_snapshot = SeveritySummary(**{sev: snap_d.get(sev, 0) for sev in _SEVERITIES})

    # ── Approximate time-to-resolve ──────────────────────────────────────────
    res_q = (
        select(Finding.first_seen, Finding.last_seen)
        .join(Scan, Finding.scan_id_fk == Scan.id)
        .where(Finding.status.in_(_TERMINAL_STATUSES), Finding.last_seen >= since)
    )
    if eng_filter is not None:
        res_q = res_q.join(Engagement, Scan.engagement_id == Engagement.id).where(eng_filter)
    res_rows = (await db.execute(res_q)).all()

    durations = [
        (last_seen - first_seen).total_seconds() / 86400
        for first_seen, last_seen in res_rows
        if first_seen and last_seen and last_seen > first_seen
    ]
    avg_days_to_resolve = round(sum(durations) / len(durations), 1) if durations else None

    return DashboardTrends(
        days=days,
        findings_by_week=findings_by_week,
        scans_by_week=scans_by_week,
        open_severity_snapshot=open_severity_snapshot,
        resolved_count=len(durations),
        avg_days_to_resolve=avg_days_to_resolve,
    )
