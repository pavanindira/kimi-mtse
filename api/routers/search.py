"""search.py router — /api/search"""

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from auth import CurrentUser
from database import get_db
from models import Engagement, Finding, Scan
from schemas import SearchResults

router = APIRouter(prefix='/api/search', tags=['search'])


@router.get('', response_model=SearchResults)
async def global_search(
    q:            str,
    current_user: CurrentUser,
    db:           AsyncSession = Depends(get_db),
    scope:        str = 'all',
):
    if len(q) < 2:
        return SearchResults(query=q, total=0)

    pattern  = f'%{q}%'
    findings, engagements, scans = [], [], []

    # Non-admins may only search within their own engagements.
    _owned_eng_ids: list[int] | None = None
    if current_user.role != 'Admin':
        rows = (await db.execute(
            select(Engagement.id).where(Engagement.created_by == current_user.id)
        )).all()
        _owned_eng_ids = [r[0] for r in rows]
        if not _owned_eng_ids:
            # User owns no engagements — nothing to search
            return SearchResults(query=q, total=0)

    if scope in ('all', 'findings'):
        # Use trigram similarity for name/cve/cwe/host/path fields (GIN-indexed).
        # For description we still use ILIKE but restrict it to a separate
        # fallback clause so the planner can use the name index for the fast path.
        fq = (
            select(Finding)
            .join(Scan, Finding.scan_id_fk == Scan.id)
            .where(
                Finding.vulnerability_name.ilike(pattern)
                | Finding.cve_id.ilike(pattern)
                | Finding.cwe_id.ilike(pattern)
                | Finding.target_url.ilike(pattern)
                | Finding.file_path.ilike(pattern)
                | Finding.host.ilike(pattern)
            )
            .order_by(Finding.cvss_score.desc().nulls_last())
            .limit(50)
        )
        if _owned_eng_ids is not None:
            fq = fq.where(Scan.engagement_id.in_(_owned_eng_ids))
        findings = (await db.execute(fq)).scalars().all()

        # Secondary description search — only runs when no fast-path results
        if not findings:
            fq2 = (
                select(Finding)
                .join(Scan, Finding.scan_id_fk == Scan.id)
                .where(Finding.description.ilike(pattern))
                .order_by(Finding.cvss_score.desc().nulls_last())
                .limit(50)
            )
            if _owned_eng_ids is not None:
                fq2 = fq2.where(Scan.engagement_id.in_(_owned_eng_ids))
            findings = (await db.execute(fq2)).scalars().all()

    if scope in ('all', 'engagements'):
        eq = (
            select(Engagement)
            .where(
                Engagement.name.ilike(pattern)
                | Engagement.client_name.ilike(pattern)
                | Engagement.description.ilike(pattern)
            )
            .order_by(Engagement.updated_at.desc())
            .limit(20)
        )
        if _owned_eng_ids is not None:
            eq = eq.where(Engagement.id.in_(_owned_eng_ids))
        engagements = (await db.execute(eq)).scalars().all()

    if scope in ('all', 'scans'):
        sq = (
            select(Scan)
            .where(Scan.target.ilike(pattern))
            .order_by(Scan.created_at.desc())
            .limit(20)
        )
        if _owned_eng_ids is not None:
            sq = sq.where(Scan.engagement_id.in_(_owned_eng_ids))
        scans = (await db.execute(sq)).scalars().all()

    total = len(findings) + len(engagements) + len(scans)
    return SearchResults(
        query=q, total=total,
        findings=findings,
        engagements=engagements,
        scans=scans,
    )
