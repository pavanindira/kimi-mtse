"""admin.py router — /api/admin/*"""

import base64

from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from auth import AdminUser, hash_password, invalidate_user_cache
from database import get_db
from models import AuditLog, ReportTemplate, User
from schemas import (AuditLogOut, PaginatedAuditLog, ReportTemplateOut,
                     UserCreate, UserOut, UserRoleUpdate)
from utils import add_audit_log, get_client_ip

router = APIRouter(prefix='/api/admin', tags=['admin'])


# ── Users ─────────────────────────────────────────────────────────────────────

@router.get('/users', response_model=list[UserOut])
async def list_users(
    admin: AdminUser,
    db:    AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(User).order_by(User.created_at.asc())
    )
    return result.scalars().all()


@router.post('/users', response_model=UserOut, status_code=status.HTTP_201_CREATED)
async def create_user(
    body:    UserCreate,
    admin:   AdminUser,
    request: Request,
    db:      AsyncSession = Depends(get_db),
):
    exists = (await db.execute(
        select(User).where(User.username == body.username)
    )).scalar_one_or_none()
    if exists:
        raise HTTPException(status_code=409,
                            detail=f'Username "{body.username}" already exists')

    user = User(username=body.username, role=body.role,
                password_hash=hash_password(body.password))
    db.add(user)
    await db.flush()

    add_audit_log(db, action='user.created',
                  user_id=admin.id, username=admin.username,
                  target_type='user', target_id=user.id, target_name=user.username,
                  detail={'role': body.role}, ip_address=get_client_ip(request))
    return user


@router.patch('/users/{user_id}/role', response_model=UserOut)
async def change_role(
    user_id: int,
    body:    UserRoleUpdate,
    admin:   AdminUser,
    request: Request,
    db:      AsyncSession = Depends(get_db),
):
    user = (await db.execute(
        select(User).where(User.id == user_id)
    )).scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail='User not found')
    if user.username == 'admin' and admin.id != user.id:
        raise HTTPException(status_code=403,
                            detail='Built-in admin role cannot be changed')

    old_role   = user.role
    user.role  = body.role
    # Invalidate cache immediately — the user's next request must see the new
    # role without waiting for the 5-minute TTL to expire.
    await invalidate_user_cache(user.id)
    add_audit_log(db, action='user.role_changed',
                  user_id=admin.id, username=admin.username,
                  target_type='user', target_id=user.id, target_name=user.username,
                  detail={'old': old_role, 'new': body.role},
                  ip_address=get_client_ip(request))
    return user


@router.delete('/users/{user_id}', status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(
    user_id: int,
    admin:   AdminUser,
    request: Request,
    db:      AsyncSession = Depends(get_db),
):
    user = (await db.execute(
        select(User).where(User.id == user_id)
    )).scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail='User not found')
    if user.id == admin.id:
        raise HTTPException(status_code=400, detail='Cannot delete your own account')
    if user.username == 'admin':
        raise HTTPException(status_code=400, detail='Built-in admin cannot be deleted')

    uname   = user.username
    uid     = user.id
    await db.delete(user)
    # Invalidate before commit so any in-flight request using this user_id
    # fails on the next DB lookup rather than serving stale cached data.
    await invalidate_user_cache(uid)
    add_audit_log(db, action='user.deleted',
                  user_id=admin.id, username=admin.username,
                  target_type='user', target_name=uname,
                  ip_address=get_client_ip(request))


# ── Audit log ─────────────────────────────────────────────────────────────────

@router.get('/audit', response_model=PaginatedAuditLog)
async def audit_log(
    admin:         AdminUser,
    db:            AsyncSession = Depends(get_db),
    page:          int = 1,
    per_page:      int = 50,
    action_filter: str | None = None,
    user_filter:   str | None = None,
):
    q = select(AuditLog)
    if action_filter:
        q = q.where(AuditLog.action == action_filter)
    if user_filter:
        q = q.where(AuditLog.username.ilike(f'%{user_filter}%'))

    total   = (await db.execute(
        select(func.count()).select_from(q.subquery())
    )).scalar_one()
    pages   = max(1, -(-total // per_page))  # ceiling division
    offset  = (page - 1) * per_page

    result  = await db.execute(
        q.order_by(AuditLog.timestamp.desc())
        .limit(per_page).offset(offset)
    )
    items = result.scalars().all()

    return PaginatedAuditLog(
        items=items, total=total,
        page=page, pages=pages, per_page=per_page,
    )


# ── Report templates ──────────────────────────────────────────────────────────

_ALLOWED_LOGO_TYPES = {'image/png', 'image/svg+xml', 'image/jpeg', 'image/webp'}
_MAX_LOGO_BYTES     = 512 * 1024  # 512 KB — keeps PDF size reasonable


@router.get('/report-templates', response_model=list[ReportTemplateOut])
async def list_report_templates(
    admin: AdminUser,
    db:    AsyncSession = Depends(get_db),
):
    """List all report templates (id, name, is_default, has_logo)."""
    rows = (await db.execute(select(ReportTemplate))).scalars().all()
    return [ReportTemplateOut.from_orm_obj(r) for r in rows]


@router.post('/report-templates/{template_id}/logo',
             response_model=ReportTemplateOut)
async def upload_logo(
    template_id: int,
    request:     Request,
    admin:       AdminUser,
    db:          AsyncSession = Depends(get_db),
    file:        UploadFile = File(..., description='PNG, JPEG, SVG, or WebP logo file'),
):
    """
    Upload a logo image for a report template.

    The file is base64-encoded and stored in ReportTemplate.logo_base64.
    The PDF template embeds it as a data URI — no external file storage needed.

    Limits:
      - Accepted types: PNG, JPEG, SVG, WebP
      - Max size: 512 KB (keeps rendered PDF under 5 MB for typical reports)
    """
    template = (await db.execute(
        select(ReportTemplate).where(ReportTemplate.id == template_id)
    )).scalar_one_or_none()
    if not template:
        raise HTTPException(status_code=404, detail='Report template not found')

    content_type = (file.content_type or '').lower()
    if content_type not in _ALLOWED_LOGO_TYPES:
        raise HTTPException(
            status_code=422,
            detail=f'Unsupported file type "{content_type}". '
                   f'Allowed: PNG, JPEG, SVG, WebP.',
        )

    raw = await file.read()
    if len(raw) > _MAX_LOGO_BYTES:
        raise HTTPException(
            status_code=422,
            detail=f'Logo file too large ({len(raw) // 1024} KB). '
                   f'Maximum is {_MAX_LOGO_BYTES // 1024} KB.',
        )
    if not raw:
        raise HTTPException(status_code=422, detail='Uploaded file is empty.')

    # Store as a data URI so the PDF renderer can embed it inline.
    encoded       = base64.b64encode(raw).decode('ascii')
    template.logo_base64 = f'data:{content_type};base64,{encoded}'

    add_audit_log(db, action='report_template.logo_uploaded',
                  user_id=admin.id, username=admin.username,
                  target_type='report_template', target_id=template.id,
                  target_name=template.name,
                  detail={'content_type': content_type, 'size_bytes': len(raw)},
                  ip_address=get_client_ip(request))

    await db.flush()
    return ReportTemplateOut.from_orm_obj(template)


@router.delete('/report-templates/{template_id}/logo',
               status_code=status.HTTP_204_NO_CONTENT)
async def delete_logo(
    template_id: int,
    request:     Request,
    admin:       AdminUser,
    db:          AsyncSession = Depends(get_db),
):
    """Remove the custom logo from a report template, reverting to text-only."""
    template = (await db.execute(
        select(ReportTemplate).where(ReportTemplate.id == template_id)
    )).scalar_one_or_none()
    if not template:
        raise HTTPException(status_code=404, detail='Report template not found')

    template.logo_base64 = None

    add_audit_log(db, action='report_template.logo_deleted',
                  user_id=admin.id, username=admin.username,
                  target_type='report_template', target_id=template.id,
                  target_name=template.name,
                  ip_address=get_client_ip(request))


@router.patch('/report-templates/{template_id}/set-default',
              response_model=ReportTemplateOut)
async def set_default_template(
    template_id: int,
    request:     Request,
    admin:       AdminUser,
    db:          AsyncSession = Depends(get_db),
):
    """
    Mark a report template as the system default.

    Clears is_default on all other templates first — only one can be default
    at a time.  Engagements without an explicit report_template_id use this one.
    """
    template = (await db.execute(
        select(ReportTemplate).where(ReportTemplate.id == template_id)
    )).scalar_one_or_none()
    if not template:
        raise HTTPException(status_code=404, detail='Report template not found')

    # Clear current default(s) before setting new one
    current_defaults = (await db.execute(
        select(ReportTemplate).where(ReportTemplate.is_default.is_(True))
    )).scalars().all()
    for t in current_defaults:
        if t.id != template_id:
            t.is_default = False

    template.is_default = True

    add_audit_log(db, action='report_template.set_default',
                  user_id=admin.id, username=admin.username,
                  target_type='report_template', target_id=template.id,
                  target_name=template.name,
                  ip_address=get_client_ip(request))

    await db.flush()
    return ReportTemplateOut.from_orm_obj(template)
