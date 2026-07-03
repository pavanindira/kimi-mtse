"""auth.py router — /api/auth/*"""

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from slowapi import Limiter
from slowapi.util import get_remote_address
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from auth import (CurrentUser, create_access_token, decode_token,
                  hash_password, invalidate_user_cache, verify_password)
from config import settings
from database import get_db
from models import User
from schemas import (ChangePasswordRequest, LoginRequest, RefreshOut,
                     TokenOut, UserOut)
from utils import add_audit_log, get_client_ip

router  = APIRouter(prefix='/api/auth', tags=['auth'])
limiter = Limiter(key_func=get_remote_address)

# In test mode, use permissive limits so the test suite never hits 429.
_LIMIT_LOGIN   = '10000/minute' if settings.testing else '10/minute'
_LIMIT_REFRESH = '10000/minute' if settings.testing else '30/minute'
_LIMIT_CHGPASS = '10000/minute' if settings.testing else '5/minute'


@router.post('/login', response_model=TokenOut)
@limiter.limit(_LIMIT_LOGIN)
async def login(
    body:    LoginRequest,
    request: Request,
    db:      AsyncSession = Depends(get_db),
):
    result = await db.execute(select(User).where(User.username == body.username))
    user   = result.scalar_one_or_none()

    if not user or not verify_password(body.password, user.password_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail='Invalid username or password')

    user.last_login = datetime.now(timezone.utc)
    token = create_access_token(user.id, user.username, user.role)
    add_audit_log(db, action='user.login', user_id=user.id,
                  username=user.username, ip_address=get_client_ip(request))
    # commit handled by get_db dependency
    return TokenOut(
        access_token=token,
        token_type='bearer',
        expires_in=settings.jwt_expire_minutes * 60,
    )


@router.get('/me', response_model=UserOut)
async def get_me(current_user: CurrentUser):
    return current_user


@router.post('/refresh', response_model=RefreshOut)
@limiter.limit(_LIMIT_REFRESH)
async def refresh_token(
    request:      Request,
    current_user: CurrentUser,
    db:           AsyncSession = Depends(get_db),
):
    """
    Issue a fresh token to an already-authenticated user.

    The caller must present a valid, non-expired Bearer token — this is not a
    silent-refresh / refresh-token flow, it is an explicit re-issue.  It lets
    the SPA extend its session without asking the user to re-enter credentials,
    while keeping the window of exposure to any single token short.

    Rate-limited to 30/minute per IP to prevent token-churn abuse.
    """
    new_token = create_access_token(
        current_user.id, current_user.username, current_user.role
    )
    add_audit_log(db, action='user.token_refreshed',
                  user_id=current_user.id, username=current_user.username,
                  ip_address=get_client_ip(request))
    return RefreshOut(
        access_token=new_token,
        token_type='bearer',
        expires_in=settings.jwt_expire_minutes * 60,
    )


@router.post('/change-password', status_code=200)
@limiter.limit(_LIMIT_CHGPASS)
async def change_password(
    body:         ChangePasswordRequest,
    request:      Request,
    current_user: CurrentUser,
    db:           AsyncSession = Depends(get_db),
):
    """
    Change the authenticated user's own password.

    Requires the current password for verification — prevents an attacker who
    has stolen a JWT from locking the real user out by changing their password.

    After a successful change:
    - The password_hash is updated.
    - The user cache entry is invalidated immediately so the new hash is used
      on the very next request.
    - A new access token is issued so the caller does not need to log in again.
    - The change is audit-logged.
    """
    from sqlalchemy import select
    result = await db.execute(select(User).where(User.id == current_user.id))
    user   = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail='User not found')

    if not verify_password(body.current_password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail='Current password is incorrect',
        )

    if body.current_password == body.new_password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail='New password must differ from the current password',
        )

    user.password_hash = hash_password(body.new_password)

    # Invalidate cache — the cached record carries password_hash which is now stale
    await invalidate_user_cache(user.id)

    add_audit_log(db, action='user.password_changed',
                  user_id=user.id, username=user.username,
                  ip_address=get_client_ip(request))

    # Issue a fresh token so the caller stays logged in seamlessly
    new_token = create_access_token(user.id, user.username, user.role)
    return {
        'message':      'Password changed successfully',
        'access_token': new_token,
        'token_type':   'bearer',
        'expires_in':   settings.jwt_expire_minutes * 60,
    }
