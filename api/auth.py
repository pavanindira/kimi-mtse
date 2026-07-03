"""
auth.py — JWT authentication for the FastAPI backend.

Replaces Flask-Login sessions + Flask-WTF CSRF with stateless JWT tokens.
The React SPA stores the token in memory (not localStorage — XSS safe) and
sends it as a Bearer token on every request.

Token lifecycle:
    POST /api/auth/login  → returns { access_token, token_type }
    All protected routes  → Authorization: Bearer <token>
    Token expiry          → JWT_EXPIRE_MINUTES (default 480 = 8 hours)

RBAC:
    require_auth          → any authenticated user
    require_analyst       → Admin or Analyst
    require_admin         → Admin only

User cache:
    _get_current_user used to issue a SELECT on every request.  Now it caches
    the serialised user in Redis for USER_CACHE_TTL seconds.  On role change or
    user deletion the cache key is invalidated immediately via
    invalidate_user_cache().  Admin routes bypass the cache and always hit the
    DB to ensure fresh privilege data.
"""

import json
from datetime import datetime, timedelta, timezone
from typing import Annotated

import bcrypt as _bcrypt
import redis.asyncio as _aioredis
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from config import settings
from database import get_db
from models import User

# ── Password hashing (direct bcrypt, avoids passlib/bcrypt compat issues) ─────

def hash_password(password: str) -> str:
    return _bcrypt.hashpw(password.encode(), _bcrypt.gensalt()).decode()

def verify_password(plain: str, hashed: str) -> bool:
    try:
        return _bcrypt.checkpw(plain.encode(), hashed.encode())
    except Exception:
        return False


# ── JWT ───────────────────────────────────────────────────────────────────────
oauth2_scheme = OAuth2PasswordBearer(tokenUrl='/api/auth/login')

def create_access_token(user_id: int, username: str, role: str) -> str:
    """Create a signed JWT containing user identity and role."""
    expire = datetime.now(timezone.utc) + timedelta(
        minutes=settings.jwt_expire_minutes
    )
    payload = {
        'sub':      str(user_id),
        'username': username,
        'role':     role,
        'exp':      expire,
        'iat':      datetime.now(timezone.utc),
    }
    return jwt.encode(payload, settings.jwt_secret,
                      algorithm=settings.jwt_algorithm)


def decode_token(token: str) -> dict:
    """Decode and verify a JWT. Raises HTTPException on failure."""
    try:
        return jwt.decode(token, settings.jwt_secret,
                          algorithms=[settings.jwt_algorithm])
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Invalid or expired token',
            headers={'WWW-Authenticate': 'Bearer'},
        )


# ── User cache ────────────────────────────────────────────────────────────────
# Caching the user record in Redis avoids a DB round-trip on every request.
# TTL is short (5 min) so stale data is bounded.  Role changes and deletions
# call invalidate_user_cache() immediately so they take effect within one
# request rather than waiting for TTL expiry.

USER_CACHE_TTL = 300  # seconds (5 minutes)
_CACHE_PREFIX  = 'user_cache:'

_redis_cache: _aioredis.Redis | None = None


def _cache_key(user_id: int) -> str:
    return f'{_CACHE_PREFIX}{user_id}'


async def _get_redis_cache() -> _aioredis.Redis:
    """Lazy-init a module-level async Redis client for user caching."""
    global _redis_cache
    if _redis_cache is None:
        _redis_cache = _aioredis.from_url(
            settings.redis_url,
            decode_responses=True,
            socket_connect_timeout=2,
            socket_keepalive=True,
        )
    return _redis_cache


def _user_to_dict(user: User) -> dict:
    """
    Serialise a User for the Redis cache.

    password_hash is intentionally excluded — it is sensitive and not needed
    for the cache's purpose (identity + role lookup on every request).
    If a route needs the hash (e.g. change-password), it must hit the DB.
    """
    return {
        'id':         user.id,
        'username':   user.username,
        'role':       user.role,
        'last_login': user.last_login.isoformat() if user.last_login else None,
        'created_at': user.created_at.isoformat() if user.created_at else None,
    }


def _dict_to_user(data: dict) -> User:
    """Reconstruct a detached (non-ORM) User-like object from cache."""
    u = User.__new__(User)
    u.id            = data['id']
    u.username      = data['username']
    u.role          = data['role']
    u.password_hash = ''  # not cached — routes that need it must hit the DB
    raw_login = data.get('last_login')
    u.last_login    = datetime.fromisoformat(raw_login) if raw_login else None
    raw_created = data.get('created_at')
    u.created_at    = datetime.fromisoformat(raw_created) if raw_created else None
    return u


async def invalidate_user_cache(user_id: int) -> None:
    """
    Delete the cached user record for user_id.

    Call this immediately after:
      - changing a user's role        (admin.py change_role)
      - deleting a user               (admin.py delete_user)
      - changing a user's password    (future password-change endpoint)

    If Redis is unavailable the invalidation silently fails — the cache entry
    will expire naturally after USER_CACHE_TTL seconds.
    """
    try:
        r = await _get_redis_cache()
        await r.delete(_cache_key(user_id))
    except Exception:
        pass  # non-fatal — TTL provides eventual consistency


# ── Dependencies ──────────────────────────────────────────────────────────────

async def _get_current_user(
    token: Annotated[str, Depends(oauth2_scheme)],
    db:    Annotated[AsyncSession, Depends(get_db)],
) -> User:
    """
    Resolve a JWT token to a User object.

    Fast path (non-admin routes):
        1. Decode and verify the JWT (pure CPU, no I/O).
        2. Attempt a Redis GET for user:{id}.
           • Hit  → deserialise and return without touching the DB.
           • Miss → fall through to DB.
        3. DB SELECT — writes result to Redis with USER_CACHE_TTL TTL.

    Admin routes always go to the DB directly (see require_admin below) so
    privilege escalation or account suspension is enforced without waiting for
    TTL expiry.
    """
    payload = decode_token(token)
    user_id = int(payload.get('sub', 0))

    # ── Try cache first ───────────────────────────────────────────────────────
    if not settings.testing:
        try:
            r    = await _get_redis_cache()
            raw  = await r.get(_cache_key(user_id))
            if raw:
                user = _dict_to_user(json.loads(raw))
                return user
        except HTTPException:
            raise
        except Exception:
            pass  # Redis unavailable — fall through to DB silently

    # ── DB lookup (cache miss or Redis unavailable) ───────────────────────────
    result = await db.execute(select(User).where(User.id == user_id))
    user   = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail='User not found')
    # ── Populate cache ────────────────────────────────────────────────────────
    if not settings.testing:
        try:
            r = await _get_redis_cache()
            await r.setex(_cache_key(user_id), USER_CACHE_TTL,
                          json.dumps(_user_to_dict(user)))
        except Exception:
            pass  # non-fatal

    return user


CurrentUser = Annotated[User, Depends(_get_current_user)]


async def require_analyst(user: CurrentUser) -> User:
    """Dependency: Admin or Analyst only."""
    if user.role not in ('Admin', 'Analyst'):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail='Analyst role required')
    return user


async def require_admin(
    token: Annotated[str, Depends(oauth2_scheme)],
    db:    Annotated[AsyncSession, Depends(get_db)],
) -> User:
    """
    Dependency: Admin only.

    Deliberately does NOT depend on CurrentUser/_get_current_user — that
    dependency is cache-first, and FastAPI dedupes dependencies within a
    request, so depending on CurrentUser here would just re-check `.role`
    on the same cached object every other dependency in the request already
    resolved. That previously meant a demoted admin could keep admin access
    for up to USER_CACHE_TTL if invalidate_user_cache() ever failed silently
    (e.g. Redis briefly unreachable at demotion time) — a real gap, not just
    a stale comment.

    This does its own token decode + DB SELECT, skipping the cache entirely,
    so role demotions and deletions take effect on the very next request
    regardless of cache state. It's the only dependency that pays this cost;
    admin routes are low-traffic enough that it's worth it.
    """
    payload = decode_token(token)
    user_id = int(payload.get('sub', 0))

    result = await db.execute(select(User).where(User.id == user_id))
    user   = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail='User not found')
    if user.role != 'Admin':
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail='Admin role required')
    return user


AnalystUser = Annotated[User, Depends(require_analyst)]
AdminUser   = Annotated[User, Depends(require_admin)]


