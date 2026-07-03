"""
database.py — Async SQLAlchemy engine, session factory, and base model.

FastAPI uses async database access throughout. Each request gets its own
AsyncSession via the get_db() dependency, which is injected into route
handlers. Sessions are committed on success and rolled back on exception.

Usage in a route:
    from database import get_db
    from sqlalchemy.ext.asyncio import AsyncSession

    @router.get('/things')
    async def list_things(db: AsyncSession = Depends(get_db)):
        result = await db.execute(select(Thing))
        return result.scalars().all()
"""

from contextlib import asynccontextmanager
from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

from config import settings

# ── Engine ────────────────────────────────────────────────────────────────────
# pool_pre_ping ensures stale connections are detected and recycled,
# which matters for long-running pentest workflows.
#
# pool_size/max_overflow are QueuePool-only options. They're appropriate for
# the real postgres+asyncpg engine but SQLite (used by the test suite via
# sqlite+aiosqlite) uses a different default pool class that doesn't accept
# them — create_async_engine raises TypeError if they're passed regardless.
_pool_kwargs: dict = {}
if not settings.database_url.startswith('sqlite'):
    _pool_kwargs = dict(pool_size=10, max_overflow=20)

engine = create_async_engine(
    settings.database_url,
    echo=settings.testing,          # log SQL in test mode only
    pool_pre_ping=True,
    **_pool_kwargs,
)

AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,         # keep objects usable after commit
    autocommit=False,
    autoflush=False,
)


# ── Base ──────────────────────────────────────────────────────────────────────
class Base(DeclarativeBase):
    pass


# ── Dependency ────────────────────────────────────────────────────────────────
async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency — yields a DB session per request."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


# ── Startup / shutdown ────────────────────────────────────────────────────────
async def init_db():
    """Create all tables on first run (Alembic handles subsequent migrations)."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def close_db():
    """Dispose the engine connection pool on shutdown."""
    await engine.dispose()
