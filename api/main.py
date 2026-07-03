"""
main.py — MSTE FastAPI application.

Key differences from the Flask version:
  - Async throughout: routes, DB queries, SSE streaming are all non-blocking
  - JWT replaces Flask-Login sessions — stateless, scales across workers
  - Pydantic schemas replace manual validation in every route
  - Auto-generated OpenAPI docs at /docs and /redoc
  - CORS configured for the React SPA origin
  - Rate limiting via slowapi (same limits library, FastAPI-native)
  - Lifespan context manager replaces Flask's app context for startup/shutdown
"""

import logging
import logging.config
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pythonjsonlogger import jsonlogger
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from sqlalchemy import select, text

from config import settings
from database import AsyncSessionLocal, close_db, init_db
from models import AuditLog, ReportTemplate, User
from auth import hash_password


# ── Structured JSON logging ───────────────────────────────────────────────────
# In production every log line is a JSON object with consistent fields so log
# aggregators (Loki, CloudWatch, Datadog) can filter by scan_id, level, etc.
# In test mode we keep plain text to keep test output readable.

class _MsteJsonFormatter(jsonlogger.JsonFormatter):
    """Extend the base formatter with a fixed set of fields on every record."""

    def add_fields(self, log_record: dict, record: logging.LogRecord,
                   message_dict: dict) -> None:
        super().add_fields(log_record, record, message_dict)
        log_record['timestamp'] = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
        log_record['level']     = record.levelname
        log_record['logger']    = record.name
        # Promote scan_id / engagement_id to top-level if present in the
        # message string so they can be indexed directly.
        for key in ('scan_id', 'engagement_id', 'user_id'):
            if key not in log_record:
                import re as _re
                m = _re.search(rf'{key}[=: ]+([a-f0-9\-]+)', record.getMessage())
                if m:
                    log_record[key] = m.group(1)


def _configure_logging() -> None:
    handler: logging.Handler
    if settings.testing:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter(
            '%(levelname)-8s %(name)s — %(message)s'
        ))
    else:
        handler = logging.StreamHandler()
        handler.setFormatter(_MsteJsonFormatter(
            fmt='%(timestamp)s %(level)s %(name)s %(message)s'
        ))

    root = logging.getLogger()
    root.setLevel(logging.INFO)
    # Replace any handlers already attached (e.g. from uvicorn startup)
    root.handlers = [handler]

    # Quiet chatty third-party loggers that add noise without value
    for noisy in ('sqlalchemy.engine', 'asyncio', 'urllib3',
                  'httpcore', 'httpx', 'weasyprint', 'fontTools'):
        logging.getLogger(noisy).setLevel(logging.WARNING)


_configure_logging()
logger = logging.getLogger(__name__)


# ── Rate limiter ──────────────────────────────────────────────────────────────
limiter = Limiter(
    key_func=get_remote_address,
    storage_uri='memory://' if settings.testing else settings.redis_url,
)


# ── Lifespan ──────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown logic — replaces Flask's app context blocks."""
    logger.info('MSTE API starting up…')

    await init_db()

    async with AsyncSessionLocal() as db:
        # Recover stale Running scans atomically
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=5)
        result = await db.execute(
            text("UPDATE scans SET status='Failed' "
                 "WHERE status='Running' AND started_at < :c"),
            {'c': cutoff}
        )
        if result.rowcount:
            logger.warning(f'Recovered {result.rowcount} stale scan(s) → Failed')

        # Bootstrap admin user
        existing = (await db.execute(
            select(User).where(User.username == 'admin')
        )).scalar_one_or_none()
        if not existing:
            admin = User(
                username='admin',
                password_hash=hash_password(settings.admin_password),
                role='Admin',
            )
            db.add(admin)
            logger.info('Created default admin user')

        # Seed default report template
        from report import DEFAULT_TEMPLATE_HTML
        tmpl = (await db.execute(
            select(ReportTemplate).where(ReportTemplate.is_default == True)
        )).scalar_one_or_none()
        if not tmpl:
            db.add(ReportTemplate(
                name='Default',
                html_template=DEFAULT_TEMPLATE_HTML,
                is_default=True,
            ))

        await db.commit()

    logger.info('MSTE API ready.')
    yield

    # Shutdown
    await close_db()
    logger.info('MSTE API shut down.')


# ── App ───────────────────────────────────────────────────────────────────────

app = FastAPI(
    title='MSTE — Modular Security Testing Engine',
    description=(
        'REST API for the MSTE penetration testing platform. '
        'Authenticate via POST /api/auth/login to get a JWT token, '
        'then include it as Authorization: Bearer <token> on all requests.'
    ),
    version='2.0.0',
    docs_url='/docs',
    redoc_url='/redoc',
    lifespan=lifespan,
)

# Rate limiter error handler
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# CORS — allow the React SPA and any configured origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=['GET', 'POST', 'PATCH', 'DELETE', 'OPTIONS'],
    allow_headers=['Authorization', 'Content-Type', 'X-Request-ID'],
)


# ── Security headers middleware ───────────────────────────────────────────────

@app.middleware('http')
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers['X-Content-Type-Options']  = 'nosniff'
    response.headers['X-Frame-Options']         = 'DENY'
    response.headers['Referrer-Policy']         = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy']      = 'geolocation=(), microphone=()'
    # Restrict resource origins; unsafe-inline is required for WeasyPrint PDF
    # rendering but can be tightened once PDF export moves to a separate service.
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "font-src 'self'; "
        "connect-src 'self'; "
        "frame-ancestors 'none';"
    )
    # Don't set HSTS here — nginx handles it for the full domain
    return response


# ── Routers ───────────────────────────────────────────────────────────────────

from routers.auth        import router as auth_router
from routers.engagements import router as engagements_router
from routers.findings    import router as findings_router
from routers.search      import router as search_router
from routers.admin       import router as admin_router

app.include_router(auth_router)
app.include_router(engagements_router)
app.include_router(findings_router)
app.include_router(search_router)
app.include_router(admin_router)


# ── Health probes (unauthenticated — used by Docker / K8s) ───────────────────
#
# Two endpoints to match the Kubernetes probe model:
#
#   /health/live  — Liveness probe.  Always returns 200 if the process is up.
#                   Must NEVER check external dependencies (DB, Redis) because
#                   a failed dependency would cause K8s to kill and restart the
#                   pod in a loop, making the outage worse.
#
#   /health/ready — Readiness probe.  Returns 200 only when the API can serve
#                   traffic: database reachable, Redis reachable.  K8s stops
#                   sending traffic to the pod while this returns non-200,
#                   without restarting it.

@app.get('/health/live', include_in_schema=False)
async def health_live():
    """Liveness — is the process alive?"""
    return {'status': 'ok', 'version': '2.0.0'}


@app.get('/health/ready', include_in_schema=False)
async def health_ready():
    """Readiness — can we actually serve requests right now?"""
    checks: dict[str, str] = {}
    errors: list[str]      = []

    # ── Database ──────────────────────────────────────────────────────────────
    try:
        async with AsyncSessionLocal() as db:
            await db.execute(text('SELECT 1'))
        checks['database'] = 'ok'
    except Exception as exc:
        checks['database'] = f'error: {exc}'
        errors.append('database')

    # ── Redis ─────────────────────────────────────────────────────────────────
    try:
        import redis.asyncio as aioredis
        r = aioredis.from_url(settings.redis_url, socket_connect_timeout=2)
        await r.ping()
        await r.aclose()
        checks['redis'] = 'ok'
    except Exception as exc:
        checks['redis'] = f'error: {exc}'
        errors.append('redis')

    if errors:
        return JSONResponse(
            status_code=503,
            content={'status': 'degraded', 'checks': checks,
                     'failed': errors, 'version': '2.0.0'},
        )
    return {'status': 'ok', 'checks': checks, 'version': '2.0.0'}


# Legacy alias so existing docker-compose healthcheck lines keep working
# during the transition.  Remove once all deployments are updated to /health/live.
@app.get('/health', include_in_schema=False)
async def health_legacy():
    return {'status': 'ok', 'version': '2.0.0'}
