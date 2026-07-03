"""
conftest.py — pytest fixtures for the MSTE v2 test suite.

Uses FastAPI's TestClient (sync wrapper around the async app) with an
in-memory SQLite database so no real PostgreSQL or Redis is required.

Celery tasks are mocked so tests never attempt broker connections.
The JWT token flow is tested end-to-end: login → get token → use token.
"""

import os
import sys
import pytest
from typing import Generator

# Set env vars BEFORE any app module is imported
os.environ['TESTING']        = '1'
os.environ['DATABASE_URL']   = 'sqlite+aiosqlite:///./test.db'
os.environ['REDIS_URL']      = 'redis://localhost:6379/0'
os.environ['JWT_SECRET']     = 'test-jwt-secret-at-least-32-characters-long'
os.environ['ADMIN_PASSWORD'] = 'adminpass123'
os.environ['HOST_PROJECT_PATH'] = '/tmp'
os.environ['ZAP_API_KEY']    = 'test-zap-key'

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'api'))

# Mock Celery tasks before importing app
import unittest.mock as mock

_TASK_NAMES = [
    'tasks.run_web_scan', 'tasks.run_sast_scan', 'tasks.run_infra_scan',
    'tasks.run_cloud_scan', 'tasks.run_mobile_scan',
    # Also patch the local bindings imported into the engagements router
    'routers.engagements.run_web_scan', 'routers.engagements.run_sast_scan',
    'routers.engagements.run_infra_scan', 'routers.engagements.run_cloud_scan',
    'routers.engagements.run_mobile_scan',
]


@pytest.fixture(scope='session', autouse=True)
def mock_celery_tasks():
    """Prevent Celery from trying to connect to Redis broker during tests."""
    mock_task = mock.MagicMock()
    mock_task.delay.return_value = mock.MagicMock(id='mock-task-id')

    # Patch each task in the tasks module
    task_patches = []
    for name in _TASK_NAMES:
        module, attr = name.rsplit('.', 1)
        p = mock.patch(f'{module}.{attr}', mock_task)
        p.start()
        task_patches.append(p)

    # Patch TASK_MAP in the engagements router — it is built at import time
    # from direct references, so patching the source module is not enough.
    import routers.engagements as eng_router
    original_task_map = dict(eng_router.TASK_MAP)
    for key in eng_router.TASK_MAP:
        eng_router.TASK_MAP[key] = mock_task

    # Prevent celery.control.revoke from trying to reach the broker
    revoke_patch = mock.patch('routers.engagements.celery', mock.MagicMock())
    revoke_patch.start()

    yield

    for p in task_patches:
        p.stop()
    revoke_patch.stop()
    eng_router.TASK_MAP.update(original_task_map)


# ── App + DB fixtures ─────────────────────────────────────────────────────────

@pytest.fixture(scope='session')
def app():
    """Create the FastAPI app with a fresh in-memory SQLite database."""
    import asyncio
    from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
    from database import Base

    engine       = create_async_engine('sqlite+aiosqlite:///./test.db', echo=False)
    SessionLocal = async_sessionmaker(bind=engine, expire_on_commit=False)

    async def _setup():
        async with engine.begin() as conn:
            # Drop and recreate on every test run so schema changes are
            # always reflected without needing to delete the file manually.
            await conn.run_sync(Base.metadata.drop_all)
            await conn.run_sync(Base.metadata.create_all)

    asyncio.run(_setup())

    import database
    database.engine            = engine
    database.AsyncSessionLocal = SessionLocal

    from main import app as fastapi_app
    fastapi_app.state.testing = True
    return fastapi_app


@pytest.fixture(scope='session')
def client(app):
    from fastapi.testclient import TestClient
    with TestClient(app, raise_server_exceptions=True) as c:
        yield c


@pytest.fixture(scope='session')
def admin_token(client) -> str:
    """Get a JWT token for the admin user (created by app lifespan)."""
    res = client.post('/api/auth/login',
                      json={'username': 'admin', 'password': 'adminpass123'})
    assert res.status_code == 200, res.text
    return res.json()['access_token']


@pytest.fixture(scope='session')
def admin_headers(admin_token) -> dict:
    return {'Authorization': f'Bearer {admin_token}'}


@pytest.fixture(scope='session')
def analyst_token(client, admin_headers) -> str:
    """Create an Analyst user and return their token."""
    client.post('/api/admin/users',
                json={'username': 'analyst', 'password': 'analystpass123',
                      'role': 'Analyst'},
                headers=admin_headers)
    res = client.post('/api/auth/login',
                      json={'username': 'analyst', 'password': 'analystpass123'})
    assert res.status_code == 200
    return res.json()['access_token']


@pytest.fixture(scope='session')
def analyst_headers(analyst_token) -> dict:
    return {'Authorization': f'Bearer {analyst_token}'}


@pytest.fixture(scope='session')
def viewer_token(client, admin_headers) -> str:
    """Create a Viewer user and return their token."""
    client.post('/api/admin/users',
                json={'username': 'viewer', 'password': 'viewerpass123',
                      'role': 'Viewer'},
                headers=admin_headers)
    res = client.post('/api/auth/login',
                      json={'username': 'viewer', 'password': 'viewerpass123'})
    assert res.status_code == 200
    return res.json()['access_token']


@pytest.fixture(scope='session')
def viewer_headers(viewer_token) -> dict:
    return {'Authorization': f'Bearer {viewer_token}'}


@pytest.fixture(scope='session')
def sample_engagement(client, analyst_headers) -> dict:
    """Create a test engagement and return it."""
    res = client.post('/api/engagements',
                      json={'name': 'Test Engagement',
                            'client_name': 'Test Client',
                            'description': 'Integration test engagement'},
                      headers=analyst_headers)
    assert res.status_code == 201
    return res.json()


@pytest.fixture(scope='session')
def sample_findings(client, analyst_headers, sample_engagement) -> list[dict]:
    """Insert findings directly via the DB for test speed."""
    import asyncio
    from database import AsyncSessionLocal
    from models import Finding, Scan
    from sqlalchemy import select

    eng_id = sample_engagement['id']

    async def _create():
        async with AsyncSessionLocal() as db:
            # Check if scan already exists
            existing_scan = (await db.execute(
                select(Scan).where(Scan.scan_id == 'testsc01')
            )).scalar_one_or_none()

            if existing_scan:
                result = await db.execute(select(Finding))
                return [{'id': f.id, 'vulnerability_name': f.vulnerability_name,
                         'severity': f.severity, 'status': f.status}
                        for f in result.scalars().all()]

            scan = Scan(
                scan_id='testsc01', engagement_id=eng_id,
                scan_type='web', target='https://test.example.com',
                folder_name='test_folder', status='Completed',
                created_by=1,
            )
            db.add(scan)
            await db.flush()

            findings = [
                Finding(scan_id_fk=scan.id, tool='Nuclei',
                        vulnerability_name='SQL Injection',
                        severity='Critical', status='Open',
                        dedup_hash='aaa111', cvss_score=9.8,
                        cve_id='CVE-2021-0001',
                        target_url='https://test.example.com/login'),
                Finding(scan_id_fk=scan.id, tool='ZAP',
                        vulnerability_name='Reflected XSS',
                        severity='High', status='Open',
                        dedup_hash='bbb222', cvss_score=7.4,
                        target_url='https://test.example.com/search'),
                Finding(scan_id_fk=scan.id, tool='Semgrep',
                        vulnerability_name='Hardcoded Secret',
                        severity='Critical', status='Open',
                        dedup_hash='ccc333', cvss_score=9.1,
                        file_path='app/config.py', line_number=42),
            ]
            for f in findings:
                db.add(f)
            await db.commit()

            result = await db.execute(select(Finding))
            return [{'id': f.id, 'vulnerability_name': f.vulnerability_name,
                     'severity': f.severity, 'status': f.status}
                    for f in result.scalars().all()]

    return asyncio.run(_create())


@pytest.fixture(scope='session')
def sample_report_template(client) -> dict:
    """
    Insert a ReportTemplate directly via the DB — there is no API endpoint
    to create one (admin routes only manage logo/default on existing rows),
    so tests that need a valid report_template_id foreign key use this.
    """
    import asyncio
    from database import AsyncSessionLocal
    from models import ReportTemplate
    from sqlalchemy import select

    async def _create():
        async with AsyncSessionLocal() as db:
            existing = (await db.execute(
                select(ReportTemplate).where(ReportTemplate.name == 'Test Template')
            )).scalar_one_or_none()
            if existing:
                return {'id': existing.id, 'name': existing.name}
            tmpl = ReportTemplate(name='Test Template', is_default=False,
                                  html_template='<html></html>')
            db.add(tmpl)
            await db.commit()
            await db.refresh(tmpl)
            return {'id': tmpl.id, 'name': tmpl.name}

    return asyncio.run(_create())


@pytest.fixture(autouse=True, scope='function')
def ensure_admin_role(client, request):
    """
    After every test, check if the admin user's role has been corrupted
    and restore it. This guards against tests that accidentally change it.
    Only runs for tests in TestAdminUsers and TestAuditLog classes.
    """
    yield
    # Only repair if we're in a class that touches user management
    if hasattr(request, 'cls') and request.cls is not None:
        cls_name = request.cls.__name__
        if cls_name in ('TestAdminUsers', 'TestAuditLog'):
            import asyncio
            from database import AsyncSessionLocal
            from models import User
            from sqlalchemy import select

            async def _restore():
                async with AsyncSessionLocal() as db:
                    user = (await db.execute(
                        select(User).where(User.username == 'admin')
                    )).scalar_one_or_none()
                    if user and user.role != 'Admin':
                        user.role = 'Admin'
                        await db.commit()

            asyncio.run(_restore())
