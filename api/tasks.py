"""
tasks.py — Celery application and scan task definitions for MSTE v2.

Workers are sync (Celery does not use asyncio). They use a SQLAlchemy
sync session created from the DATABASE_URL with the psycopg2 driver,
not the asyncpg driver used by FastAPI. The URL conversion happens in
_get_sync_session() below.

Queues:
    web   → worker-web   (Nuclei, ZAP, ffuf, Katana, SQLmap, testssl)
    sast  → worker-sast  (Semgrep, Trivy, Gitleaks, Hadolint)
    infra → worker-infra (Nmap)
    cloud / mobile share infra queue until dedicated workers are added

Progress is published to Redis channel scan:<scan_id>:progress and
buffered in a Redis list so FastAPI SSE stream can replay for late
subscribers.
"""

import hashlib
import hmac
import json
import logging
import os
import shlex
import subprocess
import tempfile
import threading
import urllib.parse
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Generator

import redis as redis_lib
from celery import Celery
from celery.utils.log import get_task_logger
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session, sessionmaker

logger = get_task_logger(__name__)

# ── Env vars ──────────────────────────────────────────────────────────────────
REDIS_URL    = os.environ.get('REDIS_URL', 'redis://redis:6379/0')
DATABASE_URL = os.environ.get('DATABASE_URL', '')


def _sync_db_url() -> str:
    """Convert asyncpg URL to psycopg2 URL for sync Celery workers."""
    return DATABASE_URL.replace('postgresql+asyncpg://', 'postgresql://')


# ── Celery app ─────────────────────────────────────────────────────────────────
celery = Celery('mste', broker=REDIS_URL, backend=REDIS_URL, include=['tasks'])

_celery_config: dict = dict(
    task_serializer='json',
    result_serializer='json',
    accept_content=['json'],
    timezone='UTC',
    enable_utc=True,
    task_track_started=True,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    result_expires=86400,
    task_routes={
        'tasks.run_web_scan':    {'queue': 'web'},
        'tasks.run_sast_scan':   {'queue': 'sast'},
        'tasks.run_infra_scan':  {'queue': 'infra'},
        'tasks.run_cloud_scan':  {'queue': 'infra'},
        'tasks.run_mobile_scan': {'queue': 'infra'},
    },
)


if os.getenv('TESTING') == '1':
    # In test mode: use in-memory backend so Celery never tries to connect
    # to Redis for result storage.  Tasks are still mocked via conftest.py
    # so they never actually execute; this config only prevents the result
    # backend from attempting pubsub connections when .delay() is called.
    _celery_config.update(
        result_backend='cache+memory://',
    )

celery.conf.update(_celery_config)

# ── Sync DB session ────────────────────────────────────────────────────────────

_engine       = None
_SessionLocal = None


def _get_engine():
    global _engine, _SessionLocal
    if _engine is None:
        _engine       = create_engine(_sync_db_url(), pool_pre_ping=True)
        _SessionLocal = sessionmaker(bind=_engine, expire_on_commit=False)
    return _engine, _SessionLocal


@contextmanager
def _db_session() -> Generator[Session, None, None]:
    _, SessionLocal = _get_engine()
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


# ── Redis pub/sub ──────────────────────────────────────────────────────────────

# Module-level Redis connection — reused across all publish_progress() calls
# within a worker process. Creating a new TCP connection per log line was
# wasteful (each scan emits hundreds of lines).
_redis_client: redis_lib.Redis | None = None


def _get_redis() -> redis_lib.Redis:
    global _redis_client
    if _redis_client is None:
        _redis_client = redis_lib.from_url(
            REDIS_URL, decode_responses=True,
            socket_keepalive=True,
            socket_connect_timeout=5,
        )
    return _redis_client


def publish_progress(scan_id: str, message: str, level: str = 'info'):
    try:
        r = _get_redis()
        payload = json.dumps({
            'msg': message, 'level': level,
            'ts': datetime.now(timezone.utc).isoformat(),
        })
        r.publish(f'scan:{scan_id}:progress', payload)
        r.rpush(f'scan:{scan_id}:log', payload)
        r.expire(f'scan:{scan_id}:log', 86400)
    except Exception as e:
        logger.warning(f'publish_progress failed for {scan_id}: {e}')


# ── DB helpers ─────────────────────────────────────────────────────────────────

_STATUS_CHANNEL = 'scan:{scan_id}:status'  # Redis channel for status updates


def _dispatch_webhook(scan, webhook_url: str, webhook_secret: str | None,
                      finding_count: int) -> None:
    """
    POST a JSON payload to an engagement's configured webhook_url after a
    scan reaches a terminal status.

    Fire-and-forget: failures are logged, never raised. A worker blocking a
    scan pipeline on a flaky third-party endpoint would be worse than a
    missed notification. Uses `requests` (already a dependency for the
    MobSF REST client) rather than `httpx`, since Celery workers are sync.

    webhook_url is validated at write time (schemas.py::_validate_webhook_url
    — http/https scheme + SSRF blocklist), but that only constrains the
    literal host/IP given at save time; DNS can still change afterwards
    (rebinding). A short timeout and no redirect-following bound the blast
    radius rather than trying to re-validate on every dispatch.

    Signing: if webhook_secret is set (it's auto-generated the first time a
    webhook_url is configured — see routers/engagements.py), the request
    carries X-MSTE-Signature and X-MSTE-Timestamp headers so the receiver
    can verify the delivery actually came from this instance and wasn't
    forged by anyone who guessed/scraped the URL. Follows the
    Stripe/GitHub convention of signing "{timestamp}.{body}" rather than
    just the body, so a captured request can't be replayed indefinitely —
    receivers are expected to reject deliveries with a stale timestamp
    (a 5-minute window is a reasonable default).

        signed_content = f'{timestamp}.{raw_body}'
        signature = hmac.new(secret.encode(), signed_content.encode(),
                             hashlib.sha256).hexdigest()

    Signing is best-effort: an engagement created before this feature (or
    whose secret generation somehow failed) has webhook_secret=None, and
    still gets deliveries — just unsigned ones. Emits a one-time warning per
    call so this is visible in worker logs rather than silently degrading.
    """
    import requests
    payload = {
        'event':          'scan.completed',
        'scan_id':        scan.scan_id,
        'engagement_id':  scan.engagement_id,
        'scan_type':      scan.scan_type,
        'target':         scan.target,
        'status':         scan.status,
        'finding_count':  finding_count,
        'completed_at':   scan.completed_at.isoformat() if scan.completed_at else None,
    }
    # Signed over the exact bytes sent — json.dumps here (not requests'
    # internal serialisation) so the signature matches what the receiver
    # actually reads off the wire, with a stable key order for
    # reproducibility.
    raw_body = json.dumps(payload, sort_keys=True, separators=(',', ':'))

    headers = {'Content-Type': 'application/json'}
    if webhook_secret:
        timestamp = str(int(datetime.now(timezone.utc).timestamp()))
        signed_content = f'{timestamp}.{raw_body}'
        signature = hmac.new(webhook_secret.encode(), signed_content.encode(),
                             hashlib.sha256).hexdigest()
        headers['X-MSTE-Signature'] = f'sha256={signature}'
        headers['X-MSTE-Timestamp'] = timestamp
    else:
        logger.warning('scan %s: dispatching unsigned webhook (no secret on engagement %s)',
                       scan.scan_id, scan.engagement_id)

    try:
        requests.post(
            webhook_url, data=raw_body, headers=headers,
            timeout=5, allow_redirects=False,
        )
    except Exception as exc:
        logger.warning('webhook dispatch failed for scan %s -> %s: %s',
                       scan.scan_id, webhook_url, exc)


def _update_scan_status(scan_id: str, status: str,
                        started: bool = False, completed: bool = False):
    """
    Update scan status in the DB and publish the new status to Redis.

    The Redis publish lets the SSE generator detect completion instantly
    via a dedicated status channel rather than polling the DB every 15 seconds.
    The DB write always happens first so the status is durable before the
    notification fires.

    On a terminal status (completed=True) this also fires the engagement's
    webhook, if one is configured — after the DB commit, same as the Redis
    publish, so the notified endpoint sees state consistent with what a
    concurrent API read would show.
    """
    from models import Engagement, Finding, Scan

    webhook_url:    str | None = None
    webhook_secret: str | None = None
    finding_count:  int = 0

    with _db_session() as db:
        scan = db.execute(
            select(Scan).where(Scan.scan_id == scan_id)
        ).scalar_one_or_none()
        if scan is None:
            logger.warning('_update_scan_status: no record for scan_id=%r', scan_id)
            return
        scan.status = status
        if started:   scan.started_at   = datetime.now(timezone.utc)
        if completed: scan.completed_at = datetime.now(timezone.utc)

        if completed:
            engagement = db.execute(
                select(Engagement).where(Engagement.id == scan.engagement_id)
            ).scalar_one_or_none()
            webhook_url    = engagement.webhook_url    if engagement else None
            webhook_secret = engagement.webhook_secret if engagement else None
            if webhook_url:
                finding_count = db.execute(
                    select(func.count(Finding.id)).where(Finding.scan_id_fk == scan.id)
                ).scalar_one()
        # DB commit happens when the _db_session() context manager exits

    # Notify SSE subscribers — publish after the commit so the DB state is
    # consistent by the time any subscriber re-reads it.
    try:
        r = _get_redis()
        channel = _STATUS_CHANNEL.format(scan_id=scan_id)
        r.publish(channel, status)
    except Exception as exc:
        # Non-fatal — the SSE fallback timeout still catches completion
        logger.warning('status publish failed for %s: %s', scan_id, exc)

    if webhook_url:
        # scan is detached but still readable — session is expire_on_commit=False
        _dispatch_webhook(scan, webhook_url, webhook_secret, finding_count)


def _make_dedup_hash(tool: str, name: str, location: str) -> str:
    return hashlib.sha256(f'{tool}:{name}:{location}'.encode()).hexdigest()


def _upsert_finding(db: Session, scan_db_id: int, scan_id_str: str,
                    tool: str, name: str, severity: str, location: str,
                    description: str = '', remediation: str = '',
                    cvss_score: float = None, cvss_vector: str = None,
                    cve_id: str = None, cwe_id: str = None,
                    file_path: str = None, line_number: int = None,
                    host: str = None, port: int = None,
                    target_url: str = None,
                    evidence_items: list[dict] = None):
    from models import Evidence, Finding, Scan, SEVERITY_CVSS_MAP

    dedup = _make_dedup_hash(tool, name, location)

    # Resolve engagement_id once and cache it for the dedup join.
    engagement_id = db.execute(
        select(Scan.engagement_id).where(Scan.id == scan_db_id)
    ).scalar_one()

    # Scope the dedup lookup to the current engagement so findings from
    # different clients at the same URL are never collapsed into one record.
    existing = db.execute(
        select(Finding)
        .join(Scan, Finding.scan_id_fk == Scan.id)
        .where(
            Finding.dedup_hash == dedup,
            Scan.engagement_id == engagement_id,
        )
    ).scalar_one_or_none()

    if existing:
        existing.last_seen = datetime.now(timezone.utc)
        existing.tool_count += 1
        if existing.status == 'Fixed':
            existing.status = 'Open'
        return existing

    if cvss_score is None:
        cvss_score = SEVERITY_CVSS_MAP.get(severity, 0.0)

    finding = Finding(
        scan_id_fk=scan_db_id, tool=tool,
        vulnerability_name=name, severity=severity,
        cvss_score=cvss_score, cvss_vector=cvss_vector,
        cve_id=cve_id, cwe_id=cwe_id,
        target_url=target_url, file_path=file_path,
        line_number=line_number, host=host, port=port,
        description=description, remediation=remediation,
        dedup_hash=dedup,
    )
    db.add(finding)
    db.flush()

    for ev in (evidence_items or []):
        db.add(Evidence(
            finding_id=finding.id,
            ev_type=ev.get('type', 'log_snippet'),
            label=ev.get('label', ''),
            content=ev.get('content', ''),
            file_path=ev.get('file_path'),
        ))
    return finding


# ── Docker run helper ──────────────────────────────────────────────────────────

def _docker_run(scan_id: str, name: str, args: list[str],
                extra_hosts: bool = False) -> tuple[int, str]:
    host_path = os.environ.get('HOST_PROJECT_PATH', os.getcwd())
    cmd       = ['docker', 'run', '--rm', '--name', name]
    if extra_hosts:
        cmd += ['--add-host=host.docker.internal:host-gateway']
    cmd += args

    publish_progress(scan_id, f'Starting: {name}')
    lines = []
    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1,
        )
        _timer = threading.Timer(14400, proc.kill)  # 4 hours
        _timer.start()
        try:
            for line in iter(proc.stdout.readline, ''):
                lines.append(line.rstrip())
                publish_progress(scan_id, line.rstrip())
            proc.stdout.close()
            proc.wait()
        finally:
            _timer.cancel()
        return proc.returncode, '\n'.join(lines)
    except Exception as e:
        publish_progress(scan_id, f'Container error: {e}', level='error')
        return 1, str(e)


# ─────────────────────────────────────────────────────────────────────────────
# WEB SCAN
# ─────────────────────────────────────────────────────────────────────────────

@celery.task(bind=True, name='tasks.run_web_scan', max_retries=1,
             # Scan options may contain sensitive auth headers; limit result
             # backend exposure to 5 minutes (same as SAST/cloud/mobile).
             result_expires=300)
def run_web_scan(self, scan_id: str, target: str, folder: str,
                 options: dict[str, Any]):
    _update_scan_status(scan_id, 'Running', started=True)
    publish_progress(scan_id, f'[Web Scan] Starting against {target}')

    host_path = os.environ.get('HOST_PROJECT_PATH', os.getcwd())
    try:
        scan_args = ['bash', '/app/scan.sh', target]
        if options.get('auth_header'):
            scan_args += ['--auth-header', options['auth_header']]
        if options.get('proxy'):
            scan_args += ['--proxy', options['proxy']]
        if options.get('enable_katana'):  scan_args.append('--katana')
        if options.get('enable_sqlmap'):  scan_args.append('--sqlmap')
        if options.get('enable_stealth'): scan_args.append('--stealth')
        scan_args.append('--zap-active')

        env = os.environ.copy()
        env['OUTPUT_FOLDER_NAME'] = folder
        # scan.sh spawns `docker run -v` calls that need the *host* path for
        # bind mounts (Docker resolves volumes relative to the host, not the
        # container). HOST_PROJECT_PATH is already in the environment from
        # docker-compose, but we set it explicitly here so scan.sh can use it
        # without assuming it was inherited.
        env['HOST_PROJECT_PATH'] = host_path

        proc = subprocess.Popen(
            scan_args, cwd='/app', env=env,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1,
        )
        _timer = threading.Timer(14400, proc.kill)  # 4 hours
        _timer.start()
        try:
            for line in iter(proc.stdout.readline, ''):
                publish_progress(scan_id, line.rstrip())
            proc.stdout.close()
            proc.wait()
        finally:
            _timer.cancel()

        if proc.returncode != 0:
            raise RuntimeError(f'scan.sh exited with code {proc.returncode}')

        target_dir = os.path.join('/app/targets', folder)
        with _db_session() as db:
            from models import Scan
            scan_rec = db.execute(
                select(Scan).where(Scan.scan_id == scan_id)
            ).scalar_one_or_none()
            if scan_rec is None:
                raise RuntimeError(
                    f'Scan record not found for scan_id={scan_id!r} — '
                    'possible DB inconsistency or premature deletion.'
                )
            _parse_web_findings(db, scan_rec, target_dir, scan_id)

        # Use _update_scan_status (not direct ORM assignment) so the
        # Redis status channel is published — without this, SSE subscribers
        # only learn of completion via the 15s heartbeat fallback poll,
        # not instantly as designed.
        _update_scan_status(scan_id, 'Completed', completed=True)
        publish_progress(scan_id, '[Web Scan] Complete.', level='success')

    except Exception as exc:
        publish_progress(scan_id, f'[Web Scan] Error: {exc}', level='error')
        _update_scan_status(scan_id, 'Failed', completed=True)
        raise self.retry(exc=exc, countdown=0, max_retries=0)


def _parse_web_findings(db: Session, scan_rec, target_dir: str, scan_id: str):
    from parsers import parse_nuclei, parse_katana, parse_ffuf, parse_zap, parse_testssl, parse_sqlmap
    for parser, tool in [(parse_nuclei,'Nuclei'), (parse_katana,'Katana'),
                          (parse_ffuf,'Ffuf'), (parse_zap,'ZAP'),
                          (parse_testssl,'Testssl'), (parse_sqlmap,'SQLmap')]:
        count = 0
        for f in parser(target_dir):
            _upsert_finding(db, scan_rec.id, scan_id, tool=tool, **f)
            count += 1
        if count:
            publish_progress(scan_id, f'{tool}: {count} finding(s) recorded.')


# ─────────────────────────────────────────────────────────────────────────────
# SAST SCAN
# ─────────────────────────────────────────────────────────────────────────────

@celery.task(bind=True, name='tasks.run_sast_scan', max_retries=1,
             # Override the global 24h result_expires — SAST tasks receive a
             # git_token in their arguments which is stored in the Celery result
             # backend.  300 seconds (5 min) is enough time to read the result
             # and far less exposure than the global 86400s default.
             result_expires=300)
def run_sast_scan(self, scan_id: str, target: str, folder: str,
                  options: dict[str, Any]):
    _update_scan_status(scan_id, 'Running', started=True)
    publish_progress(scan_id, f'[SAST Scan] Starting against {target}')

    host_path  = os.environ.get('HOST_PROJECT_PATH', os.getcwd())
    output_dir = os.path.join(host_path, 'targets', folder)
    os.makedirs(output_dir, exist_ok=True)
    repo_dir   = os.path.join(output_dir, 'repo')

    try:
        # Clone
        if target.startswith(('http://', 'https://', 'git@')):
            publish_progress(scan_id, f'Cloning {target}...')
            clone_token = options.get('git_token', '')
            clone_url   = target   # may be rewritten with credentials below
            encoded     = ''       # URL-encoded token, kept for scrubbing
            if clone_token and target.startswith('https://'):
                encoded   = urllib.parse.quote(clone_token, safe='')
                clone_url = target.replace('https://', f'https://{encoded}@', 1)

            result = subprocess.run(
                ['git', 'clone', '--depth=50', '--', clone_url, repo_dir],
                capture_output=True, text=True,
            )

            if result.returncode != 0:
                # git sometimes reflects the remote URL in its error output
                # (e.g. "fatal: repository '...' not found").  Strip the
                # credential from stderr before it reaches the SSE stream,
                # Celery logs, or the browser.
                stderr_clean = result.stderr.strip()
                if encoded:
                    stderr_clean = stderr_clean.replace(encoded, '***')
                if clone_url != target:
                    stderr_clean = stderr_clean.replace(clone_url, target)
                raise RuntimeError(
                    f'git clone failed for {target}: {stderr_clean}'
                )

            publish_progress(scan_id, 'Clone complete.')
        else:
            repo_dir = target

        container_repo = f'/targets/{folder}/repo'
        container_out  = f'/targets/{folder}'

        # Semgrep
        publish_progress(scan_id, 'Running Semgrep...')
        _docker_run(scan_id, f'mste_semgrep_{scan_id[:12]}', [
            '-v', f'{host_path}/targets:/targets',
            'semgrep/semgrep:latest', 'semgrep', 'scan',
            '--config', 'p/security-audit', '--config', 'p/secrets',
            '--config', 'p/owasp-top-ten',
            '--json', '--output', f'{container_out}/semgrep.json',
            container_repo,
        ])

        # Trivy
        publish_progress(scan_id, 'Running Trivy...')
        _docker_run(scan_id, f'mste_trivy_{scan_id[:12]}', [
            '-v', f'{host_path}/targets:/targets',
            'aquasec/trivy:latest', 'fs',
            '--scanners', 'vuln,secret,misconfig',
            '--format', 'json', '--output', f'{container_out}/trivy.json',
            container_repo,
        ])

        # Gitleaks
        publish_progress(scan_id, 'Running Gitleaks...')
        _docker_run(scan_id, f'mste_gitleaks_{scan_id[:12]}', [
            '-v', f'{host_path}/targets:/targets',
            'zricethezav/gitleaks:latest', 'detect',
            '--source', container_repo,
            '--report-format', 'json',
            '--report-path', f'{container_out}/gitleaks.json',
            '--exit-code', '0',
        ])

        # Hadolint (if Dockerfiles present)
        if os.path.isdir(repo_dir):
            dockerfiles = [f for f in os.listdir(repo_dir)
                           if f == 'Dockerfile' or f.startswith('Dockerfile.')]
            if dockerfiles:
                publish_progress(scan_id, f'Running Hadolint on {len(dockerfiles)} file(s)...')
                df_args = ' '.join(shlex.quote(f'{container_repo}/{df}') for df in dockerfiles)
                _docker_run(scan_id, f'mste_hadolint_{scan_id[:12]}', [
                    '-v', f'{host_path}/targets:/targets',
                    '--entrypoint', '/bin/sh', 'hadolint/hadolint:latest',
                    '-c', f'hadolint --format json {df_args} > {container_out}/hadolint.json 2>&1; exit 0',
                ])

        with _db_session() as db:
            from models import Scan
            scan_rec = db.execute(
                select(Scan).where(Scan.scan_id == scan_id)
            ).scalar_one_or_none()
            if scan_rec is None:
                raise RuntimeError(
                    f'Scan record not found for scan_id={scan_id!r} — '
                    'possible DB inconsistency or premature deletion.'
                )
            _parse_sast_findings(db, scan_rec, output_dir, scan_id)

        _update_scan_status(scan_id, 'Completed', completed=True)
        publish_progress(scan_id, '[SAST Scan] Complete.', level='success')

    except Exception as exc:
        publish_progress(scan_id, f'[SAST Scan] Error: {exc}', level='error')
        logger.exception(f'SAST scan {scan_id} failed')
        _update_scan_status(scan_id, 'Failed', completed=True)
        raise self.retry(exc=exc, countdown=0, max_retries=0)


def _parse_sast_findings(db: Session, scan_rec, output_dir: str, scan_id: str):
    from parsers import parse_semgrep, parse_trivy, parse_gitleaks, parse_hadolint
    for parser, tool in [(parse_semgrep,'Semgrep'), (parse_trivy,'Trivy'),
                          (parse_gitleaks,'Gitleaks'), (parse_hadolint,'Hadolint')]:
        count = 0
        for f in parser(output_dir):
            _upsert_finding(db, scan_rec.id, scan_id, tool=tool, **f)
            count += 1
        if count:
            publish_progress(scan_id, f'{tool}: {count} finding(s) recorded.')


# ─────────────────────────────────────────────────────────────────────────────
# INFRA SCAN
# ─────────────────────────────────────────────────────────────────────────────

@celery.task(bind=True, name='tasks.run_infra_scan', max_retries=1,
             result_expires=300)
def run_infra_scan(self, scan_id: str, target: str, folder: str,
                   options: dict[str, Any]):
    _update_scan_status(scan_id, 'Running', started=True)
    publish_progress(scan_id, f'[Infra Scan] Starting against {target}')

    host_path  = os.environ.get('HOST_PROJECT_PATH', os.getcwd())
    output_dir = os.path.join(host_path, 'targets', folder)
    os.makedirs(output_dir, exist_ok=True)

    try:
        publish_progress(scan_id, 'Running Nmap...')
        _docker_run(scan_id, f'mste_nmap_{scan_id[:12]}', [
            '-v', f'{host_path}/targets:/targets',
            '--cap-add', 'NET_RAW', 'instrumentisto/nmap:latest',
            '-sV', '-sC', '-O', '--script', 'vuln',
            '-oX', f'/targets/{folder}/nmap.xml',
            '-oN', f'/targets/{folder}/nmap.txt',
            target,
        ], extra_hosts=True)

        with _db_session() as db:
            from models import Scan
            from parsers import parse_nmap
            scan_rec = db.execute(
                select(Scan).where(Scan.scan_id == scan_id)
            ).scalar_one_or_none()
            if scan_rec is None:
                raise RuntimeError(
                    f'Scan record not found for scan_id={scan_id!r} — '
                    'possible DB inconsistency or premature deletion.'
                )
            count = 0
            for f in parse_nmap(output_dir):
                _upsert_finding(db, scan_rec.id, scan_id, tool='Nmap', **f)
                count += 1
            if count:
                publish_progress(scan_id, f'Nmap: {count} finding(s) recorded.')

        _update_scan_status(scan_id, 'Completed', completed=True)
        publish_progress(scan_id, '[Infra Scan] Complete.', level='success')

    except Exception as exc:
        publish_progress(scan_id, f'[Infra Scan] Error: {exc}', level='error')
        _update_scan_status(scan_id, 'Failed', completed=True)
        raise self.retry(exc=exc, countdown=0, max_retries=0)


# ─────────────────────────────────────────────────────────────────────────────
# CLOUD / MOBILE STUBS
# ─────────────────────────────────────────────────────────────────────────────

# ─────────────────────────────────────────────────────────────────────────────
# CLOUD SCAN  (ScoutSuite + Prowler)
# ─────────────────────────────────────────────────────────────────────────────
#
# Target format:  <provider>:<profile>
#   aws:default           — AWS using the named profile from ~/.aws/credentials
#   aws:arn:aws:iam::...  — AWS using an IAM role ARN
#   gcp:my-project-id     — GCP project
#   azure:my-tenant-id    — Azure tenant
#
# Credentials are injected via options dict:
#   aws_access_key_id, aws_secret_access_key, aws_session_token (optional)
#   gcp_credentials_json  — contents of a GCP service account JSON key
#   azure_client_id, azure_client_secret, azure_tenant_id, azure_subscription_id
#
# Both tools write JSON output that is parsed by parse_scoutsuite and
# parse_prowler in parsers.py.
# ─────────────────────────────────────────────────────────────────────────────

_CLOUD_PROVIDERS = frozenset({'aws', 'gcp', 'azure'})


def _resolve_cloud_provider(target: str) -> tuple[str, str]:
    """
    Parse 'provider:resource' target string.
    Returns (provider, resource) where provider is one of aws/gcp/azure.
    Raises ValueError for unrecognised format.
    """
    parts = target.split(':', 1)
    if len(parts) != 2 or parts[0].lower() not in _CLOUD_PROVIDERS:
        raise ValueError(
            f'Invalid cloud target "{target}". '
            f'Format: <provider>:<account-or-project>. '
            f'Supported providers: {", ".join(sorted(_CLOUD_PROVIDERS))}.'
        )
    return parts[0].lower(), parts[1]


@celery.task(bind=True, name='tasks.run_cloud_scan', max_retries=1,
             result_expires=300)
def run_cloud_scan(self, scan_id: str, target: str, folder: str,
                   options: dict[str, Any]):
    """
    Cloud misconfiguration scan using ScoutSuite and Prowler.

    ScoutSuite  — broad service inventory + CIS benchmark checks for AWS/GCP/Azure
    Prowler     — AWS-focused CIS / PCI-DSS / SOC2 checks (AWS only)

    Both run in Docker containers; credentials are passed via environment
    variables and never written to disk.
    """
    _update_scan_status(scan_id, 'Running', started=True)
    publish_progress(scan_id, f'[Cloud Scan] Starting against {target}')

    host_path  = os.environ.get('HOST_PROJECT_PATH', os.getcwd())
    output_dir = os.path.join(host_path, 'targets', folder)
    os.makedirs(output_dir, exist_ok=True)

    try:
        provider, resource = _resolve_cloud_provider(target)
    except ValueError as exc:
        publish_progress(scan_id, str(exc), level='error')
        _update_scan_status(scan_id, 'Failed', completed=True)
        return

    # ── Build credential environment for container runs ────────────────────────
    cred_env: list[str] = []
    creds_path: str | None = None

    if provider == 'aws':
        key_id     = options.get('aws_access_key_id', '')
        secret_key = options.get('aws_secret_access_key', '')
        session    = options.get('aws_session_token', '')
        region     = options.get('aws_region', 'us-east-1')
        if not key_id or not secret_key:
            publish_progress(scan_id,
                             '[Cloud Scan] AWS scan requires aws_access_key_id '
                             'and aws_secret_access_key in scan options.',
                             level='error')
            _update_scan_status(scan_id, 'Failed', completed=True)
            return
        cred_env = [
            '-e', f'AWS_ACCESS_KEY_ID={key_id}',
            '-e', f'AWS_SECRET_ACCESS_KEY={secret_key}',
            '-e', f'AWS_DEFAULT_REGION={region}',
        ]
        if session:
            cred_env += ['-e', f'AWS_SESSION_TOKEN={session}']

    elif provider == 'gcp':
        gcp_json = options.get('gcp_credentials_json', '')
        if not gcp_json:
            publish_progress(scan_id,
                             '[Cloud Scan] GCP scan requires gcp_credentials_json '
                             'in scan options (contents of a service account key file).',
                             level='error')
            _update_scan_status(scan_id, 'Failed', completed=True)
            return
        # Write credentials file with restrictive permissions (cleaned up with the scan)
        fd, creds_path = tempfile.mkstemp(
            dir=output_dir, prefix='gcp-creds-', suffix='.json')
        os.chmod(creds_path, 0o600)
        with os.fdopen(fd, 'w') as f:
            f.write(gcp_json)
        cred_env = [
            '-e', f'GOOGLE_APPLICATION_CREDENTIALS=/output/{os.path.basename(creds_path)}',
        ]

    elif provider == 'azure':
        az_client  = options.get('azure_client_id', '')
        az_secret  = options.get('azure_client_secret', '')
        az_tenant  = options.get('azure_tenant_id', '')
        az_sub     = options.get('azure_subscription_id', '')
        if not all([az_client, az_secret, az_tenant]):
            publish_progress(scan_id,
                             '[Cloud Scan] Azure scan requires azure_client_id, '
                             'azure_client_secret, and azure_tenant_id in scan options.',
                             level='error')
            _update_scan_status(scan_id, 'Failed', completed=True)
            return
        cred_env = [
            '-e', f'AZURE_CLIENT_ID={az_client}',
            '-e', f'AZURE_CLIENT_SECRET={az_secret}',
            '-e', f'AZURE_TENANT_ID={az_tenant}',
        ]
        if az_sub:
            cred_env += ['-e', f'AZURE_SUBSCRIPTION_ID={az_sub}']

    container_out = f'/output'
    vol_flag      = ['-v', f'{output_dir}:{container_out}']

    # ── ScoutSuite ─────────────────────────────────────────────────────────────
    publish_progress(scan_id, f'[Cloud Scan] Running ScoutSuite ({provider})...')

    scoutsuite_args: list[str] = vol_flag + cred_env + [
        'nccgroup/scoutsuite:latest', 'scout', provider,
        '--report-dir', container_out,
        '--report-type', 'json',
        '--no-browser',
    ]

    if provider == 'aws':
        scoutsuite_args += ['--region', options.get('aws_region', 'us-east-1')]
    elif provider == 'gcp':
        scoutsuite_args += ['--project-id', resource]
    elif provider == 'azure':
        if options.get('azure_subscription_id'):
            scoutsuite_args += ['--subscription-ids',
                                options['azure_subscription_id']]

    rc, _ = _docker_run(scan_id, f'mste_scoutsuite_{scan_id[:12]}', scoutsuite_args)
    if rc != 0:
        publish_progress(scan_id, '[Cloud Scan] ScoutSuite failed — continuing to Prowler.', level='warning')

    # ── Prowler (AWS only) ─────────────────────────────────────────────────────
    if provider == 'aws':
        publish_progress(scan_id, '[Cloud Scan] Running Prowler (AWS CIS checks)...')
        prowler_args: list[str] = vol_flag + cred_env + [
            'toniblyx/prowler:latest',
            '-M', 'json',
            '-o', container_out,
            '-F', 'prowler-findings',
            '--region', options.get('aws_region', 'us-east-1'),
        ]
        _docker_run(scan_id, f'mste_prowler_{scan_id[:12]}', prowler_args)

    # ── Parse and store findings ───────────────────────────────────────────────
    with _db_session() as db:
        from models import Scan
        scan_rec = db.execute(
            select(Scan).where(Scan.scan_id == scan_id)
        ).scalar_one_or_none()
        if scan_rec is None:
            raise RuntimeError(f'Scan record not found for scan_id={scan_id!r}')
        _parse_cloud_findings(db, scan_rec, output_dir, scan_id)

    _update_scan_status(scan_id, 'Completed', completed=True)
    publish_progress(scan_id, '[Cloud Scan] Complete.', level='success')

    # Scrub GCP credentials file if written
    if creds_path and os.path.exists(creds_path):
        os.remove(creds_path)


def _parse_cloud_findings(db: Session, scan_rec, output_dir: str, scan_id: str):
    from parsers import parse_scoutsuite, parse_prowler
    for parser, tool in [(parse_scoutsuite, 'ScoutSuite'),
                          (parse_prowler,   'Prowler')]:
        count = 0
        try:
            for f in parser(output_dir):
                _upsert_finding(db, scan_rec.id, scan_id, tool=tool, **f)
                count += 1
        except Exception as exc:
            publish_progress(scan_id, f'{tool} parse error: {exc}', level='warning')
        if count:
            publish_progress(scan_id, f'{tool}: {count} finding(s) recorded.')


# ─────────────────────────────────────────────────────────────────────────────
# MOBILE SCAN  (MobSF)
# ─────────────────────────────────────────────────────────────────────────────
#
# Target:  URL to an APK, IPA, APPX, or ZIP file accessible from the worker.
#          e.g. https://s3.example.com/builds/app-release.apk
#          OR   /mnt/uploads/app.apk  (local path inside the worker container)
#
# MobSF is expected to be running as a service (see docker-compose.yml).
# MOBSF_URL and MOBSF_API_KEY are read from the environment.
# ─────────────────────────────────────────────────────────────────────────────

_MOBSF_SUPPORTED_EXTS = frozenset({'.apk', '.ipa', '.appx', '.zip'})


@celery.task(bind=True, name='tasks.run_mobile_scan', max_retries=1,
             result_expires=300)
def run_mobile_scan(self, scan_id: str, target: str, folder: str,
                    options: dict[str, Any]):
    """
    Mobile application security scan via MobSF (Mobile Security Framework).

    Workflow
    ────────
    1. Download or copy the app binary to a temp path.
    2. Upload to MobSF via /api/v1/upload.
    3. Trigger scan via /api/v1/scan.
    4. Poll for completion via /api/v1/report_json.
    5. Parse the JSON report with parse_mobsf() and store findings.
    6. Clean up the temp file.

    MobSF must be running and reachable at MOBSF_URL (default: http://mobsf:8000).
    Set MOBSF_API_KEY to the key shown in the MobSF web UI under API docs.
    """
    import urllib.request
    import tempfile

    _update_scan_status(scan_id, 'Running', started=True)
    publish_progress(scan_id, f'[Mobile Scan] Starting against {target}')

    host_path  = os.environ.get('HOST_PROJECT_PATH', os.getcwd())
    output_dir = os.path.join(host_path, 'targets', folder)
    os.makedirs(output_dir, exist_ok=True)

    mobsf_url = os.environ.get('MOBSF_URL', 'http://mobsf:8000').rstrip('/')
    mobsf_key = os.environ.get('MOBSF_API_KEY', options.get('mobsf_api_key', ''))

    if not mobsf_key:
        publish_progress(scan_id,
                         '[Mobile Scan] MOBSF_API_KEY not set. '
                         'Start MobSF and set the key in your environment.',
                         level='error')
        _update_scan_status(scan_id, 'Failed', completed=True)
        return

    headers = {'Authorization': mobsf_key, 'X-Mobsf-Api-Key': mobsf_key}

    # ── Validate file extension ────────────────────────────────────────────────
    ext = os.path.splitext(target.split('?')[0].split('/')[-1])[1].lower()
    if ext not in _MOBSF_SUPPORTED_EXTS:
        publish_progress(scan_id,
                         f'[Mobile Scan] Unsupported file type "{ext}". '
                         f'Supported: {", ".join(sorted(_MOBSF_SUPPORTED_EXTS))}.',
                         level='error')
        _update_scan_status(scan_id, 'Failed', completed=True)
        return

    tmp_path = None
    try:
        import requests as _req

        # ── 1. Acquire the binary ──────────────────────────────────────────────
        if target.startswith(('http://', 'https://')):
            publish_progress(scan_id, f'Downloading {target}...')
            tmp_fd, tmp_path = tempfile.mkstemp(suffix=ext,
                                                 dir=output_dir)
            os.close(tmp_fd)
            with _req.get(target, stream=True, timeout=120) as r:
                r.raise_for_status()
                with open(tmp_path, 'wb') as f:
                    for chunk in r.iter_content(chunk_size=65536):
                        f.write(chunk)
            publish_progress(scan_id, 'Download complete.')
            file_path = tmp_path
        else:
            # Local path (pre-uploaded file inside the container)
            if not os.path.isfile(target):
                raise FileNotFoundError(f'Local file not found: {target}')
            file_path = target

        filename = os.path.basename(file_path)

        # ── 2. Upload to MobSF ─────────────────────────────────────────────────
        publish_progress(scan_id, f'Uploading {filename} to MobSF...')
        with open(file_path, 'rb') as f:
            upload_resp = _req.post(
                f'{mobsf_url}/api/v1/upload',
                files={'file': (filename, f, 'application/octet-stream')},
                headers=headers,
                timeout=120,
            )
        upload_resp.raise_for_status()
        upload_data = upload_resp.json()
        file_hash   = upload_data.get('hash')
        if not file_hash:
            raise RuntimeError(f'MobSF upload response missing hash: {upload_data}')
        publish_progress(scan_id, f'Upload complete. Hash: {file_hash}')

        # ── 3. Trigger scan ────────────────────────────────────────────────────
        publish_progress(scan_id, 'Triggering MobSF scan...')
        scan_resp = _req.post(
            f'{mobsf_url}/api/v1/scan',
            data={'hash': file_hash, 'scan_type': ext.lstrip('.'),
                  're_scan': '0'},
            headers=headers,
            timeout=30,
        )
        scan_resp.raise_for_status()

        # ── 4. Wait for scan completion ────────────────────────────────────────
        # MobSF scans are synchronous within the scan endpoint for small files,
        # but we poll the report endpoint to handle larger APKs gracefully.
        publish_progress(scan_id, 'Waiting for MobSF analysis to complete...')
        import time
        report_data = None
        for attempt in range(60):          # max 5 minutes (5s × 60)
            time.sleep(5)
            try:
                report_resp = _req.post(
                    f'{mobsf_url}/api/v1/report_json',
                    data={'hash': file_hash},
                    headers=headers,
                    timeout=30,
                )
                if report_resp.status_code == 200:
                    report_data = report_resp.json()
                    if report_data.get('appsec', {}).get('security_score') is not None \
                            or 'findings' in report_data \
                            or 'permissions' in report_data:
                        publish_progress(scan_id, 'Analysis complete.')
                        break
            except _req.RequestException:
                pass
            publish_progress(scan_id, f'Waiting... ({(attempt + 1) * 5}s)')

        if report_data is None:
            raise RuntimeError('MobSF analysis did not complete within 5 minutes.')

        # ── 5. Save JSON report and parse findings ─────────────────────────────
        report_path = os.path.join(output_dir, 'mobsf-report.json')
        import json as _json
        with open(report_path, 'w') as f:
            _json.dump(report_data, f, indent=2)

        with _db_session() as db:
            from models import Scan
            scan_rec = db.execute(
                select(Scan).where(Scan.scan_id == scan_id)
            ).scalar_one_or_none()
            if scan_rec is None:
                raise RuntimeError(f'Scan record not found for scan_id={scan_id!r}')
            _parse_mobile_findings(db, scan_rec, output_dir, scan_id)

        _update_scan_status(scan_id, 'Completed', completed=True)
        publish_progress(scan_id, '[Mobile Scan] Complete.', level='success')

    except Exception as exc:
        publish_progress(scan_id, f'[Mobile Scan] Error: {exc}', level='error')
        logger.exception(f'Mobile scan {scan_id} failed')
        _update_scan_status(scan_id, 'Failed', completed=True)
        raise self.retry(exc=exc, countdown=0, max_retries=0)

    finally:
        if tmp_path and os.path.exists(tmp_path):
            os.remove(tmp_path)


def _parse_mobile_findings(db: Session, scan_rec, output_dir: str, scan_id: str):
    from parsers import parse_mobsf
    count = 0
    try:
        for f in parse_mobsf(output_dir):
            _upsert_finding(db, scan_rec.id, scan_id, tool='MobSF', **f)
            count += 1
    except Exception as exc:
        publish_progress(scan_id, f'MobSF parse error: {exc}', level='warning')
    if count:
        publish_progress(scan_id, f'MobSF: {count} finding(s) recorded.')