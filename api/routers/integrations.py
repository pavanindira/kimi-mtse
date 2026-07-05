"""integrations.py router — /api/integrations/* and ticket creation"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from auth import AdminUser, AnalystUser, CurrentUser
from config import settings
from database import get_db
from integrations.jira import JiraClient, format_finding_for_jira
from models import Engagement, Finding, IntegrationConfig
from schemas import IntegrationConfigCreate, IntegrationConfigOut
from utils import add_audit_log, get_client_ip

router = APIRouter(prefix='/api/integrations', tags=['integrations'])


# ── Helpers ───────────────────────────────────────────────────────────────────

def _encrypt_token(token: str) -> str:
    """Encrypt an integration auth token using Fernet derived from JWT_SECRET.
    In production, use a dedicated encryption key, not JWT_SECRET."""
    from cryptography.fernet import Fernet
    import hashlib
    key = hashlib.sha256(settings.secret_key.get_secret_value().encode()).digest()
    f = Fernet(base64.urlsafe_b64encode(key))
    return f.encrypt(token.encode()).decode()


def _decrypt_token(encrypted: str) -> str:
    """Decrypt a previously encrypted auth token."""
    from cryptography.fernet import Fernet
    import hashlib, base64
    key = hashlib.sha256(settings.secret_key.get_secret_value().encode()).digest()
    f = Fernet(base64.urlsafe_b64encode(key))
    return f.decrypt(encrypted.encode()).decode()


# ── Integration Config CRUD ───────────────────────────────────────────────────

@router.post('', response_model=IntegrationConfigOut)
async def create_integration(
    body: IntegrationConfigCreate,
    current_user: AnalystUser,
    db: AsyncSession = Depends(get_db),
):
    """Create an integration config for an engagement."""
    # Verify engagement access
    eng = (await db.execute(
        select(Engagement).where(Engagement.id == body.engagement_id)
    )).scalar_one_or_none()
    if not eng:
        raise HTTPException(status_code=404, detail='Engagement not found')
    if current_user.role != 'Admin' and eng.created_by != current_user.id:
        raise HTTPException(status_code=403, detail='Access denied')

    cfg = IntegrationConfig(
        engagement_id=body.engagement_id,
        provider=body.provider,
        base_url=body.base_url,
        auth_token_encrypted=_encrypt_token(body.auth_token),
        project_key=body.project_key,
        is_active=True,
    )
    db.add(cfg)
    await db.flush()
    return cfg


@router.get('/engagement/{eng_id}', response_model=list[IntegrationConfigOut])
async def list_integrations(
    eng_id: int,
    current_user: CurrentUser,
    db: AsyncSession = Depends(get_db),
):
    """List integrations for an engagement."""
    eng = (await db.execute(
        select(Engagement).where(Engagement.id == eng_id)
    )).scalar_one_or_none()
    if not eng:
        raise HTTPException(status_code=404, detail='Engagement not found')
    if current_user.role != 'Admin' and eng.created_by != current_user.id:
        raise HTTPException(status_code=403, detail='Access denied')

    rows = await db.execute(
        select(IntegrationConfig).where(
            IntegrationConfig.engagement_id == eng_id,
            IntegrationConfig.is_active.is_(True),
        )
    )
    return rows.scalars().all()


@router.delete('/{cfg_id}')
async def delete_integration(
    cfg_id: int,
    current_user: AnalystUser,
    db: AsyncSession = Depends(get_db),
):
    """Soft-delete an integration config."""
    cfg = (await db.execute(
        select(IntegrationConfig).where(IntegrationConfig.id == cfg_id)
    )).scalar_one_or_none()
    if not cfg:
        raise HTTPException(status_code=404, detail='Integration not found')

    eng = (await db.execute(
        select(Engagement).where(Engagement.id == cfg.engagement_id)
    )).scalar_one_or_none()
    if current_user.role != 'Admin' and eng.created_by != current_user.id:
        raise HTTPException(status_code=403, detail='Access denied')

    cfg.is_active = False
    return {'success': True}


# ── Ticket Creation ───────────────────────────────────────────────────────────

@router.post('/{cfg_id}/ticket/{finding_id}')
async def create_ticket(
    cfg_id: int,
    finding_id: int,
    current_user: AnalystUser,
    db: AsyncSession = Depends(get_db),
):
    """Create a ticket in the integrated tracker for a specific finding."""
    cfg = (await db.execute(
        select(IntegrationConfig).where(
            IntegrationConfig.id == cfg_id,
            IntegrationConfig.is_active.is_(True),
        )
    )).scalar_one_or_none()
    if not cfg:
        raise HTTPException(status_code=404, detail='Integration not found')

    # Verify engagement access
    eng = (await db.execute(
        select(Engagement).where(Engagement.id == cfg.engagement_id)
    )).scalar_one_or_none()
    if current_user.role != 'Admin' and eng.created_by != current_user.id:
        raise HTTPException(status_code=403, detail='Access denied')

    # Fetch finding
    finding = (await db.execute(
        select(Finding).where(Finding.id == finding_id)
    )).scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail='Finding not found')

    # Ensure finding belongs to the engagement
    scan = (await db.execute(
        select(Scan).where(Scan.id == finding.scan_id_fk)
    )).scalar_one_or_none()
    if not scan or scan.engagement_id != cfg.engagement_id:
        raise HTTPException(status_code=403, detail='Finding does not belong to this engagement')

    if cfg.provider == 'jira':
        client = JiraClient(cfg.base_url, _decrypt_token(cfg.auth_token_encrypted))
        description = format_finding_for_jira(
            {
                'severity': finding.severity,
                'tool': finding.tool,
                'cvss_score': finding.cvss_score,
                'status': finding.status,
                'target_url': finding.target_url,
                'file_path': finding.file_path,
                'line_number': finding.line_number,
                'host': finding.host,
                'port': finding.port,
                'cve_id': finding.cve_id,
                'cwe_id': finding.cwe_id,
                'description': finding.description,
                'remediation': finding.remediation,
            },
            engagement_name=eng.name,
        )

        priority_map = {
            'Critical': 'Highest',
            'High': 'High',
            'Medium': 'Medium',
            'Low': 'Low',
            'Info': 'Lowest',
        }

        try:
            issue = await client.create_issue(
                project_key=cfg.project_key or '',
                summary=f"[MSTE] {finding.vulnerability_name}",
                description=description,
                issue_type="Bug",
                priority=priority_map.get(finding.severity),
                labels=["mste", f"severity-{finding.severity.lower()}"],
            )
        except Exception as e:
            raise HTTPException(status_code=502, detail=f'Jira API error: {e}')

        # Store ticket reference on finding
        finding.external_ticket_id = issue.get('key')
        finding.external_ticket_url = f"{cfg.base_url}/browse/{issue['key']}"

        add_audit_log(db, action='finding.ticket_created',
                      user_id=current_user.id, username=current_user.username,
                      target_type='finding', target_id=finding.id,
                      target_name=finding.vulnerability_name,
                      detail={'ticket_id': issue['key'], 'provider': 'jira'})

        return {
            'success': True,
            'ticket_id': issue['key'],
            'ticket_url': finding.external_ticket_url,
        }

    else:
        raise HTTPException(status_code=400, detail=f'Provider {cfg.provider} not yet supported')
