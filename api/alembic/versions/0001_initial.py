"""initial schema

Revision ID: 0001_initial
Revises:
Create Date: 2025-01-01 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa

revision       = '0001_initial'
down_revision  = None
branch_labels  = None
depends_on     = None


def upgrade() -> None:
    # ── users ──────────────────────────────────────────────────────────────
    op.create_table(
        'users',
        sa.Column('id',            sa.Integer(),     primary_key=True),
        sa.Column('username',      sa.String(100),   nullable=False, unique=True),
        sa.Column('password_hash', sa.String(255),   nullable=False),
        sa.Column('role',          sa.String(50),    nullable=False, server_default='Analyst'),
        sa.Column('created_at',    sa.DateTime(),    nullable=False,
                  server_default=sa.text('NOW()')),
        sa.Column('last_login',    sa.DateTime(),    nullable=True),
    )
    op.create_index('ix_users_username', 'users', ['username'], unique=True)

    # ── engagements ────────────────────────────────────────────────────────
    op.create_table(
        'engagements',
        sa.Column('id',           sa.Integer(),   primary_key=True),
        sa.Column('name',         sa.String(200), nullable=False),
        sa.Column('client_name',  sa.String(200), nullable=False),
        sa.Column('description',  sa.Text(),      nullable=True),
        sa.Column('status',       sa.String(50),  nullable=False, server_default='Active'),
        sa.Column('created_at',   sa.DateTime(),  nullable=False,
                  server_default=sa.text('NOW()')),
        sa.Column('updated_at',   sa.DateTime(),  nullable=False,
                  server_default=sa.text('NOW()')),
        sa.Column('started_at',   sa.DateTime(),  nullable=True),
        sa.Column('completed_at', sa.DateTime(),  nullable=True),
        sa.Column('created_by',   sa.Integer(),
                  sa.ForeignKey('users.id'), nullable=True),
    )

    # ── scans ──────────────────────────────────────────────────────────────
    op.create_table(
        'scans',
        sa.Column('id',             sa.Integer(),     primary_key=True),
        sa.Column('scan_id',        sa.String(16),    nullable=False, unique=True),
        sa.Column('engagement_id',  sa.Integer(),
                  sa.ForeignKey('engagements.id'), nullable=False),
        sa.Column('scan_type',      sa.String(20),    nullable=False),
        sa.Column('target',         sa.String(500),   nullable=False),
        sa.Column('folder_name',    sa.String(255),   nullable=False),
        sa.Column('status',         sa.String(50),    nullable=False,
                  server_default='Queued'),
        sa.Column('celery_task_id', sa.String(255),   nullable=True),
        sa.Column('options',        sa.JSON(),        nullable=True),
        sa.Column('created_at',     sa.DateTime(),    nullable=False,
                  server_default=sa.text('NOW()')),
        sa.Column('started_at',     sa.DateTime(),    nullable=True),
        sa.Column('completed_at',   sa.DateTime(),    nullable=True),
        sa.Column('created_by',     sa.Integer(),
                  sa.ForeignKey('users.id'), nullable=True),
    )
    op.create_index('ix_scans_scan_id',       'scans', ['scan_id'],       unique=True)
    op.create_index('ix_scans_status',        'scans', ['status'])
    op.create_index('ix_scans_engagement_id', 'scans', ['engagement_id'])

    # ── findings ───────────────────────────────────────────────────────────
    op.create_table(
        'findings',
        sa.Column('id',                 sa.Integer(),     primary_key=True),
        sa.Column('scan_id_fk',         sa.Integer(),
                  sa.ForeignKey('scans.id'), nullable=False),
        sa.Column('tool',               sa.String(50),    nullable=False),
        sa.Column('vulnerability_name', sa.String(500),   nullable=False),
        sa.Column('severity',           sa.String(50),    nullable=False),
        sa.Column('cvss_score',         sa.Float(),       nullable=True),
        sa.Column('cvss_vector',        sa.String(100),   nullable=True),
        sa.Column('cve_id',             sa.String(50),    nullable=True),
        sa.Column('cwe_id',             sa.String(50),    nullable=True),
        sa.Column('target_url',         sa.String(2048),  nullable=True),
        sa.Column('file_path',          sa.String(1024),  nullable=True),
        sa.Column('line_number',        sa.Integer(),     nullable=True),
        sa.Column('host',               sa.String(255),   nullable=True),
        sa.Column('port',               sa.Integer(),     nullable=True),
        sa.Column('description',        sa.Text(),        nullable=True),
        sa.Column('remediation',        sa.Text(),        nullable=True),
        sa.Column('status',             sa.String(50),    nullable=False,
                  server_default='Open'),
        sa.Column('analyst_notes',      sa.Text(),        nullable=True),
        sa.Column('dedup_hash',         sa.String(64),    nullable=True),
        sa.Column('first_seen',         sa.DateTime(),    nullable=False,
                  server_default=sa.text('NOW()')),
        sa.Column('last_seen',          sa.DateTime(),    nullable=False,
                  server_default=sa.text('NOW()')),
    )
    op.create_index('ix_findings_severity',   'findings', ['severity'])
    op.create_index('ix_findings_status',     'findings', ['status'])
    op.create_index('ix_findings_dedup_hash', 'findings', ['dedup_hash'])
    op.create_index('ix_findings_scan_id_fk', 'findings', ['scan_id_fk'])

    # pg_trgm index for fast ILIKE search on vulnerability names
    op.execute("CREATE EXTENSION IF NOT EXISTS pg_trgm")
    op.execute("""
        CREATE INDEX ix_findings_vuln_name_trgm
        ON findings USING gin (vulnerability_name gin_trgm_ops)
    """)

    # ── evidence ───────────────────────────────────────────────────────────
    op.create_table(
        'evidence',
        sa.Column('id',         sa.Integer(),    primary_key=True),
        sa.Column('finding_id', sa.Integer(),
                  sa.ForeignKey('findings.id'), nullable=False),
        sa.Column('ev_type',    sa.String(50),   nullable=False),
        sa.Column('label',      sa.String(200),  nullable=True),
        sa.Column('content',    sa.Text(),       nullable=True),
        sa.Column('file_path',  sa.String(512),  nullable=True),
        sa.Column('created_at', sa.DateTime(),   nullable=False,
                  server_default=sa.text('NOW()')),
    )
    op.create_index('ix_evidence_finding_id', 'evidence', ['finding_id'])

    # ── report_templates ───────────────────────────────────────────────────
    op.create_table(
        'report_templates',
        sa.Column('id',            sa.Integer(),  primary_key=True),
        sa.Column('name',          sa.String(200), nullable=False),
        sa.Column('html_template', sa.Text(),      nullable=False),
        sa.Column('logo_base64',   sa.Text(),      nullable=True),
        sa.Column('is_default',    sa.Boolean(),   nullable=False,
                  server_default='false'),
        sa.Column('created_at',    sa.DateTime(),  nullable=False,
                  server_default=sa.text('NOW()')),
    )

    # ── audit_logs ─────────────────────────────────────────────────────────
    op.create_table(
        'audit_logs',
        sa.Column('id',          sa.Integer(),    primary_key=True),
        sa.Column('timestamp',   sa.DateTime(),   nullable=False,
                  server_default=sa.text('NOW()')),
        sa.Column('user_id',     sa.Integer(),
                  sa.ForeignKey('users.id'), nullable=True),
        sa.Column('username',    sa.String(100),  nullable=True),
        sa.Column('action',      sa.String(80),   nullable=False),
        sa.Column('target_type', sa.String(50),   nullable=True),
        sa.Column('target_id',   sa.Integer(),    nullable=True),
        sa.Column('target_name', sa.String(255),  nullable=True),
        sa.Column('detail',      sa.JSON(),       nullable=True),
        sa.Column('ip_address',  sa.String(45),   nullable=True),
    )
    op.create_index('ix_audit_logs_timestamp', 'audit_logs', ['timestamp'])
    op.create_index('ix_audit_logs_action',    'audit_logs', ['action'])


def downgrade() -> None:
    op.drop_table('audit_logs')
    op.drop_table('report_templates')
    op.drop_table('evidence')
    op.drop_table('findings')
    op.drop_table('scans')
    op.drop_table('engagements')
    op.drop_table('users')
