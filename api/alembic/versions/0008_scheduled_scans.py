"""add scheduled_scans table

Revision ID: 0008_scheduled_scans
Revises: 0007_webhook_deliveries
Create Date: 2026-07-05 00:00:00.000000

Changes
-------
- scheduled_scans — recurring scan configs, dispatched by a periodic Celery
  Beat task (tasks.py::run_scheduled_scans). Recurrence is a plain interval
  in hours rather than cron syntax. git_token_encrypted holds a
  Fernet-encrypted (crypto_utils.py) credential for scheduled SAST scans
  against private repos — never returned by any API response.
"""

from alembic import op
import sqlalchemy as sa

revision      = '0008_scheduled_scans'
down_revision = '0007_webhook_deliveries'
branch_labels = None
depends_on    = None


def upgrade() -> None:
    op.create_table(
        'scheduled_scans',
        sa.Column('id',                   sa.Integer(), primary_key=True),
        sa.Column('engagement_id',        sa.Integer(), nullable=False),
        sa.Column('scan_type',            sa.String(length=20), nullable=False),
        sa.Column('target',               sa.String(length=500), nullable=False),
        sa.Column('interval_hours',       sa.Integer(), nullable=False),
        sa.Column('enabled',              sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column('options',              sa.JSON(), nullable=True),
        sa.Column('git_token_encrypted',  sa.Text(), nullable=True),
        sa.Column('next_run_at',          sa.DateTime(), nullable=False),
        sa.Column('last_run_at',          sa.DateTime(), nullable=True),
        sa.Column('last_scan_id',         sa.String(length=16), nullable=True),
        sa.Column('created_by',           sa.Integer(), nullable=True),
        sa.Column('created_at',           sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['engagement_id'], ['engagements.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['created_by'], ['users.id']),
    )
    op.create_index('ix_scheduled_scans_engagement_id', 'scheduled_scans', ['engagement_id'])
    op.create_index('ix_scheduled_scans_next_run_at',   'scheduled_scans', ['next_run_at'])


def downgrade() -> None:
    op.drop_index('ix_scheduled_scans_next_run_at', table_name='scheduled_scans')
    op.drop_index('ix_scheduled_scans_engagement_id', table_name='scheduled_scans')
    op.drop_table('scheduled_scans')
