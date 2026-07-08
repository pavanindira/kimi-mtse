"""add webhook_deliveries table

Revision ID: 0007_webhook_deliveries
Revises: 0006_engagement_webhook_secret
Create Date: 2026-07-04 00:00:00.000000

Changes
-------
- webhook_deliveries — delivery history for engagement webhooks (both real
  scan-completion dispatches and on-demand test pings). Capped at
  MAX_DELIVERIES_PER_ENGAGEMENT (20) rows per engagement, pruned on insert
  at the application layer — this is diagnostic history, not an audit
  trail, so no separate retention/cleanup job.
"""

from alembic import op
import sqlalchemy as sa

revision      = '0007_webhook_deliveries'
down_revision = '0006_engagement_webhook_secret'
branch_labels = None
depends_on    = None


def upgrade() -> None:
    op.create_table(
        'webhook_deliveries',
        sa.Column('id',               sa.Integer(), primary_key=True),
        sa.Column('engagement_id',    sa.Integer(), nullable=False),
        sa.Column('scan_id',          sa.String(length=64), nullable=True),
        sa.Column('event',            sa.String(length=50), nullable=False),
        sa.Column('url',              sa.String(length=500), nullable=False),
        sa.Column('success',          sa.Boolean(), nullable=False),
        sa.Column('status_code',      sa.Integer(), nullable=True),
        sa.Column('error',            sa.Text(), nullable=True),
        sa.Column('response_snippet', sa.String(length=500), nullable=True),
        sa.Column('duration_ms',      sa.Integer(), nullable=True),
        sa.Column('created_at',       sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['engagement_id'], ['engagements.id'], ondelete='CASCADE'),
    )
    op.create_index('ix_webhook_deliveries_engagement_id', 'webhook_deliveries',
                    ['engagement_id'])
    op.create_index('ix_webhook_deliveries_created_at', 'webhook_deliveries',
                    ['created_at'])


def downgrade() -> None:
    op.drop_index('ix_webhook_deliveries_created_at', table_name='webhook_deliveries')
    op.drop_index('ix_webhook_deliveries_engagement_id', table_name='webhook_deliveries')
    op.drop_table('webhook_deliveries')
