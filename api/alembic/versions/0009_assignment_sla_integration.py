"""add assignment sla integration notification

Revision ID: 0009_assignment_sla_integration
Revises: 0008_tool_count
Create Date: 2025-07-04 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa

revision       = '0009_assignment_sla_integration'
down_revision  = '0008_tool_count'
branch_labels  = None
depends_on     = None


def upgrade() -> None:
    # ── Finding assignment & SLA fields ────────────────────────────────────────
    op.add_column('findings', sa.Column('assigned_to', sa.Integer(), nullable=True))
    op.add_column('findings', sa.Column('due_date', sa.DateTime(), nullable=True))
    op.add_column('findings', sa.Column('external_ticket_id', sa.String(length=100), nullable=True))
    op.add_column('findings', sa.Column('external_ticket_url', sa.String(length=500), nullable=True))
    op.create_index('ix_findings_assigned_to', 'findings', ['assigned_to'])
    op.create_foreign_key(
        'fk_findings_assigned_to_users', 'findings', 'users',
        ['assigned_to'], ['id'],
    )

    # ── Integration configs table ──────────────────────────────────────────────
    op.create_table(
        'integration_configs',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('engagement_id', sa.Integer(), sa.ForeignKey('engagements.id'), nullable=False),
        sa.Column('provider', sa.String(length=50), nullable=False),
        sa.Column('base_url', sa.String(length=500), nullable=False),
        sa.Column('auth_token_encrypted', sa.String(length=500), nullable=False),
        sa.Column('project_key', sa.String(length=100), nullable=True),
        sa.Column('is_active', sa.Boolean(), default=True),
        sa.Column('created_at', sa.DateTime(), default=sa.func.now()),
    )
    op.create_index('ix_integration_configs_engagement', 'integration_configs', ['engagement_id'])

    # ── Notifications table ────────────────────────────────────────────────────
    op.create_table(
        'notifications',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('user_id', sa.Integer(), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('event_type', sa.String(length=80), nullable=False),
        sa.Column('title', sa.String(length=255), nullable=False),
        sa.Column('message', sa.Text(), nullable=False),
        sa.Column('link', sa.String(length=500), nullable=True),
        sa.Column('is_read', sa.Boolean(), default=False),
        sa.Column('created_at', sa.DateTime(), default=sa.func.now()),
    )
    op.create_index('ix_notifications_user_id', 'notifications', ['user_id'])
    op.create_index('ix_notifications_created_at', 'notifications', ['created_at'])


def downgrade() -> None:
    op.drop_index('ix_notifications_created_at', table_name='notifications')
    op.drop_index('ix_notifications_user_id', table_name='notifications')
    op.drop_table('notifications')

    op.drop_index('ix_integration_configs_engagement', table_name='integration_configs')
    op.drop_table('integration_configs')

    op.drop_constraint('fk_findings_assigned_to_users', 'findings', type_='foreignkey')
    op.drop_index('ix_findings_assigned_to', table_name='findings')
    op.drop_column('findings', 'external_ticket_url')
    op.drop_column('findings', 'external_ticket_id')
    op.drop_column('findings', 'due_date')
    op.drop_column('findings', 'assigned_to')
