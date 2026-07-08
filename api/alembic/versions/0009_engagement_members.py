"""add engagement_members table

Revision ID: 0009_engagement_members
Revises: 0008_scheduled_scans
Create Date: 2026-07-06 00:00:00.000000

Changes
-------
- engagement_members — grants additional users access to an engagement
  beyond its creator (engagements.created_by). Membership grants the same
  per-engagement access as ownership; it does not grant additional global
  role permissions. Only the owner or an Admin can add/remove members.
"""

from alembic import op
import sqlalchemy as sa

revision      = '0009_engagement_members'
down_revision = '0008_scheduled_scans'
branch_labels = None
depends_on    = None


def upgrade() -> None:
    op.create_table(
        'engagement_members',
        sa.Column('id',            sa.Integer(), primary_key=True),
        sa.Column('engagement_id', sa.Integer(), nullable=False),
        sa.Column('user_id',       sa.Integer(), nullable=False),
        sa.Column('added_by',      sa.Integer(), nullable=True),
        sa.Column('created_at',    sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['engagement_id'], ['engagements.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['added_by'], ['users.id']),
        sa.UniqueConstraint('engagement_id', 'user_id', name='uq_engagement_member'),
    )
    op.create_index('ix_engagement_members_engagement_id', 'engagement_members',
                    ['engagement_id'])
    op.create_index('ix_engagement_members_user_id', 'engagement_members', ['user_id'])


def downgrade() -> None:
    op.drop_index('ix_engagement_members_user_id', table_name='engagement_members')
    op.drop_index('ix_engagement_members_engagement_id', table_name='engagement_members')
    op.drop_table('engagement_members')
