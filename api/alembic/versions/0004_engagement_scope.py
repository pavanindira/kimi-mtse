"""add scope to engagements

Revision ID: 0004_engagement_scope
Revises: 0003_engagement_template_fk
Create Date: 2025-06-01 02:00:00.000000

Changes
-------
- engagements.scope  — nullable Text column for newline-separated scope entries
  (CIDRs, hostnames, URL prefixes).  NULL means "no scope restriction defined".
"""

from alembic import op
import sqlalchemy as sa

revision      = '0004_engagement_scope'
down_revision = '0003_engagement_template_fk'
branch_labels = None
depends_on    = None


def upgrade() -> None:
    op.add_column(
        'engagements',
        sa.Column('scope', sa.Text(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column('engagements', 'scope')
