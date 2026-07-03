"""add report_template_id to engagements

Revision ID: 0003_engagement_template_fk
Revises: 0002_perf_and_integrity
Create Date: 2025-06-01 01:00:00.000000

Changes
-------
- engagements.report_template_id  — nullable FK to report_templates.id
  Allows per-engagement custom logo/branding.  NULL means "use the system
  default template" (the template with is_default=True).
"""

from alembic import op
import sqlalchemy as sa

revision      = '0003_engagement_template_fk'
down_revision = '0002_perf_and_integrity'
branch_labels = None
depends_on    = None


def upgrade() -> None:
    op.add_column(
        'engagements',
        sa.Column('report_template_id', sa.Integer(), nullable=True),
    )
    op.create_foreign_key(
        'fk_engagements_report_template',
        'engagements', 'report_templates',
        ['report_template_id'], ['id'],
        ondelete='SET NULL',   # removing a template reverts to system default
    )
    op.create_index(
        'ix_engagements_report_template_id',
        'engagements', ['report_template_id'],
    )


def downgrade() -> None:
    op.drop_index('ix_engagements_report_template_id', table_name='engagements')
    op.drop_constraint('fk_engagements_report_template',
                       'engagements', type_='foreignkey')
    op.drop_column('engagements', 'report_template_id')
