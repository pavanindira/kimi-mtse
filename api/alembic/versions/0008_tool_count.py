"""add tool_count to findings

Revision ID: 0008_tool_count
Revises: 0007_gin_search_indexes
Create Date: 2025-07-04 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa

revision       = '0008_tool_count'
down_revision  = '0007_gin_search_indexes'
branch_labels  = None
depends_on     = None


def upgrade() -> None:
    op.add_column(
        'findings',
        sa.Column('tool_count', sa.Integer(), nullable=False, server_default='1'),
    )
    # Create an index for fast filtering on multi-tool confirmed findings
    op.create_index(
        'ix_findings_tool_count',
        'findings',
        ['tool_count'],
    )


def downgrade() -> None:
    op.drop_index('ix_findings_tool_count', table_name='findings')
    op.drop_column('findings', 'tool_count')
