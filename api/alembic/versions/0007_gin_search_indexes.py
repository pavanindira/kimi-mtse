"""add trigram gin indexes for search columns

Revision ID: 0007_gin_search_indexes
Revises: 0006_engagement_webhook_secret
Create Date: 2025-07-04 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa

revision       = '0007_gin_search_indexes'
down_revision  = '0006_engagement_webhook_secret'
branch_labels  = None
depends_on     = None


def upgrade() -> None:
    # Ensure pg_trgm is available (idempotent — already created in 0001_initial)
    op.execute("CREATE EXTENSION IF NOT EXISTS pg_trgm")

    # GIN trigram index on findings.description for fast ILIKE search
    op.execute("""
        CREATE INDEX IF NOT EXISTS ix_findings_description_trgm
        ON findings USING gin (description gin_trgm_ops)
    """)

    # GIN trigram index on findings.remediation for fast ILIKE search
    op.execute("""
        CREATE INDEX IF NOT EXISTS ix_findings_remediation_trgm
        ON findings USING gin (remediation gin_trgm_ops)
    """)

    # GIN trigram index on engagements.name for fast ILIKE search
    op.execute("""
        CREATE INDEX IF NOT EXISTS ix_engagements_name_trgm
        ON engagements USING gin (name gin_trgm_ops)
    """)

    # GIN trigram index on engagements.client_name for fast ILIKE search
    op.execute("""
        CREATE INDEX IF NOT EXISTS ix_engagements_client_name_trgm
        ON engagements USING gin (client_name gin_trgm_ops)
    """)


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_engagements_client_name_trgm")
    op.execute("DROP INDEX IF EXISTS ix_engagements_name_trgm")
    op.execute("DROP INDEX IF EXISTS ix_findings_remediation_trgm")
    op.execute("DROP INDEX IF EXISTS ix_findings_description_trgm")
