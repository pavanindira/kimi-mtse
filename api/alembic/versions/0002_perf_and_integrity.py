"""add composite indexes, engagement status constraint, description trgm index

Revision ID: 0002_perf_and_integrity
Revises: 0001_initial
Create Date: 2025-06-01 00:00:00.000000

Changes
-------
Engagements
  - ix_engagements_created_by  — speeds up list_engagements for non-Admin users
                                  (WHERE created_by = ?) after multi-tenancy work
  - ix_engagements_status      — speeds up status filter on engagement list
  - ck_engagements_status      — CHECK constraint: only Active/Completed/Archived

Findings
  - ix_findings_scan_severity  — composite (scan_id_fk, severity): findings panel
  - ix_findings_scan_status    — composite (scan_id_fk, status):   findings panel
  - ix_findings_scan_dedup     — composite (scan_id_fk, dedup_hash): delta view

Full-text search
  - ix_findings_desc_trgm      — GIN trigram index on description column;
                                  replaces the leading-wildcard ILIKE that forced
                                  a full table scan.
"""

from alembic import op
import sqlalchemy as sa

revision      = '0002_perf_and_integrity'
down_revision = '0001_initial'
branch_labels = None
depends_on    = None


def upgrade() -> None:
    # ── Engagements: indexes + status constraint ───────────────────────────────
    op.create_index(
        'ix_engagements_created_by', 'engagements', ['created_by']
    )
    op.create_index(
        'ix_engagements_status', 'engagements', ['status']
    )
    op.create_check_constraint(
        'ck_engagements_status',
        'engagements',
        "status IN ('Active', 'Completed', 'Archived')",
    )

    # ── Findings: composite indexes ────────────────────────────────────────────
    op.create_index(
        'ix_findings_scan_severity', 'findings', ['scan_id_fk', 'severity']
    )
    op.create_index(
        'ix_findings_scan_status', 'findings', ['scan_id_fk', 'status']
    )
    op.create_index(
        'ix_findings_scan_dedup', 'findings', ['scan_id_fk', 'dedup_hash']
    )

    # ── Full-text search: GIN trigram index on description ─────────────────────
    # pg_trgm is already enabled by the initial migration.
    # This index allows the search router's description ILIKE to use the
    # index instead of a sequential scan.
    op.execute("""
        CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_findings_desc_trgm
        ON findings USING gin (description gin_trgm_ops)
    """)


def downgrade() -> None:
    op.execute('DROP INDEX IF EXISTS ix_findings_desc_trgm')

    op.drop_index('ix_findings_scan_dedup',    table_name='findings')
    op.drop_index('ix_findings_scan_status',   table_name='findings')
    op.drop_index('ix_findings_scan_severity', table_name='findings')

    op.drop_constraint('ck_engagements_status', 'engagements', type_='check')
    op.drop_index('ix_engagements_status',     table_name='engagements')
    op.drop_index('ix_engagements_created_by', table_name='engagements')
