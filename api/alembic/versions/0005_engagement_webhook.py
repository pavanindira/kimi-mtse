"""add webhook_url to engagements

Revision ID: 0005_engagement_webhook
Revises: 0004_engagement_scope
Create Date: 2026-07-03 00:00:00.000000

Changes
-------
- engagements.webhook_url — nullable String(500). When set, the scan-
  completion worker POSTs a JSON payload to this URL after a scan on the
  engagement reaches a terminal status (Completed/Failed/Cancelled).
  NULL means "no webhook configured". Validated at the API layer (http/https
  scheme + SSRF blocklist) — see schemas.py::_validate_webhook_url.
"""

from alembic import op
import sqlalchemy as sa

revision      = '0005_engagement_webhook'
down_revision = '0004_engagement_scope'
branch_labels = None
depends_on    = None


def upgrade() -> None:
    op.add_column(
        'engagements',
        sa.Column('webhook_url', sa.String(length=500), nullable=True),
    )


def downgrade() -> None:
    op.drop_column('engagements', 'webhook_url')
