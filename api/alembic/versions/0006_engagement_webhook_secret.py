"""add webhook_secret to engagements

Revision ID: 0006_engagement_webhook_secret
Revises: 0005_engagement_webhook
Create Date: 2026-07-03 00:00:00.000000

Changes
-------
- engagements.webhook_secret — nullable String(64). Auto-generated
  (secrets.token_hex(32)) the first time webhook_url is set on an
  engagement, used to HMAC-SHA256-sign the JSON body sent on scan
  completion. Never exposed via EngagementOut — only through the
  dedicated GET/POST reveal and rotate endpoints.
"""

from alembic import op
import sqlalchemy as sa

revision      = '0006_engagement_webhook_secret'
down_revision = '0005_engagement_webhook'
branch_labels = None
depends_on    = None


def upgrade() -> None:
    op.add_column(
        'engagements',
        sa.Column('webhook_secret', sa.String(length=64), nullable=True),
    )


def downgrade() -> None:
    op.drop_column('engagements', 'webhook_secret')
