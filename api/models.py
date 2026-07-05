"""
models.py — SQLAlchemy 2.0 ORM models for MSTE v2.

Uses pure SQLAlchemy (no Flask-SQLAlchemy).
The Base class comes from database.py so Alembic and the async engine
share the same metadata.

Hierarchy:
    User
    Engagement  (one per client engagement)
      └── Scan  (web / sast / infra / cloud / mobile)
            └── Finding  (one per unique vulnerability instance)
                  └── Evidence  (request/response, code snippets, screenshots)
    AuditLog    (append-only action record)
    ReportTemplate
"""

from __future__ import annotations
from datetime import datetime, timezone
from typing import List, Optional

from sqlalchemy import (
    Boolean, CheckConstraint, DateTime, Float, ForeignKey, func, Index, Integer,
    JSON, select, String, Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from database import Base


# ── Constants shared with schemas.py ─────────────────────────────────────────

SCAN_TYPES       = ('web', 'sast', 'infra', 'cloud', 'mobile')
SEVERITIES       = ('Critical', 'High', 'Medium', 'Low', 'Info')
FINDING_STATUSES = ('Open', 'Confirmed', 'False Positive', 'Fixed', 'Accepted Risk')
SCAN_STATUSES    = ('Queued', 'Running', 'Completed', 'Failed', 'Cancelled')

SEVERITY_CVSS_MAP = {
    'Critical': 9.5, 'High': 8.0, 'Medium': 5.5, 'Low': 2.5, 'Info': 0.0,
}

AUDIT_ACTIONS = (
    'user.login', 'user.logout', 'user.token_refreshed', 'user.password_changed',
    'user.created', 'user.deleted', 'user.role_changed',
    'engagement.created', 'engagement.updated', 'engagement.deleted',
    'scan.started', 'scan.completed', 'scan.failed', 'scan.cancelled',
    'finding.status_changed', 'finding.bulk_status_changed',
    'finding.notes_updated',  'finding.created_manual',
    'report.exported',
    'report_template.logo_uploaded', 'report_template.logo_deleted',
    'report_template.set_default',
)


# ── Users ─────────────────────────────────────────────────────────────────────

class User(Base):
    __tablename__ = 'users'

    id:            Mapped[int]          = mapped_column(Integer, primary_key=True)
    username:      Mapped[str]          = mapped_column(String(100), unique=True, nullable=False)
    password_hash: Mapped[str]          = mapped_column(String(255), nullable=False)
    role:          Mapped[str]          = mapped_column(String(50), default='Analyst')
    created_at:    Mapped[datetime]     = mapped_column(DateTime, default=func.now())
    last_login:    Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    def __repr__(self) -> str:
        return f'<User {self.username} ({self.role})>'


# ── Engagements ───────────────────────────────────────────────────────────────

class Engagement(Base):
    __tablename__ = 'engagements'
    __table_args__ = (
        # created_by is now the primary filter for non-admin list queries
        Index('ix_engagements_created_by', 'created_by'),
        # status is filtered on list_engagements and delta queries
        Index('ix_engagements_status', 'status'),
        # Enforce valid status values at the DB level
        CheckConstraint(
            "status IN ('Active', 'Completed', 'Archived')",
            name='ck_engagements_status',
        ),
    )

    id:           Mapped[int]               = mapped_column(Integer, primary_key=True)
    name:         Mapped[str]               = mapped_column(String(200), nullable=False)
    client_name:  Mapped[str]               = mapped_column(String(200), nullable=False)
    description:  Mapped[Optional[str]]     = mapped_column(Text, nullable=True)
    status:       Mapped[str]               = mapped_column(String(50), default='Active')
    created_at:   Mapped[datetime]          = mapped_column(DateTime, default=func.now())
    updated_at:   Mapped[datetime]          = mapped_column(
        DateTime, default=func.now(), onupdate=func.now())
    started_at:   Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    created_by:   Mapped[Optional[int]]     = mapped_column(
        Integer, ForeignKey('users.id'), nullable=True)
    # Optional scope definition for the engagement.
    # Stored as a newline-separated list of allowed targets:
    # CIDR ranges (10.0.0.0/8), hostnames (*.example.com), URL prefixes (https://app.example.com).
    # When set, start_scan warns (but does not block) if the target falls outside scope.
    scope:        Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    report_template_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey('report_templates.id'), nullable=True)
    # Optional HTTP(S) endpoint notified when a scan on this engagement
    # finishes (Completed/Failed/Cancelled). Validated at write time in
    # schemas.py (http/https + SSRF blocklist) — see EngagementCreate/Update.
    webhook_url:  Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    # HMAC-SHA256 signing key for webhook payloads. Auto-generated the first
    # time webhook_url is set (see routers/engagements.py), never returned by
    # EngagementOut — only via the dedicated reveal/rotate endpoints, since
    # it's a bearer credential for anyone verifying webhook authenticity.
    webhook_secret: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    scans:           Mapped[List[Scan]]             = relationship('Scan', back_populates='engagement',
                                                                    cascade='all, delete-orphan', lazy='select')
    creator:         Mapped[Optional[User]]          = relationship('User', foreign_keys=[created_by])
    report_template: Mapped[Optional['ReportTemplate']] = relationship(
        'ReportTemplate', foreign_keys=[report_template_id])

    def __repr__(self) -> str:
        return f'<Engagement {self.name} — {self.client_name}>'


# ── Scans ─────────────────────────────────────────────────────────────────────

class Scan(Base):
    __tablename__ = 'scans'
    __table_args__ = (
        Index('ix_scans_scan_id',      'scan_id'),
        Index('ix_scans_status',       'status'),
        Index('ix_scans_engagement_id','engagement_id'),
    )

    id:             Mapped[int]          = mapped_column(Integer, primary_key=True)
    scan_id:        Mapped[str]          = mapped_column(String(16), unique=True, nullable=False)
    engagement_id:  Mapped[int]          = mapped_column(
        Integer, ForeignKey('engagements.id'), nullable=False)
    scan_type:      Mapped[str]          = mapped_column(String(20), nullable=False)
    target:         Mapped[str]          = mapped_column(String(500), nullable=False)
    folder_name:    Mapped[str]          = mapped_column(String(255), nullable=False)
    status:         Mapped[str]          = mapped_column(String(50), default='Queued')
    celery_task_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    options:        Mapped[Optional[dict]] = mapped_column(JSON, default=dict)
    created_at:     Mapped[datetime]     = mapped_column(DateTime, default=func.now())
    started_at:     Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    completed_at:   Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    created_by:     Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey('users.id'), nullable=True)

    engagement: Mapped[Engagement]        = relationship('Engagement', back_populates='scans')
    findings:   Mapped[List[Finding]]    = relationship('Finding', back_populates='scan',
                                                         cascade='all, delete-orphan', lazy='select')
    creator:    Mapped[Optional[User]]   = relationship('User', foreign_keys=[created_by])

    def __repr__(self) -> str:
        return f'<Scan {self.scan_id} [{self.scan_type}] {self.target}>'


# ── Findings ──────────────────────────────────────────────────────────────────

class Finding(Base):
    __tablename__ = 'findings'
    __table_args__ = (
        # Single-column indexes (existing)
        Index('ix_findings_severity',   'severity'),
        Index('ix_findings_status',     'status'),
        Index('ix_findings_dedup_hash', 'dedup_hash'),
        Index('ix_findings_scan_id_fk', 'scan_id_fk'),
        # Composite indexes for the most common filtered list queries:
        #   list_findings(scan_id_fk, severity)  — findings panel with sev filter
        #   list_findings(scan_id_fk, status)    — findings panel with status filter
        #   delta view joins on (scan_id_fk, dedup_hash)
        Index('ix_findings_scan_severity', 'scan_id_fk', 'severity'),
        Index('ix_findings_scan_status',   'scan_id_fk', 'status'),
        Index('ix_findings_scan_dedup',    'scan_id_fk', 'dedup_hash'),
    )

    id:                 Mapped[int]           = mapped_column(Integer, primary_key=True)
    scan_id_fk:         Mapped[int]           = mapped_column(
        Integer, ForeignKey('scans.id'), nullable=False)
    tool:               Mapped[str]           = mapped_column(String(50), nullable=False)
    vulnerability_name: Mapped[str]           = mapped_column(String(500), nullable=False)
    severity:           Mapped[str]           = mapped_column(String(50), nullable=False)
    cvss_score:         Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    cvss_vector:        Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    cve_id:             Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    cwe_id:             Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    target_url:         Mapped[Optional[str]] = mapped_column(String(2048), nullable=True)
    file_path:          Mapped[Optional[str]] = mapped_column(String(1024), nullable=True)
    line_number:        Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    host:               Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    port:               Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    description:        Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    remediation:        Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    status:             Mapped[str]           = mapped_column(String(50), default='Open')
    analyst_notes:      Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    dedup_hash:         Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    tool_count:         Mapped[int]           = mapped_column(Integer, default=1)
    # ── Assignment & SLA ───────────────────────────────────────────────────────
    assigned_to:        Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey('users.id'), nullable=True, index=True)
    due_date:           Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    # ── External ticket tracking ───────────────────────────────────────────────
    external_ticket_id:  Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    external_ticket_url: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    first_seen:         Mapped[datetime]      = mapped_column(DateTime, default=func.now())
    last_seen:          Mapped[datetime]      = mapped_column(DateTime, default=func.now())

    scan:     Mapped[Scan]              = relationship('Scan', back_populates='findings')
    evidence: Mapped[List[Evidence]]   = relationship('Evidence', back_populates='finding',
                                                       cascade='all, delete-orphan')
    assignee: Mapped[Optional[User]]   = relationship('User', foreign_keys=[assigned_to])

    def __repr__(self) -> str:
        return f'<Finding [{self.severity}] {self.vulnerability_name}>'


# ── Evidence ──────────────────────────────────────────────────────────────────

# NOTE: Scan.finding_count is intentionally NOT a column_property here.
# SQLAlchemy correlated subquery column_properties are deferred by default
# in async mode and require explicit options(undefer()) on every query,
# making them fragile.  Instead, list_scans uses a single bulk COUNT query
# (see engagements router) and start_scan returns 0 on creation (correct —
# a newly created scan has no findings yet).

class Evidence(Base):
    __tablename__ = 'evidence'

    id:         Mapped[int]           = mapped_column(Integer, primary_key=True)
    finding_id: Mapped[int]           = mapped_column(
        Integer, ForeignKey('findings.id'), nullable=False)
    ev_type:    Mapped[str]           = mapped_column(String(50), nullable=False)
    label:      Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    content:    Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    file_path:  Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    created_at: Mapped[datetime]      = mapped_column(DateTime, default=func.now())

    finding: Mapped[Finding] = relationship('Finding', back_populates='evidence')

    def __repr__(self) -> str:
        return f'<Evidence [{self.ev_type}] finding={self.finding_id}>'


# ── Report Templates ──────────────────────────────────────────────────────────

class ReportTemplate(Base):
    __tablename__ = 'report_templates'

    id:            Mapped[int]           = mapped_column(Integer, primary_key=True)
    name:          Mapped[str]           = mapped_column(String(200), nullable=False)
    html_template: Mapped[str]           = mapped_column(Text, nullable=False)
    logo_base64:   Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    is_default:    Mapped[bool]          = mapped_column(Boolean, default=False)
    created_at:    Mapped[datetime]      = mapped_column(DateTime, default=func.now())

    def __repr__(self) -> str:
        return f'<ReportTemplate {self.name}>'


# ── Audit Log ─────────────────────────────────────────────────────────────────

class AuditLog(Base):
    __tablename__ = 'audit_logs'
    __table_args__ = (
        Index('ix_audit_logs_timestamp', 'timestamp'),
        Index('ix_audit_logs_action',    'action'),
    )

    id:          Mapped[int]              = mapped_column(Integer, primary_key=True)
    timestamp:   Mapped[datetime]         = mapped_column(
        DateTime, default=func.now(), nullable=False)
    user_id:     Mapped[Optional[int]]    = mapped_column(
        Integer, ForeignKey('users.id'), nullable=True)
    username:    Mapped[Optional[str]]    = mapped_column(String(100), nullable=True)
    action:      Mapped[str]              = mapped_column(String(80), nullable=False)
    target_type: Mapped[Optional[str]]    = mapped_column(String(50), nullable=True)
    target_id:   Mapped[Optional[int]]    = mapped_column(Integer, nullable=True)
    target_name: Mapped[Optional[str]]    = mapped_column(String(255), nullable=True)
    detail:      Mapped[Optional[dict]]   = mapped_column(JSON, nullable=True)
    ip_address:  Mapped[Optional[str]]    = mapped_column(String(45), nullable=True)

    user: Mapped[Optional[User]] = relationship('User', foreign_keys=[user_id])

    def __repr__(self) -> str:
        return f'<AuditLog {self.action} by {self.username} @ {self.timestamp}>'


# ── Integration Config (Jira, ServiceNow, etc.) ─────────────────────────────────

class IntegrationConfig(Base):
    __tablename__ = 'integration_configs'
    __table_args__ = (
        Index('ix_integration_configs_engagement', 'engagement_id'),
    )

    id:            Mapped[int]           = mapped_column(Integer, primary_key=True)
    engagement_id: Mapped[int]           = mapped_column(
        Integer, ForeignKey('engagements.id'), nullable=False)
    provider:      Mapped[str]           = mapped_column(String(50), nullable=False)
    # e.g. 'jira', 'servicenow', 'azure_devops'
    base_url:      Mapped[str]           = mapped_column(String(500), nullable=False)
    # Token / API key — stored encrypted at the application level, not here.
    # The raw token is encrypted with a per-instance Fernet key derived from
    # JWT_SECRET so that a DB dump alone cannot decrypt credentials.
    auth_token_encrypted: Mapped[str]   = mapped_column(String(500), nullable=False)
    project_key:   Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    # Jira project key, ServiceNow table name, etc.
    is_active:     Mapped[bool]          = mapped_column(Boolean, default=True)
    created_at:    Mapped[datetime]      = mapped_column(DateTime, default=func.now())

    engagement: Mapped[Engagement] = relationship('Engagement')


# ── Notifications (in-app) ──────────────────────────────────────────────────────

class Notification(Base):
    __tablename__ = 'notifications'
    __table_args__ = (
        Index('ix_notifications_user_id', 'user_id'),
        Index('ix_notifications_created_at', 'created_at'),
    )

    id:         Mapped[int]           = mapped_column(Integer, primary_key=True)
    user_id:    Mapped[int]           = mapped_column(
        Integer, ForeignKey('users.id'), nullable=False)
    event_type: Mapped[str]           = mapped_column(String(80), nullable=False)
    # e.g. 'scan.completed', 'finding.assigned', 'sla.breach'
    title:      Mapped[str]           = mapped_column(String(255), nullable=False)
    message:    Mapped[str]           = mapped_column(Text, nullable=False)
    link:       Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    # URL path fragment the user should navigate to, e.g. '/findings/123'
    is_read:    Mapped[bool]          = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime]      = mapped_column(DateTime, default=func.now())

    user: Mapped[User] = relationship('User')

