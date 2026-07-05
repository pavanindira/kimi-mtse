"""
schemas.py — Pydantic v2 request/response models.

Every API route declares its input and output types here. FastAPI uses these
for automatic validation, serialisation, and OpenAPI doc generation.

Naming convention:
    <Entity>Create   — request body for POST (creation)
    <Entity>Update   — request body for PATCH (partial update)
    <Entity>Out      — response body (safe to serialise to JSON)
    <Entity>Detail   — extended response with nested objects
"""

from __future__ import annotations

import ipaddress
import os
import re
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


# ── Shared ────────────────────────────────────────────────────────────────────

class OrmModel(BaseModel):
    """Base for all ORM-backed response schemas."""
    model_config = ConfigDict(from_attributes=True)


# ── Auth ──────────────────────────────────────────────────────────────────────

class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=100)
    password: str = Field(min_length=1)


class TokenOut(BaseModel):
    access_token: str
    token_type:   str = 'bearer'
    expires_in:   int          # seconds


class RefreshOut(BaseModel):
    access_token: str
    token_type:   str = 'bearer'
    expires_in:   int


class ChangePasswordRequest(BaseModel):
    current_password: str = Field(min_length=1)
    new_password:     str = Field(min_length=8,
                                  description='Minimum 8 characters')

    @field_validator('new_password')
    @classmethod
    def strong_enough(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError('New password must be at least 8 characters')
        if v.isdigit():
            raise ValueError('New password must not be all digits')
        return v


class UserOut(OrmModel):
    id:         int
    username:   str
    role:       str
    created_at: datetime | None = None
    last_login: datetime | None = None


class UserCreate(BaseModel):
    username: str = Field(min_length=1, max_length=100)
    password: str = Field(min_length=8)
    role:     str = Field(default='Analyst')

    @field_validator('role')
    @classmethod
    def valid_role(cls, v: str) -> str:
        if v not in ('Admin', 'Analyst', 'Viewer'):
            raise ValueError('Role must be Admin, Analyst, or Viewer')
        return v


class UserRoleUpdate(BaseModel):
    role: str

    @field_validator('role')
    @classmethod
    def valid_role(cls, v: str) -> str:
        if v not in ('Admin', 'Analyst', 'Viewer'):
            raise ValueError('Role must be Admin, Analyst, or Viewer')
        return v


# ── Engagements ───────────────────────────────────────────────────────────────

def _validate_webhook_url(v: str | None) -> str | None:
    """
    Shared http/https + SSRF validation for engagement webhook URLs.

    Reuses the same private/internal-address blocklist as ScanCreate's web
    target validation (_is_private_host / _BLOCKED_HOSTNAMES, defined below
    in this module) — a misconfigured webhook is just as capable of
    triggering an internal request as a misconfigured scan target, so it
    gets the same treatment.

    Deliberately returns falsy input (None or '') unchanged rather than
    normalising '' -> None here: EngagementUpdate relies on '' surviving
    validation so the router's `body.webhook_url or None` can tell "field
    omitted" (None) apart from "field explicitly cleared" ('') — the same
    pattern already used for `scope`.
    """
    if not v:
        return v
    from urllib.parse import urlparse
    p = urlparse(v)
    if p.scheme not in ('http', 'https') or not p.netloc:
        raise ValueError('Webhook URL must be a valid http/https URL')
    host = (p.hostname or '').lower()
    if _is_private_host(host):
        raise ValueError('Webhook URL resolves to a private/internal address')
    if len(v) > 500:
        raise ValueError('Webhook URL must be 500 characters or fewer')
    return v


class EngagementCreate(BaseModel):
    name:        str = Field(min_length=1, max_length=200)
    client_name: str = Field(min_length=1, max_length=200)
    description: str = ''
    scope:       str = Field(default='',
                             description='Newline-separated list of in-scope targets: CIDRs, hostnames, URL prefixes')
    webhook_url: str | None = Field(
        default=None,
        description='Optional http(s) endpoint POSTed to when a scan on this engagement completes')

    @field_validator('webhook_url')
    @classmethod
    def check_webhook_url(cls, v: str | None) -> str | None:
        return _validate_webhook_url(v)


class EngagementUpdate(BaseModel):
    """Partial update — all fields optional. Only provided fields are changed."""
    name:               str | None = Field(default=None, min_length=1, max_length=200)
    client_name:        str | None = Field(default=None, min_length=1, max_length=200)
    description:        str | None = None
    status:             str | None = None
    scope:              str | None = None
    report_template_id: int | None = None
    webhook_url:        str | None = None

    @field_validator('status')
    @classmethod
    def valid_status(cls, v: str | None) -> str | None:
        if v is not None and v not in ('Active', 'Completed', 'Archived'):
            raise ValueError('Engagement status must be Active, Completed, or Archived')
        return v

    @field_validator('webhook_url')
    @classmethod
    def check_webhook_url(cls, v: str | None) -> str | None:
        return _validate_webhook_url(v)


class WebhookSecretOut(BaseModel):
    """
    Response for the reveal/rotate webhook-secret endpoints. Deliberately its
    own schema rather than a field on EngagementOut — the secret is a bearer
    credential (used to verify HMAC signatures on incoming webhook
    deliveries), so it should only appear in responses the caller explicitly
    asked for, not in every GET/list of an engagement.
    """
    webhook_secret: str


class ReportTemplateOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id:         int
    name:       str
    is_default: bool
    has_logo:   bool
    created_at: datetime | None

    @classmethod
    def from_orm_obj(cls, obj) -> 'ReportTemplateOut':
        """Build from an ORM ReportTemplate, computing has_logo from logo_base64."""
        return cls(
            id         = obj.id,
            name       = obj.name,
            is_default = obj.is_default,
            has_logo   = bool(getattr(obj, 'logo_base64', None)),
            created_at = getattr(obj, 'created_at', None),
        )


class SeveritySummary(BaseModel):
    Critical: int = 0
    High:     int = 0
    Medium:   int = 0
    Low:      int = 0
    Info:     int = 0


class EngagementOut(OrmModel):
    id:                 int
    name:               str
    client_name:        str
    description:        str | None
    status:             str
    scope:              str | None
    webhook_url:        str | None
    report_template_id: int | None
    created_at:         datetime | None
    updated_at:         datetime | None
    started_at:         datetime | None
    completed_at:       datetime | None


class EngagementDetail(EngagementOut):
    severity_summary: SeveritySummary = Field(default_factory=SeveritySummary)
    finding_count:    int = 0
    scan_count:       int = 0


# ── Scans ─────────────────────────────────────────────────────────────────────

_SAFE_HEADER_RE = re.compile(r'^[\x20-\x7E]+$')

# Hostnames that are always internal regardless of what DNS says
_BLOCKED_HOSTNAMES = frozenset({
    'localhost',
    'metadata.google.internal',     # GCP IMDS
    '169.254.169.254',              # AWS/Azure/GCP IMDS (as hostname)
})


def _is_private_host(host: str) -> bool:
    """
    Return True if *host* resolves to a private/internal address space.

    We check only the literal value supplied — we do NOT perform DNS
    resolution (that would require a network call and is vulnerable to
    TOCTOU / DNS rebinding anyway). This stops direct IP attacks; DNS
    rebinding is mitigated at the network layer via firewall egress rules.

    Covers:
      - IPv4 private, loopback, link-local, CGNAT, documentation ranges
      - IPv6 loopback (::1), link-local (fe80::/10), ULA (fc00::/7),
        unspecified (::), IPv4-mapped (::ffff:10.x.x.x), etc.
    """
    if host in _BLOCKED_HOSTNAMES:
        return True
    # Ranges that ipaddress.is_private misses (treated as "public" by the stdlib)
    _EXTRA_BLOCKED = (
        ipaddress.ip_network('100.64.0.0/10'),   # CGNAT (RFC 6598)
    )

    try:
        addr = ipaddress.ip_address(host)
        if (
            addr.is_private
            or addr.is_loopback
            or addr.is_link_local
            or addr.is_reserved
            or addr.is_unspecified
            or addr.is_multicast
        ):
            return True
        return any(addr in net for net in _EXTRA_BLOCKED)
    except ValueError:
        # Not a bare IP address — it's a hostname. We allow it through here;
        # DNS rebinding is an operational concern, not a validator concern.
        return False

class ScanCreate(BaseModel):
    scan_type:      str
    target:         str = Field(min_length=1, max_length=500)
    auth_header:    str | None = None
    proxy:          str | None = None
    git_token:      str | None = None
    enable_katana:  bool = False
    enable_sqlmap:  bool = False
    enable_stealth: bool = False

    @field_validator('scan_type')
    @classmethod
    def valid_scan_type(cls, v: str) -> str:
        if v not in ('web', 'sast', 'infra', 'cloud', 'mobile'):
            raise ValueError('scan_type must be web, sast, infra, cloud, or mobile')
        return v

    @field_validator('auth_header')
    @classmethod
    def safe_header_chars(cls, v: str | None) -> str | None:
        if v and not _SAFE_HEADER_RE.match(v):
            raise ValueError('Auth header contains invalid characters (printable ASCII only)')
        return v

    @model_validator(mode='after')
    def validate_target_for_type(self) -> ScanCreate:
        """Apply type-specific target validation and SSRF blocklist."""
        if self.target.startswith('-'):
            raise ValueError('Target cannot start with a dash')

        if self.scan_type == 'web':
            from urllib.parse import urlparse
            p = urlparse(self.target)
            if p.scheme not in ('http', 'https') or not p.netloc:
                raise ValueError('Web scan target must be a valid http/https URL')
            host = (p.hostname or '').lower()
            if _is_private_host(host):
                raise ValueError('Target resolves to a private/internal address')

        elif self.scan_type == 'infra':
            # Infra targets are bare hostnames or IPs, not URLs
            host = self.target.strip().lower()
            if _is_private_host(host):
                raise ValueError('Target resolves to a private/internal address')

        elif self.scan_type == 'cloud':
            # Format: provider:resource  e.g. aws:default, gcp:my-project
            parts = self.target.split(':', 1)
            if len(parts) != 2 or parts[0].lower() not in ('aws', 'gcp', 'azure'):
                raise ValueError(
                    'Cloud scan target must be in the format provider:resource '
                    '(e.g. aws:default, gcp:my-project-id, azure:my-tenant-id). '
                    'Supported providers: aws, gcp, azure.'
                )
            if not parts[1].strip():
                raise ValueError(
                    'Cloud scan target must include a resource identifier after the colon '
                    '(e.g. aws:default, gcp:my-project-id).'
                )

        elif self.scan_type == 'mobile':
            # Targets are URLs to an app binary or local paths
            _MOBILE_EXTS = ('.apk', '.ipa', '.appx', '.zip')
            from urllib.parse import urlparse as _up
            parsed = _up(self.target)
            path_part = (parsed.path or self.target).split('?')[0].lower()
            ext = os.path.splitext(path_part)[1]
            if ext not in _MOBILE_EXTS:
                raise ValueError(
                    f'Mobile scan target must point to an app binary '
                    f'({", ".join(_MOBILE_EXTS)}). Got extension: "{ext or "(none)"}".'
                )

        return self


class ScanOut(OrmModel):
    id:             int
    scan_id:        str
    engagement_id:  int
    scan_type:      str
    target:         str
    status:         str
    celery_task_id: str | None
    created_at:     datetime | None
    started_at:     datetime | None
    completed_at:   datetime | None
    # Populated by the bulk COUNT query in list_scans (engagements router) —
    # not a SQLAlchemy column_property.  No manual setting required.
    finding_count:  int = 0


# ── Findings ──────────────────────────────────────────────────────────────────

class EvidenceOut(OrmModel):
    id:         int
    ev_type:    str
    label:      str | None
    content:    str | None
    created_at: datetime | None


class FindingOut(OrmModel):
    id:                 int
    tool:               str
    vulnerability_name: str
    severity:           str
    cvss_score:         float | None
    cvss_vector:        str | None
    cve_id:             str | None
    cwe_id:             str | None
    target_url:         str | None
    file_path:          str | None
    line_number:        int | None
    host:               str | None
    port:               int | None
    description:        str | None
    remediation:        str | None
    status:             str
    analyst_notes:      str | None
    tool_count:         int = 1
    # ── Assignment & SLA ───────────────────────────────────────────────────────
    assigned_to:        int | None = None
    due_date:           datetime | None = None
    # ── External ticket ────────────────────────────────────────────────────────
    external_ticket_id:  str | None = None
    external_ticket_url: str | None = None
    first_seen:         datetime | None
    last_seen:          datetime | None


class FindingDetail(FindingOut):
    evidence:     list[EvidenceOut] = []
    scan_id:      str | None = None
    engagement_id: int | None = None


class FindingStatusUpdate(BaseModel):
    status: str
    notes:  str | None = None

    @field_validator('status')
    @classmethod
    def valid_status(cls, v: str) -> str:
        valid = ('Open', 'Confirmed', 'False Positive', 'Fixed', 'Accepted Risk')
        if v not in valid:
            raise ValueError(f'Status must be one of: {valid}')
        return v


class FindingNotesUpdate(BaseModel):
    """Update analyst notes on a finding without changing its status."""
    notes: str = Field(default='', max_length=10000,
                       description='Markdown-formatted analyst notes')


class ManualFindingCreate(BaseModel):
    """Schema for creating a manual finding added by an analyst."""
    vulnerability_name: str   = Field(min_length=1, max_length=300)
    severity:           str
    description:        str   = ''
    remediation:        str   = ''
    analyst_notes:      str   = ''
    cvss_score:         float | None = Field(default=None, ge=0.0, le=10.0)
    cve_id:             str   | None = None
    cwe_id:             str   | None = None
    target_url:         str   | None = None
    host:               str   | None = None
    port:               int   | None = Field(default=None, ge=1, le=65535)
    file_path:          str   | None = None
    line_number:        int   | None = None
    location:           str   | None = None

    @field_validator('severity')
    @classmethod
    def valid_severity(cls, v: str) -> str:
        valid = ('Critical', 'High', 'Medium', 'Low', 'Info')
        if v not in valid:
            raise ValueError(f'Severity must be one of: {valid}')
        return v


class BulkStatusUpdate(BaseModel):
    finding_ids: list[int] = Field(min_length=1, max_length=500)
    status:      str
    notes:       str = ''

    @field_validator('status')
    @classmethod
    def valid_status(cls, v: str) -> str:
        valid = ('Open', 'Confirmed', 'False Positive', 'Fixed', 'Accepted Risk')
        if v not in valid:
            raise ValueError(f'Status must be one of: {valid}')
        return v

    @field_validator('finding_ids')
    @classmethod
    def valid_ids(cls, v: list[int]) -> list[int]:
        if len(v) > 500:
            raise ValueError('Cannot bulk-update more than 500 findings at once')
        return v


class PaginatedFindings(BaseModel):
    """
    Paginated wrapper for the findings list endpoint.

    Gives the frontend everything it needs to render page controls:
      total   — total matching findings (with current filters applied)
      items   — the page of FindingOut objects
      limit   — page size used for this request
      offset  — starting index used for this request
      pages   — total number of pages at the current limit
    """
    total:  int
    items:  list[FindingOut]
    limit:  int
    offset: int
    pages:  int


class FindingDelta(BaseModel):
    """
    Diff of findings between a baseline scan and the most recent scan in an
    engagement.  Used for re-test / remediation-verification reporting.

    new        — findings that did not exist in the baseline scan (new risk)
    recurring  — findings present in both baseline and current (not fixed)
    resolved   — findings in baseline that are absent from current (fixed)
    """
    baseline_scan_id:  str
    current_scan_id:   str
    new:               list[FindingOut] = []
    recurring:         list[FindingOut] = []
    resolved:          list[FindingOut] = []
    new_count:         int = 0
    recurring_count:   int = 0
    resolved_count:    int = 0


# ── Search ────────────────────────────────────────────────────────────────────

class SearchResults(BaseModel):
    query:       str
    total:       int
    findings:    list[FindingOut]    = []
    engagements: list[EngagementOut] = []
    scans:       list[ScanOut]       = []


# ── Audit log ─────────────────────────────────────────────────────────────────

class AuditLogOut(OrmModel):
    id:          int
    timestamp:   datetime
    username:    str | None
    action:      str
    target_type: str | None
    target_id:   int | None
    target_name: str | None
    detail:      dict[str, Any] | None
    ip_address:  str | None


class PaginatedAuditLog(BaseModel):
    items:   list[AuditLogOut]
    total:   int
    page:    int
    pages:   int
    per_page: int


# ── SSE progress event ────────────────────────────────────────────────────────

class ProgressEvent(BaseModel):
    msg:   str
    level: str = 'info'    # info | success | error | warning
    ts:    str             # ISO timestamp


# ── Integration Config ────────────────────────────────────────────────────────

class IntegrationConfigCreate(BaseModel):
    provider: str = Field(description='jira, servicenow, or azure_devops')
    base_url: str = Field(min_length=1, max_length=500)
    auth_token: str = Field(min_length=1, max_length=500, description='API token or password')
    project_key: str | None = Field(default=None, max_length=100)

    @field_validator('provider')
    @classmethod
    def valid_provider(cls, v: str) -> str:
        valid = ('jira', 'servicenow', 'azure_devops')
        if v not in valid:
            raise ValueError(f'Provider must be one of: {valid}')
        return v


class IntegrationConfigOut(OrmModel):
    id:            int
    engagement_id: int
    provider:      str
    base_url:      str
    project_key:   str | None
    is_active:     bool
    created_at:    datetime | None


# ── Notifications ─────────────────────────────────────────────────────────────

class NotificationOut(OrmModel):
    id:         int
    event_type: str
    title:      str
    message:    str
    link:       str | None
    is_read:    bool
    created_at: datetime | None


class PaginatedNotifications(BaseModel):
    items: list[NotificationOut]
    total: int
    unread: int


# ── Assignment ────────────────────────────────────────────────────────────────

class FindingAssignmentUpdate(BaseModel):
    """Assign a finding to a specific user with an optional due date."""
    assigned_to: int | None = None
    due_date:    datetime | None = None

