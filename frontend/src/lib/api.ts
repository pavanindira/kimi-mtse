/**
 * api.ts — Typed API client for the MSTE FastAPI backend.
 *
 * JWT is stored in module-level memory (never localStorage/sessionStorage)
 * so XSS attacks cannot steal it. On page refresh the user must re-login —
 * acceptable for a security tool used in controlled sessions.
 */

// ── Token store (in-memory only) ─────────────────────────────────────────────

let _token: string | null = null;

export const setToken   = (t: string) => { _token = t; };
export const clearToken = ()          => { _token = null; };
export const hasToken   = ()          => !!_token;


// ── Base fetch ───────────────────────────────────────────────────────────────

const BASE = import.meta.env.VITE_API_URL ?? '/api';

async function apiFetch<T>(
  path:    string,
  options: RequestInit = {},
): Promise<T> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(options.headers as Record<string, string> ?? {}),
  };
  if (_token) headers['Authorization'] = `Bearer ${_token}`;

  const res = await fetch(`${BASE}${path}`, { ...options, headers });

  if (res.status === 204) return undefined as T;

  const data = await res.json().catch(() => ({ detail: res.statusText }));

  if (!res.ok) {
    const msg = data.detail ?? data.error ?? `HTTP ${res.status}`;
    throw new Error(Array.isArray(msg)
      ? msg.map((e: { msg: string }) => e.msg).join('; ')
      : String(msg));
  }
  return data as T;
}

async function apiUpload<T>(path: string, formData: FormData): Promise<T> {
  const headers: Record<string, string> = {};
  if (_token) headers['Authorization'] = `Bearer ${_token}`;
  const res = await fetch(`${BASE}${path}`, { method: 'POST', headers, body: formData });
  const data = await res.json().catch(() => ({ detail: res.statusText }));
  if (!res.ok) throw new Error(data.detail ?? `HTTP ${res.status}`);
  return data as T;
}


// ── Types ─────────────────────────────────────────────────────────────────────

export interface TokenOut {
  access_token: string;
  token_type:   string;
  expires_in:   number;
}

export interface UserOut {
  id:         number;
  username:   string;
  role:       string;
  created_at: string | null;
  last_login: string | null;
}

export interface SeveritySummary {
  Critical: number; High: number; Medium: number; Low: number; Info: number;
}

export interface EngagementOut {
  id:                 number;
  name:               string;
  client_name:        string;
  description:        string | null;
  status:             string;
  scope:              string | null;
  webhook_url:        string | null;
  report_template_id: number | null;
  created_by:         number | null;
  created_at:         string | null;
  updated_at:         string | null;
  started_at:         string | null;
  completed_at:       string | null;
}

export interface EngagementDetail extends EngagementOut {
  severity_summary: SeveritySummary;
  finding_count:    number;
  scan_count:       number;
}

export interface ScanOut {
  id:             number;
  scan_id:        string;
  engagement_id:  number;
  scan_type:      string;
  target:         string;
  status:         string;
  celery_task_id: string | null;
  created_at:     string | null;
  started_at:     string | null;
  completed_at:   string | null;
  finding_count:  number;
  scope_warning?: string | null;
}

export interface ScheduledScanOut {
  id:             number;
  scan_type:      string;
  target:         string;
  interval_hours: number;
  enabled:        boolean;
  next_run_at:    string | null;
  last_run_at:    string | null;
  last_scan_id:   string | null;
  created_at:     string | null;
  has_git_token:  boolean;
  scope_warning?: string | null;
}

export interface EngagementMemberOut {
  id:       number;
  user_id:  number;
  username: string;
  role:     string;
  added_at: string | null;
}

export interface FindingsTrendPoint {
  week_start: string;
  Critical:   number;
  High:       number;
  Medium:     number;
  Low:        number;
  Info:       number;
}

export interface ScansTrendPoint {
  week_start: string;
  total:      number;
  completed:  number;
  failed:     number;
}

export interface DashboardTrends {
  days:                    number;
  findings_by_week:        FindingsTrendPoint[];
  scans_by_week:           ScansTrendPoint[];
  open_severity_snapshot:  { Critical: number; High: number; Medium: number; Low: number; Info: number };
  resolved_count:          number;
  avg_days_to_resolve:     number | null;
}

export interface EvidenceOut {
  id:         number;
  ev_type:    string;
  label:      string | null;
  content:    string | null;
  created_at: string | null;
}

export interface FindingOut {
  id:                 number;
  tool:               string;
  vulnerability_name: string;
  severity:           string;
  cvss_score:         number | null;
  cvss_vector:        string | null;
  cve_id:             string | null;
  cwe_id:             string | null;
  target_url:         string | null;
  file_path:          string | null;
  line_number:        number | null;
  host:               string | null;
  port:               number | null;
  description:        string | null;
  remediation:        string | null;
  analyst_notes:      string | null;
  status:             string;
  first_seen:         string | null;
  last_seen:          string | null;
}

export interface FindingDetail extends FindingOut {
  evidence:      EvidenceOut[];
  scan_id:       string | null;
  engagement_id: number | null;
}

export interface PaginatedFindings {
  total:  number;
  items:  FindingOut[];
  limit:  number;
  offset: number;
  pages:  number;
}

export interface FindingDelta {
  baseline_scan_id: string;
  current_scan_id:  string;
  new:              FindingOut[];
  recurring:        FindingOut[];
  resolved:         FindingOut[];
  new_count:        number;
  recurring_count:  number;
  resolved_count:   number;
}

export interface ReportTemplateOut {
  id:         number;
  name:       string;
  is_default: boolean;
  has_logo:   boolean;
  created_at: string | null;
}

export interface ReportTemplateDetail extends ReportTemplateOut {
  html_template: string;
}

export interface WebhookSecretOut {
  webhook_secret: string;
}

export interface WebhookDeliveryOut {
  id:               number;
  scan_id:          string | null;
  event:            string;
  url:              string;
  success:          boolean;
  status_code:      number | null;
  error:            string | null;
  response_snippet: string | null;
  duration_ms:      number | null;
  created_at:       string | null;
}

export interface AuditLogOut {
  id:          number;
  timestamp:   string;
  username:    string | null;
  action:      string;
  target_type: string | null;
  target_id:   number | null;
  target_name: string | null;
  detail:      Record<string, unknown> | null;
  ip_address:  string | null;
}

export interface PaginatedAuditLog {
  items:    AuditLogOut[];
  total:    number;
  page:     number;
  pages:    number;
  per_page: number;
}

export interface SearchResults {
  query:       string;
  total:       number;
  findings:    FindingOut[];
  engagements: EngagementOut[];
  scans:       ScanOut[];
}


// ── Auth ──────────────────────────────────────────────────────────────────────

export const auth = {
  login: (username: string, password: string) =>
    apiFetch<TokenOut>('/auth/login', {
      method: 'POST',
      body:   JSON.stringify({ username, password }),
    }),
  me: () => apiFetch<UserOut>('/auth/me'),
  refresh: () => apiFetch<TokenOut>('/auth/refresh', { method: 'POST' }),
  changePassword: (current_password: string, new_password: string) =>
    apiFetch<{ message: string; access_token: string; expires_in: number }>(
      '/auth/change-password', {
        method: 'POST',
        body:   JSON.stringify({ current_password, new_password }),
      }
    ),
};


// ── Engagements ───────────────────────────────────────────────────────────────

export const engagements = {
  list: (status?: string) =>
    apiFetch<EngagementOut[]>(`/engagements${status ? `?status=${status}` : ''}`),

  get: (id: number) =>
    apiFetch<EngagementDetail>(`/engagements/${id}`),

  create: (body: {
    name: string; client_name: string; description?: string; scope?: string;
    webhook_url?: string;
  }) =>
    apiFetch<EngagementOut>('/engagements', {
      method: 'POST', body: JSON.stringify(body),
    }),

  update: (id: number, body: {
    name?: string; client_name?: string; description?: string;
    status?: string; scope?: string; report_template_id?: number | null;
    webhook_url?: string;
  }) =>
    apiFetch<EngagementOut>(`/engagements/${id}`, {
      method: 'PATCH', body: JSON.stringify(body),
    }),

  // Analyst-accessible template listing for the per-engagement picker —
  // distinct from admin.reportTemplates.list(), which is Admin-only and
  // used for logo/default management.
  reportTemplates: () =>
    apiFetch<ReportTemplateOut[]>('/engagements/report-templates'),

  webhookSecret: {
    // 404s if no webhook has been configured yet (no secret exists).
    get: (id: number) =>
      apiFetch<WebhookSecretOut>(`/engagements/${id}/webhook-secret`),
    rotate: (id: number) =>
      apiFetch<WebhookSecretOut>(`/engagements/${id}/webhook-secret/rotate`, {
        method: 'POST',
      }),
  },

  webhookDeliveries: {
    list: (id: number) =>
      apiFetch<WebhookDeliveryOut[]>(`/engagements/${id}/webhook-deliveries`),
    test: (id: number) =>
      apiFetch<WebhookDeliveryOut>(`/engagements/${id}/webhook-test`, { method: 'POST' }),
  },

  scheduledScans: {
    list: (id: number) =>
      apiFetch<ScheduledScanOut[]>(`/engagements/${id}/scheduled-scans`),
    create: (id: number, body: {
      scan_type: string; target: string; interval_hours: number;
      run_immediately?: boolean; auth_header?: string; proxy?: string;
      git_token?: string; enable_katana?: boolean; enable_sqlmap?: boolean;
      enable_stealth?: boolean;
    }) =>
      apiFetch<ScheduledScanOut>(`/engagements/${id}/scheduled-scans`, {
        method: 'POST', body: JSON.stringify(body),
      }),
    update: (id: number, schedId: number, body: { enabled?: boolean; interval_hours?: number }) =>
      apiFetch<ScheduledScanOut>(`/engagements/${id}/scheduled-scans/${schedId}`, {
        method: 'PATCH', body: JSON.stringify(body),
      }),
    delete: (id: number, schedId: number) =>
      apiFetch<void>(`/engagements/${id}/scheduled-scans/${schedId}`, { method: 'DELETE' }),
  },

  members: {
    list: (id: number) =>
      apiFetch<EngagementMemberOut[]>(`/engagements/${id}/members`),
    add: (id: number, username: string) =>
      apiFetch<EngagementMemberOut>(`/engagements/${id}/members`, {
        method: 'POST', body: JSON.stringify({ username }),
      }),
    remove: (id: number, userId: number) =>
      apiFetch<void>(`/engagements/${id}/members/${userId}`, { method: 'DELETE' }),
  },

  delete: (id: number) =>
    apiFetch<void>(`/engagements/${id}`, { method: 'DELETE' }),

  scans: (id: number) =>
    apiFetch<ScanOut[]>(`/engagements/${id}/scans`),

  startScan: (engId: number, body: Record<string, unknown>) =>
    apiFetch<ScanOut>(`/engagements/${engId}/scans`, {
      method: 'POST', body: JSON.stringify(body),
    }),

  cancelScan: (engId: number, scanId: string) =>
    apiFetch<{ scan_id: string; status: string; containers_killed: string[] }>(
      `/engagements/${engId}/scans/${scanId}`, { method: 'DELETE' }
    ),

  delta: (engId: number, sinceScanId?: string) =>
    apiFetch<FindingDelta>(
      `/engagements/${engId}/delta${sinceScanId ? `?since_scan_id=${sinceScanId}` : ''}`
    ),

  reportUrl: (engId: number) => `${BASE}/engagements/${engId}/report`,
};


// ── Findings ──────────────────────────────────────────────────────────────────

export const findings = {
  list: (params?: {
    severity?: string; status?: string; tool?: string;
    scan_id?: string; engagement_id?: number; limit?: number; offset?: number;
  }) => {
    const q = new URLSearchParams(
      Object.entries(params ?? {})
        .filter(([, v]) => v !== undefined)
        .map(([k, v]) => [k, String(v)])
    ).toString();
    return apiFetch<PaginatedFindings>(`/findings${q ? `?${q}` : ''}`);
  },

  get: (id: number) =>
    apiFetch<FindingDetail>(`/findings/${id}`),

  updateStatus: (id: number, status: string, notes?: string) =>
    apiFetch<FindingOut>(`/findings/${id}`, {
      method: 'PATCH',
      body:   JSON.stringify({ status, notes: notes ?? undefined }),
    }),

  updateNotes: (id: number, notes: string) =>
    apiFetch<FindingOut>(`/findings/${id}/notes`, {
      method: 'PATCH',
      body:   JSON.stringify({ notes }),
    }),

  createManual: (scanId: string, body: {
    vulnerability_name: string; severity: string;
    description?: string; remediation?: string;
    cvss_score?: number; cve_id?: string; cwe_id?: string;
    target_url?: string; host?: string; port?: number;
    file_path?: string; line_number?: number;
    location?: string; analyst_notes?: string;
  }) =>
    apiFetch<FindingOut>(`/scans/${scanId}/findings`, {
      method: 'POST', body: JSON.stringify(body),
    }),

  bulkStatus: (finding_ids: number[], status: string, notes?: string) =>
    apiFetch<{ success: boolean; updated: number; status: string }>(
      '/findings/bulk-status', {
        method: 'POST',
        body:   JSON.stringify({ finding_ids, status, notes: notes ?? '' }),
      }
    ),

  scanStatus: (scanId: string) =>
    apiFetch<{ scan_id: string; status: string; findings: number }>(
      `/scans/${scanId}/status`
    ),
};


// ── Search ────────────────────────────────────────────────────────────────────

export const search = {
  query: (q: string, scope = 'all') =>
    apiFetch<SearchResults>(`/search?q=${encodeURIComponent(q)}&scope=${scope}`),
};


// ── Dashboard ─────────────────────────────────────────────────────────────────

export const dashboard = {
  trends: (days = 90) =>
    apiFetch<DashboardTrends>(`/dashboard/trends?days=${days}`),
};


// ── Admin ─────────────────────────────────────────────────────────────────────

export const admin = {
  users: {
    list:   () => apiFetch<UserOut[]>('/admin/users'),
    create: (body: { username: string; password: string; role: string }) =>
      apiFetch<UserOut>('/admin/users', { method: 'POST', body: JSON.stringify(body) }),
    setRole: (userId: number, role: string) =>
      apiFetch<UserOut>(`/admin/users/${userId}/role`, {
        method: 'PATCH', body: JSON.stringify({ role }),
      }),
    delete: (userId: number) =>
      apiFetch<void>(`/admin/users/${userId}`, { method: 'DELETE' }),
  },

  audit: (params?: {
    page?: number; action_filter?: string; user_filter?: string;
  }) => {
    const q = new URLSearchParams(
      Object.entries(params ?? {})
        .filter(([, v]) => v !== undefined)
        .map(([k, v]) => [k, String(v)])
    ).toString();
    return apiFetch<PaginatedAuditLog>(`/admin/audit${q ? `?${q}` : ''}`);
  },

  reportTemplates: {
    list:      () => apiFetch<ReportTemplateOut[]>('/admin/report-templates'),
    get:       (templateId: number) =>
      apiFetch<ReportTemplateDetail>(`/admin/report-templates/${templateId}`),
    create:    (body: { name: string; html_template: string }) =>
      apiFetch<ReportTemplateDetail>('/admin/report-templates', {
        method: 'POST', body: JSON.stringify(body),
      }),
    update:    (templateId: number, body: { name?: string; html_template?: string }) =>
      apiFetch<ReportTemplateDetail>(`/admin/report-templates/${templateId}`, {
        method: 'PATCH', body: JSON.stringify(body),
      }),
    delete:    (templateId: number) =>
      apiFetch<void>(`/admin/report-templates/${templateId}`, { method: 'DELETE' }),
    uploadLogo: (templateId: number, file: File) => {
      const fd = new FormData();
      fd.append('file', file);
      return apiUpload<ReportTemplateOut>(
        `/admin/report-templates/${templateId}/logo`, fd
      );
    },
    deleteLogo:   (templateId: number) =>
      apiFetch<void>(`/admin/report-templates/${templateId}/logo`, { method: 'DELETE' }),
    setDefault:   (templateId: number) =>
      apiFetch<ReportTemplateOut>(`/admin/report-templates/${templateId}/set-default`, {
        method: 'PATCH',
      }),
  },
};
