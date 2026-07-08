import { useState, useRef, useEffect } from 'react';
import { Link, useParams, useNavigate } from 'react-router-dom';
import { useAuth } from '../lib/auth-context';
import {
  useEngagement, useScans, useStartScan, useCancelScan,
  useDelta, useUpdateEngagement, useCreateManualFinding,
  useDeleteEngagement, useScanStatus, useEngagementReportTemplates,
  useRevealWebhookSecret, useRotateWebhookSecret,
  useWebhookDeliveries, useTestWebhook,
  useScheduledScans, useCreateScheduledScan, useUpdateScheduledScan, useDeleteScheduledScan,
  useEngagementMembers, useAddEngagementMember, useRemoveEngagementMember,
} from '../lib/hooks';
import { SevBadge, StatusBadge } from '../components/Badges';
import { engagements, findings } from '../lib/api';
import type { FindingOut, WebhookDeliveryOut } from '../lib/api';

const SEV_COLORS: Record<string, string> = {
  Critical:'#ef4444', High:'#f97316', Medium:'#eab308', Low:'#3b82f6', Info:'#6b7280',
};

type Tab = 'scans' | 'scheduled' | 'delta' | 'scope' | 'settings';

export default function Engagement() {
  const { id }   = useParams<{ id: string }>();
  const navigate = useNavigate();
  const engId    = Number(id);

  const { user } = useAuth();
  const { data: eng,   isLoading: engLoading  } = useEngagement(engId);
  const { data: scans, isLoading: scansLoading } = useScans(engId);

  const [tab,       setTab      ] = useState<Tab>('scans');
  const [showScan,  setShowScan ] = useState(false);
  const [logScanId, setLogScanId] = useState<string | null>(null);
  const [editScope, setEditScope ] = useState(false);
  const [editWebhook, setEditWebhook] = useState(false);
  const [editTemplate, setEditTemplate] = useState(false);

  if (engLoading) return <div style={{ padding:40, color:'var(--muted)' }}>Loading…</div>;
  if (!eng)       return <div style={{ padding:40, color:'#ef4444' }}>Engagement not found.</div>;

  const summary = eng.severity_summary;

  return (
    <>
      {/* Header */}
      <div className="topbar">
        <div>
          <div style={{ fontSize:12, color:'var(--muted)', marginBottom:4 }}>
            <Link to="/engagements" style={{ color:'var(--muted)', textDecoration:'none' }}>
              Engagements
            </Link> / {eng.client_name}
          </div>
          <h1>{eng.name}</h1>
          <div className="sub">
            <StatusBadge status={eng.status} />
            {eng.description && <span style={{ marginLeft:10 }}>{eng.description.slice(0,80)}</span>}
          </div>
        </div>
        <div style={{ display:'flex', gap:8 }}>
          <a href={engagements.reportUrl(engId)} target="_blank" rel="noreferrer"
             className="btn btn-ghost">
            ↓ Export PDF
          </a>
          <ExportCsvButton engId={engId} engName={eng.name} />
          {user?.role === 'Admin' && (
            <DeleteEngagementButton engId={engId} name={eng.name} />
          )}
          <button className="btn btn-primary" onClick={() => setShowScan(true)}>
            + New Scan
          </button>
        </div>
      </div>

      {/* Severity summary */}
      <div className="grid-5" style={{ marginBottom:24 }}>
        {(['Critical','High','Medium','Low','Info'] as const).map(sev => (
          <Link key={sev}
                to={`/findings?engagement_id=${engId}&severity=${sev}&status=Open`}
                style={{ textDecoration:'none' }}>
            <div className="stat-card" style={{ borderTop:`3px solid ${SEV_COLORS[sev]}`,
                                                cursor:'pointer' }}>
              <div className="num" style={{ color:SEV_COLORS[sev] }}>{summary[sev]}</div>
              <div className="lbl">{sev}</div>
            </div>
          </Link>
        ))}
      </div>

      {/* Tabs */}
      <div style={{ display:'flex', gap:2, marginBottom:16, borderBottom:'1px solid var(--border)' }}>
        {(['scans','scheduled','delta','scope','settings'] as Tab[]).map(t => (
          <button key={t} onClick={() => setTab(t)} style={{
            padding:'8px 18px', background:'none', border:'none',
            borderBottom: tab === t ? '2px solid var(--accent)' : '2px solid transparent',
            color: tab === t ? 'var(--accent)' : 'var(--muted)',
            fontSize:13, fontWeight:500, cursor:'pointer', marginBottom:-1, textTransform:'capitalize',
          }}>
            {t === 'delta' ? '⟳ Delta / Re-test' : t.charAt(0).toUpperCase() + t.slice(1)}
          </button>
        ))}
      </div>

      {/* Scans tab */}
      {tab === 'scans' && (
        <div className="card">
          <div className="card-head">
            <h2>Scans</h2>
            <span style={{ color:'var(--muted)', fontSize:12 }}>
              {scans?.length ?? 0} scan{scans?.length !== 1 ? 's' : ''}
            </span>
          </div>
          {scansLoading ? (
            <div className="empty">Loading…</div>
          ) : !scans?.length ? (
            <div className="empty">No scans yet. Start one above.</div>
          ) : (
            <table>
              <thead><tr>
                <th>Type</th><th>Target</th><th>Status</th>
                <th>Findings</th><th>Started</th><th></th>
              </tr></thead>
              <tbody>
                {scans.map(scan => (
                  <tr key={scan.scan_id}>
                    <td>
                      <span className="mono" style={{
                        fontSize:11, background:'var(--surface2)',
                        padding:'2px 6px', borderRadius:4,
                      }}>
                        {scan.scan_type.toUpperCase()}
                      </span>
                    </td>
                    <td className="truncate mono" style={{ maxWidth:240, fontSize:12 }}
                        title={scan.target}>
                      {scan.target}
                    </td>
                    <td><StatusBadge status={scan.status} /></td>
                    <td>
                      {scan.finding_count > 0 ? (
                        <Link to={`/findings?scan_id=${scan.scan_id}`}
                              style={{ color:'var(--accent)', fontWeight:500 }}>
                          {scan.finding_count}
                        </Link>
                      ) : scan.finding_count}
                    </td>
                    <td style={{ color:'var(--muted)', fontSize:12 }}>
                      {scan.started_at ? new Date(scan.started_at).toLocaleString() : '—'}
                    </td>
                    <td>
                      <div style={{ display:'flex', gap:6 }}>
                        {(scan.status === 'Running' || scan.status === 'Queued') && (
                          <>
                            <button className="btn btn-ghost btn-sm"
                                    onClick={() => setLogScanId(scan.scan_id)}>
                              View log
                            </button>
                            <CancelButton engId={engId} scanId={scan.scan_id} />
                          </>
                        )}
                        {scan.status === 'Running' && (
                          <button className="btn btn-ghost btn-sm"
                                  onClick={() => setLogScanId(scan.scan_id)}>
                            Log
                          </button>
                        )}
                        {scan.status === 'Completed' && (
                          <>
                            <Link to={`/findings?scan_id=${scan.scan_id}`}
                                  className="btn btn-ghost btn-sm">
                              Findings
                            </Link>
                            <ManualFindingButton scanId={scan.scan_id} />
                          </>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}

      {/* Scheduled scans tab */}
      {tab === 'scheduled' && <ScheduledScansPanel engId={engId} />}

      {/* Delta tab */}
      {tab === 'delta' && <DeltaPanel engId={engId} scans={scans ?? []} />}

      {/* Scope tab */}
      {tab === 'scope' && (
        <ScopePanel engId={engId} scope={eng.scope}
                    editing={editScope} setEditing={setEditScope} />
      )}

      {/* Settings tab */}
      {tab === 'settings' && (
        <div style={{ display:'flex', flexDirection:'column', gap:16 }}>
          <MembersPanel engId={engId} isOwnerOrAdmin={
            user?.role === 'Admin' || eng.created_by === user?.id
          } />
          <WebhookPanel engId={engId} webhookUrl={eng.webhook_url}
                        editing={editWebhook} setEditing={setEditWebhook} />
          <ReportTemplatePanel engId={engId}
                               reportTemplateId={eng.report_template_id}
                               editing={editTemplate} setEditing={setEditTemplate} />
        </div>
      )}

      {showScan && (
        <ScanModal engId={engId} onClose={() => setShowScan(false)}
                   onStarted={(sid) => { setShowScan(false); setLogScanId(sid); }} />
      )}
      {logScanId && (
        <LogModal scanId={logScanId} onClose={() => setLogScanId(null)} />
      )}
    </>
  );
}

/* ── CSV export ─────────────────────────────────────────────────────────────
   No backend export endpoint exists (yet) — this pages through the
   existing /api/findings list (max 500/page) and builds the CSV client-side.
   Fine for the volumes a single engagement produces; if that changes, move
   this to a streamed backend endpoint instead of raising the client-side
   page count indefinitely. */
const CSV_COLUMNS: (keyof FindingOut)[] = [
  'id', 'tool', 'vulnerability_name', 'severity', 'cvss_score', 'cve_id',
  'cwe_id', 'target_url', 'host', 'port', 'file_path', 'line_number',
  'status', 'first_seen', 'last_seen',
];

function _csvCell(value: unknown): string {
  const s = value === null || value === undefined ? '' : String(value);
  return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

async function _fetchAllFindings(engId: number): Promise<FindingOut[]> {
  const pageSize = 500;
  const all: FindingOut[] = [];
  let offset = 0;
  for (;;) {
    const page = await findings.list({ engagement_id: engId, limit: pageSize, offset });
    all.push(...page.items);
    if (all.length >= page.total || page.items.length === 0) break;
    offset += pageSize;
  }
  return all;
}

function ExportCsvButton({ engId, engName }: { engId: number; engName: string }) {
  const [busy, setBusy] = useState(false);
  const [err,  setErr ] = useState('');

  async function doExport() {
    setBusy(true);
    setErr('');
    try {
      const rows = await _fetchAllFindings(engId);
      const header = CSV_COLUMNS.join(',');
      const body   = rows.map(r => CSV_COLUMNS.map(c => _csvCell(r[c])).join(',')).join('\n');
      const blob   = new Blob([header + '\n' + body], { type: 'text/csv;charset=utf-8;' });
      const url    = URL.createObjectURL(blob);
      const a      = document.createElement('a');
      const slug   = engName.replace(/[^\w.-]/g, '_').slice(0, 60);
      a.href = url;
      a.download = `${slug}_findings.csv`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
    } catch (e: unknown) {
      setErr(e instanceof Error ? e.message : 'Export failed');
    } finally {
      setBusy(false);
    }
  }

  return (
    <span style={{ display:'flex', alignItems:'center', gap:6 }}>
      {err && <span style={{ fontSize:12, color:'#ef4444' }}>{err}</span>}
      <button className="btn btn-ghost" onClick={doExport} disabled={busy}>
        {busy ? 'Exporting…' : '↓ Export CSV'}
      </button>
    </span>
  );
}

/* ── Delete Engagement Button ───────────────────────────────────────────────── */
function DeleteEngagementButton({ engId, name }: { engId: number; name: string }) {
  const navigate   = useNavigate();
  const deleteEng  = useDeleteEngagement();
  const [confirm, setConfirm] = useState(false);
  const [err,     setErr    ] = useState('');

  async function doDelete() {
    try {
      await deleteEng.mutateAsync(engId);
      navigate('/engagements');
    } catch (e: unknown) {
      setErr(e instanceof Error ? e.message : 'Delete failed');
      setConfirm(false);
    }
  }

  if (!confirm) {
    return (
      <button className="btn btn-ghost"
              style={{ color:'#ef4444' }}
              onClick={() => setConfirm(true)}>
        Delete
      </button>
    );
  }

  return (
    <div style={{ display:'flex', gap:6, alignItems:'center' }}>
      {err && <span style={{ fontSize:12, color:'#ef4444' }}>{err}</span>}
      <span style={{ fontSize:12, color:'var(--muted)' }}>
        Delete "{name.slice(0,20)}{name.length>20?'…':''}"?
      </span>
      <button className="btn btn-danger btn-sm"
              disabled={deleteEng.isPending}
              onClick={doDelete}>
        {deleteEng.isPending ? '…' : 'Confirm Delete'}
      </button>
      <button className="btn btn-ghost btn-sm" onClick={() => setConfirm(false)}>
        Cancel
      </button>
    </div>
  );
}

/* ── Cancel button ─────────────────────────────────────────────────────────── */
function CancelButton({ engId, scanId }: { engId: number; scanId: string }) {
  const cancel = useCancelScan(engId);
  const [confirming, setConfirming] = useState(false);

  if (confirming) {
    return (
      <span style={{ display:'flex', gap:4 }}>
        <button className="btn btn-danger btn-sm"
                disabled={cancel.isPending}
                onClick={() => cancel.mutate(scanId, { onSettled: () => setConfirming(false) })}>
          {cancel.isPending ? '…' : 'Confirm'}
        </button>
        <button className="btn btn-ghost btn-sm" onClick={() => setConfirming(false)}>✕</button>
      </span>
    );
  }
  return (
    <button className="btn btn-ghost btn-sm" style={{ color:'#ef4444' }}
            onClick={() => setConfirming(true)}>
      Cancel
    </button>
  );
}

/* ── Scope panel ───────────────────────────────────────────────────────────── */
function ScopePanel({ engId, scope, editing, setEditing }: {
  engId: number; scope: string | null;
  editing: boolean; setEditing: (v: boolean) => void;
}) {
  const update = useUpdateEngagement(engId);
  const [draft, setDraft] = useState(scope ?? '');
  const [msg,   setMsg  ] = useState('');

  async function save() {
    try {
      await update.mutateAsync({ scope: draft || undefined });
      setMsg('✓ Scope saved');
      setEditing(false);
      setTimeout(() => setMsg(''), 2500);
    } catch (e: unknown) {
      setMsg(e instanceof Error ? e.message : 'Save failed');
    }
  }

  const lines = (scope ?? '').split('\n').filter(Boolean);

  return (
    <div className="card" style={{ padding:24 }}>
      <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center',
                    marginBottom:16 }}>
        <h2 style={{ fontSize:14, fontWeight:600 }}>Engagement Scope</h2>
        {!editing && (
          <button className="btn btn-ghost btn-sm" onClick={() => { setDraft(scope??''); setEditing(true); }}>
            Edit
          </button>
        )}
      </div>

      {msg && (
        <div style={{ fontSize:12, color: msg.startsWith('✓') ? '#4ade80' : '#ef4444',
                      marginBottom:12 }}>
          {msg}
        </div>
      )}

      {editing ? (
        <>
          <div style={{ fontSize:12, color:'var(--muted)', marginBottom:8, lineHeight:1.6 }}>
            One entry per line: CIDR (<code>10.0.0.0/8</code>), hostname glob (<code>*.example.com</code>),
            or URL prefix (<code>https://app.example.com</code>).
          </div>
          <textarea value={draft} onChange={e => setDraft(e.target.value)}
                    rows={8}
                    placeholder={'*.example.com\nhttps://app.example.com/api\n10.10.0.0/16'}
                    style={{ fontFamily:'monospace', fontSize:12, marginBottom:12, resize:'vertical' }} />
          <div style={{ display:'flex', gap:8 }}>
            <button className="btn btn-primary" onClick={save} disabled={update.isPending}>
              {update.isPending ? 'Saving…' : 'Save Scope'}
            </button>
            <button className="btn btn-ghost" onClick={() => setEditing(false)}>Cancel</button>
          </div>
        </>
      ) : lines.length === 0 ? (
        <div style={{ color:'var(--muted)', fontSize:13, padding:'24px 0', textAlign:'center' }}>
          No scope defined — all targets are treated as in-scope.
          <br />
          <button className="btn btn-ghost btn-sm" style={{ marginTop:12 }}
                  onClick={() => { setDraft(''); setEditing(true); }}>
            Define scope
          </button>
        </div>
      ) : (
        <div style={{
          background:'var(--surface2)', borderRadius:8, padding:'12px 16px',
          fontFamily:'monospace', fontSize:12, lineHeight:2,
        }}>
          {lines.map((line, i) => (
            <div key={i} style={{ color:'var(--text)' }}>
              <span style={{ color:'var(--muted)', marginRight:12 }}>●</span>{line}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

/* ── Members (engagement sharing) ─────────────────────────────────────────── */
function MembersPanel({ engId, isOwnerOrAdmin }: { engId: number; isOwnerOrAdmin: boolean }) {
  const { data: members = [], isLoading } = useEngagementMembers(engId);
  const add    = useAddEngagementMember(engId);
  const remove = useRemoveEngagementMember(engId);
  const [username, setUsername] = useState('');
  const [error, setError] = useState('');

  async function handleAdd() {
    setError('');
    if (!username.trim()) { setError('Username is required'); return; }
    try {
      await add.mutateAsync(username.trim());
      setUsername('');
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed to add member');
    }
  }

  async function handleRemove(userId: number, uname: string) {
    if (!confirm(`Remove ${uname} from this engagement?`)) return;
    try {
      await remove.mutateAsync(userId);
    } catch (e: unknown) {
      alert(e instanceof Error ? e.message : 'Failed to remove member');
    }
  }

  return (
    <div className="card" style={{ padding:24 }}>
      <h2 style={{ fontSize:14, fontWeight:600, marginBottom:4 }}>Members</h2>
      <div style={{ fontSize:12, color:'var(--muted)', marginBottom:16 }}>
        People with access to this engagement beyond its creator. A member gets
        the same read/write access as the owner, bounded by their own account role
        — a Viewer added here still can't edit, only view.
      </div>

      {error && <div style={{ fontSize:12, color:'#ef4444', marginBottom:10 }}>{error}</div>}

      {isLoading ? (
        <div style={{ fontSize:13, color:'var(--muted)' }}>Loading…</div>
      ) : members.length === 0 ? (
        <div style={{ fontSize:13, color:'var(--muted)', marginBottom:16 }}>
          No additional members — only the owner (and Admins) can access this engagement.
        </div>
      ) : (
        <div style={{ display:'flex', flexDirection:'column', gap:6, marginBottom:16 }}>
          {members.map(m => (
            <div key={m.id} style={{
              display:'flex', alignItems:'center', gap:10, fontSize:13,
              background:'var(--surface2)', borderRadius:6, padding:'8px 12px',
            }}>
              <span style={{ fontWeight:500 }}>{m.username}</span>
              <span style={{ fontSize:11, color:'var(--muted)' }}>{m.role}</span>
              <span style={{ flex:1 }} />
              {isOwnerOrAdmin && (
                <button className="btn btn-ghost btn-sm" style={{ color:'#ef4444' }}
                        onClick={() => handleRemove(m.user_id, m.username)}>
                  Remove
                </button>
              )}
            </div>
          ))}
        </div>
      )}

      {isOwnerOrAdmin && (
        <div style={{ display:'flex', gap:8 }}>
          <input value={username} onChange={e => setUsername(e.target.value)}
                 placeholder="Username to add" style={{ flex:1 }}
                 onKeyDown={e => { if (e.key === 'Enter') handleAdd(); }} />
          <button className="btn btn-primary btn-sm" onClick={handleAdd} disabled={add.isPending}>
            {add.isPending ? 'Adding…' : 'Add Member'}
          </button>
        </div>
      )}
    </div>
  );
}

/* ── Webhook settings ─────────────────────────────────────────────────────── */
function WebhookPanel({ engId, webhookUrl, editing, setEditing }: {
  engId: number; webhookUrl: string | null;
  editing: boolean; setEditing: (v: boolean) => void;
}) {
  const update = useUpdateEngagement(engId);
  const [draft, setDraft] = useState(webhookUrl ?? '');
  const [msg,   setMsg  ] = useState('');

  async function save() {
    const trimmed = draft.trim();
    if (trimmed && !/^https?:\/\/.+/i.test(trimmed)) {
      setMsg('Webhook URL must start with http:// or https://');
      return;
    }
    try {
      // '' explicitly clears the webhook; omitting the field leaves it unchanged.
      await update.mutateAsync({ webhook_url: trimmed || '' });
      setMsg('✓ Webhook saved');
      setEditing(false);
      setTimeout(() => setMsg(''), 2500);
    } catch (e: unknown) {
      setMsg(e instanceof Error ? e.message : 'Save failed');
    }
  }

  return (
    <div className="card" style={{ padding:24 }}>
      <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center',
                    marginBottom:16 }}>
        <h2 style={{ fontSize:14, fontWeight:600 }}>Webhook</h2>
        {!editing && (
          <button className="btn btn-ghost btn-sm"
                  onClick={() => { setDraft(webhookUrl ?? ''); setEditing(true); }}>
            Edit
          </button>
        )}
      </div>

      {msg && (
        <div style={{ fontSize:12, color: msg.startsWith('✓') ? '#4ade80' : '#ef4444',
                      marginBottom:12 }}>
          {msg}
        </div>
      )}

      {editing ? (
        <>
          <div style={{ fontSize:12, color:'var(--muted)', marginBottom:8, lineHeight:1.6 }}>
            A JSON POST is sent here whenever a scan on this engagement finishes
            (Completed / Failed / Cancelled). Must be a public http(s) endpoint —
            internal/private addresses are rejected. Leave blank to disable.
          </div>
          <input value={draft} onChange={e => setDraft(e.target.value)}
                 placeholder="https://hooks.example.com/mste"
                 style={{ marginBottom:12 }} />
          <div style={{ display:'flex', gap:8 }}>
            <button className="btn btn-primary" onClick={save} disabled={update.isPending}>
              {update.isPending ? 'Saving…' : 'Save Webhook'}
            </button>
            <button className="btn btn-ghost" onClick={() => setEditing(false)}>Cancel</button>
          </div>
        </>
      ) : !webhookUrl ? (
        <div style={{ color:'var(--muted)', fontSize:13, padding:'24px 0', textAlign:'center' }}>
          No webhook configured — scan completions are not sent anywhere.
          <br />
          <button className="btn btn-ghost btn-sm" style={{ marginTop:12 }}
                  onClick={() => { setDraft(''); setEditing(true); }}>
            Add webhook
          </button>
        </div>
      ) : (
        <div style={{
          background:'var(--surface2)', borderRadius:8, padding:'12px 16px',
          fontFamily:'monospace', fontSize:12,
        }}>
          {webhookUrl}
        </div>
      )}

      {webhookUrl && !editing && <WebhookSecretSection engId={engId} />}
      {webhookUrl && !editing && <WebhookDeliverySection engId={engId} />}
    </div>
  );
}

/* ── Webhook delivery history + test ping ────────────────────────────────── */
function WebhookDeliverySection({ engId }: { engId: number }) {
  const [expanded, setExpanded] = useState(false);
  const { data: deliveries = [], isLoading } = useWebhookDeliveries(engId, expanded);
  const test = useTestWebhook(engId);
  const [testResult, setTestResult] = useState<WebhookDeliveryOut | null>(null);

  async function sendTest() {
    setTestResult(null);
    try {
      const result = await test.mutateAsync();
      setTestResult(result);
      setExpanded(true);
    } catch {
      // test.error renders below
    }
  }

  return (
    <div style={{ marginTop:16, paddingTop:16, borderTop:'1px solid var(--border)' }}>
      <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center',
                    marginBottom:8 }}>
        <button className="btn btn-ghost btn-sm" onClick={() => setExpanded(v => !v)}>
          {expanded ? '▾' : '▸'} Delivery History
        </button>
        <button className="btn btn-ghost btn-sm" onClick={sendTest} disabled={test.isPending}>
          {test.isPending ? 'Sending…' : 'Send Test Ping'}
        </button>
      </div>

      {test.error && (
        <div style={{ fontSize:12, color:'#ef4444', marginBottom:8 }}>
          {test.error instanceof Error ? test.error.message : 'Test ping failed'}
        </div>
      )}

      {testResult && (
        <div style={{
          fontSize:12, marginBottom:8, padding:'8px 12px', borderRadius:6,
          background: testResult.success
            ? 'color-mix(in srgb, #4ade80 15%, transparent)'
            : 'color-mix(in srgb, #ef4444 15%, transparent)',
          color: testResult.success ? '#4ade80' : '#ef4444',
        }}>
          {testResult.success
            ? `✓ Test ping delivered (HTTP ${testResult.status_code}, ${testResult.duration_ms}ms)`
            : `✗ Test ping failed${testResult.status_code ? ` (HTTP ${testResult.status_code})` : ''}${testResult.error ? ` — ${testResult.error}` : ''}`}
        </div>
      )}

      {expanded && (
        isLoading ? (
          <div style={{ fontSize:12, color:'var(--muted)' }}>Loading…</div>
        ) : deliveries.length === 0 ? (
          <div style={{ fontSize:12, color:'var(--muted)' }}>
            No deliveries yet — they'll show up here once a scan completes or
            you send a test ping.
          </div>
        ) : (
          <div style={{ display:'flex', flexDirection:'column', gap:6 }}>
            {deliveries.map(d => (
              <div key={d.id} style={{
                display:'flex', alignItems:'center', gap:10, fontSize:12,
                background:'var(--surface2)', borderRadius:6, padding:'8px 12px',
              }}>
                <span style={{ color: d.success ? '#4ade80' : '#ef4444', fontWeight:600 }}>
                  {d.success ? '✓' : '✗'}
                </span>
                <span style={{
                  fontSize:11, textTransform:'uppercase', color:'var(--muted)',
                  minWidth:90,
                }}>
                  {d.event === 'webhook.test' ? 'Test Ping' : 'Scan Complete'}
                </span>
                <span style={{ color:'var(--muted)', minWidth:60 }}>
                  {d.status_code ?? '—'}
                </span>
                <span style={{ color:'var(--muted)', flex:1 }}>
                  {d.error ?? (d.duration_ms !== null ? `${d.duration_ms}ms` : '')}
                </span>
                <span style={{ color:'var(--muted)', fontSize:11 }}>
                  {d.created_at ? new Date(d.created_at).toLocaleString() : ''}
                </span>
              </div>
            ))}
          </div>
        )
      )}
    </div>
  );
}

/* ── Webhook signing secret ───────────────────────────────────────────────── */
function WebhookSecretSection({ engId }: { engId: number }) {
  const reveal  = useRevealWebhookSecret(engId);
  const rotate  = useRotateWebhookSecret(engId);
  const [shown, setShown] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  async function doReveal() {
    try {
      const res = await reveal.mutateAsync();
      setShown(res.webhook_secret);
    } catch {
      // reveal.error is rendered below
    }
  }

  async function doRotate() {
    if (!confirm(
      'Rotate the signing secret? Deliveries will fail signature checks on ' +
      'the receiving end until it is updated with the new secret.'
    )) return;
    try {
      const res = await rotate.mutateAsync();
      setShown(res.webhook_secret);
    } catch {
      // rotate.error is rendered below
    }
  }

  function copy() {
    if (!shown) return;
    navigator.clipboard.writeText(shown);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  }

  return (
    <div style={{ marginTop:16, paddingTop:16, borderTop:'1px solid var(--border)' }}>
      <div style={{ fontSize:12, fontWeight:600, marginBottom:6 }}>Signing Secret</div>
      <div style={{ fontSize:12, color:'var(--muted)', marginBottom:10, lineHeight:1.6 }}>
        Every delivery includes an <code>X-MSTE-Signature</code> header
        (<code>sha256=&lt;hmac&gt;</code>) computed over{' '}
        <code>{'{timestamp}.{body}'}</code> using this secret, plus an{' '}
        <code>X-MSTE-Timestamp</code> header — verify both and reject stale
        timestamps (5+ minutes old) to guard against replay.
      </div>

      {(reveal.error || rotate.error) && (
        <div style={{ fontSize:12, color:'#ef4444', marginBottom:8 }}>
          {(reveal.error ?? rotate.error) instanceof Error
            ? (reveal.error ?? rotate.error)!.message
            : 'Request failed'}
        </div>
      )}

      {shown ? (
        <div style={{ display:'flex', alignItems:'center', gap:8, marginBottom:10 }}>
          <code style={{
            background:'var(--surface2)', borderRadius:8, padding:'8px 12px',
            fontSize:12, flex:1, wordBreak:'break-all',
          }}>
            {shown}
          </code>
          <button className="btn btn-ghost btn-sm" onClick={copy}>
            {copied ? '✓ Copied' : 'Copy'}
          </button>
        </div>
      ) : (
        <button className="btn btn-ghost btn-sm" onClick={doReveal}
                disabled={reveal.isPending} style={{ marginBottom:10 }}>
          {reveal.isPending ? 'Revealing…' : 'Reveal Secret'}
        </button>
      )}

      <div>
        <button className="btn btn-ghost btn-sm" onClick={doRotate} disabled={rotate.isPending}>
          {rotate.isPending ? 'Rotating…' : 'Rotate Secret'}
        </button>
      </div>
    </div>
  );
}

/* ── Report template settings ─────────────────────────────────────────────── */
function ReportTemplatePanel({ engId, reportTemplateId, editing, setEditing }: {
  engId: number; reportTemplateId: number | null;
  editing: boolean; setEditing: (v: boolean) => void;
}) {
  const update = useUpdateEngagement(engId);
  const { data: templates = [], isLoading, error } = useEngagementReportTemplates();
  const [draft, setDraft] = useState<number | null>(reportTemplateId);
  const [msg,   setMsg  ] = useState('');

  const current = templates.find(t => t.id === reportTemplateId);
  const defaultTemplate = templates.find(t => t.is_default);

  async function save() {
    try {
      // draft === null explicitly clears the override (falls back to the
      // global default) — distinct from omitting the field, which the
      // backend now treats as "leave unchanged".
      await update.mutateAsync({ report_template_id: draft });
      setMsg('✓ Saved');
      setEditing(false);
      setTimeout(() => setMsg(''), 2500);
    } catch (e: unknown) {
      setMsg(e instanceof Error ? e.message : 'Save failed');
    }
  }

  return (
    <div className="card" style={{ padding:24 }}>
      <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center',
                    marginBottom:16 }}>
        <h2 style={{ fontSize:14, fontWeight:600 }}>Report Template</h2>
        {!editing && (
          <button className="btn btn-ghost btn-sm"
                  onClick={() => { setDraft(reportTemplateId); setEditing(true); }}>
            Edit
          </button>
        )}
      </div>

      {msg && (
        <div style={{ fontSize:12, color: msg.startsWith('✓') ? '#4ade80' : '#ef4444',
                      marginBottom:12 }}>
          {msg}
        </div>
      )}

      {error && (
        <div style={{ fontSize:12, color:'#ef4444' }}>
          Could not load templates — {error instanceof Error ? error.message : 'unknown error'}
        </div>
      )}

      {editing ? (
        <>
          <div style={{ fontSize:12, color:'var(--muted)', marginBottom:8, lineHeight:1.6 }}>
            Overrides which template is used when exporting this engagement's PDF report.
            Leave on "Use global default" to follow whatever's set as default in
            Report Templates.
          </div>
          <select
            value={draft ?? ''}
            onChange={e => setDraft(e.target.value ? Number(e.target.value) : null)}
            disabled={isLoading}
            style={{ marginBottom:12 }}
          >
            <option value="">
              Use global default{defaultTemplate ? ` (${defaultTemplate.name})` : ''}
            </option>
            {templates.map(t => (
              <option key={t.id} value={t.id}>{t.name}{t.is_default ? ' (default)' : ''}</option>
            ))}
          </select>
          <div style={{ display:'flex', gap:8 }}>
            <button className="btn btn-primary" onClick={save} disabled={update.isPending}>
              {update.isPending ? 'Saving…' : 'Save'}
            </button>
            <button className="btn btn-ghost" onClick={() => setEditing(false)}>Cancel</button>
          </div>
        </>
      ) : (
        <div style={{
          background:'var(--surface2)', borderRadius:8, padding:'12px 16px', fontSize:13,
        }}>
          {reportTemplateId === null
            ? `Using global default${defaultTemplate ? ` (${defaultTemplate.name})` : ''}`
            : current
              ? current.name
              : `Template #${reportTemplateId} (not found — may have been deleted)`}
        </div>
      )}
    </div>
  );
}

/* ── Delta panel ───────────────────────────────────────────────────────────── */
function DeltaPanel({ engId, scans }: {
  engId: number;
  scans: { scan_id: string; status: string; scan_type: string; started_at: string | null }[];
}) {
  const completedScans = scans.filter(s => s.status === 'Completed');
  const [baseline, setBaseline] = useState('');

  const { data: delta, isLoading, error } = useDelta(
    engId, baseline || undefined
  );

  if (completedScans.length < 2 && !baseline) {
    return (
      <div className="card">
        <div className="empty" style={{ padding:'48px 20px' }}>
          <p style={{ fontSize:15, marginBottom:8 }}>⟳ Re-test Delta</p>
          <p style={{ fontSize:13, color:'var(--muted)' }}>
            Run at least two scans on this engagement to compare results.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div style={{ display:'flex', flexDirection:'column', gap:16 }}>
      {/* Baseline selector */}
      <div className="card" style={{ padding:'14px 18px' }}>
        <div style={{ display:'flex', alignItems:'center', gap:12 }}>
          <label style={{ fontSize:12, color:'var(--muted)', whiteSpace:'nowrap' }}>
            Compare against:
          </label>
          <select value={baseline} onChange={e => setBaseline(e.target.value)}
                  style={{ width:320 }}>
            <option value="">← Previous scan (default)</option>
            {completedScans.slice(0, -1).map(s => (
              <option key={s.scan_id} value={s.scan_id}>
                {s.scan_type.toUpperCase()} — {s.started_at
                  ? new Date(s.started_at).toLocaleString() : s.scan_id.slice(0,12)}
              </option>
            ))}
          </select>
        </div>
      </div>

      {isLoading && <div className="card"><div className="empty">Computing delta…</div></div>}

      {error && (
        <div className="card">
          <div className="empty" style={{ color:'var(--muted)' }}>
            {(error as Error).message}
          </div>
        </div>
      )}

      {delta && (
        <>
          {/* Summary pills */}
          <div style={{ display:'grid', gridTemplateColumns:'repeat(3,1fr)', gap:12 }}>
            {[
              { label:'New',      count:delta.new_count,       color:'#ef4444' },
              { label:'Recurring', count:delta.recurring_count, color:'#f97316' },
              { label:'Resolved', count:delta.resolved_count,  color:'#4ade80' },
            ].map(({ label, count, color }) => (
              <div key={label} className="stat-card" style={{ borderTop:`3px solid ${color}` }}>
                <div className="num" style={{ color }}>{count}</div>
                <div className="lbl">{label}</div>
              </div>
            ))}
          </div>

          <DeltaBucket title="🔴 New Findings" color="#ef4444" findings={delta.new} />
          <DeltaBucket title="🔁 Recurring (Not Fixed)" color="#f97316" findings={delta.recurring} />
          <DeltaBucket title="✅ Resolved" color="#4ade80" findings={delta.resolved} />
        </>
      )}
    </div>
  );
}

function DeltaBucket({ title, color, findings }: {
  title: string; color: string; findings: FindingOut[];
}) {
  if (!findings.length) return null;
  return (
    <div className="card">
      <div className="card-head">
        <h2 style={{ color }}>{title}</h2>
        <span style={{ color:'var(--muted)', fontSize:12 }}>{findings.length}</span>
      </div>
      <table>
        <thead><tr>
          <th>Severity</th><th>Finding</th><th>Tool</th><th>Status</th>
        </tr></thead>
        <tbody>
          {findings.map(f => (
            <tr key={f.id}>
              <td><SevBadge severity={f.severity} /></td>
              <td>
                <Link to={`/findings/${f.id}`} style={{ fontWeight:500 }}>
                  {f.vulnerability_name.slice(0,72)}{f.vulnerability_name.length>72?'…':''}
                </Link>
              </td>
              <td style={{ color:'var(--muted)', fontSize:12 }}>{f.tool}</td>
              <td><StatusBadge status={f.status} /></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/* ── New Scan Modal ─────────────────────────────────────────────────────────── */
/* ── Scheduled scans ──────────────────────────────────────────────────────── */
function ScheduledScansPanel({ engId }: { engId: number }) {
  const { data: schedules = [], isLoading } = useScheduledScans(engId);
  const update = useUpdateScheduledScan(engId);
  const del    = useDeleteScheduledScan(engId);
  const [showNew, setShowNew] = useState(false);

  async function toggleEnabled(schedId: number, enabled: boolean) {
    try {
      await update.mutateAsync({ schedId, body: { enabled } });
    } catch (e: unknown) {
      alert(e instanceof Error ? e.message : 'Update failed');
    }
  }

  async function handleDelete(schedId: number, target: string) {
    if (!confirm(`Delete the recurring scan for "${target}"? This cannot be undone.`)) return;
    try {
      await del.mutateAsync(schedId);
    } catch (e: unknown) {
      alert(e instanceof Error ? e.message : 'Delete failed');
    }
  }

  return (
    <div className="card">
      <div className="card-head" style={{ display:'flex', justifyContent:'space-between',
                                           alignItems:'center' }}>
        <div>
          <h2 style={{ fontSize:14, fontWeight:600 }}>Scheduled Scans</h2>
          <div style={{ fontSize:12, color:'var(--muted)', marginTop:2 }}>
            Recurring scans dispatched automatically on an interval.
          </div>
        </div>
        <button className="btn btn-primary btn-sm" onClick={() => setShowNew(true)}>
          + New Schedule
        </button>
      </div>

      {isLoading ? (
        <div className="empty">Loading…</div>
      ) : schedules.length === 0 ? (
        <div className="empty" style={{ padding:'32px 20px' }}>
          No recurring scans configured for this engagement.
        </div>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Type</th><th>Target</th><th>Interval</th>
              <th>Next Run</th><th>Last Run</th><th>Status</th><th></th>
            </tr>
          </thead>
          <tbody>
            {schedules.map(s => (
              <tr key={s.id}>
                <td style={{ textTransform:'uppercase', fontSize:11 }}>{s.scan_type}</td>
                <td style={{ maxWidth:220, overflow:'hidden', textOverflow:'ellipsis' }}>
                  {s.target}
                </td>
                <td>{formatInterval(s.interval_hours)}</td>
                <td style={{ fontSize:12, color:'var(--muted)' }}>
                  {s.enabled && s.next_run_at ? new Date(s.next_run_at).toLocaleString() : '—'}
                </td>
                <td style={{ fontSize:12, color:'var(--muted)' }}>
                  {s.last_run_at ? new Date(s.last_run_at).toLocaleString() : 'Never'}
                </td>
                <td>
                  <label style={{ display:'flex', alignItems:'center', gap:6, cursor:'pointer' }}>
                    <input type="checkbox" checked={s.enabled}
                          onChange={e => toggleEnabled(s.id, e.target.checked)}
                          style={{ width:14, height:14, accentColor:'var(--accent)' }} />
                    <span style={{ fontSize:12, color: s.enabled ? '#4ade80' : 'var(--muted)' }}>
                      {s.enabled ? 'Active' : 'Paused'}
                    </span>
                  </label>
                </td>
                <td>
                  <button className="btn btn-ghost btn-sm" style={{ color:'#ef4444' }}
                          onClick={() => handleDelete(s.id, s.target)}>
                    Delete
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {showNew && <ScheduleModal engId={engId} onClose={() => setShowNew(false)} />}
    </div>
  );
}

function formatInterval(hours: number): string {
  if (hours === 1)   return 'Hourly';
  if (hours === 24)  return 'Daily';
  if (hours === 168) return 'Weekly';
  if (hours === 720) return 'Monthly';
  return hours < 24 ? `Every ${hours}h` : `Every ${Math.round(hours / 24)}d`;
}

function ScheduleModal({ engId, onClose }: { engId: number; onClose: () => void }) {
  const create = useCreateScheduledScan(engId);
  const [scanType, setScanType] = useState('web');
  const [target,   setTarget  ] = useState('');
  const [interval, setInterval_] = useState(24);
  const [customHours, setCustomHours] = useState('');
  const [runNow,   setRunNow  ] = useState(false);
  const [auth,     setAuth    ] = useState('');
  const [proxy,    setProxy   ] = useState('');
  const [katana,   setKatana  ] = useState(false);
  const [sqlmap,   setSqlmap  ] = useState(false);
  const [stealth,  setStealth ] = useState(false);
  const [gitToken, setGitToken] = useState('');
  const [error,    setError   ] = useState('');
  const [warning,  setWarning ] = useState('');

  const isCustom = interval === -1;
  const effectiveHours = isCustom ? parseInt(customHours, 10) : interval;

  async function submit() {
    setError(''); setWarning('');
    if (!target.trim()) { setError('Target is required'); return; }
    if (!effectiveHours || effectiveHours < 1 || effectiveHours > 8760) {
      setError('Interval must be between 1 and 8760 hours'); return;
    }
    try {
      const body: Parameters<typeof create.mutateAsync>[0] = {
        scan_type: scanType, target, interval_hours: effectiveHours,
        run_immediately: runNow,
      };
      if (auth)     body.auth_header = auth;
      if (proxy)    body.proxy       = proxy;
      if (gitToken) body.git_token   = gitToken;
      body.enable_katana  = katana;
      body.enable_sqlmap  = sqlmap;
      body.enable_stealth = stealth;
      const result = await create.mutateAsync(body);
      if (result.scope_warning) {
        setWarning(result.scope_warning);
      }
      onClose();
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed to create schedule');
    }
  }

  const cloudHint: Record<string, string> = {
    cloud:  'Format: provider:resource — e.g. aws:default, gcp:my-project, azure:my-tenant',
    mobile: 'URL to APK/IPA file — e.g. https://builds.example.com/app.apk',
    sast:   'Git repository URL — e.g. https://github.com/org/repo',
    infra:  'IP address or CIDR range — e.g. 192.168.1.0/24',
    web:    'Full URL including scheme — e.g. https://app.example.com',
  };

  return (
    <Overlay onClose={onClose}>
      <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom:20 }}>
        <h2 style={{ fontSize:16 }}>New Scheduled Scan</h2>
        <button onClick={onClose} style={closeBtn}>×</button>
      </div>

      {error   && <div style={errorBox}>{error}</div>}
      {warning && <div style={{ ...errorBox, background:'#1a1400', color:'#eab308',
                                border:'1px solid #5a4a00' }}>{warning}</div>}

      <Field label="Scan Type">
        <select value={scanType} onChange={e => { setScanType(e.target.value); setTarget(''); }}>
          <option value="web">Web / API</option>
          <option value="sast">SAST / SCA (Git repo)</option>
          <option value="infra">Infrastructure (IP / CIDR)</option>
          <option value="cloud">Cloud (AWS / GCP / Azure)</option>
          <option value="mobile">Mobile (APK / IPA)</option>
        </select>
      </Field>

      <Field label="Target" hint={cloudHint[scanType]}>
        <input value={target} onChange={e => setTarget(e.target.value)}
               placeholder={
                 scanType === 'cloud'  ? 'aws:default' :
                 scanType === 'mobile' ? 'https://cdn.example.com/app.apk' :
                 scanType === 'sast'   ? 'https://github.com/org/repo' :
                 scanType === 'infra'  ? '192.168.1.0/24' :
                                         'https://app.example.com'
               } />
      </Field>

      <Field label="Repeat">
        <select value={interval} onChange={e => setInterval_(Number(e.target.value))}>
          <option value={1}>Hourly</option>
          <option value={24}>Daily</option>
          <option value={168}>Weekly</option>
          <option value={720}>Monthly (30 days)</option>
          <option value={-1}>Custom…</option>
        </select>
      </Field>

      {isCustom && (
        <Field label="Custom interval (hours)">
          <input type="number" min={1} max={8760} value={customHours}
                 onChange={e => setCustomHours(e.target.value)} placeholder="e.g. 12" />
        </Field>
      )}

      <label style={{ display:'flex', alignItems:'center', gap:8, fontSize:13,
                      cursor:'pointer', marginBottom:18 }}>
        <input type="checkbox" checked={runNow} onChange={e => setRunNow(e.target.checked)}
               style={{ width:15, height:15, accentColor:'var(--accent)' }} />
        Run the first scan immediately (otherwise, first run is one interval from now)
      </label>

      {scanType === 'web' && <>
        <Field label="Auth Header (optional)">
          <input value={auth} onChange={e => setAuth(e.target.value)}
                 placeholder="Cookie: PHPSESSID=abc  or  Bearer eyJ…" />
        </Field>
        <Field label="Proxy URL (optional)">
          <input value={proxy} onChange={e => setProxy(e.target.value)}
                 placeholder="http://host.docker.internal:8081" />
        </Field>
        <div style={{ display:'flex', flexDirection:'column', gap:10, marginBottom:18 }}>
          {([
            ['Katana SPA crawler',          katana,  setKatana ] as const,
            ['SQLmap database probe',       sqlmap,  setSqlmap ] as const,
            ['Stealth mode (rate limiting)', stealth, setStealth] as const,
          ]).map(([label, val, set]) => (
            <label key={label} style={{ display:'flex', alignItems:'center', gap:8, fontSize:13, cursor:'pointer' }}>
              <input type="checkbox" checked={val} onChange={e => set(e.target.checked)}
                     style={{ width:15, height:15, accentColor:'var(--accent)' }} />
              {label}
            </label>
          ))}
        </div>
      </>}

      {scanType === 'sast' && (
        <Field label="Git Token (optional — private repos)"
               hint="Stored encrypted at rest — needed on every recurring run, unlike a one-off scan.">
          <input type="password" value={gitToken} onChange={e => setGitToken(e.target.value)}
                 placeholder="ghp_…" />
        </Field>
      )}

      <div style={{ display:'flex', gap:10, justifyContent:'flex-end', marginTop:8 }}>
        <button onClick={onClose} className="btn btn-ghost">Cancel</button>
        <button onClick={submit} disabled={create.isPending} className="btn btn-primary">
          {create.isPending ? 'Creating…' : 'Create Schedule'}
        </button>
      </div>
    </Overlay>
  );
}

/* ── Scan Modal ──────────────────────────────────────────────────────────────── */
function ScanModal({ engId, onClose, onStarted }: {
  engId: number; onClose: () => void; onStarted: (scanId: string) => void;
}) {
  const startScan = useStartScan(engId);
  const [scanType, setScanType] = useState('web');
  const [target,   setTarget  ] = useState('');
  const [auth,     setAuth    ] = useState('');
  const [proxy,    setProxy   ] = useState('');
  const [katana,   setKatana  ] = useState(false);
  const [sqlmap,   setSqlmap  ] = useState(false);
  const [stealth,  setStealth ] = useState(false);
  const [gitToken, setGitToken] = useState('');
  const [error,    setError   ] = useState('');
  const [warning,  setWarning ] = useState('');

  async function submit() {
    setError(''); setWarning('');
    if (!target.trim()) { setError('Target is required'); return; }
    try {
      const body: Record<string, unknown> = { scan_type: scanType, target };
      if (auth)     body.auth_header    = auth;
      if (proxy)    body.proxy          = proxy;
      if (gitToken) body.git_token      = gitToken;
      body.enable_katana  = katana;
      body.enable_sqlmap  = sqlmap;
      body.enable_stealth = stealth;
      const scan = await startScan.mutateAsync(body);
      if (scan.scope_warning) {
        setWarning(scan.scope_warning);
        // Still proceed — analyst acknowledged
      }
      onStarted(scan.scan_id);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed to start scan');
    }
  }

  const cloudHint: Record<string, string> = {
    cloud:  'Format: provider:resource — e.g. aws:default, gcp:my-project, azure:my-tenant',
    mobile: 'URL to APK/IPA file — e.g. https://builds.example.com/app.apk',
    sast:   'Git repository URL — e.g. https://github.com/org/repo',
    infra:  'IP address or CIDR range — e.g. 192.168.1.0/24',
    web:    'Full URL including scheme — e.g. https://app.example.com',
  };

  return (
    <Overlay onClose={onClose}>
      <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom:20 }}>
        <h2 style={{ fontSize:16 }}>New Scan</h2>
        <button onClick={onClose} style={closeBtn}>×</button>
      </div>

      {error   && <div style={errorBox}>{error}</div>}
      {warning && <div style={{ ...errorBox, background:'#1a1400', color:'#eab308',
                                border:'1px solid #5a4a00' }}>{warning}</div>}

      <Field label="Scan Type">
        <select value={scanType} onChange={e => { setScanType(e.target.value); setTarget(''); }}>
          <option value="web">Web / API</option>
          <option value="sast">SAST / SCA (Git repo)</option>
          <option value="infra">Infrastructure (IP / CIDR)</option>
          <option value="cloud">Cloud (AWS / GCP / Azure)</option>
          <option value="mobile">Mobile (APK / IPA)</option>
        </select>
      </Field>

      <Field label="Target" hint={cloudHint[scanType]}>
        <input value={target} onChange={e => setTarget(e.target.value)}
               placeholder={
                 scanType === 'cloud'  ? 'aws:default' :
                 scanType === 'mobile' ? 'https://cdn.example.com/app.apk' :
                 scanType === 'sast'   ? 'https://github.com/org/repo' :
                 scanType === 'infra'  ? '192.168.1.0/24' :
                                         'https://app.example.com'
               } />
      </Field>

      {scanType === 'web' && <>
        <Field label="Auth Header (optional)">
          <input value={auth} onChange={e => setAuth(e.target.value)}
                 placeholder="Cookie: PHPSESSID=abc  or  Bearer eyJ…" />
        </Field>
        <Field label="Proxy URL (optional)">
          <input value={proxy} onChange={e => setProxy(e.target.value)}
                 placeholder="http://host.docker.internal:8081" />
        </Field>
        <div style={{ display:'flex', flexDirection:'column', gap:10, marginBottom:18 }}>
          {([
            ['Katana SPA crawler',         katana,  setKatana ] as const,
            ['SQLmap database probe',       sqlmap,  setSqlmap ] as const,
            ['Stealth mode (rate limiting)', stealth, setStealth] as const,
          ]).map(([label, val, set]) => (
            <label key={label} style={{ display:'flex', alignItems:'center', gap:8, fontSize:13, cursor:'pointer' }}>
              <input type="checkbox" checked={val} onChange={e => set(e.target.checked)}
                     style={{ width:15, height:15, accentColor:'var(--accent)' }} />
              {label}
            </label>
          ))}
        </div>
      </>}

      {scanType === 'sast' && (
        <Field label="Git Token (optional — private repos)">
          <input type="password" value={gitToken} onChange={e => setGitToken(e.target.value)}
                 placeholder="ghp_…" />
        </Field>
      )}

      <div style={{ display:'flex', gap:10, justifyContent:'flex-end', marginTop:8 }}>
        <button onClick={onClose} className="btn btn-ghost">Cancel</button>
        <button onClick={submit} disabled={startScan.isPending} className="btn btn-primary">
          {startScan.isPending ? 'Starting…' : 'Start Scan'}
        </button>
      </div>
    </Overlay>
  );
}

/* ── Log Modal ──────────────────────────────────────────────────────────────── */
function LogModal({ scanId, onClose }: { scanId: string; onClose: () => void }) {
  const logRef = useRef<HTMLDivElement>(null);
  const [lines,    setLines   ] = useState<{ text: string; cls: string }[]>([]);
  const [done,     setDone    ] = useState(false);
  const [sseFailed, setSseFailed] = useState(false);

  // Fallback: poll scan status when SSE is unavailable (proxy issues, etc.)
  const { data: statusData } = useScanStatus(scanId, sseFailed && !done);
  useEffect(() => {
    if (!sseFailed) return;
    const s = statusData?.status ?? '';
    if (['Completed','Failed','Cancelled'].includes(s)) setDone(true);
  }, [statusData, sseFailed]);

  useEffect(() => {
    const es = new EventSource(`/api/scans/${scanId}/stream`);
    es.onmessage = (e) => {
      try {
        const parsed = JSON.parse(e.data);
        const cls = parsed.level === 'error'   ? 'err'
                  : parsed.level === 'success' ? 'ok'
                  : parsed.level === 'warning' ? 'warn' : '';
        setLines(prev => [...prev, { text: parsed.msg, cls }]);
        setTimeout(() => logRef.current?.scrollTo(0, logRef.current.scrollHeight), 10);
      } catch { /* ignore */ }
    };
    es.addEventListener('end',    () => { setDone(true); es.close(); });
    es.addEventListener('status', () => { /* non-terminal status change */ });
    es.onerror = () => {
      // SSE connection failed — switch to polling fallback
      setSseFailed(true);
      es.close();
    };
    return () => es.close();
  }, [scanId]);

  return (
    <Overlay onClose={onClose} wide>
      <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom:16 }}>
        <h2 style={{ fontSize:16 }}>
          Scan Log
          {done && <span style={{ marginLeft:10, fontSize:12, color:'#4ade80' }}>✓ Complete</span>}
        </h2>
        <button onClick={onClose} style={closeBtn}>×</button>
      </div>
      <div ref={logRef} style={{
        background:'#0a0c12', border:'1px solid var(--border)', borderRadius:8,
        padding:'14px 16px', fontFamily:'monospace', fontSize:12, lineHeight:1.7,
        maxHeight:440, overflowY:'auto', whiteSpace:'pre-wrap', wordBreak:'break-all',
        color:'#a0aec0',
      }}>
        {lines.map((l, i) => (
          <div key={i} style={{
            color: l.cls === 'ok'   ? '#4ade80'
                 : l.cls === 'err'  ? '#ef4444'
                 : l.cls === 'warn' ? '#eab308' : undefined,
          }}>
            {l.text}
          </div>
        ))}
        {!lines.length && <span style={{ color:'var(--muted)' }}>Connecting…</span>}
      </div>
    </Overlay>
  );
}


/* ── Manual Finding Button + Modal ─────────────────────────────────────────── */
function ManualFindingButton({ scanId }: { scanId: string }) {
  const [open, setOpen] = useState(false);
  return (
    <>
      <button className="btn btn-ghost btn-sm" onClick={() => setOpen(true)}>
        + Manual Finding
      </button>
      {open && <ManualFindingModal scanId={scanId} onClose={() => setOpen(false)} />}
    </>
  );
}

const SEVERITIES = ['Critical', 'High', 'Medium', 'Low', 'Info'];

function ManualFindingModal({ scanId, onClose }: {
  scanId: string; onClose: () => void;
}) {
  const create = useCreateManualFinding(scanId);
  const [form, setForm] = useState({
    vulnerability_name: '',
    severity:           'High',
    description:        '',
    remediation:        '',
    target_url:         '',
    cvss_score:         '',
    cve_id:             '',
    cwe_id:             '',
    analyst_notes:      '',
    location:           '',
  });
  const [err, setErr] = useState('');

  function set(key: string, val: string) {
    setForm(prev => ({ ...prev, [key]: val }));
  }

  async function submit() {
    setErr('');
    if (!form.vulnerability_name.trim()) { setErr('Finding name is required'); return; }
    try {
      await create.mutateAsync({
        vulnerability_name: form.vulnerability_name.trim(),
        severity:           form.severity,
        description:        form.description || undefined,
        remediation:        form.remediation || undefined,
        target_url:         form.target_url  || undefined,
        location:           form.location    || undefined,
        cve_id:             form.cve_id      || undefined,
        cwe_id:             form.cwe_id      || undefined,
        analyst_notes:      form.analyst_notes || undefined,
        cvss_score:         form.cvss_score ? Number(form.cvss_score) : undefined,
      });
      onClose();
    } catch (e: unknown) {
      setErr(e instanceof Error ? e.message : 'Failed to create finding');
    }
  }

  return (
    <Overlay onClose={onClose} wide>
      <div style={{ display:'flex', justifyContent:'space-between', marginBottom:20 }}>
        <h2 style={{ fontSize:16 }}>Add Manual Finding</h2>
        <button onClick={onClose} style={closeBtn}>×</button>
      </div>
      <div style={{ fontSize:12, color:'var(--muted)', marginBottom:16, lineHeight:1.5 }}>
        Manual findings are added directly to this scan with <code>tool=Manual</code> and
        start with <strong>Confirmed</strong> status.
      </div>

      {err && <div style={errorBox}>{err}</div>}

      <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:12 }}>
        <div style={{ gridColumn:'1/-1' }}>
          <Field label="Finding Name *">
            <input value={form.vulnerability_name}
                   onChange={e => set('vulnerability_name', e.target.value)}
                   placeholder="SQL Injection in /api/users" autoFocus />
          </Field>
        </div>

        <Field label="Severity">
          <select value={form.severity} onChange={e => set('severity', e.target.value)}>
            {SEVERITIES.map(s => <option key={s}>{s}</option>)}
          </select>
        </Field>

        <Field label="CVSS Score (0–10)">
          <input type="number" min="0" max="10" step="0.1"
                 value={form.cvss_score}
                 onChange={e => set('cvss_score', e.target.value)}
                 placeholder="7.5" />
        </Field>

        <div style={{ gridColumn:'1/-1' }}>
          <Field label="Target URL / Location">
            <input value={form.target_url}
                   onChange={e => set('target_url', e.target.value)}
                   placeholder="https://app.example.com/api/users?id=1" />
          </Field>
        </div>

        <Field label="CVE ID">
          <input value={form.cve_id}
                 onChange={e => set('cve_id', e.target.value)}
                 placeholder="CVE-2024-12345" />
        </Field>

        <Field label="CWE ID">
          <input value={form.cwe_id}
                 onChange={e => set('cwe_id', e.target.value)}
                 placeholder="CWE-89" />
        </Field>

        <div style={{ gridColumn:'1/-1' }}>
          <Field label="Description">
            <textarea value={form.description}
                      onChange={e => set('description', e.target.value)}
                      rows={3} placeholder="Explain the vulnerability…" style={{ resize:'vertical' }} />
          </Field>
        </div>

        <div style={{ gridColumn:'1/-1' }}>
          <Field label="Remediation">
            <textarea value={form.remediation}
                      onChange={e => set('remediation', e.target.value)}
                      rows={2} placeholder="How to fix it…" style={{ resize:'vertical' }} />
          </Field>
        </div>

        <div style={{ gridColumn:'1/-1' }}>
          <Field label="Analyst Notes">
            <textarea value={form.analyst_notes}
                      onChange={e => set('analyst_notes', e.target.value)}
                      rows={2}
                      placeholder="Proof of concept, reproduction steps, business impact…"
                      style={{ resize:'vertical' }} />
          </Field>
        </div>
      </div>

      <div style={{ display:'flex', gap:10, justifyContent:'flex-end', marginTop:8 }}>
        <button onClick={onClose} className="btn btn-ghost">Cancel</button>
        <button onClick={submit} disabled={create.isPending} className="btn btn-primary">
          {create.isPending ? 'Adding…' : 'Add Finding'}
        </button>
      </div>
    </Overlay>
  );
}

/* ── Shared helpers ─────────────────────────────────────────────────────────── */
function Overlay({ children, onClose, wide = false }: {
  children: React.ReactNode; onClose: () => void; wide?: boolean;
}) {
  return (
    <div style={{
      position:'fixed', inset:0, zIndex:200, background:'rgba(0,0,0,.7)',
      display:'flex', alignItems:'center', justifyContent:'center',
    }} onClick={e => e.target === e.currentTarget && onClose()}>
      <div style={{
        background:'var(--surface)', border:'1px solid var(--border)',
        borderRadius:10, width: wide ? 720 : 520,
        maxHeight:'90vh', overflowY:'auto', padding:28,
      }}>
        {children}
      </div>
    </div>
  );
}

function Field({ label, hint, children }: {
  label: string; hint?: string; children: React.ReactNode;
}) {
  return (
    <div style={{ marginBottom:16 }}>
      <label style={{ display:'block', fontSize:11, fontWeight:600, color:'var(--muted)',
                      textTransform:'uppercase', letterSpacing:'.4px', marginBottom:6 }}>
        {label}
      </label>
      {children}
      {hint && (
        <div style={{ fontSize:11, color:'var(--muted)', marginTop:4, lineHeight:1.5 }}>{hint}</div>
      )}
    </div>
  );
}

const closeBtn: React.CSSProperties = {
  background:'none', border:'none', color:'var(--muted)', fontSize:20, cursor:'pointer',
};
const errorBox: React.CSSProperties = {
  background:'#2d1414', color:'#ef4444', border:'1px solid #5a2020',
  borderRadius:8, padding:'10px 12px', marginBottom:16, fontSize:13,
};
