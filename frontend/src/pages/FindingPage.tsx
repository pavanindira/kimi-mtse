import { useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { useFinding, useUpdateFindingStatus, useUpdateFindingNotes } from '../lib/hooks';
import { SevBadge, StatusBadge, CvssBadge } from '../components/Badges';

const STATUSES = ['Open','Confirmed','False Positive','Fixed','Accepted Risk'];

export default function FindingPage() {
  const { id }     = useParams<{ id: string }>();
  const { data: f, isLoading } = useFinding(Number(id));
  const updateStatus = useUpdateFindingStatus();
  const updateNotes  = useUpdateFindingNotes();

  const [status,  setStatus ] = useState('');
  const [notes,   setNotes  ] = useState<string | null>(null); // null = not yet edited
  const [saveMsg, setSaveMsg] = useState('');
  const [saving,  setSaving ] = useState(false);

  if (isLoading) return <div style={{ padding:40, color:'var(--muted)' }}>Loading…</div>;
  if (!f)        return <div style={{ padding:40, color:'#ef4444' }}>Finding not found.</div>;

  const currentStatus = status || f.status;
  const currentNotes  = notes  ?? (f.analyst_notes ?? '');
  const loc = f.target_url || f.file_path || f.host;

  // Status changed from server value
  const statusDirty = status && status !== f.status;
  // Notes changed from server value
  const notesDirty  = notes !== null && notes !== (f.analyst_notes ?? '');
  const dirty = statusDirty || notesDirty;

  async function save() {
    setSaving(true); setSaveMsg('');
    try {
      // Notes PATCH and status PATCH independently — only what changed
      if (notesDirty) {
        await updateNotes.mutateAsync({ id: f?.id ?? 0, notes: currentNotes });
      }
      if (statusDirty) {
        await updateStatus.mutateAsync({ id: f?.id ?? 0, status: currentStatus });
      }
      setSaveMsg('✓ Saved');
      setTimeout(() => setSaveMsg(''), 2500);
      setStatus('');
      setNotes(null);
    } catch (e: unknown) {
      setSaveMsg(e instanceof Error ? e.message : 'Save failed');
    } finally {
      setSaving(false);
    }
  }

  return (
    <>
      <div className="topbar">
        <div>
          <div style={{ fontSize:12, color:'var(--muted)', marginBottom:4 }}>
            <Link to="/findings" style={{ color:'var(--muted)', textDecoration:'none' }}>
              Findings
            </Link>
            {f.engagement_id && (
              <> / <Link to={`/engagements/${f.engagement_id}`}
                         style={{ color:'var(--muted)', textDecoration:'none' }}>
                Engagement
              </Link></>
            )}
          </div>
          <h1 style={{ fontSize:17, maxWidth:700 }}>{f.vulnerability_name}</h1>
          <div style={{ display:'flex', gap:8, alignItems:'center', marginTop:8, flexWrap:'wrap' }}>
            <SevBadge severity={f.severity} />
            <StatusBadge status={currentStatus} />
            <span style={{ color:'var(--muted)', fontSize:12 }}>{f.tool}</span>
            {f.cvss_score && <CvssBadge score={f.cvss_score} />}
            {f.cve_id && <code style={codeStyle}>{f.cve_id}</code>}
            {f.cwe_id && <code style={codeStyle}>{f.cwe_id}</code>}
          </div>
        </div>
      </div>

      <div className="grid-2" style={{ alignItems:'start' }}>

        {/* Left: detail */}
        <div style={{ display:'flex', flexDirection:'column', gap:16 }}>

          {loc && (
            <div className="card">
              <div className="card-head"><h2>Location</h2></div>
              <div style={{ padding:'14px 20px' }}>
                <div className="mono" style={{ fontSize:12, color:'var(--accent)', wordBreak:'break-all' }}>
                  {loc}{f.line_number ? `:${f.line_number}` : ''}{f.port ? `:${f.port}` : ''}
                </div>
                {f.host && f.port && (
                  <div style={{ color:'var(--muted)', fontSize:11, marginTop:6 }}>
                    Host: {f.host} · Port: {f.port}
                  </div>
                )}
              </div>
            </div>
          )}

          {f.description && (
            <div className="card">
              <div className="card-head"><h2>Description</h2></div>
              <div style={{ padding:'14px 20px', lineHeight:1.7, fontSize:13, whiteSpace:'pre-wrap' }}>
                {f.description}
              </div>
            </div>
          )}

          {f.remediation && (
            <div className="card" style={{ borderLeft:'3px solid #4ade80' }}>
              <div className="card-head"><h2>Remediation</h2></div>
              <div style={{ padding:'14px 20px', lineHeight:1.7, fontSize:13, whiteSpace:'pre-wrap' }}>
                {f.remediation}
              </div>
            </div>
          )}

          {(f.evidence?.length ?? 0) > 0 && (
            <div className="card">
              <div className="card-head">
                <h2>Evidence</h2>
                <span style={{ color:'var(--muted)', fontSize:12 }}>
                  {f.evidence!.length} item{f.evidence!.length !== 1 ? 's' : ''}
                </span>
              </div>
              <div style={{ padding:'16px 20px', display:'flex', flexDirection:'column', gap:14 }}>
                {f.evidence!.map(ev => (
                  <div key={ev.id}>
                    <div style={{ fontSize:11, fontWeight:600, color:'var(--muted)',
                                  textTransform:'uppercase', letterSpacing:'.4px', marginBottom:6 }}>
                      {ev.ev_type.replace(/_/g,' ')}{ev.label ? ` — ${ev.label}` : ''}
                    </div>
                    {ev.content && (
                      <pre style={{
                        background:'#0a0c12', border:'1px solid var(--border)',
                        borderRadius:8, padding:14, fontSize:12, fontFamily:'monospace',
                        lineHeight:1.7, overflowX:'auto', whiteSpace:'pre-wrap',
                        wordBreak:'break-all', maxHeight:320, color:'#a0aec0', margin:0,
                      }}>
                        {ev.content.slice(0, 3000)}
                      </pre>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Right: triage + metadata */}
        <div style={{ display:'flex', flexDirection:'column', gap:16 }}>

          <div className="card">
            <div className="card-head"><h2>Triage</h2></div>
            <div style={{ padding:'16px 20px' }}>

              <div style={{ marginBottom:16 }}>
                <label style={fieldLabel}>Status</label>
                <select value={currentStatus} onChange={e => setStatus(e.target.value)}>
                  {STATUSES.map(s => <option key={s}>{s}</option>)}
                </select>
              </div>

              <div style={{ marginBottom:16 }}>
                <label style={fieldLabel}>Analyst Notes</label>
                <textarea rows={5}
                          value={currentNotes}
                          onChange={e => setNotes(e.target.value)}
                          placeholder="Add context, PoC details, or false-positive rationale…"
                          style={{ resize:'vertical' }} />
                <div style={{ fontSize:11, color:'var(--muted)', marginTop:4 }}>
                  Supports plain text. Saved independently from status.
                </div>
              </div>

              <div style={{ display:'flex', alignItems:'center', gap:10 }}>
                <button onClick={save} disabled={saving || !dirty}
                        className="btn btn-primary">
                  {saving ? 'Saving…' : 'Save Changes'}
                </button>
                {dirty && !saveMsg && (
                  <span style={{ fontSize:12, color:'var(--muted)' }}>Unsaved changes</span>
                )}
                {saveMsg && (
                  <span style={{ fontSize:12,
                                 color: saveMsg.startsWith('✓') ? '#4ade80' : '#ef4444' }}>
                    {saveMsg}
                  </span>
                )}
              </div>
            </div>
          </div>

          <div className="card">
            <div className="card-head"><h2>Metadata</h2></div>
            <div style={{ padding:'14px 20px' }}>
              <table style={{ width:'100%', fontSize:12, borderCollapse:'collapse' }}>
                <tbody>
                  {[
                    ['Tool',        f.tool],
                    ['Severity',    f.severity],
                    ['CVSS Score',  f.cvss_score?.toFixed(1) ?? '—'],
                    ['CVSS Vector', f.cvss_vector ?? '—'],
                    ['CVE',         f.cve_id ?? '—'],
                    ['CWE',         f.cwe_id ?? '—'],
                    ['First Seen',  f.first_seen ? new Date(f.first_seen).toLocaleString() : '—'],
                    ['Last Seen',   f.last_seen  ? new Date(f.last_seen).toLocaleString()  : '—'],
                    ['Scan ID',     f.scan_id ?? '—'],
                  ].map(([label, val]) => (
                    <tr key={label as string}>
                      <td style={{ color:'var(--muted)', padding:'5px 0', width:'42%' }}>{label}</td>
                      <td style={{ padding:'5px 0', wordBreak:'break-all' }}>{val}</td>
                    </tr>
                  ))}
                  {f.engagement_id && (
                    <tr>
                      <td style={{ color:'var(--muted)', padding:'5px 0' }}>Engagement</td>
                      <td style={{ padding:'5px 0' }}>
                        <Link to={`/engagements/${f.engagement_id}`}
                              style={{ color:'var(--accent)' }}>
                          View →
                        </Link>
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>

        </div>
      </div>
    </>
  );
}

const codeStyle: React.CSSProperties = {
  background:'var(--surface2)', padding:'1px 5px', borderRadius:3,
  fontFamily:'monospace', fontSize:12,
};
const fieldLabel: React.CSSProperties = {
  display:'block', fontSize:11, fontWeight:600, color:'var(--muted)',
  textTransform:'uppercase', letterSpacing:'.4px', marginBottom:6,
};
