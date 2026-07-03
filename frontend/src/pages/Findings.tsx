import { useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { useFindings, useBulkStatus } from '../lib/hooks';
import { SevBadge, StatusBadge, CvssBadge } from '../components/Badges';

const SEVERITIES = ['Critical','High','Medium','Low','Info'];
const STATUSES   = ['Open','Confirmed','False Positive','Fixed','Accepted Risk'];
const PAGE_SIZE  = 50;

export default function Findings() {
  const [params, setParams] = useSearchParams();
  const severity = params.get('severity') || '';
  const status   = params.get('status')   || 'Open';
  const tool     = params.get('tool')     || '';
  const scanId   = params.get('scan_id')  || '';
  const engId    = params.get('engagement_id') ? Number(params.get('engagement_id')) : undefined;
  const offset   = Number(params.get('offset') || 0);

  const [selected,   setSelected  ] = useState<Set<number>>(new Set());
  const [bulkStatus, setBulkStatus] = useState('False Positive');
  const [bulkNotes,  setBulkNotes ] = useState('');
  const [bulkMsg,    setBulkMsg   ] = useState('');

  const { data, isLoading } = useFindings({
    severity:      severity      || undefined,
    status:        status        || undefined,
    tool:          tool          || undefined,
    scan_id:       scanId        || undefined,
    engagement_id: engId,
    limit:         PAGE_SIZE,
    offset,
  });

  const items = data?.items ?? [];
  const total = data?.total ?? 0;
  const pages = data?.pages ?? 1;
  const page  = Math.floor(offset / PAGE_SIZE) + 1;

  const bulk = useBulkStatus();

  function setParam(key: string, val: string) {
    const next = new URLSearchParams(params);
    if (val) next.set(key, val); else next.delete(key);
    next.delete('offset'); // reset to page 1 on filter change
    setParams(next);
    setSelected(new Set());
  }

  function goToPage(p: number) {
    const next = new URLSearchParams(params);
    next.set('offset', String((p - 1) * PAGE_SIZE));
    setParams(next);
    setSelected(new Set());
    window.scrollTo(0, 0);
  }

  function toggleAll(checked: boolean) {
    setSelected(checked ? new Set(items.map(f => f.id)) : new Set());
  }

  function toggleOne(id: number, checked: boolean) {
    const next = new Set(selected);
    if (checked) next.add(id); else next.delete(id);
    setSelected(next);
  }

  async function applyBulk() {
    if (!selected.size) return;
    setBulkMsg('');
    try {
      const res = await bulk.mutateAsync({
        ids: Array.from(selected), status: bulkStatus, notes: bulkNotes,
      });
      setBulkMsg(`✓ Updated ${res.updated} finding${res.updated !== 1 ? 's' : ''}`);
      setSelected(new Set());
      setTimeout(() => setBulkMsg(''), 3000);
    } catch (e: unknown) {
      setBulkMsg(e instanceof Error ? e.message : 'Bulk update failed');
    }
  }

  const allSelected  = items.length > 0 && selected.size === items.length;
  const someSelected = selected.size > 0 && !allSelected;

  return (
    <>
      <div className="topbar">
        <div>
          <h1>Findings</h1>
          <div className="sub">
            {total} finding{total !== 1 ? 's' : ''}
            {pages > 1 && ` · page ${page} of ${pages}`}
          </div>
        </div>
      </div>

      {/* Filters */}
      <div className="card" style={{ padding:'14px 18px', marginBottom:16 }}>
        <div style={{ display:'flex', gap:10, flexWrap:'wrap', alignItems:'flex-end' }}>
          {[
            { label:'Severity', key:'severity', options:['', ...SEVERITIES] },
            { label:'Status',   key:'status',   options:['', ...STATUSES]   },
          ].map(({ label, key, options }) => (
            <div key={key}>
              <label style={filterLabel}>{label}</label>
              <select value={params.get(key) || ''}
                      onChange={e => setParam(key, e.target.value)}
                      style={{ width: 140 }}>
                {options.map(o => (
                  <option key={o} value={o}>{o || 'All'}</option>
                ))}
              </select>
            </div>
          ))}
          {(severity || tool || (status && status !== 'Open')) && (
            <button className="btn btn-ghost btn-sm"
                    style={{ alignSelf:'flex-end' }}
                    onClick={() => setParams({})}>
              Clear filters
            </button>
          )}
        </div>
      </div>

      {/* Bulk toolbar */}
      {selected.size > 0 && (
        <div style={{
          background:'var(--surface2)', border:'1px solid var(--border)',
          borderRadius:8, padding:'12px 16px', marginBottom:12,
          display:'flex', alignItems:'center', gap:12, flexWrap:'wrap',
        }}>
          <span style={{ fontWeight:600, fontSize:13 }}>{selected.size} selected</span>
          <label style={filterLabel}>Change to:</label>
          <select value={bulkStatus} onChange={e => setBulkStatus(e.target.value)}
                  style={{ width:160 }}>
            {STATUSES.map(s => <option key={s}>{s}</option>)}
          </select>
          <input value={bulkNotes} onChange={e => setBulkNotes(e.target.value)}
                 placeholder="Optional note…" style={{ width:220 }} />
          <button onClick={applyBulk} disabled={bulk.isPending}
                  className="btn btn-primary btn-sm">
            {bulk.isPending ? 'Applying…' : 'Apply'}
          </button>
          <button onClick={() => setSelected(new Set())} className="btn btn-ghost btn-sm">
            Clear
          </button>
          {bulkMsg && (
            <span style={{ fontSize:12, color: bulkMsg.startsWith('✓') ? '#4ade80' : '#ef4444' }}>
              {bulkMsg}
            </span>
          )}
        </div>
      )}

      {isLoading ? (
        <div className="card"><div className="empty">Loading…</div></div>
      ) : items.length === 0 ? (
        <div className="card">
          <div className="empty" style={{ padding:'64px 20px' }}>
            No findings match these filters.
          </div>
        </div>
      ) : (
        <div className="card">
          <table>
            <thead><tr>
              <th style={{ width:36 }}>
                <input type="checkbox"
                       checked={allSelected}
                       ref={el => el && (el.indeterminate = someSelected)}
                       onChange={e => toggleAll(e.target.checked)}
                       style={{ width:15, height:15, accentColor:'var(--accent)', cursor:'pointer' }} />
              </th>
              <th>Severity</th><th>CVSS</th><th>Finding</th>
              <th>Tool</th><th>Location</th><th>Status</th><th>Last Seen</th><th></th>
            </tr></thead>
            <tbody>
              {items.map(f => {
                const loc = f.target_url || f.file_path || f.host;
                const isSelected = selected.has(f.id);
                return (
                  <tr key={f.id} style={{
                    background: isSelected
                      ? 'color-mix(in srgb, var(--accent) 8%, transparent)' : undefined,
                  }}>
                    <td>
                      <input type="checkbox" checked={isSelected}
                             onChange={e => toggleOne(f.id, e.target.checked)}
                             style={{ width:15, height:15, accentColor:'var(--accent)', cursor:'pointer' }} />
                    </td>
                    <td><SevBadge severity={f.severity} /></td>
                    <td><CvssBadge score={f.cvss_score} /></td>
                    <td style={{ maxWidth:320 }}>
                      <Link to={`/findings/${f.id}`} style={{ fontWeight:500, display:'block' }}
                            className="truncate" title={f.vulnerability_name}>
                        {f.vulnerability_name.slice(0,68)}{f.vulnerability_name.length>68?'…':''}
                      </Link>
                      {f.cve_id && (
                        <span className="mono" style={{ fontSize:11, color:'var(--muted)' }}>
                          {f.cve_id}
                        </span>
                      )}
                    </td>
                    <td style={{ color:'var(--muted)', fontSize:12 }}>{f.tool}</td>
                    <td style={{ maxWidth:220 }}>
                      {loc ? (
                        <span className="truncate mono" style={{ fontSize:12, display:'block' }}
                              title={loc}>
                          {loc}{f.line_number ? `:${f.line_number}` : ''}{f.port ? `:${f.port}` : ''}
                        </span>
                      ) : '—'}
                    </td>
                    <td><StatusBadge status={f.status} /></td>
                    <td style={{ color:'var(--muted)', fontSize:12 }}>
                      {f.last_seen ? new Date(f.last_seen).toLocaleDateString() : '—'}
                    </td>
                    <td>
                      <Link to={`/findings/${f.id}`} className="btn btn-ghost btn-sm">View</Link>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>

          {/* Pagination */}
          {pages > 1 && (
            <div style={{
              display:'flex', alignItems:'center', justifyContent:'space-between',
              padding:'14px 18px', borderTop:'1px solid var(--border)',
            }}>
              <span style={{ fontSize:12, color:'var(--muted)' }}>
                Showing {offset + 1}–{Math.min(offset + PAGE_SIZE, total)} of {total}
              </span>
              <div style={{ display:'flex', gap:6 }}>
                <button className="btn btn-ghost btn-sm"
                        disabled={page === 1}
                        onClick={() => goToPage(page - 1)}>
                  ← Prev
                </button>
                {Array.from({ length: Math.min(pages, 7) }, (_, i) => {
                  const p = page <= 4 ? i + 1
                          : page >= pages - 3 ? pages - 6 + i
                          : page - 3 + i;
                  if (p < 1 || p > pages) return null;
                  return (
                    <button key={p}
                            className={`btn btn-sm ${p === page ? 'btn-primary' : 'btn-ghost'}`}
                            onClick={() => goToPage(p)}>
                      {p}
                    </button>
                  );
                })}
                <button className="btn btn-ghost btn-sm"
                        disabled={page === pages}
                        onClick={() => goToPage(page + 1)}>
                  Next →
                </button>
              </div>
            </div>
          )}
        </div>
      )}
    </>
  );
}

const filterLabel: React.CSSProperties = {
  display:'block', fontSize:11, fontWeight:600, color:'var(--muted)',
  textTransform:'uppercase', letterSpacing:'.4px', marginBottom:5,
};
