import { useState } from 'react';
import { useAuditLog } from '../lib/hooks';

const ACTION_COLORS: Record<string, string> = {
  'user.login':                  'var(--accent)',
  'user.deleted':                '#ef4444',
  'user.role_changed':           '#eab308',
  'finding.bulk_status_changed': '#eab308',
  'finding.status_changed':      '#3b82f6',
  'scan.started':                'var(--accent)',
  'report.exported':             '#4ade80',
};

export default function AdminAudit() {
  const [page,   setPage  ] = useState(1);
  const [action, setAction] = useState('');
  const [user,   setUser  ] = useState('');

  const { data, isLoading } = useAuditLog({
    page,
    action_filter: action || undefined,
    user_filter:   user   || undefined,
  });

  function applyFilter() { setPage(1); }

  return (
    <>
      <div className="topbar">
        <div>
          <h1>Audit Log</h1>
          {data && (
            <div className="sub">
              {data.total} event{data.total !== 1 ? 's' : ''}
              {' · '}page {data.page} of {data.pages}
            </div>
          )}
        </div>
      </div>

      {/* Filters */}
      <div className="card" style={{ padding:'14px 18px', marginBottom:16 }}>
        <div style={{ display:'flex', gap:10, flexWrap:'wrap', alignItems:'flex-end' }}>
          <div>
            <label style={filterLabel}>Action</label>
            <input value={action} onChange={e => setAction(e.target.value)}
                   placeholder="e.g. user.login" style={{ width:200 }}
                   onKeyDown={e => e.key === 'Enter' && applyFilter()} />
          </div>
          <div>
            <label style={filterLabel}>User</label>
            <input value={user} onChange={e => setUser(e.target.value)}
                   placeholder="Username…" style={{ width:160 }}
                   onKeyDown={e => e.key === 'Enter' && applyFilter()} />
          </div>
          <button onClick={applyFilter} className="btn btn-ghost btn-sm"
                  style={{ alignSelf:'flex-end' }}>
            Filter
          </button>
          {(action || user) && (
            <button onClick={() => { setAction(''); setUser(''); setPage(1); }}
                    className="btn btn-ghost btn-sm" style={{ alignSelf:'flex-end' }}>
              Clear
            </button>
          )}
        </div>
      </div>

      {isLoading ? (
        <div className="card"><div className="empty">Loading…</div></div>
      ) : !data?.items.length ? (
        <div className="card">
          <div className="empty" style={{ padding:'56px 20px' }}>
            No audit events match these filters.
          </div>
        </div>
      ) : (
        <>
          <div className="card">
            <table>
              <thead><tr>
                <th>Timestamp</th><th>User</th><th>Action</th>
                <th>Target</th><th>Detail</th><th>IP</th>
              </tr></thead>
              <tbody>
                {data.items.map(entry => (
                  <tr key={entry.id}>
                    <td className="mono" style={{ fontSize:11, whiteSpace:'nowrap' }}>
                      {new Date(entry.timestamp).toLocaleString()}
                    </td>
                    <td style={{ fontWeight:500 }}>{entry.username ?? '—'}</td>
                    <td>
                      <code style={{
                        fontSize:11,
                        color: ACTION_COLORS[entry.action] ?? 'var(--muted)',
                        background:'var(--surface2)', padding:'1px 5px', borderRadius:3,
                      }}>
                        {entry.action}
                      </code>
                    </td>
                    <td style={{ fontSize:12 }}>
                      {entry.target_name ? (
                        <>
                          <span className="truncate" style={{ maxWidth:180, display:'block' }}
                                title={entry.target_name}>
                            {entry.target_name.slice(0, 40)}
                            {entry.target_name.length > 40 ? '…' : ''}
                          </span>
                          {entry.target_type && entry.target_id && (
                            <span style={{ color:'var(--muted)', fontSize:11 }}>
                              {entry.target_type}#{entry.target_id}
                            </span>
                          )}
                        </>
                      ) : '—'}
                    </td>
                    <td style={{ fontSize:11, color:'var(--muted)', maxWidth:200 }}>
                      {entry.detail
                        ? Object.entries(entry.detail)
                            .filter(([, v]) => v !== null && v !== undefined)
                            .map(([k, v]) => (
                              <span key={k} style={{ marginRight:8 }}>
                                <span style={{ color:'var(--muted)' }}>{k}:</span>{' '}
                                <strong style={{ color:'var(--text)' }}>
                                  {Array.isArray(v) ? `${v.length} items` : String(v)}
                                </strong>
                              </span>
                            ))
                        : '—'}
                    </td>
                    <td className="mono" style={{ fontSize:11, color:'var(--muted)' }}>
                      {entry.ip_address ?? '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Pagination */}
          {data.pages > 1 && (
            <div style={{ display:'flex', justifyContent:'center', gap:6, marginTop:20 }}>
              <button disabled={page <= 1} onClick={() => setPage(p => p - 1)}
                      className="btn btn-ghost btn-sm">← Prev</button>
              {Array.from({ length: data.pages }, (_, i) => i + 1)
                .filter(p => p === 1 || p === data.pages ||
                             Math.abs(p - page) <= 2)
                .reduce<(number|'…')[]>((acc, p, i, arr) => {
                  if (i > 0 && (p as number) - (arr[i-1] as number) > 1) acc.push('…');
                  acc.push(p);
                  return acc;
                }, [])
                .map((p, i) => p === '…' ? (
                  <span key={`ellipsis-${i}`}
                        style={{ padding:'5px 4px', color:'var(--muted)' }}>…</span>
                ) : (
                  <button key={p} onClick={() => setPage(p as number)}
                          className={`btn btn-sm ${p === page ? 'btn-primary' : 'btn-ghost'}`}>
                    {p}
                  </button>
                ))}
              <button disabled={page >= data.pages} onClick={() => setPage(p => p + 1)}
                      className="btn btn-ghost btn-sm">Next →</button>
            </div>
          )}
        </>
      )}
    </>
  );
}

const filterLabel: React.CSSProperties = {
  display:'block', fontSize:11, fontWeight:600, color:'var(--muted)',
  textTransform:'uppercase', letterSpacing:'.4px', marginBottom:5,
};
