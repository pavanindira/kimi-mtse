import { useState, FormEvent } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { useSearch } from '../lib/hooks';
import { SevBadge, StatusBadge } from '../components/Badges';

export default function Search() {
  const [params, setParams] = useSearchParams();
  const [input,  setInput ] = useState(params.get('q') ?? '');
  const q     = params.get('q') ?? '';
  const scope = params.get('scope') ?? 'all';

  const { data, isLoading, isFetching } = useSearch(q, scope);

  function submit(e: FormEvent) {
    e.preventDefault();
    const next = new URLSearchParams();
    if (input.trim()) next.set('q', input.trim());
    if (scope !== 'all') next.set('scope', scope);
    setParams(next);
  }

  return (
    <>
      <div className="topbar">
        <div>
          <h1>Search</h1>
          {q && data && (
            <div className="sub">
              {data.total} result{data.total !== 1 ? 's' : ''} for "{q}"
            </div>
          )}
        </div>
      </div>

      {/* Search bar */}
      <div className="card" style={{ padding:'16px 20px', marginBottom:24 }}>
        <form onSubmit={submit}
              style={{ display:'flex', gap:10, alignItems:'center' }}>
          <input value={input} onChange={e => setInput(e.target.value)}
                 autoFocus placeholder="Search CVEs, hostnames, vulnerability names, clients…"
                 style={{ flex:1, fontSize:14 }}/>
          <select value={scope}
                  onChange={e => setParams(q ? { q, scope:e.target.value } : { scope:e.target.value })}
                  style={{ width:160 }}>
            <option value="all">All</option>
            <option value="findings">Findings only</option>
            <option value="engagements">Engagements only</option>
          </select>
          <button type="submit" className="btn btn-primary">Search</button>
        </form>
      </div>

      {/* Loading */}
      {(isLoading || isFetching) && q && (
        <div style={{ color:'var(--muted)', padding:'8px 0' }}>Searching…</div>
      )}

      {/* No query */}
      {!q && (
        <div className="card">
          <div className="empty" style={{ padding:'64px 20px' }}>
            <p style={{ fontSize:15 }}>Search findings, CVEs, clients, and targets</p>
            <p style={{ fontSize:12, color:'var(--muted)', marginTop:8 }}>
              Try: <code>CVE-2021-44228</code> &nbsp;·&nbsp;
                   <code>SQL injection</code> &nbsp;·&nbsp;
                   <code>acme.com</code>
            </p>
          </div>
        </div>
      )}

      {/* Results */}
      {q && data && !isLoading && (
        <>
          {/* Findings */}
          {data.findings.length > 0 && (
            <div className="card" style={{ marginBottom:16 }}>
              <div className="card-head">
                <h2>Findings</h2>
                <span style={{ color:'var(--muted)', fontSize:12 }}>
                  {data.findings.length}{data.findings.length === 50 ? '+' : ''}
                </span>
              </div>
              <table>
                <thead><tr>
                  <th>Severity</th><th>Finding</th><th>Tool</th>
                  <th>Status</th><th>Engagement</th><th></th>
                </tr></thead>
                <tbody>
                  {data.findings.map(f => (
                    <tr key={f.id}>
                      <td><SevBadge severity={f.severity} /></td>
                      <td style={{ maxWidth:340 }}>
                        <Link to={`/findings/${f.id}`}
                              style={{ fontWeight:500, display:'block' }}
                              className="truncate" title={f.vulnerability_name}>
                          {f.vulnerability_name.slice(0,64)}{f.vulnerability_name.length>64?'…':''}
                        </Link>
                        {f.cve_id && (
                          <span className="mono" style={{ fontSize:11, color:'var(--muted)' }}>
                            {f.cve_id}
                          </span>
                        )}
                      </td>
                      <td style={{ color:'var(--muted)', fontSize:12 }}>{f.tool}</td>
                      <td><StatusBadge status={f.status} /></td>
                      <td style={{ fontSize:12 }}>
{'—'}
                      </td>
                      <td>
                        <Link to={`/findings/${f.id}`} className="btn btn-ghost btn-sm">
                          View
                        </Link>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {/* Engagements */}
          {data.engagements.length > 0 && (
            <div className="card" style={{ marginBottom:16 }}>
              <div className="card-head">
                <h2>Engagements</h2>
                <span style={{ color:'var(--muted)', fontSize:12 }}>
                  {data.engagements.length}
                </span>
              </div>
              <table>
                <thead><tr><th>Client</th><th>Name</th><th>Status</th><th></th></tr></thead>
                <tbody>
                  {data.engagements.map(eng => (
                    <tr key={eng.id}>
                      <td style={{ color:'var(--muted)', fontSize:12 }}>{eng.client_name}</td>
                      <td><Link to={`/engagements/${eng.id}`}>{eng.name}</Link></td>
                      <td><StatusBadge status={eng.status} /></td>
                      <td>
                        <Link to={`/engagements/${eng.id}`} className="btn btn-ghost btn-sm">
                          Open
                        </Link>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {/* Scans */}
          {data.scans.length > 0 && (
            <div className="card">
              <div className="card-head">
                <h2>Scans</h2>
                <span style={{ color:'var(--muted)', fontSize:12 }}>{data.scans.length}</span>
              </div>
              <table>
                <thead><tr><th>Type</th><th>Target</th><th>Status</th><th>Date</th></tr></thead>
                <tbody>
                  {data.scans.map(s => (
                    <tr key={s.scan_id}>
                      <td>
                        <span className="mono" style={{
                          fontSize:11, background:'var(--surface2)',
                          padding:'2px 6px', borderRadius:4,
                        }}>
                          {s.scan_type.toUpperCase()}
                        </span>
                      </td>
                      <td className="mono truncate" style={{ maxWidth:300, fontSize:12 }}
                          title={s.target}>
                        {s.target}
                      </td>
                      <td><StatusBadge status={s.status} /></td>
                      <td style={{ color:'var(--muted)', fontSize:12 }}>
                        {s.created_at ? new Date(s.created_at).toLocaleDateString() : '—'}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {/* No results */}
          {data.total === 0 && (
            <div className="card">
              <div className="empty" style={{ padding:'56px 20px' }}>
                <p style={{ fontSize:15 }}>No results for "{q}"</p>
                <p style={{ fontSize:12, color:'var(--muted)', marginTop:6 }}>
                  Try a shorter term, a CVE ID, or an IP address.
                </p>
              </div>
            </div>
          )}
        </>
      )}
    </>
  );
}
