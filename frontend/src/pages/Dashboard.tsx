import { Link } from 'react-router-dom';
import { useEngagements, useFindings } from '../lib/hooks';
import { SevBadge, StatusBadge } from '../components/Badges';
import { useAuth } from '../lib/auth-context';

const SEV_COLORS: Record<string, string> = {
  Critical:'#ef4444', High:'#f97316', Medium:'#eab308', Low:'#3b82f6', Info:'#6b7280',
};

export default function Dashboard() {
  const { user } = useAuth();
  const { data: engs = []   } = useEngagements('Active');
  const { data: critData    } = useFindings({ severity:'Critical', status:'Open', limit:5 });
  const { data: openData    } = useFindings({ status:'Open', limit:1 });

  const critFindings = critData?.items ?? [];
  const openCount    = openData?.total ?? 0;
  const activeCount  = engs.length;

  // Aggregate severity counts across active engagements
  const sevTotals: Record<string, number> = {
    Critical:0, High:0, Medium:0, Low:0, Info:0,
  };
  engs.forEach(e => {
    // engagements list doesn't carry severity_summary — only detail does.
    // Show per-engagement severity on the engagement detail page.
  });

  return (
    <>
      <div className="topbar">
        <div>
          <h1>Dashboard</h1>
          <div className="sub">Welcome back, {user?.username}</div>
        </div>
        <Link to="/engagements/new" className="btn btn-primary">+ New Engagement</Link>
      </div>

      {/* Quick stats */}
      <div style={{ display:'grid', gridTemplateColumns:'repeat(3,1fr)', gap:12, marginBottom:24 }}>
        <div className="stat-card">
          <div className="num" style={{ color:'var(--accent)' }}>{activeCount}</div>
          <div className="lbl">Active Engagements</div>
        </div>
        <div className="stat-card">
          <div className="num" style={{ color:'#ef4444' }}>{openCount}</div>
          <div className="lbl">Open Findings</div>
        </div>
        <div className="stat-card">
          <div className="num" style={{ color:'#f97316' }}>{critData?.total ?? 0}</div>
          <div className="lbl">Critical (Open)</div>
        </div>
      </div>

      <div className="grid-2" style={{ alignItems:'start' }}>

        {/* Active engagements */}
        <div className="card">
          <div className="card-head">
            <h2>Active Engagements</h2>
            <Link to="/engagements" style={{ fontSize:12, color:'var(--accent)' }}>All →</Link>
          </div>
          {engs.length === 0 ? (
            <div className="empty" style={{ padding:32 }}>
              No active engagements.{' '}
              <Link to="/engagements/new" style={{ color:'var(--accent)' }}>Create one</Link>.
            </div>
          ) : (
            <table>
              <thead><tr>
                <th>Client</th><th>Engagement</th><th>Status</th>
              </tr></thead>
              <tbody>
                {engs.slice(0, 8).map(e => (
                  <tr key={e.id}>
                    <td style={{ color:'var(--muted)', fontSize:12 }}>{e.client_name}</td>
                    <td>
                      <Link to={`/engagements/${e.id}`} style={{ fontWeight:500 }}>
                        {e.name}
                      </Link>
                    </td>
                    <td><StatusBadge status={e.status} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>

        {/* Critical open findings */}
        <div className="card">
          <div className="card-head">
            <h2>Critical Open Findings</h2>
            <Link to="/findings?severity=Critical&status=Open"
                  style={{ fontSize:12, color:'var(--accent)' }}>
              All →
            </Link>
          </div>
          {critFindings.length === 0 ? (
            <div className="empty" style={{ padding:32, color:'#4ade80' }}>
              ✓ No critical open findings
            </div>
          ) : (
            <table>
              <thead><tr>
                <th>Finding</th><th>Tool</th>
              </tr></thead>
              <tbody>
                {critFindings.map(f => (
                  <tr key={f.id}>
                    <td>
                      <Link to={`/findings/${f.id}`}
                            title={f.vulnerability_name}
                            style={{ display:'block', fontWeight:500, maxWidth:260,
                                     overflow:'hidden', textOverflow:'ellipsis',
                                     whiteSpace:'nowrap' }}>
                        {f.vulnerability_name}
                      </Link>
                      <div style={{ marginTop:4 }}>
                        <SevBadge severity={f.severity} />
                      </div>
                    </td>
                    <td style={{ color:'var(--muted)', fontSize:12 }}>{f.tool}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </>
  );
}
