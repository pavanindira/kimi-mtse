import { useState } from 'react';
import { Link } from 'react-router-dom';
import { useEngagements, useFindings, useDashboardTrends } from '../lib/hooks';
import { SevBadge, StatusBadge } from '../components/Badges';
import { useAuth } from '../lib/auth-context';
import type { FindingsTrendPoint, ScansTrendPoint } from '../lib/api';

const SEV_COLORS: Record<string, string> = {
  Critical:'#ef4444', High:'#f97316', Medium:'#eab308', Low:'#3b82f6', Info:'#6b7280',
};

const SEVERITIES: (keyof Omit<FindingsTrendPoint, 'week_start'>)[] =
  ['Critical', 'High', 'Medium', 'Low', 'Info'];

const PERIODS = [
  { label: '30d',  days: 30  },
  { label: '90d',  days: 90  },
  { label: '180d', days: 180 },
  { label: '365d', days: 365 },
];

function formatWeekLabel(iso: string): string {
  const d = new Date(iso + 'T00:00:00Z');
  return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric', timeZone: 'UTC' });
}

export default function Dashboard() {
  const { user } = useAuth();
  const [days, setDays] = useState(90);
  const { data: engs = []   } = useEngagements('Active');
  const { data: critData    } = useFindings({ severity:'Critical', status:'Open', limit:5 });
  const { data: openData    } = useFindings({ status:'Open', limit:1 });
  const { data: trends, isLoading: trendsLoading } = useDashboardTrends(days);

  const critFindings = critData?.items ?? [];
  const openCount    = openData?.total ?? 0;
  const activeCount  = engs.length;

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

      <div className="grid-2" style={{ alignItems:'start', marginBottom:24 }}>

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

      {/* Trends */}
      <div className="card-head" style={{ marginBottom: 12 }}>
        <h2 style={{ fontSize: 14, fontWeight: 600 }}>Trends</h2>
        <div style={{ display:'flex', gap:4 }}>
          {PERIODS.map(p => (
            <button key={p.days}
                    className={days === p.days ? 'btn btn-primary btn-sm' : 'btn btn-ghost btn-sm'}
                    onClick={() => setDays(p.days)}>
              {p.label}
            </button>
          ))}
        </div>
      </div>

      <div className="grid-2" style={{ alignItems:'start', marginBottom:24 }}>
        <div className="card">
          <div className="card-head">
            <h2>Findings Discovered</h2>
          </div>
          {trendsLoading ? (
            <div className="empty" style={{ padding:32 }}>Loading…</div>
          ) : (
            <FindingsTrendChart data={trends?.findings_by_week ?? []} />
          )}
        </div>

        <div className="card">
          <div className="card-head">
            <h2>Scan Activity</h2>
          </div>
          {trendsLoading ? (
            <div className="empty" style={{ padding:32 }}>Loading…</div>
          ) : (
            <ScansTrendChart data={trends?.scans_by_week ?? []} />
          )}
        </div>
      </div>

      {/* Resolution stats */}
      <div style={{ display:'grid', gridTemplateColumns:'repeat(2,1fr)', gap:12 }}>
        <div className="stat-card">
          <div className="num" style={{ color:'#4ade80' }}>
            {trends?.avg_days_to_resolve ?? '—'}
          </div>
          <div className="lbl">
            Avg. Days to Resolve
            {trends && trends.resolved_count > 0 && ` (${trends.resolved_count} findings)`}
          </div>
        </div>
        <div className="stat-card">
          <div className="num" style={{ color:'var(--accent)' }}>
            {trends?.resolved_count ?? 0}
          </div>
          <div className="lbl">Findings Resolved (last {days}d)</div>
        </div>
      </div>
    </>
  );
}

/* ── Findings trend: stacked bar chart, one bar per week ──────────────────── */
function FindingsTrendChart({ data }: { data: FindingsTrendPoint[] }) {
  if (data.length === 0) {
    return <div className="empty" style={{ padding:32 }}>No findings discovered in this period.</div>;
  }

  const width = 640, height = 220, padTop = 12, padBottom = 26, padSide = 8;
  const plotHeight = height - padTop - padBottom;
  const maxTotal = Math.max(1, ...data.map(d =>
    SEVERITIES.reduce((sum, sev) => sum + d[sev], 0)
  ));
  const slot     = (width - padSide * 2) / data.length;
  const barWidth = Math.max(2, slot * 0.6);
  // Thin out labels so they don't overlap when there are many weeks.
  const labelEvery = Math.max(1, Math.ceil(data.length / 10));

  return (
    <>
      <svg viewBox={`0 0 ${width} ${height}`} style={{ width:'100%', height:'auto', display:'block' }}>
        {data.map((d, i) => {
          const x = padSide + i * slot + (slot - barWidth) / 2;
          let yCursor = height - padBottom;
          return (
            <g key={d.week_start}>
              {SEVERITIES.map(sev => {
                const val = d[sev];
                if (val === 0) return null;
                const h = (val / maxTotal) * plotHeight;
                yCursor -= h;
                return (
                  <rect key={sev} x={x} y={yCursor} width={barWidth} height={h}
                        fill={SEV_COLORS[sev]}>
                    <title>{`${sev}: ${val} (week of ${d.week_start})`}</title>
                  </rect>
                );
              })}
              {i % labelEvery === 0 && (
                <text x={x + barWidth / 2} y={height - padBottom + 14}
                      fontSize={9} textAnchor="middle" fill="var(--muted)">
                  {formatWeekLabel(d.week_start)}
                </text>
              )}
            </g>
          );
        })}
      </svg>
      <div style={{ display:'flex', gap:14, flexWrap:'wrap', padding:'8px 4px 0' }}>
        {SEVERITIES.map(sev => (
          <div key={sev} style={{ display:'flex', alignItems:'center', gap:5, fontSize:11,
                                   color:'var(--muted)' }}>
            <span style={{ width:9, height:9, borderRadius:2, background:SEV_COLORS[sev],
                          display:'inline-block' }} />
            {sev}
          </div>
        ))}
      </div>
    </>
  );
}

/* ── Scan activity: completed vs failed per week ──────────────────────────── */
function ScansTrendChart({ data }: { data: ScansTrendPoint[] }) {
  if (data.length === 0) {
    return <div className="empty" style={{ padding:32 }}>No scans run in this period.</div>;
  }

  const width = 640, height = 220, padTop = 12, padBottom = 26, padSide = 8;
  const plotHeight = height - padTop - padBottom;
  const maxTotal = Math.max(1, ...data.map(d => d.total));
  const slot     = (width - padSide * 2) / data.length;
  const barWidth = Math.max(2, slot * 0.6);
  const labelEvery = Math.max(1, Math.ceil(data.length / 10));

  return (
    <>
      <svg viewBox={`0 0 ${width} ${height}`} style={{ width:'100%', height:'auto', display:'block' }}>
        {data.map((d, i) => {
          const x = padSide + i * slot + (slot - barWidth) / 2;
          const other = Math.max(0, d.total - d.completed - d.failed);
          let yCursor = height - padBottom;
          const segments: [number, string][] = [
            [d.completed, '#4ade80'],
            [d.failed,    '#ef4444'],
            [other,       'var(--muted)'],
          ];
          return (
            <g key={d.week_start}>
              {segments.map(([val, color], si) => {
                if (val === 0) return null;
                const h = (val / maxTotal) * plotHeight;
                yCursor -= h;
                return <rect key={si} x={x} y={yCursor} width={barWidth} height={h} fill={color} />;
              })}
              {i % labelEvery === 0 && (
                <text x={x + barWidth / 2} y={height - padBottom + 14}
                      fontSize={9} textAnchor="middle" fill="var(--muted)">
                  {formatWeekLabel(d.week_start)}
                </text>
              )}
            </g>
          );
        })}
      </svg>
      <div style={{ display:'flex', gap:14, flexWrap:'wrap', padding:'8px 4px 0' }}>
        {[['Completed', '#4ade80'], ['Failed', '#ef4444'], ['Other', 'var(--muted)']].map(
          ([label, color]) => (
            <div key={label} style={{ display:'flex', alignItems:'center', gap:5, fontSize:11,
                                       color:'var(--muted)' }}>
              <span style={{ width:9, height:9, borderRadius:2, background:color,
                            display:'inline-block' }} />
              {label}
            </div>
          )
        )}
      </div>
    </>
  );
}
