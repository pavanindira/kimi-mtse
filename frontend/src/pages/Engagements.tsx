import { Link } from 'react-router-dom';
import { useEngagements } from '../lib/hooks';
import { StatusBadge } from '../components/Badges';

export default function Engagements() {
  const { data: engs = [], isLoading } = useEngagements();

  return (
    <>
      <div className="topbar">
        <div>
          <h1>Engagements</h1>
          <div className="sub">{engs.length} engagement{engs.length !== 1 ? 's' : ''}</div>
        </div>
        <Link to="/engagements/new" className="btn btn-primary">+ New</Link>
      </div>

      {isLoading ? (
        <div className="card"><div className="empty">Loading…</div></div>
      ) : engs.length === 0 ? (
        <div className="card">
          <div className="empty" style={{ padding: '64px 20px' }}>
            <p style={{ fontSize: 15, marginBottom: 8 }}>No engagements yet</p>
            <Link to="/engagements/new" className="btn btn-primary" style={{ marginTop: 16 }}>
              New Engagement
            </Link>
          </div>
        </div>
      ) : (
        <div className="card">
          <table>
            <thead><tr>
              <th>Client</th><th>Engagement</th><th>Status</th>
              <th>Started</th><th>Updated</th><th></th>
            </tr></thead>
            <tbody>
              {engs.map(eng => (
                <tr key={eng.id}>
                  <td style={{ color: 'var(--muted)', fontSize: 12 }}>{eng.client_name}</td>
                  <td>
                    <Link to={`/engagements/${eng.id}`} style={{ fontWeight: 500 }}>
                      {eng.name}
                    </Link>
                    {eng.description && (
                      <div style={{ color: 'var(--muted)', fontSize: 11, marginTop: 2 }}>
                        {eng.description.slice(0, 60)}{eng.description.length > 60 ? '…' : ''}
                      </div>
                    )}
                  </td>
                  <td><StatusBadge status={eng.status} /></td>
                  <td style={{ color: 'var(--muted)', fontSize: 12 }}>
                    {eng.started_at ? new Date(eng.started_at).toLocaleDateString() : '—'}
                  </td>
                  <td style={{ color: 'var(--muted)', fontSize: 12 }}>
                    {eng.updated_at ? new Date(eng.updated_at).toLocaleDateString() : '—'}
                  </td>
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
    </>
  );
}
