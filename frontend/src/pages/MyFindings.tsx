import { useNavigate } from 'react-router-dom';
import { useMyFindings } from '../lib/hooks';
import { SEV_COLOR } from '../components/Layout';

export default function MyFindings() {
  const { data, isLoading } = useMyFindings();
  const navigate = useNavigate();

  const items = data?.items ?? [];

  return (
    <div>
      <div className="topbar">
        <div>
          <h1>My Findings</h1>
          <div className="sub">Findings assigned to you, sorted by due date</div>
        </div>
      </div>

      {isLoading && <div className="empty">Loading…</div>}
      {!isLoading && items.length === 0 && (
        <div className="empty">
          <h3 style={{ fontSize: 18, marginBottom: 8, fontWeight: 600 }}>Nothing assigned yet</h3>
          <p style={{ color: 'var(--muted)' }}>
            When findings are assigned to you, they will appear here.
          </p>
        </div>
      )}

      {!isLoading && items.length > 0 && (
        <div className="card">
          <table>
            <thead>
              <tr>
                <th>Severity</th>
                <th>Name</th>
                <th>Tool</th>
                <th>Status</th>
                <th>Due Date</th>
                <th style={{ width: 80 }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {items.map((f: any) => (
                <tr key={f.id} style={{ cursor: 'pointer' }} onClick={() => navigate(`/findings/${f.id}`)}>
                  <td>
                    <span style={{
                      display: 'inline-block', padding: '2px 8px', borderRadius: 4,
                      fontSize: 11, fontWeight: 600, textTransform: 'uppercase',
                      background: SEV_COLOR[f.severity as keyof typeof SEV_COLOR] ?? 'var(--muted)',
                      color: '#fff',
                    }}>
                      {f.severity}
                    </span>
                  </td>
                  <td className="truncate" style={{ maxWidth: 300 }}>
                    {f.vulnerability_name}
                  </td>
                  <td>{f.tool}</td>
                  <td>{f.status}</td>
                  <td>
                    {f.due_date ? (
                      <span style={{
                        color: new Date(f.due_date) < new Date() ? '#ef4444' : 'var(--muted)',
                      }}>
                        {new Date(f.due_date).toLocaleDateString()}
                      </span>
                    ) : '—'}
                  </td>
                  <td>
                    <button className="btn btn-sm btn-ghost" onClick={(e) => {
                      e.stopPropagation();
                      navigate(`/findings/${f.id}`);
                    }}>View</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
