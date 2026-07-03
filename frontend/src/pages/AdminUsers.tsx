import { useState, FormEvent } from 'react';
import { useUsers, useCreateUser, useSetUserRole, useDeleteUser } from '../lib/hooks';
import { useAuth } from '../lib/auth-context';

export default function AdminUsers() {
  const { user: me }   = useAuth();
  const { data: users = [], isLoading } = useUsers();
  const createUser  = useCreateUser();
  const setRole     = useSetUserRole();
  const deleteUser  = useDeleteUser();

  const [showModal, setShowModal] = useState(false);
  const [formError, setFormError] = useState('');

  async function handleCreate(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setFormError('');
    const fd = new FormData(e.currentTarget);
    try {
      await createUser.mutateAsync({
        username: fd.get('username') as string,
        password: fd.get('password') as string,
        role:     fd.get('role')     as string,
      });
      setShowModal(false);
      (e.target as HTMLFormElement).reset();
    } catch (err: unknown) {
      setFormError(err instanceof Error ? err.message : 'Create failed');
    }
  }

  async function handleRoleChange(userId: number, role: string) {
    try { await setRole.mutateAsync({ userId, role }); }
    catch (err) { alert(err instanceof Error ? err.message : 'Role update failed'); }
  }

  async function handleDelete(userId: number, username: string) {
    if (!confirm(`Delete user "${username}"? This cannot be undone.`)) return;
    try { await deleteUser.mutateAsync(userId); }
    catch (err) { alert(err instanceof Error ? err.message : 'Delete failed'); }
  }

  return (
    <>
      <div className="topbar">
        <div>
          <h1>User Management</h1>
          <div className="sub">{users.length} user{users.length !== 1 ? 's' : ''}</div>
        </div>
        <button onClick={() => setShowModal(true)} className="btn btn-primary">
          + New User
        </button>
      </div>

      <div className="card">
        {isLoading ? (
          <div className="empty">Loading…</div>
        ) : (
          <table>
            <thead><tr>
              <th>Username</th><th>Role</th><th>Created</th><th>Last Login</th><th>Actions</th>
            </tr></thead>
            <tbody>
              {users.map(u => (
                <tr key={u.id}>
                  <td style={{ fontWeight:500 }}>
                    {u.username}
                    {u.id === me?.id && (
                      <span style={{ color:'var(--muted)', fontSize:11, marginLeft:6 }}>
                        (you)
                      </span>
                    )}
                  </td>
                  <td>
                    <select defaultValue={u.role}
                            onChange={e => handleRoleChange(u.id, e.target.value)}
                            style={{ width:100, padding:'4px 8px', fontSize:12 }}>
                      {['Admin','Analyst','Viewer'].map(r => (
                        <option key={r}>{r}</option>
                      ))}
                    </select>
                  </td>
                  <td style={{ color:'var(--muted)', fontSize:12 }}>
                    {u.created_at ? new Date(u.created_at).toLocaleDateString() : '—'}
                  </td>
                  <td style={{ color:'var(--muted)', fontSize:12 }}>
                    {u.last_login ? new Date(u.last_login).toLocaleString() : 'Never'}
                  </td>
                  <td>
                    {u.id !== me?.id && u.username !== 'admin' ? (
                      <button onClick={() => handleDelete(u.id, u.username)}
                              className="btn btn-danger btn-sm">
                        Delete
                      </button>
                    ) : (
                      <span style={{ color:'var(--muted)', fontSize:11 }}>—</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* Role reference table */}
      <div className="card" style={{ maxWidth:480, marginTop:24 }}>
        <div className="card-head"><h2>Role Permissions</h2></div>
        <div style={{ padding:'14px 20px' }}>
          <table style={{ fontSize:12, borderCollapse:'collapse', width:'100%' }}>
            <thead>
              <tr>
                <th style={{ textAlign:'left', padding:'6px 8px', color:'var(--muted)',
                             borderBottom:'1px solid var(--border)' }}>Action</th>
                {['Viewer','Analyst','Admin'].map(r => (
                  <th key={r} style={{ padding:'6px 8px', color:'var(--muted)',
                                      borderBottom:'1px solid var(--border)' }}>{r}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {[
                ['View engagements & findings', '✓','✓','✓'],
                ['Export PDF reports',          '✓','✓','✓'],
                ['Start scans',                 '✗','✓','✓'],
                ['Update finding status',       '✗','✓','✓'],
                ['Create engagements',          '✗','✓','✓'],
                ['Manage users',                '✗','✗','✓'],
              ].map(([action, ...vals]) => (
                <tr key={action as string}>
                  <td style={{ padding:'6px 8px', borderBottom:'1px solid var(--border)' }}>
                    {action}
                  </td>
                  {(vals as string[]).map((v,i) => (
                    <td key={i} style={{
                      padding:'6px 8px', textAlign:'center',
                      borderBottom:'1px solid var(--border)',
                      color: v === '✓' ? '#4ade80' : '#ef4444',
                    }}>
                      {v}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* New user modal */}
      {showModal && (
        <div style={{
          position:'fixed', inset:0, zIndex:200,
          background:'rgba(0,0,0,.7)', display:'flex',
          alignItems:'center', justifyContent:'center',
        }} onClick={e => e.target === e.currentTarget && setShowModal(false)}>
          <div style={{
            background:'var(--surface)', border:'1px solid var(--border)',
            borderRadius:10, width:400, padding:28,
          }}>
            <div style={{ display:'flex', justifyContent:'space-between',
                          alignItems:'center', marginBottom:20 }}>
              <h2 style={{ fontSize:16 }}>New User</h2>
              <button onClick={() => setShowModal(false)}
                      style={{ background:'none', border:'none',
                               color:'var(--muted)', fontSize:20, cursor:'pointer' }}>
                ×
              </button>
            </div>
            {formError && (
              <div style={{ background:'#2d1414', color:'#ef4444',
                            border:'1px solid #5a2020', borderRadius:8,
                            padding:'8px 12px', marginBottom:14, fontSize:13 }}>
                {formError}
              </div>
            )}
            <form onSubmit={handleCreate}>
              {[
                { name:'username', label:'Username', type:'text',     placeholder:'analyst1' },
                { name:'password', label:'Password', type:'password', placeholder:'••••••••' },
              ].map(f => (
                <div key={f.name} style={{ marginBottom:16 }}>
                  <label style={fieldLabel}>{f.label}</label>
                  <input name={f.name} type={f.type} required placeholder={f.placeholder}
                         minLength={f.name === 'password' ? 8 : 1} />
                </div>
              ))}
              <div style={{ marginBottom:16 }}>
                <label style={fieldLabel}>Role</label>
                <select name="role" defaultValue="Analyst">
                  <option value="Analyst">Analyst</option>
                  <option value="Viewer">Viewer</option>
                  <option value="Admin">Admin</option>
                </select>
              </div>
              <div style={{ display:'flex', gap:10, justifyContent:'flex-end', marginTop:8 }}>
                <button type="button" onClick={() => setShowModal(false)}
                        className="btn btn-ghost">Cancel</button>
                <button type="submit" disabled={createUser.isPending}
                        className="btn btn-primary">
                  {createUser.isPending ? 'Creating…' : 'Create User'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </>
  );
}

const fieldLabel: React.CSSProperties = {
  display:'block', fontSize:11, fontWeight:600, color:'var(--muted)',
  textTransform:'uppercase', letterSpacing:'.4px', marginBottom:6,
};
