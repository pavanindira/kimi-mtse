import { useState } from 'react';
import { useAuth } from '../lib/auth-context';
import { useChangePassword } from '../lib/hooks';

export default function Profile() {
  const { user } = useAuth();
  const changePassword = useChangePassword();

  const [current, setCurrent] = useState('');
  const [next,    setNext   ] = useState('');
  const [confirm, setConfirm] = useState('');
  const [msg,     setMsg    ] = useState('');
  const [err,     setErr    ] = useState('');

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setMsg(''); setErr('');
    if (next !== confirm) { setErr('New passwords do not match'); return; }
    if (next.length < 8)  { setErr('New password must be at least 8 characters'); return; }
    try {
      const result = await changePassword.mutateAsync({
        current_password: current,
        new_password:     next,
      });
      // Update the persisted token so the session continues after password change
      if (result.access_token) {
        sessionStorage.setItem('mste_token', result.access_token);
        import('../lib/api').then(({ setToken }) => setToken(result.access_token));
      }
      setMsg('✓ Password changed successfully');
      setCurrent(''); setNext(''); setConfirm('');
    } catch (e: unknown) {
      setErr(e instanceof Error ? e.message : 'Failed to change password');
    }
  }

  return (
    <>
      <div className="topbar">
        <div>
          <h1>Profile</h1>
          <div className="sub">{user?.username} · {user?.role}</div>
        </div>
      </div>

      <div style={{ maxWidth: 480 }}>
        <div className="card" style={{ padding: 28 }}>
          <h2 style={{ fontSize: 14, fontWeight: 600, marginBottom: 20 }}>Change Password</h2>

          {err && (
            <div style={{
              background:'#2d1414', color:'#ef4444',
              border:'1px solid #5a2020', borderRadius:8,
              padding:'10px 12px', marginBottom:20, fontSize:13,
            }}>{err}</div>
          )}
          {msg && (
            <div style={{
              background:'#0d2a1a', color:'#4ade80',
              border:'1px solid #1a5a2a', borderRadius:8,
              padding:'10px 12px', marginBottom:20, fontSize:13,
            }}>{msg}</div>
          )}

          <form onSubmit={submit}>
            {[
              { label:'Current Password', value:current, set:setCurrent, name:'current' },
              { label:'New Password',     value:next,    set:setNext,    name:'new'     },
              { label:'Confirm New',      value:confirm, set:setConfirm, name:'confirm' },
            ].map(({ label, value, set, name }) => (
              <div key={name} style={{ marginBottom:16 }}>
                <label style={fieldLabel}>{label}</label>
                <input type="password" value={value}
                       onChange={e => set(e.target.value)}
                       required minLength={name === 'current' ? 1 : 8}
                       autoComplete={name === 'current' ? 'current-password' : 'new-password'} />
              </div>
            ))}
            <div style={{ marginTop:8 }}>
              <button type="submit" className="btn btn-primary"
                      disabled={changePassword.isPending}>
                {changePassword.isPending ? 'Saving…' : 'Change Password'}
              </button>
            </div>
          </form>
        </div>

        <div className="card" style={{ padding:24, marginTop:16 }}>
          <h2 style={{ fontSize:14, fontWeight:600, marginBottom:16 }}>Account Details</h2>
          <table style={{ width:'100%', fontSize:13, borderCollapse:'collapse' }}>
            <tbody>
              {[
                ['Username',   user?.username ?? '—'],
                ['Role',       user?.role     ?? '—'],
                ['Last Login', user?.last_login
                  ? new Date(user.last_login).toLocaleString() : 'Unknown'],
                ['Member Since', user?.created_at
                  ? new Date(user.created_at).toLocaleDateString() : '—'],
              ].map(([label, val]) => (
                <tr key={label}>
                  <td style={{ color:'var(--muted)', padding:'7px 0', width:'40%' }}>{label}</td>
                  <td style={{ padding:'7px 0', fontWeight:500 }}>{val}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </>
  );
}

const fieldLabel: React.CSSProperties = {
  display:'block', fontSize:11, fontWeight:600, color:'var(--muted)',
  textTransform:'uppercase', letterSpacing:'.4px', marginBottom:6,
};
