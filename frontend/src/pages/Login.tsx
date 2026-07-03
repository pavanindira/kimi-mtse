// ─────────────────────────────────────────────────────────────────────────────
// Login.tsx
// ─────────────────────────────────────────────────────────────────────────────
import { FormEvent, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../lib/auth-context';

export function Login() {
  const { login, loading } = useAuth();
  const navigate = useNavigate();
  const [error, setError] = useState('');

  async function handleSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setError('');
    const fd = new FormData(e.currentTarget);
    try {
      await login(fd.get('username') as string, fd.get('password') as string);
      navigate('/');
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Login failed');
    }
  }

  return (
    <div style={{
      minHeight: '100vh', display: 'flex', alignItems: 'center',
      justifyContent: 'center', background: 'var(--bg)',
    }}>
      <div style={{ width: '100%', maxWidth: 380, padding: '0 16px' }}>
        {/* Brand */}
        <div style={{ textAlign: 'center', marginBottom: 36 }}>
          <div style={{
            width: 52, height: 52, background: 'var(--accent)', borderRadius: 14,
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            margin: '0 auto 14px',
          }}>
            <svg width="26" height="26" fill="none" stroke="white" strokeWidth="2" viewBox="0 0 24 24">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            </svg>
          </div>
          <h1 style={{ fontSize: 22, fontWeight: 700, margin: 0 }}>MSTE</h1>
          <p style={{ color: 'var(--muted)', fontSize: 13, marginTop: 4 }}>
            Modular Security Testing Engine
          </p>
        </div>

        {error && (
          <div style={{
            background: '#2d1414', color: '#ef4444', border: '1px solid #5a2020',
            borderRadius: 8, padding: '10px 12px', marginBottom: 16, fontSize: 13,
          }}>{error}</div>
        )}

        <div style={{
          background: 'var(--surface)', border: '1px solid var(--border)',
          borderRadius: 8, padding: 28,
        }}>
          <form onSubmit={handleSubmit}>
            <div style={{ marginBottom: 16 }}>
              <label style={labelStyle}>Username</label>
              <input name="username" type="text" required autoFocus style={inputStyle}
                     placeholder="admin" autoComplete="username"/>
            </div>
            <div style={{ marginBottom: 8 }}>
              <label style={labelStyle}>Password</label>
              <input name="password" type="password" required style={inputStyle}
                     placeholder="••••••••" autoComplete="current-password"/>
            </div>
            <button type="submit" disabled={loading} style={{
              width: '100%', padding: 11, marginTop: 16, borderRadius: 8,
              background: loading ? '#2a3d6a' : 'var(--accent)',
              color: 'white', border: 'none', fontSize: 14, fontWeight: 600,
              cursor: loading ? 'default' : 'pointer',
            }}>
              {loading ? 'Signing in…' : 'Sign in'}
            </button>
          </form>
        </div>
      </div>
    </div>
  );
}

const labelStyle: React.CSSProperties = {
  display: 'block', fontSize: 11, fontWeight: 600, color: 'var(--muted)',
  textTransform: 'uppercase', letterSpacing: '.5px', marginBottom: 6,
};
const inputStyle: React.CSSProperties = {
  width: '100%', background: 'var(--surface2)', border: '1px solid var(--border)',
  borderRadius: 8, padding: '10px 12px', color: 'var(--text)', fontSize: 14,
  fontFamily: 'inherit', boxSizing: 'border-box',
};
