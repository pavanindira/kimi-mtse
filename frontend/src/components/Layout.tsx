import { Link, NavLink, Outlet, useNavigate } from 'react-router-dom';
import { useAuth } from '../lib/auth-context';
import { useState } from 'react';
import { useNotifications } from '../lib/hooks';
import { useState } from 'react';
import { useNotifications } from '../lib/hooks';

const NAV_ITEMS = [
  {
    label: 'Dashboard',
    to:    '/',
    icon:  (
      <svg width="16" height="16" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
        <rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/>
        <rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/>
      </svg>
    ),
  },
  {
    label: 'Engagements',
    to:    '/engagements',
    icon:  (
      <svg width="16" height="16" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
        <path d="M22 16.92v3a2 2 0 01-2.18 2 19.79 19.79 0 01-8.63-3.07A19.5 19.5 0 013.07 9.8a19.79 19.79 0 01-3.07-8.68A2 2 0 012 .9h3a2 2 0 012 1.72c.13.96.36 1.9.7 2.81a2 2 0 01-.45 2.11L6.09 8.91a16 16 0 006 6l1.27-1.27a2 2 0 012.11-.45c.91.34 1.85.57 2.81.7A2 2 0 0122 16.92z"/>
      </svg>
    ),
  },
  {
    label: 'My Findings',
    to:    '/my-findings',
    icon:  (
      <svg width="16" height="16" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
        <path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/>
        <polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/>
        <polyline points="10 9 9 9 8 9"/>
      </svg>
    ),
  },
  {
    label: 'Findings',
    to:    '/findings',
    icon:  (
      <svg width="16" height="16" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
        <path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/>
        <line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>
      </svg>
    ),
  },
  {
    label: 'Search',
    to:    '/search',
    icon:  (
      <svg width="16" height="16" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
        <circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>
      </svg>
    ),
  },
];

const ADMIN_ITEMS = [
  { label: 'Users',            to: '/admin/users'            },
  { label: 'Audit Log',        to: '/admin/audit'            },
  { label: 'Report Templates', to: '/admin/report-templates' },
];

const SEV_COLOR = {
  Critical: '#ef4444', High: '#f97316', Medium: '#eab308',
  Low: '#3b82f6', Info: '#6b7280',
} as const;

export { SEV_COLOR };

export default function Layout() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const { notifications } = useNotifications();
  const [showNotifs, setShowNotifs] = useState(false);
  const unread = notifications?.unread ?? 0;

  return (
    <div style={{ display: 'flex', minHeight: '100vh', background: 'var(--bg)' }}>
      {/* Sidebar */}
      <nav style={{
        width: 220, minHeight: '100vh', background: 'var(--surface)',
        borderRight: '1px solid var(--border)', display: 'flex',
        flexDirection: 'column', position: 'fixed', top: 0, left: 0, zIndex: 100,
      }}>
        {/* Brand */}
        <NavLink to="/" style={{
          padding: '20px 18px 16px', borderBottom: '1px solid var(--border)',
          fontWeight: 700, fontSize: 15, letterSpacing: '.5px',
          display: 'flex', alignItems: 'center', gap: 8,
          color: 'var(--text)', textDecoration: 'none',
        }}>
          <svg width="20" height="20" fill="none" stroke="var(--accent)" strokeWidth="2" viewBox="0 0 24 24">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
          </svg>
          M<span style={{ color: 'var(--accent)' }}>STE</span>
        </NavLink>

        {/* Main nav */}
        <div style={{ padding: '12px 10px 4px', fontSize: 10, fontWeight: 600,
                      letterSpacing: 1, color: 'var(--muted)', textTransform: 'uppercase' }}>
          Workspace
        </div>
        {NAV_ITEMS.map(item => (
          <NavLink key={item.to} to={item.to} end={item.to === '/'} style={({ isActive }) => ({
            display: 'flex', alignItems: 'center', gap: 10,
            padding: '9px 14px', borderRadius: 6, margin: '1px 8px',
            color: isActive ? 'var(--accent)' : 'var(--muted)',
            background: isActive ? 'color-mix(in srgb, var(--accent) 12%, transparent)' : 'transparent',
            textDecoration: 'none', fontSize: 13,
          })}>
            {item.icon}
            {item.label}
          </NavLink>
        ))}

        {/* Admin nav */}
        {user?.role === 'Admin' && (
          <>
            <div style={{ padding: '12px 10px 4px', fontSize: 10, fontWeight: 600,
                          letterSpacing: 1, color: 'var(--muted)', textTransform: 'uppercase',
                          marginTop: 8 }}>
              Admin
            </div>
            {ADMIN_ITEMS.map(item => (
              <NavLink key={item.to} to={item.to} style={({ isActive }) => ({
                display: 'flex', alignItems: 'center', gap: 10,
                padding: '9px 14px', borderRadius: 6, margin: '1px 8px',
                color: isActive ? 'var(--accent)' : 'var(--muted)',
                background: isActive ? 'color-mix(in srgb, var(--accent) 12%, transparent)' : 'transparent',
                textDecoration: 'none', fontSize: 13,
              })}>
                {item.label}
              </NavLink>
            ))}
          </>
        )}

        {/* User footer */}
        <div style={{ marginTop: 'auto', padding: 12, borderTop: '1px solid var(--border)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '8px 6px' }}>
            <div style={{
              width: 28, height: 28, borderRadius: '50%', background: 'var(--accent)',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              fontSize: 11, fontWeight: 700, color: 'white', flexShrink: 0,
            }}>
              {user?.username?.[0]?.toUpperCase() ?? '?'}
            </div>
            <span style={{ fontSize: 12, color: 'var(--muted)', flex: 1 }}>
              {user?.username}
            </span>
            <Link to="/profile" title="Profile & password"
                  style={{ color: 'var(--muted)', fontSize: 13, lineHeight: 1,
                           textDecoration: 'none', padding: '0 4px' }}>
              ⚙
            </Link>
            <button onClick={logout} style={{
              background: 'none', border: 'none', color: 'var(--muted)',
              cursor: 'pointer', fontSize: 14, lineHeight: 1,
            }} title="Log out">✕</button>
          </div>
        </div>
      </nav>

      {/* Main content */}
      <main style={{ marginLeft: 220, flex: 1, minHeight: '100vh' }}>
        {/* Header with notification bell */}
        <div style={{
          position: 'sticky', top: 0, zIndex: 50,
          background: 'var(--bg)', borderBottom: '1px solid var(--border)',
          padding: '12px 36px', display: 'flex', justifyContent: 'flex-end', alignItems: 'center',
        }}>
          <div style={{ position: 'relative' }}>
            <button
              onClick={() => setShowNotifs(!showNotifs)}
              style={{
                background: 'none', border: 'none', cursor: 'pointer',
                color: 'var(--muted)', position: 'relative', padding: 8,
              }}
              title="Notifications"
            >
              <svg width="20" height="20" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
                <path d="M18 8A6 6 0 006 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 01-3.46 0"/>
              </svg>
              {unread > 0 && (
                <span style={{
                  position: 'absolute', top: 2, right: 2,
                  background: '#ef4444', color: 'white', borderRadius: '50%',
                  fontSize: 10, fontWeight: 700, width: 16, height: 16,
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                }}>
                  {unread > 9 ? '9+' : unread}
                </span>
              )}
            </button>

            {showNotifs && (
              <div style={{
                position: 'absolute', top: 40, right: 0, width: 340,
                background: 'var(--surface)', border: '1px solid var(--border)',
                borderRadius: 'var(--radius)', boxShadow: '0 8px 24px rgba(0,0,0,.35)',
                zIndex: 200, maxHeight: 400, overflow: 'auto',
              }}>
                <div style={{
                  padding: '12px 16px', borderBottom: '1px solid var(--border)',
                  display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                }}>
                  <span style={{ fontSize: 13, fontWeight: 600 }}>Notifications</span>
                  {unread > 0 && (
                    <button
                      onClick={() => { /* markAllRead.mutate() */ setShowNotifs(false); }}
                      style={{
                        fontSize: 11, color: 'var(--accent)', background: 'none',
                        border: 'none', cursor: 'pointer',
                      }}
                    >
                      Mark all read
                    </button>
                  )}
                </div>
                {(notifications?.items?.length ?? 0) === 0 ? (
                  <div style={{ padding: 20, textAlign: 'center', color: 'var(--muted)', fontSize: 13 }}>
                    No notifications yet
                  </div>
                ) : (
                  notifications?.items?.map((n: any) => (
                    <div
                      key={n.id}
                      onClick={() => { if (n.link) navigate(n.link); setShowNotifs(false); }}
                      style={{
                        padding: '10px 16px', borderBottom: '1px solid var(--border)',
                        cursor: 'pointer', background: n.is_read ? 'transparent' : 'color-mix(in srgb, var(--accent) 5%, transparent)',
                      }}
                    >
                      <div style={{ fontSize: 12, fontWeight: 600, marginBottom: 2 }}>{n.title}</div>
                      <div style={{ fontSize: 12, color: 'var(--muted)', lineHeight: 1.4 }}>{n.message}</div>
                      <div style={{ fontSize: 10, color: 'var(--muted)', marginTop: 4 }}>
                        {new Date(n.created_at).toLocaleString()}
                      </div>
                    </div>
                  ))
                )}
              </div>
            )}
          </div>
        </div>

        <div style={{ padding: '32px 36px', maxWidth: 1200 }}>
          <Outlet />
        </div>
      </main>
    </div>
  );
}
