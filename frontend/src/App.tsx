import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { Navigate, Route, Routes } from 'react-router-dom';
import { AuthProvider, useAuth } from './lib/auth-context';
import Layout from './components/Layout';
import { Login } from './pages/Login';
import { lazy, Suspense, type ReactNode } from 'react';

// Lazy-load pages so the initial bundle stays small
const Dashboard      = lazy(() => import('./pages/Dashboard'));
const Engagements    = lazy(() => import('./pages/Engagements'));
const Engagement     = lazy(() => import('./pages/Engagement'));
const NewEngagement  = lazy(() => import('./pages/NewEngagement'));
const Findings       = lazy(() => import('./pages/Findings'));
const FindingPage    = lazy(() => import('./pages/FindingPage'));
const Search         = lazy(() => import('./pages/Search'));
const AdminUsers          = lazy(() => import('./pages/AdminUsers'));
const AdminAudit          = lazy(() => import('./pages/AdminAudit'));
const AdminReportTemplates = lazy(() => import('./pages/AdminReportTemplates'));
const MyFindings       = lazy(() => import('./pages/MyFindings'));

const qc = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime:          30_000,
      retry:              1,
      refetchOnWindowFocus: false,
    },
  },
});

function ProtectedRoute({ children, adminOnly = false }: {
  children: ReactNode; adminOnly?: boolean;
}) {
  const { user } = useAuth();
  if (!user) return <Navigate to="/login" replace />;
  if (adminOnly && user.role !== 'Admin') return <Navigate to="/" replace />;
  return <>{children}</>;
}

function AppRoutes() {
  const { user } = useAuth();

  return (
    <Suspense fallback={
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center',
                    height: '100vh', color: 'var(--muted)' }}>
        Loading…
      </div>
    }>
      <Routes>
        <Route path="/login" element={user ? <Navigate to="/" replace /> : <Login />} />
        <Route element={<ProtectedRoute><Layout /></ProtectedRoute>}>
          <Route index                 element={<Dashboard />} />
          <Route path="engagements"          element={<Engagements />} />
          <Route path="engagements/new"      element={<NewEngagement />} />
          <Route path="engagements/:id"      element={<Engagement />} />
          <Route path="findings"       element={<Findings />} />
          <Route path="my-findings"    element={<MyFindings />} />
          <Route path="findings/:id"   element={<FindingPage />} />
          <Route path="search"         element={<Search />} />
          <Route path="admin/users"    element={
            <ProtectedRoute adminOnly><AdminUsers /></ProtectedRoute>
          }/>
          <Route path="admin/audit"    element={
            <ProtectedRoute adminOnly><AdminAudit /></ProtectedRoute>
          }/>
          <Route path="admin/report-templates" element={
            <ProtectedRoute adminOnly><AdminReportTemplates /></ProtectedRoute>
          }/>
          <Route path="profile"        element={<Profile />} />
        </Route>
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </Suspense>
  );
}

export default function App() {
  return (
    <>
      {/* Global CSS variables — same dark palette as v1 */}
      <style>{`
        *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
        :root {
          --bg:       #0f1117;
          --surface:  #181c27;
          --surface2: #1f2535;
          --border:   #2a3045;
          --text:     #e2e8f0;
          --muted:    #8892a4;
          --accent:   #4f8ef7;
          --radius:   8px;
        }
        body { font-family: system-ui, -apple-system, sans-serif; font-size: 14px;
               background: var(--bg); color: var(--text); }
        a { color: var(--text); }
        @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:.4} }
        input, select, textarea {
          background: var(--surface2); border: 1px solid var(--border);
          border-radius: var(--radius); padding: 9px 12px; color: var(--text);
          font-size: 13px; font-family: inherit; width: 100%;
        }
        input:focus, select:focus, textarea:focus {
          outline: none; border-color: var(--accent);
        }
        .btn {
          display: inline-flex; align-items: center; gap: 6px;
          padding: 8px 14px; border-radius: var(--radius); font-size: 13px;
          font-weight: 500; cursor: pointer; border: none; text-decoration: none;
          transition: opacity .15s; white-space: nowrap;
        }
        .btn:hover { opacity: .85; }
        .btn-primary { background: var(--accent); color: white; }
        .btn-ghost   { background: var(--surface2); color: var(--text);
                       border: 1px solid var(--border); }
        .btn-danger  { background: #ef4444; color: white; }
        .btn-sm      { padding: 5px 10px; font-size: 12px; }
        .card { background: var(--surface); border: 1px solid var(--border);
                border-radius: var(--radius); }
        .card-head { padding: 16px 20px; border-bottom: 1px solid var(--border);
                     display: flex; align-items: center; justify-content: space-between; }
        .card-head h2 { font-size: 14px; font-weight: 600; }
        table { width: 100%; border-collapse: collapse; font-size: 13px; }
        th { padding: 10px 14px; text-align: left; font-size: 11px; font-weight: 600;
             text-transform: uppercase; letter-spacing: .5px; color: var(--muted);
             border-bottom: 1px solid var(--border); white-space: nowrap; }
        td { padding: 11px 14px; border-bottom: 1px solid var(--border);
             vertical-align: middle; }
        tr:last-child td { border-bottom: none; }
        tr:hover td { background: var(--surface2); }
        .topbar { display: flex; align-items: center; justify-content: space-between;
                  margin-bottom: 28px; gap: 16px; flex-wrap: wrap; }
        .topbar h1 { font-size: 20px; font-weight: 600; }
        .sub { color: var(--muted); font-size: 13px; margin-top: 2px; }
        .empty { text-align: center; padding: 48px 20px; color: var(--muted); }
        .mono { font-family: 'SF Mono','Fira Code',monospace; }
        .truncate { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
        .grid-5 { display: grid; grid-template-columns: repeat(5,1fr); gap: 12px; }
        .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
        .stat-card { background: var(--surface); border: 1px solid var(--border);
                     border-radius: var(--radius); padding: 18px 20px; }
        .stat-card .num { font-size: 28px; font-weight: 700; line-height: 1; margin-bottom: 4px; }
        .stat-card .lbl { font-size: 11px; color: var(--muted);
                          text-transform: uppercase; letter-spacing: .5px; }
      `}</style>

      <QueryClientProvider client={qc}>
        <AuthProvider>
          <AppRoutes />
        </AuthProvider>
      </QueryClientProvider>
    </>
  );
}
