/**
 * auth-context.tsx — React context for authentication state.
 *
 * Wraps the token lifecycle:
 *   - login()  → calls API, stores token in memory, sets axios/fetch default
 *   - logout() → clears token, redirects to /login
 *   - user     → the current UserOut or null
 */

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useState,
  type ReactNode,
} from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { auth as authApi, clearToken, hasToken, setToken } from './api';
import type { UserOut } from './api';

interface AuthState {
  user:    UserOut | null;
  loading: boolean;
  login:   (username: string, password: string) => Promise<void>;
  logout:  () => void;
}

const AuthContext = createContext<AuthState | null>(null);

const SESSION_KEY = 'mste_token';

export function AuthProvider({ children }: { children: ReactNode }) {
  const qc = useQueryClient();
  const [user,    setUser]    = useState<UserOut | null>(null);
  const [loading, setLoading] = useState(true); // true on mount while restoring

  // ── Restore session from sessionStorage on page load ──────────────────────
  // sessionStorage is tab-scoped and cleared when the tab closes — a reasonable
  // compromise: survives page refresh (F5) but not closing the browser.
  // The token itself is still verified server-side on every request.
  useEffect(() => {
    const saved = sessionStorage.getItem(SESSION_KEY);
    if (!saved) { setLoading(false); return; }
    setToken(saved);
    authApi.me()
      .then(me  => setUser(me))
      .catch(()  => { sessionStorage.removeItem(SESSION_KEY); clearToken(); })
      .finally(() => setLoading(false));
  }, []);

  const login = useCallback(async (username: string, password: string) => {
    setLoading(true);
    try {
      const token = await authApi.login(username, password);
      setToken(token.access_token);
      sessionStorage.setItem(SESSION_KEY, token.access_token);
      const me = await authApi.me();
      setUser(me);
    } finally {
      setLoading(false);
    }
  }, []);

  const logout = useCallback(() => {
    clearToken();
    sessionStorage.removeItem(SESSION_KEY);
    setUser(null);
    qc.clear();
  }, [qc]);

  return (
    <AuthContext.Provider value={{ user, loading, login, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthState {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used inside AuthProvider');
  return ctx;
}
