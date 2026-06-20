// =============================================================================
// 认证上下文 —— 登录态全局管理
// GET /api/user/profile 探测登录态（401 视为未登录）
// =============================================================================
import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react';
import { api } from '@/lib/api';
import type { ProfileResponse, UserProfile } from '@/types/api';

interface AuthState {
  user: UserProfile | null;
  loading: boolean;
  refresh: () => Promise<UserProfile | null>;
  setUser: (u: UserProfile | null) => void;
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthState | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<UserProfile | null>(null);
  const [loading, setLoading] = useState(true);

  const refresh = useCallback(async () => {
    const res = await api<ProfileResponse>('/api/user/profile');
    if (res.ok) {
      setUser(res.data.user);
    } else {
      setUser(null);
    }
    setLoading(false);
    return res.ok ? res.data.user : null;
  }, []);

  const logout = useCallback(async () => {
    await api('/api/auth/logout', { method: 'POST', json: {} });
    setUser(null);
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const value = useMemo<AuthState>(
    () => ({ user, loading, refresh, setUser, logout }),
    [user, loading, refresh, logout],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthState {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth 必须在 AuthProvider 内使用');
  return ctx;
}
