// =============================================================================
// RequireAuth —— 登录态路由守卫
// useAuth.loading 期间显示骨架；未登录跳 /auth/login（带 redirect 参数）
// =============================================================================
import { type ReactNode } from 'react';
import { Navigate, useLocation } from 'react-router-dom';
import { useAuth } from '@/hooks/useAuth';

export default function RequireAuth({ children }: { children: ReactNode }) {
  const { user, loading } = useAuth();
  const location = useLocation();

  if (loading) {
    return (
      <div className="mx-auto max-w-3xl px-6 py-16">
        <div className="h-8 w-48 animate-pulse rounded-md bg-muted" />
      </div>
    );
  }

  if (!user) {
    const redirect = encodeURIComponent(location.pathname + location.search);
    return <Navigate to={`/auth/login?redirect=${redirect}`} replace />;
  }

  return <>{children}</>;
}
