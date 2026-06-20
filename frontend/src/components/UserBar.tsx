// =============================================================================
// UserBar —— 顶栏右侧：未登录显示「登录 / 注册」，已登录显示用户菜单
// =============================================================================
import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { Inbox, LogOut, Settings, ChevronDown } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { useAuth } from '@/hooks/useAuth';

export default function UserBar() {
  const { user, loading, logout } = useAuth();
  const navigate = useNavigate();
  const [menuOpen, setMenuOpen] = useState(false);

  if (loading) {
    return <span className="h-8 w-16 animate-pulse rounded-md bg-muted" aria-hidden />;
  }

  if (!user) {
    return (
      <Button asChild variant="ghost" size="sm">
        <Link to="/auth/login">登录 / 注册</Link>
      </Button>
    );
  }

  const displayName = user.username || user.email.split('@')[0];

  const handleLogout = async () => {
    await logout();
    navigate('/');
  };

  return (
    <div className="relative">
      <button
        type="button"
        onClick={() => setMenuOpen((v) => !v)}
        className="inline-flex items-center gap-1.5 rounded-md px-2 py-1.5 text-sm hover:bg-accent"
      >
        <span className="max-w-[8rem] truncate">你好，{displayName}</span>
        <ChevronDown className="size-3.5 text-muted-foreground" />
      </button>

      {menuOpen && (
        <>
          <div className="fixed inset-0 z-10" onClick={() => setMenuOpen(false)} aria-hidden />
          <div className="absolute right-0 top-full z-20 mt-1 w-44 overflow-hidden rounded-md border border-border bg-popover shadow-md">
            <Link
              to="/user/inbox"
              onClick={() => setMenuOpen(false)}
              className="flex items-center gap-2 px-3 py-2 text-sm hover:bg-accent"
            >
              <Inbox className="size-4" /> 收件箱
            </Link>
            <Link
              to="/user/settings"
              onClick={() => setMenuOpen(false)}
              className="flex items-center gap-2 px-3 py-2 text-sm hover:bg-accent"
            >
              <Settings className="size-4" /> 设置
            </Link>
            <button
              type="button"
              onClick={handleLogout}
              className="flex w-full items-center gap-2 px-3 py-2 text-left text-sm hover:bg-accent"
            >
              <LogOut className="size-4" /> 登出
            </button>
          </div>
        </>
      )}
    </div>
  );
}
