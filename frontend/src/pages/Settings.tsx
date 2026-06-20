// =============================================================================
// Settings —— GET/PUT /api/user/profile（登录态）
// 邮箱只读 + 用户名可改(≤50) + 注册时间 + 验证状态；PUT 走 CSRF
// 登出走 POST /api/auth/logout（CSRF，修正原 inbox.html 未带 CSRF 的不一致）
// =============================================================================
import { useEffect, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import AppShell from '@/components/layout/AppShell';
import RequireAuth from '@/components/RequireAuth';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Button } from '@/components/ui/button';
import { api } from '@/lib/api';
import { useAuth } from '@/hooks/useAuth';
import type { UserProfile } from '@/types/api';

function SettingsContent() {
  const { user, refresh, logout } = useAuth();
  const navigate = useNavigate();
  const [username, setUsername] = useState('');
  const [saving, setSaving] = useState(false);
  const [toast, setToast] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  useEffect(() => {
    if (user) setUsername(user.username);
  }, [user]);

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    const trimmed = username.trim();
    if (!trimmed) {
      setToast({ type: 'error', text: '用户名不能为空' });
      return;
    }
    if (trimmed.length > 50) {
      setToast({ type: 'error', text: '用户名不能超过 50 字' });
      return;
    }
    setSaving(true);
    const res = await api<{ success: boolean; user: UserProfile }>('/api/user/profile', {
      method: 'PUT',
      json: { username: trimmed },
    });
    setSaving(false);
    if (res.ok) {
      await refresh();
      setToast({ type: 'success', text: '保存成功' });
    } else {
      setToast({ type: 'error', text: res.data.error || '保存失败' });
    }
    window.setTimeout(() => setToast(null), 3000);
  };

  const handleLogout = async () => {
    await logout();
    navigate('/');
  };

  if (!user) return null;

  return (
    <>
      <header className="space-y-2">
        <h1 className="text-3xl font-semibold tracking-tight">账户设置</h1>
        <p className="text-sm text-muted-foreground">管理你的账户信息</p>
      </header>

      {toast && (
        <div
          className={`fixed bottom-6 left-1/2 z-50 -translate-x-1/2 rounded-md border px-4 py-2 text-sm shadow-lg animate-fade-in ${
            toast.type === 'success'
              ? 'border-lime-500/40 bg-card text-lime-700 dark:text-lime-400'
              : 'border-destructive/40 bg-card text-destructive'
          }`}
        >
          {toast.text}
        </div>
      )}

      <div className="mt-8 grid gap-4">
        <Card>
          <CardHeader>
            <CardTitle>基本信息</CardTitle>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleSave} className="space-y-4">
              <div className="space-y-1.5">
                <Label htmlFor="email">邮箱</Label>
                <Input id="email" value={user.email} readOnly className="bg-muted/50 text-muted-foreground" />
                <p className="text-xs text-muted-foreground">邮箱地址不可修改</p>
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="username">用户名</Label>
                <Input
                  id="username"
                  maxLength={50}
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  placeholder="输入你的用户名"
                />
                <p className="text-xs text-muted-foreground">用户名将显示在收件箱和信件中</p>
              </div>
              <div className="space-y-1.5">
                <Label>注册时间</Label>
                <p className="font-mono text-sm text-muted-foreground">
                  {new Date(user.created_at).toLocaleString('zh-CN')}
                </p>
              </div>
              <div className="space-y-1.5">
                <Label>验证状态</Label>
                {user.is_verified ? (
                  <p className="text-sm text-lime-700 dark:text-lime-400">✓ 已验证</p>
                ) : (
                  <p className="text-sm text-amber-700 dark:text-amber-400">
                    ⚠ 未验证
                    <span className="ml-1 text-xs text-muted-foreground">请检查邮箱中的验证链接</span>
                  </p>
                )}
              </div>
              <Button type="submit" disabled={saving}>
                {saving ? '保存中...' : '保存修改'}
              </Button>
            </form>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>快捷操作</CardTitle>
          </CardHeader>
          <CardContent className="flex flex-wrap gap-2">
            <Button asChild variant="outline" size="sm">
              <Link to="/">返回首页</Link>
            </Button>
            <Button asChild variant="outline" size="sm">
              <Link to="/user/inbox">查看收件箱</Link>
            </Button>
            <Button variant="outline" size="sm" onClick={handleLogout}>
              登出
            </Button>
          </CardContent>
        </Card>
      </div>
    </>
  );
}

export default function Settings() {
  return (
    <AppShell>
      <RequireAuth>
        <SettingsContent />
      </RequireAuth>
    </AppShell>
  );
}
