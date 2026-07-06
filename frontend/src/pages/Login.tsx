// =============================================================================
// Login —— POST /api/auth/login（rate 10/min）
// email/password；成功 navigate('/')
// 错误：401 邮箱或密码错误（+remaining_attempts）；429 锁定（locked_until）
// 读 URL ?verified=1 / ?error= 展示邮箱验证结果（来自 /verify-email 重定向）
// =============================================================================
import { useState } from 'react';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';
import AuthShell from '@/components/layout/AuthShell';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Button } from '@/components/ui/button';
import { api } from '@/lib/api';
import { useAuth } from '@/hooks/useAuth';
import type { ApiError, UserProfile } from '@/types/api';

interface LoginOk {
  success: boolean;
  user: UserProfile;
}
interface LoginErr extends ApiError {
  remaining_attempts?: number;
  locked_until?: string | null;
}

export default function Login() {
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const { refresh } = useAuth();

  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [submitting, setSubmitting] = useState(false);

  const verified = params.get('verified') === '1';
  const errorCode = params.get('error');
  const flash = errorCode
    ? errorCode === 'invalid_token'
      ? '验证链接无效或已过期'
      : '验证失败，请重试'
    : verified
      ? '✓ 邮箱验证成功，请登录'
      : '';

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setSubmitting(true);

    const body: Record<string, unknown> = {
      email: email.trim().toLowerCase(),
      password,
    };

    const res = await api<LoginOk & LoginErr>('/api/auth/login', { method: 'POST', json: body });

    if (res.ok) {
      await refresh();
      navigate('/');
      return;
    }

    const err = res.data;
    let msg = err.error || '登录失败';
    if (err.locked_until) {
      try {
        msg = `账户已锁定，解锁时间：${new Date(String(err.locked_until)).toLocaleString('zh-CN')}`;
      } catch {
        /* 保持原 msg */
      }
    } else if (err.remaining_attempts != null) {
      msg = `${err.error}（剩余尝试次数：${err.remaining_attempts}）`;
    }
    setError(msg);
    setSubmitting(false);
  };

  return (
    <AuthShell title="登录" subtitle="登录你的账户">
      {flash && (
        <p
          className={`rounded-md border px-3 py-2 text-sm ${
            verified
              ? 'border-lime-500/40 bg-lime-500/10 text-lime-700 dark:text-lime-400'
              : 'border-destructive/40 bg-destructive/10 text-destructive'
          }`}
        >
          {flash}
        </p>
      )}

      <form onSubmit={handleSubmit} className="space-y-4" noValidate>
        <div className="space-y-1.5">
          <Label htmlFor="email">邮箱</Label>
          <Input
            id="email"
            type="email"
            required
            autoComplete="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            placeholder="请输入邮箱"
          />
        </div>
        <div className="space-y-1.5">
          <Label htmlFor="password">密码</Label>
          <Input
            id="password"
            type="password"
            required
            autoComplete="current-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="请输入密码"
          />
        </div>

        {error && (
          <p className="rounded-md border border-destructive/40 bg-destructive/10 px-3 py-2 text-sm text-destructive">
            {error}
          </p>
        )}

        <Button type="submit" size="lg" className="w-full" disabled={submitting}>
          {submitting ? '登录中...' : '登录'}
        </Button>
      </form>

      <div className="space-y-1 text-center text-sm text-muted-foreground">
        <p>
          还没有账户？
          <Link to="/auth/register" className="ml-1 text-foreground underline">
            立即注册
          </Link>
        </p>
        <Link to="/" className="inline-block underline">
          返回首页
        </Link>
      </div>
    </AuthShell>
  );
}
