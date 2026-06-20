// =============================================================================
// Register —— POST /api/auth/register（rate 3/hour）
// email/username(可选)/password/confirm-password + Captcha
// 客户端 gate：密码≥6、两次一致
// 成功 → 拉取 /api/email-providers 找邮箱域名 → 显示验证 modal（含登录链接）
// =============================================================================
import { useRef, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import AuthShell from '@/components/layout/AuthShell';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Button } from '@/components/ui/button';
import { Captcha, type CaptchaHandle } from '@/components/Captcha';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription } from '@/components/ui/dialog';
import { api } from '@/lib/api';
import type { ApiError } from '@/types/api';

interface RegisterOk {
  success: boolean;
}

export default function Register() {
  const navigate = useNavigate();
  const captchaRef = useRef<CaptchaHandle>(null);

  const [email, setEmail] = useState('');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [error, setError] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [verifyOpen, setVerifyOpen] = useState(false);
  const [providerUrl, setProviderUrl] = useState('');

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');

    if (password.length < 6) {
      setError('密码长度至少6位');
      return;
    }
    if (password !== confirm) {
      setError('两次输入的密码不一致');
      return;
    }

    setSubmitting(true);

    let captchaField: { field: string; value: string } | null = null;
    try {
      captchaField = await captchaRef.current?.getToken() ?? null;
    } catch {
      setError('验证码获取失败，请重试');
      setSubmitting(false);
      return;
    }

    const body: Record<string, unknown> = {
      email: email.trim().toLowerCase(),
      password,
      username: username.trim(),
    };
    if (captchaField?.value) body[captchaField.field] = captchaField.value;

    const res = await api<RegisterOk & ApiError>('/api/auth/register', { method: 'POST', json: body });
    void captchaRef.current?.refresh();

    if (res.ok) {
      // 拉取邮箱服务商
      const pRes = await api<Record<string, string>>('/api/email-providers');
      const domain = email.substring(email.lastIndexOf('@')).toLowerCase();
      setProviderUrl(pRes.ok ? pRes.data[domain] ?? '' : '');
      setVerifyOpen(true);
      setSubmitting(false);
      return;
    }

    setError(res.data.error || '注册失败');
    setSubmitting(false);
  };

  return (
    <AuthShell title="注册" subtitle="创建你的账户">
      <p className="rounded-md border border-amber-400/40 bg-amber-400/10 px-3 py-2 text-xs text-amber-700 dark:text-amber-400">
        请务必在注册后 1 小时内完成邮箱验证，否则账户将被自动删除。
      </p>

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
          <Label htmlFor="username">用户名（可选）</Label>
          <Input
            id="username"
            type="text"
            maxLength={50}
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            placeholder="留空则使用邮箱前缀"
          />
        </div>
        <div className="space-y-1.5">
          <Label htmlFor="password">密码</Label>
          <Input
            id="password"
            type="password"
            required
            minLength={6}
            autoComplete="new-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="至少6位"
          />
        </div>
        <div className="space-y-1.5">
          <Label htmlFor="confirm">确认密码</Label>
          <Input
            id="confirm"
            type="password"
            required
            autoComplete="new-password"
            value={confirm}
            onChange={(e) => setConfirm(e.target.value)}
            placeholder="再次输入密码"
          />
        </div>

        <Captcha ref={captchaRef} action="register" />

        {error && (
          <p className="rounded-md border border-destructive/40 bg-destructive/10 px-3 py-2 text-sm text-destructive">
            {error}
          </p>
        )}

        <Button type="submit" size="lg" className="w-full" disabled={submitting}>
          {submitting ? '注册中...' : '注册'}
        </Button>
      </form>

      <div className="space-y-1 text-center text-sm text-muted-foreground">
        <p>
          已有账户？
          <Link to="/auth/login" className="ml-1 text-foreground underline">
            立即登录
          </Link>
        </p>
        <Link to="/" className="inline-block underline">
          返回首页
        </Link>
      </div>

      <Dialog open={verifyOpen} onOpenChange={setVerifyOpen}>
        <DialogContent className="max-w-sm">
          <DialogHeader>
            <DialogTitle>验证邮箱</DialogTitle>
            <DialogDescription>我们已向 {email} 发送验证邮件，请在 1 小时内完成验证。</DialogDescription>
          </DialogHeader>
          <div className="space-y-3">
            {providerUrl ? (
              <a href={providerUrl} target="_blank" rel="noreferrer" className="block text-center text-sm underline">
                前往邮箱查收
              </a>
            ) : (
              <p className="text-center text-sm text-muted-foreground">请前往邮箱查收验证邮件</p>
            )}
            <Button variant="outline" className="w-full" onClick={() => navigate('/auth/login')}>
              前往登录
            </Button>
          </div>
        </DialogContent>
      </Dialog>
    </AuthShell>
  );
}
