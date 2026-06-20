// =============================================================================
// VerifyEmail —— 邮箱验证页
// 场景 A：用户从邮件链接过来，GET /verify-email?token= 由后端处理并重定向到
//          /auth/login?verified=1（或 ?error=），通常不会停留在此页。
// 场景 B：用户手动粘贴 token 到此页 → POST /api/auth/verify-email {token}
// 提供「重发验证邮件」入口：POST /api/auth/resend-verification {email}（CSRF）
// =============================================================================
import { useState } from 'react';
import { Link } from 'react-router-dom';
import AuthShell from '@/components/layout/AuthShell';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Button } from '@/components/ui/button';
import { api } from '@/lib/api';

export default function VerifyEmail() {
  const [token, setToken] = useState('');
  const [resendEmail, setResendEmail] = useState('');
  const [message, setMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);
  const [verifying, setVerifying] = useState(false);
  const [resending, setResending] = useState(false);

  const handleVerify = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!token.trim()) return;
    setVerifying(true);
    setMessage(null);
    const res = await api<{ success: boolean }>('/api/auth/verify-email', { method: 'POST', json: { token: token.trim() } });
    setVerifying(false);
    if (res.ok) {
      setMessage({ type: 'success', text: '邮箱验证成功，请前往登录。' });
    } else {
      setMessage({ type: 'error', text: res.data.error || '验证失败' });
    }
  };

  const handleResend = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!resendEmail.trim()) return;
    setResending(true);
    setMessage(null);
    const res = await api<{ success: boolean }>('/api/auth/resend-verification', {
      method: 'POST',
      json: { email: resendEmail.trim().toLowerCase() },
    });
    setResending(false);
    if (res.ok) {
      setMessage({ type: 'success', text: '验证邮件已重新发送，请查收。' });
    } else {
      setMessage({ type: 'error', text: res.data.error || '发送失败' });
    }
  };

  return (
    <AuthShell title="邮箱验证" subtitle="验证你的邮箱地址">
      {message && (
        <p
          className={`rounded-md border px-3 py-2 text-sm ${
            message.type === 'success'
              ? 'border-lime-500/40 bg-lime-500/10 text-lime-700 dark:text-lime-400'
              : 'border-destructive/40 bg-destructive/10 text-destructive'
          }`}
        >
          {message.text}
        </p>
      )}

      <form onSubmit={handleVerify} className="space-y-4">
        <div className="space-y-1.5">
          <Label htmlFor="token">验证令牌</Label>
          <Input
            id="token"
            value={token}
            onChange={(e) => setToken(e.target.value)}
            placeholder="粘贴邮件中的验证令牌"
            autoComplete="off"
          />
        </div>
        <Button type="submit" size="lg" className="w-full" disabled={verifying}>
          {verifying ? '验证中...' : '验证'}
        </Button>
      </form>

      <div className="relative py-2 text-center">
        <span className="bg-card px-2 text-xs text-muted-foreground">未收到邮件？</span>
        <div className="absolute left-0 top-1/2 h-px w-full bg-border" />
      </div>

      <form onSubmit={handleResend} className="space-y-4">
        <div className="space-y-1.5">
          <Label htmlFor="resend-email">注册邮箱</Label>
          <Input
            id="resend-email"
            type="email"
            value={resendEmail}
            onChange={(e) => setResendEmail(e.target.value)}
            placeholder="请输入您的注册邮箱"
          />
        </div>
        <Button type="submit" variant="outline" size="lg" className="w-full" disabled={resending}>
          {resending ? '发送中...' : '重发验证邮件'}
        </Button>
      </form>

      <div className="text-center text-sm text-muted-foreground">
        <Link to="/auth/login" className="underline">
          返回登录
        </Link>
      </div>
    </AuthShell>
  );
}
