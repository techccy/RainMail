// =============================================================================
// MessageForm —— 消息投递表单
// 字段：content(≤500) + 投递方式(public/private) + private 选项（回复通知/邮箱/被回复后公开）
//       + 蜜罐(website,必须空) + Captcha + 行为字段
// 提交 → POST /api/messages（CSRF，rate 10/min）
// 成功 → onSubmitted(share_data)；require_login → onRequireLogin；blocked/其他 → 错误提示
// =============================================================================
import { useRef, useState } from 'react';
import { Textarea } from '@/components/ui/textarea';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Captcha, type CaptchaHandle } from '@/components/Captcha';
import { ProcessingOverlay } from '@/components/ProcessingOverlay';
import { api } from '@/lib/api';
import { useBehavior } from '@/hooks/useBehavior';
import { useAuth } from '@/hooks/useAuth';
import type { ApiError, ShareData } from '@/types/api';

const MAX_CHARS = 500;

interface Props {
  variant: 'sunny' | 'rainy';
  onSubmitted: (share: ShareData) => void;
  onRequireLogin?: () => void;
}

export default function MessageForm({ variant, onSubmitted, onRequireLogin }: Props) {
  const { validate, getBehaviorData, handleFocus, handleInput } = useBehavior();
  const { user } = useAuth();
  const captchaRef = useRef<CaptchaHandle>(null);

  const [content, setContent] = useState('');
  const [deliveryType, setDeliveryType] = useState<'public' | 'private'>('public');
  const [replyNotification, setReplyNotification] = useState(false);
  const [senderEmail, setSenderEmail] = useState('');
  const [publicAfterReply, setPublicAfterReply] = useState(false);
  const [honeypot, setHoneypot] = useState(''); // 必须为空
  const [error, setError] = useState('');
  const [processing, setProcessing] = useState(false);

  // 已登录时预填邮箱
  const defaultEmail = user?.email ?? '';

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');

    // 1. 蜜罐（非空 = 机器人，静默中止）
    if (honeypot) return;

    // 2. 行为校验
    const behaviorError = validate();
    if (behaviorError) {
      setError(behaviorError);
      return;
    }

    // 3. 内容校验
    const trimmed = content.trim();
    if (!trimmed) {
      setError('请输入内容');
      return;
    }
    if (trimmed.length > MAX_CHARS) {
      setError(`内容不能超过 ${MAX_CHARS} 字`);
      return;
    }

    // 4. 验证码 token
    let captchaField: { field: string; value: string } | null = null;
    try {
      captchaField = await captchaRef.current?.getToken() ?? null;
    } catch {
      setError('验证码获取失败，请重试');
      return;
    }

    // 5. 行为数据
    const behaviorData = getBehaviorData();
    if (!behaviorData) {
      setError('会话未就绪，请刷新页面重试');
      return;
    }

    setProcessing(true);

    const body: Record<string, unknown> = {
      content: trimmed,
      delivery_type: deliveryType,
      delivery_options:
        deliveryType === 'private'
          ? { type: 'private', emailNotification: replyNotification }
          : { type: 'public' },
      reply_notification: replyNotification ? 'email' : 'none',
      is_anonymous: true,
      public_after_reply: publicAfterReply,
      sender_email: deliveryType === 'private' ? (senderEmail || defaultEmail) : '',
      website: '', // 蜜罐字段，必须空
      ...behaviorData,
    };
    if (captchaField && captchaField.value) {
      body[captchaField.field] = captchaField.value;
    }

    const res = await api<{ success: boolean; share_data: ShareData } & ApiError>('/api/messages', {
      method: 'POST',
      json: body,
    });

    setProcessing(false);
    // 提交后刷新一次性验证码（成功或失败都刷新）
    void captchaRef.current?.refresh();

    if (res.ok) {
      setContent('');
      setSenderEmail('');
      setReplyNotification(false);
      setPublicAfterReply(false);
      onSubmitted(res.data.share_data);
      return;
    }

    const err = res.data;
    if (err.require_login) {
      onRequireLogin?.();
      return;
    }
    setError(err.error || '提交失败');
  };

  const formId = `message-form-${variant}`;

  return (
    <>
      <form onSubmit={handleSubmit} className="space-y-5" id={formId} noValidate>
        {/* 蜜罐：视觉隐藏，机器人会填 */
        /* eslint-disable-next-line jsx-a11y/no-tabindex */}
        <input
          type="text"
          tabIndex={-1}
          autoComplete="off"
          value={honeypot}
          onChange={(e) => setHoneypot(e.target.value)}
          className="absolute -left-[9999px] h-0 w-0 opacity-0"
          aria-hidden="true"
        />

        <div className="space-y-2">
          <div className="flex items-baseline justify-between">
            <Label htmlFor={`${variant}-content`}>你的想法（最多 {MAX_CHARS} 字）</Label>
            <span className="font-mono text-xs text-muted-foreground">
              {content.length}/{MAX_CHARS}
            </span>
          </div>
          <Textarea
            id={`${variant}-content`}
            value={content}
            maxLength={MAX_CHARS}
            placeholder="写下此刻的心情..."
            onFocus={() => handleFocus(`${variant}-content`)}
            onChange={(e) => {
              const next = e.target.value;
              const added = Math.max(0, next.length - content.length);
              handleInput(added);
              setContent(next);
            }}
            className="min-h-28 resize-y"
          />
        </div>

        {/* 投递方式 */}
        <fieldset className="space-y-2">
          <legend className="text-sm font-medium">投递方式</legend>
          <div className="grid gap-2 sm:grid-cols-2">
            <label
              className={`flex cursor-pointer flex-col gap-0.5 rounded-md border p-3 text-sm transition ${
                deliveryType === 'public' ? 'border-foreground bg-accent/50' : 'border-border hover:bg-accent/30'
              }`}
            >
              <input
                type="radio"
                name={`${variant}-delivery-type`}
                value="public"
                checked={deliveryType === 'public'}
                onChange={() => setDeliveryType('public')}
                className="sr-only"
              />
              <span className="font-medium">雨天公开广播</span>
              <span className="text-xs text-muted-foreground">雨天时所有人可见</span>
            </label>
            <label
              className={`flex cursor-pointer flex-col gap-0.5 rounded-md border p-3 text-sm transition ${
                deliveryType === 'private' ? 'border-foreground bg-accent/50' : 'border-border hover:bg-accent/30'
              }`}
            >
              <input
                type="radio"
                name={`${variant}-delivery-type`}
                value="private"
                checked={deliveryType === 'private'}
                onChange={() => setDeliveryType('private')}
                className="sr-only"
              />
              <span className="font-medium">发给陌生人</span>
              <span className="text-xs text-muted-foreground">一对一投递，雨天解锁</span>
            </label>
          </div>
        </fieldset>

        {/* private 专属选项 */}
        {deliveryType === 'private' && (
          <div className="space-y-3 rounded-md border border-border bg-muted/30 p-3 animate-fade-in">
            <label className="flex cursor-pointer items-center gap-2 text-sm">
              <input
                type="checkbox"
                checked={replyNotification}
                onChange={(e) => setReplyNotification(e.target.checked)}
              />
              收到回复时邮件通知我
            </label>

            {replyNotification && (
              <div className="space-y-1 animate-fade-in">
                <Label htmlFor={`${variant}-sender-email`}>通知邮箱</Label>
                <Input
                  id={`${variant}-sender-email`}
                  type="email"
                  value={senderEmail || defaultEmail}
                  onChange={(e) => setSenderEmail(e.target.value)}
                  placeholder="请输入您的邮箱地址"
                />
                <p className="text-xs text-muted-foreground">我们将通过此邮箱通知您收到回复</p>
              </div>
            )}

            <label className="flex cursor-pointer items-center gap-2 text-sm">
              <input
                type="checkbox"
                checked={publicAfterReply}
                onChange={(e) => setPublicAfterReply(e.target.checked)}
              />
              被回复后公开
            </label>
          </div>
        )}

        {/* 验证码 */}
        <div>
          <Captcha ref={captchaRef} action="submit" />
        </div>

        <p className="text-xs text-muted-foreground">
          提交即表示同意我们的
          <a href="/privacy-policy-cn" target="_blank" rel="noreferrer" className="ml-1 underline hover:text-foreground">
            隐私条款
          </a>
        </p>

        {error && (
          <p className="rounded-md border border-destructive/40 bg-destructive/10 px-3 py-2 text-sm text-destructive">
            {error}
          </p>
        )}

        <Button type="submit" size="lg" className="w-full">
          投递想法
        </Button>
      </form>

      {processing && <ProcessingOverlay />}
    </>
  );
}
