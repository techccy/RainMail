// =============================================================================
// ShareCardModal —— 提交成功后的存票凭证弹窗
// 展示：寄信人/第N号/唯一ID/存入时间/服务器状态/总消息数 + QR
// 「保存存票」→ html-to-image 导出 PNG（雨天信箱存票_#N.png）
// QR 用 qrcode 库渲染成 dataURL <img>（替代 vendored qrcode.min.js）
// 卡片配色由 weatherStatus 显式决定，不依赖全局 .dark 主题
// =============================================================================
import { useEffect, useRef, useState } from 'react';
import { Copy, Check } from 'lucide-react';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription } from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { useAuth } from '@/hooks/useAuth';
import type { ShareData, WeatherStatus } from '@/types/api';

interface Props {
  share: ShareData | null;
  /** 存票展示的天气模式（默认用实时天气，比服务端硬编码 sunny 更准确） */
  weatherOverride?: WeatherStatus;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

export default function ShareCardModal({ share, weatherOverride, open, onOpenChange }: Props) {
  const { user } = useAuth();
  const cardRef = useRef<HTMLDivElement>(null);
  const [qrDataUrl, setQrDataUrl] = useState('');
  const [saving, setSaving] = useState(false);
  const [copied, setCopied] = useState(false);

  const weatherStatus = weatherOverride ?? share?.weather_status ?? 'sunny';
  const weatherLabel = weatherStatus === 'rainy' ? '雨天模式' : '晴天模式';
  const senderName = user?.username || user?.email?.split('@')[0] || '匿名';

  // 卡片配色：由实时天气决定，晴天浅卡 / 雨天深卡，独立于全局 .dark 主题
  const theme =
    weatherStatus === 'rainy'
      ? {
          cardBg: '#1c1f2b', // 深蓝灰
          text: 'text-stone-100',
          label: 'text-stone-400',
          border: 'border-stone-700',
          link: 'text-stone-300',
        }
      : {
          cardBg: '#faf7f0', // 暖白票据感
          text: 'text-stone-900',
          label: 'text-stone-500',
          border: 'border-stone-200',
          link: 'text-stone-600',
        };

  // 渲染 QR 为 dataURL（懒加载 qrcode 库）
  // 用 toDataURL + state 取代直接画 canvas：不再依赖 Radix Portal 异步挂载时 qrRef 是否就绪
  useEffect(() => {
    if (!share) {
      setQrDataUrl('');
      return;
    }
    const url = share.full_share_url.startsWith('http')
      ? share.full_share_url
      : `${window.location.origin}${share.full_share_url}`;
    let cancelled = false;
    setQrDataUrl(''); // 切票时清空，避免闪旧码
    void import('qrcode').then((mod) => {
      if (cancelled) return;
      // 兼容 default 与 namespace 两种 interop
      const QRCode = (mod as { default?: typeof import('qrcode') }).default ?? mod;
      QRCode.toDataURL(url, {
        width: 128,
        margin: 1,
        errorCorrectionLevel: 'H',
        color: { dark: '#000000', light: '#ffffff' },
      })
        .then((dataUrl) => {
          if (!cancelled) setQrDataUrl(dataUrl);
        })
        .catch((e) => console.error('二维码生成失败', e));
    });
    return () => {
      cancelled = true;
    };
  }, [share]);

  const handleSave = async () => {
    if (!cardRef.current || !share) return;
    setSaving(true);
    try {
      // 懒加载 html-to-image（体积大，仅导出时需要）
      // 选用 html-to-image 而非 html2canvas：前者通过 SVG foreignObject 委托浏览器原生渲染，
      // 原生支持 oklch / 嵌套 canvas / 现代 CSS，后者会在解析 Tailwind v4 的 oklch 边框色时抛错。
      const { toPng } = await import('html-to-image');
      const dataUrl = await toPng(cardRef.current, {
        pixelRatio: 2,
        backgroundColor: theme.cardBg, // 与卡片底色一致，避免圆角透明
        cacheBust: true,
      });
      const a = document.createElement('a');
      a.href = dataUrl;
      a.download = `雨天信箱存票_#${share.message_id}.png`;
      a.click();
    } catch (e) {
      console.error('存票导出失败', e);
    } finally {
      setSaving(false);
    }
  };

  // 复制安全码到剪贴板（独立保存，避免印入存票图片）
  const handleCopyCode = async () => {
    if (!share?.security_code) return;
    try {
      await navigator.clipboard.writeText(share.security_code);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch (e) {
      console.error('复制安全码失败', e);
    }
  };

  if (!share) return null;

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-sm">
        <DialogHeader>
          <DialogTitle>存票凭证</DialogTitle>
          <DialogDescription>您的想法已存入信箱</DialogDescription>
        </DialogHeader>

        {/* AI 内容审核中提示 */}
        {share.review_status === 'pending' && (
          <p className="rounded-md border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-sm text-amber-600 dark:text-amber-400">
            ⏳ 内容审核中，通过后将出现在雨天广播。
          </p>
        )}

        {/* 存票卡（html-to-image 截图源） */}
        <div
          ref={cardRef}
          className={`space-y-3 rounded-lg border p-5 ${theme.border} ${theme.text}`}
          style={{ backgroundColor: theme.cardBg }}
        >
          <div className="flex items-center justify-between">
            <span className={`font-mono text-xs uppercase tracking-wider ${theme.label}`}>RainMail · 存票</span>
            <span className={`font-mono text-xs ${theme.label}`}>{weatherLabel}</span>
          </div>
          <div className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1.5 text-sm">
            <span className={theme.label}>寄信人</span>
            <span>{senderName}</span>
            <span className={theme.label}>第</span>
            <span>
              <span className="font-mono">#{share.message_id}</span> 号
            </span>
            <span className={theme.label}>唯一 ID</span>
            <span className="font-mono text-xs">{share.unique_identifier}</span>
            <span className={theme.label}>存入时间</span>
            <span className="font-mono text-xs">{new Date(share.created_at).toLocaleString('zh-CN')}</span>
            <span className={theme.label}>总消息数</span>
            <span className="font-mono">{share.total_messages}</span>
          </div>
          <div className="flex justify-center pt-2">
            {qrDataUrl ? (
              <img
                src={qrDataUrl}
                width={128}
                height={128}
                alt="存票二维码"
                className="rounded bg-white p-1"
              />
            ) : (
              <div className="flex size-32 items-center justify-center rounded bg-white p-1">
                <span className="text-xs text-stone-400">生成中…</span>
              </div>
            )}
          </div>
          <a
            href={share.full_share_url}
            target="_blank"
            rel="noreferrer"
            className={`block break-all text-center font-mono text-xs underline ${theme.link}`}
          >
            {share.full_share_url}
          </a>
        </div>

        {/* 删除安全码 —— 刻意置于 cardRef 截图源之外，避免被印入导出的存票图片 */}
        {share.security_code && (
          <div className="space-y-2 rounded-lg border border-amber-500/40 bg-amber-500/10 p-4">
            <p className="text-sm font-medium text-amber-700 dark:text-amber-400">
              🔐 删除安全码（请妥善保管）
            </p>
            <p className="text-xs leading-relaxed text-amber-700/80 dark:text-amber-400/80">
              这是匿名删除本消息的<strong>唯一凭证</strong>，丢失后无法找回（登录账号发布者可直接用账号删除）。
              <strong>请勿将此码截图保存在存票图片中</strong>，建议用下方按钮复制后单独保存。
            </p>
            <div className="flex items-center gap-2">
              <code className="flex-1 select-all rounded bg-white/60 px-3 py-2 font-mono text-sm tracking-[0.2em] dark:bg-black/30">
                {share.security_code}
              </code>
              <Button variant="outline" size="sm" onClick={handleCopyCode} className="shrink-0">
                {copied ? <Check className="size-4" /> : <Copy className="size-4" />}
                <span className="ml-1">{copied ? '已复制' : '复制'}</span>
              </Button>
            </div>
          </div>
        )}

        <div className="flex gap-2">
          <Button onClick={handleSave} disabled={saving} className="flex-1">
            {saving ? '导出中…' : '保存存票'}
          </Button>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            关闭
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}
