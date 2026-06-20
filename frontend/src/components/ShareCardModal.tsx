// =============================================================================
// ShareCardModal —— 提交成功后的存票凭证弹窗
// 展示：寄信人/第N号/唯一ID/存入时间/服务器状态/总消息数 + QR
// 「保存存票」→ html2canvas 导出 PNG（雨天信箱存票_#N.png）
// QR 用 qrcode 库（替代 vendored qrcode.min.js）
// =============================================================================
import { useEffect, useRef } from 'react';
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
  const qrRef = useRef<HTMLCanvasElement>(null);

  const weatherStatus = weatherOverride ?? share?.weather_status ?? 'sunny';
  const weatherLabel = weatherStatus === 'rainy' ? '雨天模式' : '晴天模式';
  const senderName = user?.username || user?.email?.split('@')[0] || '匿名';

  // 渲染 QR 到 canvas（懒加载 qrcode 库）
  useEffect(() => {
    if (!share || !qrRef.current) return;
    const url = share.full_share_url.startsWith('http')
      ? share.full_share_url
      : `${window.location.origin}${share.full_share_url}`;
    let cancelled = false;
    void import('qrcode').then(({ default: QRCode }) => {
      if (cancelled || !qrRef.current) return;
      QRCode.toCanvas(
        qrRef.current,
        url,
        { width: 128, margin: 1, errorCorrectionLevel: 'H', color: { dark: '#000000', light: '#ffffff' } },
        () => {},
      );
    });
    return () => {
      cancelled = true;
    };
  }, [share, open]);

  const handleSave = async () => {
    if (!cardRef.current || !share) return;
    // 懒加载 html2canvas（体积大，仅导出时需要）
    const { default: html2canvas } = await import('html2canvas');
    const canvas = await html2canvas(cardRef.current, {
      backgroundColor: '#0a0a0a',
      scale: 2,
      useCORS: true,
      logging: false,
    });
    const dataUrl = canvas.toDataURL('image/png');
    const a = document.createElement('a');
    a.href = dataUrl;
    a.download = `雨天信箱存票_#${share.message_id}.png`;
    a.click();
  };

  if (!share) return null;

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-sm">
        <DialogHeader>
          <DialogTitle>存票凭证</DialogTitle>
          <DialogDescription>您的想法已存入信箱</DialogDescription>
        </DialogHeader>

        {/* 存票卡（html2canvas 截图源） */}
        <div
          ref={cardRef}
          className="space-y-3 rounded-lg border border-border bg-zinc-950 p-5 text-zinc-100"
          style={{ backgroundColor: '#0a0a0a' }}
        >
          <div className="flex items-center justify-between">
            <span className="font-mono text-xs uppercase tracking-wider text-zinc-400">RainMail · 存票</span>
            <span className="font-mono text-xs text-zinc-400">{weatherLabel}</span>
          </div>
          <div className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1.5 text-sm">
            <span className="text-zinc-400">寄信人</span>
            <span>{senderName}</span>
            <span className="text-zinc-400">第</span>
            <span>
              <span className="font-mono">#{share.message_id}</span> 号
            </span>
            <span className="text-zinc-400">唯一 ID</span>
            <span className="font-mono text-xs">{share.unique_identifier}</span>
            <span className="text-zinc-400">存入时间</span>
            <span className="font-mono text-xs">{new Date(share.created_at).toLocaleString('zh-CN')}</span>
            <span className="text-zinc-400">总消息数</span>
            <span className="font-mono">{share.total_messages}</span>
          </div>
          <div className="flex justify-center pt-2">
            <canvas ref={qrRef} width={128} height={128} className="rounded bg-white p-1" />
          </div>
          <a
            href={share.full_share_url}
            target="_blank"
            rel="noreferrer"
            className="block break-all text-center font-mono text-xs text-zinc-300 underline"
          >
            {share.full_share_url}
          </a>
        </div>

        <div className="flex gap-2">
          <Button onClick={handleSave} className="flex-1">
            保存存票
          </Button>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            关闭
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}
