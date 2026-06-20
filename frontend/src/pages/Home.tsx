// =============================================================================
// Home —— 首页（晴天/雨天双接口）
// 晴天（light）：仅表单 + 「信箱封存中」提示
// 雨天（dark）：表单 + 消息墙
// 状态药丸 + WeatherMeta 条
// =============================================================================
import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import AppShell from '@/components/layout/AppShell';
import RainMailLogo from '@/components/brand/RainMailLogo';
import MessageForm from '@/components/MessageForm';
import MessageWall from '@/components/MessageWall';
import ShareCardModal from '@/components/ShareCardModal';
import WeatherMeta from '@/components/WeatherMeta';
import { Card, CardContent } from '@/components/ui/card';
import { useWeather } from '@/hooks/useWeather';
import type { ShareData } from '@/types/api';

export default function Home() {
  const { status, city } = useWeather();
  const navigate = useNavigate();
  const [share, setShare] = useState<ShareData | null>(null);
  const [modalOpen, setModalOpen] = useState(false);

  const handleSubmitted = (data: ShareData) => {
    setShare(data);
    setModalOpen(true);
  };

  return (
    <AppShell>
      <header className="space-y-2">
        <RainMailLogo width={220} className="mb-1" />
        <h1 className="text-3xl font-semibold tracking-tight">雨天信箱</h1>
        <p className="text-sm text-muted-foreground">The Raindrop Box</p>
        <div className="flex flex-wrap items-center gap-2 pt-1">
          <span
            className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-xs font-medium ${
              status === 'rainy'
                ? 'border-lime-500/40 bg-lime-500/10 text-lime-700 dark:text-lime-400'
                : 'border-amber-400/40 bg-amber-400/10 text-amber-700 dark:text-amber-400'
            }`}
          >
            <span className="size-1.5 rounded-full bg-current" aria-hidden />
            {status === 'rainy' ? '雨天模式' : '晴天模式'}
            {city ? ` · ${city}` : ''}
          </span>
        </div>
        <WeatherMeta />
      </header>

      <div className="mt-8 space-y-8">
        <MessageForm
          variant={status}
          onSubmitted={handleSubmitted}
          onRequireLogin={() => navigate('/auth/login')}
        />

        {status === 'sunny' ? (
          <Card className="bg-muted/30">
            <CardContent>
              <p className="text-sm text-muted-foreground">当前天气晴朗，信箱封存中。</p>
              <p className="mt-1 text-sm text-muted-foreground">等到下雨时，所有想法将会公开。</p>
            </CardContent>
          </Card>
        ) : (
          <MessageWall />
        )}
      </div>

      <ShareCardModal
        share={share}
        weatherOverride={status}
        open={modalOpen}
        onOpenChange={setModalOpen}
      />
    </AppShell>
  );
}
