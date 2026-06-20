// =============================================================================
// AuthShell —— 认证页共享布局：天气背景 + 居中卡片容器（无 UserBar）
// =============================================================================
import { type ReactNode } from 'react';
import { Link } from 'react-router-dom';
import WeatherBackground from '@/components/WeatherBackground';
import { useWeather } from '@/hooks/useWeather';
import { Card } from '@/components/ui/card';

interface Props {
  title: string;
  subtitle?: string;
  children: ReactNode;
}

export default function AuthShell({ title, subtitle, children }: Props) {
  const { status } = useWeather();
  return (
    <div className="relative flex min-h-screen flex-col items-center justify-center px-6 py-12">
      <WeatherBackground mode={status} />
      <div className="w-full max-w-sm animate-fade-in">
        <Link to="/" className="mb-6 flex items-center justify-center gap-2">
          <span aria-hidden className="text-xl">📮</span>
          <span className="font-display text-lg font-semibold tracking-tight">RainMail</span>
        </Link>
        <Card className="gap-5 p-6">
          <div className="space-y-1">
            <h1 className="text-2xl font-semibold tracking-tight">{title}</h1>
            {subtitle && <p className="text-sm text-muted-foreground">{subtitle}</p>}
          </div>
          {children}
        </Card>
      </div>
    </div>
  );
}
