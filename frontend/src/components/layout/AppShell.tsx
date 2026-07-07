// =============================================================================
// AppShell —— 全站共享外壳：天气背景 + 顶栏（品牌 + 用户栏/登录入口）+ 页脚
// Refined Utility 美学：800px 内容宽、1px 边框、200ms 淡入
// =============================================================================
import { type ReactNode } from 'react';
import { Link } from 'react-router-dom';
import { Github } from 'lucide-react';
import WeatherBackground from '@/components/WeatherBackground';
import UserBar from '@/components/UserBar';
import { useWeather } from '@/hooks/useWeather';

interface Props {
  children: ReactNode;
  /** 是否展示页脚，默认 true */
  footer?: boolean;
  /** 内容区缩放倍数（同时放大容器宽度与字体），默认 1 */
  zoom?: number;
}

export default function AppShell({ children, footer = true, zoom = 1 }: Props) {
  const { status } = useWeather();

  return (
    <div className="relative min-h-screen">
      <WeatherBackground mode={status} />

      {/* 顶栏：sticky + 半透明模糊卡片 */}
      <header className="sticky top-0 z-30 border-b border-border/60 bg-background/70 backdrop-blur-md">
        <div className="mx-auto flex max-w-3xl items-center justify-between px-6 py-3">
          <Link to="/" className="flex items-center gap-2">
            <span aria-hidden className="text-lg">📮</span>
            <span className="font-display text-base font-semibold tracking-tight">RainMail</span>
            <span className="hidden font-mono text-xs text-muted-foreground sm:inline">雨天信箱</span>
          </Link>
          <UserBar />
        </div>
      </header>

      <main
        className="mx-auto max-w-3xl px-6 py-10 animate-fade-in"
        style={zoom !== 1 ? { zoom } : undefined}
      >
        {children}
      </main>

      {footer && (
        <footer className="mx-auto max-w-3xl px-6 pb-10 pt-6">
          <div className="flex items-center justify-between border-t border-border pt-6 text-xs text-muted-foreground">
            <div className="flex items-center gap-3">
              <a
                href="https://github.com/techccy/RainMail"
                target="_blank"
                rel="noreferrer"
                className="inline-flex items-center gap-1.5 hover:text-foreground"
              >
                <Github className="size-3.5" />
                GitHub
              </a>
              <span aria-hidden className="text-border">·</span>
              <Link to="/about" className="hover:text-foreground">
                关于
              </Link>
            </div>
            <p className="font-mono">© {new Date().getFullYear()} TechCCY</p>
          </div>
        </footer>
      )}
    </div>
  );
}
