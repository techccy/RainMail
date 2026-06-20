// =============================================================================
// ProcessingOverlay —— 提交处理中全屏遮罩
// 保留原版「正在处理...」交互节奏（无真实加密，仅 UX 过渡）
// =============================================================================
import { useEffect, useState } from 'react';

export function ProcessingOverlay() {
  const [progress, setProgress] = useState(0);
  const [remaining, setRemaining] = useState(8);

  useEffect(() => {
    const start = Date.now();
    const duration = 8000;
    const timer = setInterval(() => {
      const elapsed = Date.now() - start;
      const pct = Math.min(100, Math.round((elapsed / duration) * 100));
      setProgress(pct);
      setRemaining(Math.max(0, Math.ceil((duration - elapsed) / 1000)));
      if (pct >= 100) clearInterval(timer);
    }, 100);
    return () => clearInterval(timer);
  }, []);

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-background/80 backdrop-blur-sm">
      <div className="w-full max-w-sm space-y-4 rounded-xl border border-border bg-card p-8 text-center shadow-lg animate-fade-in">
        <h3 className="text-lg font-semibold">正在处理您的想法...</h3>
        <p className="text-sm text-muted-foreground">正在加密...</p>
        <div className="h-1.5 w-full overflow-hidden rounded-full bg-muted">
          <div className="h-full bg-primary transition-all duration-100" style={{ width: `${progress}%` }} />
        </div>
        <p className="font-mono text-xs text-muted-foreground">预计剩余时间: {remaining} 秒</p>
      </div>
    </div>
  );
}
