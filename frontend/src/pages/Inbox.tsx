// =============================================================================
// Inbox —— GET /api/user/inbox（登录态）
// letter 卡片：地点 / 状态徽章（待解锁·已解锁·已读）/ 时间 / 解锁时间
// 已解锁 → 跳 /letters/:id；未解锁 → 等待雨天解锁
// 401 → 由 RequireAuth 守卫处理
// =============================================================================
import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { MapPin } from 'lucide-react';
import AppShell from '@/components/layout/AppShell';
import RequireAuth from '@/components/RequireAuth';
import { Card } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Skeleton } from '@/components/ui/skeleton';
import { api } from '@/lib/api';
import type { InboxLetter, InboxResponse } from '@/types/api';

function fmt(iso?: string | null): string {
  if (!iso) return '';
  try {
    return new Date(iso).toLocaleString('zh-CN', { dateStyle: 'short', timeStyle: 'short' });
  } catch {
    return iso;
  }
}

function StatusBadge({ letter }: { letter: InboxLetter }) {
  if (letter.is_unlocked && letter.is_read) {
    return <span className="text-xs text-muted-foreground">📖 已读</span>;
  }
  if (letter.is_unlocked) {
    return <span className="text-xs text-lime-700 dark:text-lime-400">🔓 已解锁</span>;
  }
  return <span className="text-xs text-amber-700 dark:text-amber-400">🔒 待解锁</span>;
}

function InboxContent() {
  const [letters, setLetters] = useState<InboxLetter[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    let cancelled = false;
    (async () => {
      const res = await api<InboxResponse>('/api/user/inbox');
      if (cancelled) return;
      if (res.ok) setLetters(res.data.letters);
      else setError(res.data.error || '加载失败');
      setLoading(false);
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <>
      <header className="space-y-2">
        <h1 className="text-3xl font-semibold tracking-tight">我的收件箱</h1>
        <p className="text-sm text-muted-foreground">收到的远方来信</p>
      </header>

      <div className="mt-8 space-y-3">
        {loading ? (
          [0, 1, 2].map((i) => (
            <Card key={i} className="gap-2 p-4">
              <Skeleton className="h-4 w-32" />
              <Skeleton className="h-3 w-48" />
            </Card>
          ))
        ) : error ? (
          <Card className="p-4 text-sm text-destructive">{error}</Card>
        ) : letters.length === 0 ? (
          <Card className="gap-2 p-8 text-center">
            <p className="text-3xl">📭</p>
            <p className="text-sm font-medium">收件箱是空的</p>
            <p className="text-sm text-muted-foreground">还没有收到远方来信</p>
            <Button asChild variant="outline" size="sm" className="mt-2">
              <Link to="/">返回首页</Link>
            </Button>
          </Card>
        ) : (
          letters.map((letter) => (
            <Card key={letter.id} className="gap-2 p-4">
              <div className="flex items-center justify-between">
                <span className="inline-flex items-center gap-1.5 text-sm font-medium">
                  <MapPin className="size-3.5 text-muted-foreground" />
                  来自 {letter.sender_location || '未知地点'}
                </span>
                <StatusBadge letter={letter} />
              </div>
              <p className="font-mono text-xs text-muted-foreground">{fmt(letter.created_at)}</p>
              {letter.unlocked_at && (
                <p className="font-mono text-xs text-muted-foreground">解锁时间: {fmt(letter.unlocked_at)}</p>
              )}
              <div className="pt-1">
                {letter.is_unlocked ? (
                  <Button asChild size="sm">
                    <Link to={`/letters/${letter.id}`}>查看信件</Link>
                  </Button>
                ) : (
                  <span className="text-xs text-muted-foreground">等待雨天解锁...</span>
                )}
              </div>
            </Card>
          ))
        )}
      </div>
    </>
  );
}

export default function Inbox() {
  return (
    <AppShell>
      <RequireAuth>
        <InboxContent />
      </RequireAuth>
    </AppShell>
  );
}
