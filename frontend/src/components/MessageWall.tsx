// =============================================================================
// MessageWall —— 雨天公开消息墙
// GET /api/messages（雨天可见，sunny 返回 403）
// =============================================================================
import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { MapPin } from 'lucide-react';
import { Card } from '@/components/ui/card';
import { Skeleton } from '@/components/ui/skeleton';
import { api } from '@/lib/api';
import { formatDateTime } from '@/lib/datetime';
import { useWeather } from '@/hooks/useWeather';
import type { MessagesResponse, PublicMessage } from '@/types/api';

export default function MessageWall() {
  const { status, effectiveTimezone } = useWeather();
  const [messages, setMessages] = useState<PublicMessage[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (status !== 'rainy') {
      setLoading(false);
      return;
    }
    let cancelled = false;
    (async () => {
      setLoading(true);
      const res = await api<MessagesResponse>('/api/messages');
      if (cancelled) return;
      if (res.ok) setMessages(res.data.messages);
      setLoading(false);
    })();
    return () => {
      cancelled = true;
    };
  }, [status]);

  if (status !== 'rainy') return null;

  return (
    <section className="space-y-3">
      <h2 className="text-lg font-semibold">公开的想法</h2>

      {loading ? (
        <div className="space-y-3">
          {[0, 1, 2].map((i) => (
            <Card key={i} className="gap-3 p-4">
              <Skeleton className="h-3 w-24" />
              <Skeleton className="h-12 w-full" />
            </Card>
          ))}
        </div>
      ) : messages.length === 0 ? (
        <p className="py-8 text-center text-sm text-muted-foreground">还没有人投递想法，成为第一个吧。</p>
      ) : (
        <div className="space-y-3">
          {messages.map((m) => (
            <Card key={m.id} className="gap-2 p-4">
              <div className="flex items-center gap-1.5 font-mono text-xs text-muted-foreground">
                <MapPin className="size-3" />
                {m.location || '未知地点'} · {formatDateTime(m.created_at, effectiveTimezone)}
              </div>
              <Link to={`/m/${m.unique_identifier}`} className="block whitespace-pre-wrap text-sm leading-relaxed hover:underline">
                {m.content}
              </Link>
              {m.hugs_count > 0 && (
                <p className="font-mono text-xs text-muted-foreground">🤗 {m.hugs_count} 个拥抱</p>
              )}
            </Card>
          ))}
        </div>
      )}
    </section>
  );
}
