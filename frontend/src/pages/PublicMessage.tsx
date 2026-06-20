// =============================================================================
// PublicMessage —— /m/:unique_id 公开消息详情
// GET /api/messages/:unique_id → { message, replies }
// 展示：消息正文 + 类型标签 + 拥抱数 + 回复列表（text / 发送了一个拥抱）
// =============================================================================
import { useEffect, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { MapPin } from 'lucide-react';
import AppShell from '@/components/layout/AppShell';
import { Card } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Skeleton } from '@/components/ui/skeleton';
import { api } from '@/lib/api';
import type { MessageReply, PublicMessage } from '@/types/api';

interface DetailResponse {
  message: PublicMessage;
  replies: MessageReply[];
}

function fmt(iso?: string | null): string {
  if (!iso) return '';
  try {
    return new Date(iso).toLocaleString('zh-CN', { dateStyle: 'short', timeStyle: 'short' });
  } catch {
    return iso;
  }
}

export default function PublicMessage() {
  const { unique_id } = useParams<{ unique_id: string }>();
  const [data, setData] = useState<DetailResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    if (!unique_id) return;
    let cancelled = false;
    (async () => {
      const res = await api<DetailResponse>(`/api/messages/${unique_id}`);
      if (cancelled) return;
      if (res.ok) setData(res.data);
      else setError(res.data.error || '加载失败');
      setLoading(false);
    })();
    return () => {
      cancelled = true;
    };
  }, [unique_id]);

  return (
    <AppShell>
      <header className="space-y-2">
        <h1 className="text-3xl font-semibold tracking-tight">消息详情</h1>
        <p className="text-sm text-muted-foreground">
          消息ID: <strong>{unique_id}</strong>
        </p>
      </header>

      <div className="mt-8 space-y-6">
        {loading ? (
          <Card className="gap-3 p-6">
            <Skeleton className="h-4 w-40" />
            <Skeleton className="h-20 w-full" />
          </Card>
        ) : error || !data ? (
          <Card className="p-6 text-sm text-destructive">{error || '消息不存在'}</Card>
        ) : (
          <>
            <Card className="gap-4 p-6">
              <div className="flex flex-wrap items-center justify-between gap-2 font-mono text-xs text-muted-foreground">
                <span className="inline-flex items-center gap-1.5">
                  <MapPin className="size-3.5" />
                  来自：{data.message.location || '未知地点'}
                </span>
                <span>{fmt(data.message.created_at)}</span>
              </div>
              <span className="inline-flex w-fit rounded-full border border-border px-2 py-0.5 text-xs">
                {data.message.delivery_type === 'public' ? '公开投递' : '一对一投递'}
              </span>
              <p className="whitespace-pre-wrap text-sm leading-relaxed">{data.message.content}</p>
              <p className="font-mono text-xs text-muted-foreground">🤗 {data.message.hugs_count} 个拥抱</p>
            </Card>

            <section className="space-y-3">
              <h2 className="text-lg font-semibold">回复列表（{data.replies.length}）</h2>
              {data.replies.length === 0 ? (
                <p className="py-4 text-center text-sm text-muted-foreground">还没有回复</p>
              ) : (
                <div className="space-y-2">
                  {data.replies.map((r) => (
                    <Card key={r.id} className="gap-1.5 p-4">
                      <p className="font-mono text-xs text-muted-foreground">{fmt(r.created_at)}</p>
                      <p className="text-sm">
                        {r.reply_type === 'text' ? r.reply_content : '发送了一个拥抱 🤗'}
                      </p>
                    </Card>
                  ))}
                </div>
              )}
            </section>
          </>
        )}

        <Button asChild variant="ghost" size="sm">
          <Link to="/">返回首页</Link>
        </Button>
      </div>
    </AppShell>
  );
}
