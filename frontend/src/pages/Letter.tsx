// =============================================================================
// Letter —— 信件详情（登录态）
// GET /api/letters/:id（按 delivery id，登录态校验）
// 锁定态：🔒 信件尚未解锁，等待雨天
// 解锁态：内容 + 元信息 + 拥抱(POST /api/messages/:id/hug) + 回复(POST /api/letters/:id/reply)
// 进入自动标记已读（POST /api/letters/:id/read）
// =============================================================================
import { useEffect, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { MapPin } from 'lucide-react';
import AppShell from '@/components/layout/AppShell';
import RequireAuth from '@/components/RequireAuth';
import { Card } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Textarea } from '@/components/ui/textarea';
import { api } from '@/lib/api';
import type { LetterDetail } from '@/types/api';

const MAX_REPLY = 500;

function fmt(iso?: string | null): string {
  if (!iso) return '';
  try {
    return new Date(iso).toLocaleString('zh-CN', { dateStyle: 'short', timeStyle: 'short' });
  } catch {
    return iso;
  }
}

function LetterContent() {
  const { id } = useParams<{ id: string }>();
  const [letter, setLetter] = useState<LetterDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  // 回复表单
  const [replyOpen, setReplyOpen] = useState(false);
  const [replyText, setReplyText] = useState('');
  const [replying, setReplying] = useState(false);
  const [replyError, setReplyError] = useState('');
  const [replySuccess, setReplySuccess] = useState(false);

  // 拥抱
  const [hugged, setHugged] = useState(false);
  const [hugCount, setHugCount] = useState(0);

  useEffect(() => {
    if (!id) return;
    let cancelled = false;
    (async () => {
      const res = await api<LetterDetail>(`/api/letters/${id}`);
      if (cancelled) return;
      if (res.ok) {
        setLetter(res.data);
        setHugCount(res.data.hugs_count);
        // 已解锁 → 标记已读
        if (res.data.is_unlocked && !res.data.is_read) {
          void api(`/api/letters/${id}/read`, { method: 'POST', json: {} });
        }
      } else {
        setError(res.data.error || '加载失败');
      }
      setLoading(false);
    })();
    return () => {
      cancelled = true;
    };
  }, [id]);

  const handleHug = async () => {
    if (!letter || hugged) return;
    const res = await api<{ success: boolean; hugs_count: number }>(
      `/api/messages/${letter.message_id}/hug`,
      { method: 'POST', json: {} },
    );
    if (res.ok) {
      setHugged(true);
      setHugCount(res.data.hugs_count);
    }
  };

  const handleReply = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!letter || !id) return;
    const trimmed = replyText.trim();
    if (!trimmed) {
      setReplyError('回复内容不能为空');
      return;
    }
    setReplying(true);
    setReplyError('');
    const res = await api<{ success: boolean }>(`/api/letters/${id}/reply`, {
      method: 'POST',
      json: { content: trimmed, reply_type: 'text' },
    });
    setReplying(false);
    if (res.ok) {
      setReplySuccess(true);
      setReplyOpen(false);
      setReplyText('');
    } else {
      setReplyError(res.data.error || '回复失败');
    }
  };

  if (loading) {
    return (
      <>
        <h1 className="text-3xl font-semibold tracking-tight">远方来信</h1>
        <p className="mt-4 font-mono text-sm text-muted-foreground">加载中...</p>
      </>
    );
  }

  if (error || !letter) {
    return (
      <>
        <h1 className="text-3xl font-semibold tracking-tight">远方来信</h1>
        <Card className="mt-8 p-6 text-sm text-destructive">{error || '信件不存在'}</Card>
        <Button asChild variant="outline" size="sm" className="mt-4">
          <Link to="/user/inbox">返回收件箱</Link>
        </Button>
      </>
    );
  }

  return (
    <>
      <header className="space-y-2">
        <h1 className="text-3xl font-semibold tracking-tight">远方来信</h1>
        <p className="text-sm text-muted-foreground">
          来自 <strong>{letter.location || '未知地点'}</strong> 的信
        </p>
      </header>

      {!letter.is_unlocked ? (
        <Card className="mt-8 gap-3 p-8 text-center">
          <p className="text-4xl">🔒</p>
          <h2 className="text-lg font-semibold">信件尚未解锁</h2>
          <p className="text-sm text-muted-foreground">这封信需要等待雨天才能解锁</p>
          <p className="text-sm text-muted-foreground">当雨落下时，信件将自动解锁</p>
        </Card>
      ) : (
        <div className="mt-8 space-y-6">
          <Card className="gap-4 p-6">
            <div className="flex items-center justify-between font-mono text-xs text-muted-foreground">
              <span className="inline-flex items-center gap-1.5">
                <MapPin className="size-3.5" />
                来自：{letter.location || '未知地点'}
              </span>
              <span>{fmt(letter.created_at)}</span>
            </div>
            <p className="whitespace-pre-wrap text-sm leading-relaxed">{letter.content}</p>
            {letter.hugs_count > 0 && (
              <p className="font-mono text-xs text-muted-foreground">🤗 {hugCount} 个拥抱</p>
            )}
          </Card>

          {replySuccess && (
            <p className="rounded-md border border-lime-500/40 bg-lime-500/10 px-3 py-2 text-sm text-lime-700 dark:text-lime-400">
              ✉️ 回复已发送！
            </p>
          )}

          <div className="flex flex-wrap gap-2">
            <Button onClick={handleHug} disabled={hugged} variant="outline">
              {hugged ? `🤗 已拥抱 (${hugCount})` : '发送拥抱'}
            </Button>
            <Button onClick={() => setReplyOpen((v) => !v)}>回复</Button>
          </div>

          {replyOpen && (
            <Card className="gap-3 p-5 animate-fade-in">
              <form onSubmit={handleReply} className="space-y-3">
                <h3 className="text-sm font-medium">写下你的回复</h3>
                <div className="space-y-1.5">
                  <Textarea
                    value={replyText}
                    maxLength={MAX_REPLY}
                    onChange={(e) => setReplyText(e.target.value)}
                    placeholder="回复内容..."
                    className="min-h-24"
                  />
                  <p className="text-right font-mono text-xs text-muted-foreground">
                    {replyText.length}/{MAX_REPLY}
                  </p>
                </div>
                {replyError && (
                  <p className="rounded-md border border-destructive/40 bg-destructive/10 px-3 py-2 text-sm text-destructive">
                    {replyError}
                  </p>
                )}
                <div className="flex gap-2">
                  <Button type="submit" disabled={replying}>
                    {replying ? '发送中...' : '发送回复'}
                  </Button>
                  <Button type="button" variant="outline" onClick={() => setReplyOpen(false)}>
                    取消
                  </Button>
                </div>
              </form>
            </Card>
          )}

          <Button asChild variant="ghost" size="sm">
            <Link to="/user/inbox">返回收件箱</Link>
          </Button>
        </div>
      )}
    </>
  );
}

export default function Letter() {
  return (
    <AppShell>
      <RequireAuth>
        <LetterContent />
      </RequireAuth>
    </AppShell>
  );
}
