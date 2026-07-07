// =============================================================================
// About —— 关于页：从后端 /api/about 拉取 about.md 原文，前端渲染 Markdown。
// 纯展示页。外层沿用 AppShell（顶栏 / 天气背景 / 页脚 / 800px 居中）。
// =============================================================================
import { useEffect, useState } from 'react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import AppShell from '@/components/layout/AppShell';

export default function About() {
  const [content, setContent] = useState<string>('');
  const [error, setError] = useState(false);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let alive = true;
    fetch('/api/about', { credentials: 'same-origin' })
      .then((r) => r.json())
      .then((d: { content?: string }) => {
        if (!alive) return;
        setContent(d.content ?? '');
        setLoading(false);
      })
      .catch(() => {
        if (!alive) return;
        setError(true);
        setLoading(false);
      });
    return () => {
      alive = false;
    };
  }, []);

  return (
    <AppShell zoom={1.25}>
      {loading ? (
        <p className="text-sm text-muted-foreground">加载中…</p>
      ) : error ? (
        <p className="text-sm text-muted-foreground">内容加载失败，请稍后再试。</p>
      ) : (
        <article className="about-markdown">
          <ReactMarkdown remarkPlugins={[remarkGfm]}>{content}</ReactMarkdown>
        </article>
      )}
    </AppShell>
  );
}
