// =============================================================================
// 页面路由 —— /privacy-policy(-cn) + 消息详情 JSON API
//
// 原 SSR 页面路由（/、/m/:unique_id）已交由 React SPA（见 frontend/），
// 由 app.ts 的 SPA fallback 提供 index.html。
// 保留：隐私政策（静态法律文本 SSR）+ /api/messages/:unique_id（SPA 取消息详情用）。
// =============================================================================
import { Hono } from 'hono';
import { eq } from 'drizzle-orm';
import { db } from '../db/index.js';
import { messages, messageReplies } from '../db/schema.js';
import { render } from '../views/nunjucks.js';

const app = new Hono();

// ----------------------------- 隐私政策（SSR 静态） -----------------------------
app.get('/privacy-policy', (c) => c.html(render('privacy_policy.html', {}, c)));
app.get('/privacy-policy-cn', (c) => c.html(render('privacy_policy_cn.html', {}, c)));

// ----------------------------- 消息详情 JSON（SPA 用） -----------------------------
app.get('/api/messages/:unique_id', (c) => {
  const uniqueId = c.req.param('unique_id');
  const message = db.select().from(messages).where(eq(messages.unique_identifier, uniqueId)).limit(1).all()[0];
  if (!message) return c.json({ error: '消息不存在' }, 404);

  const reviewStatus = message.review_status ?? 'approved';
  // 审核中：可访问但提示正在审核；被拦截：当作不存在，避免泄露拦截事实
  if (reviewStatus === 'rejected') return c.json({ error: '消息不存在' }, 404);
  if (reviewStatus === 'pending') return c.json({ review_status: 'pending', error: '内容审核中，请稍候' }, 202);

  const replies = db
    .select()
    .from(messageReplies)
    .where(eq(messageReplies.original_message_id, message.id))
    .all()
    // 仅返回已通过审核的回复
    .filter((r) => (r.review_status ?? 'approved') === 'approved')
    .sort((a, b) => (a.created_at! < b.created_at! ? 1 : -1));

  return c.json({
    message: {
      id: message.id,
      content: message.content,
      created_at: message.created_at,
      location: message.location,
      unique_identifier: message.unique_identifier,
      delivery_type: message.delivery_type,
      is_anonymous: !!message.is_anonymous,
      hugs_count: message.hugs_count ?? 0,
    },
    replies: replies.map((r) => ({
      id: r.id,
      reply_content: r.reply_content,
      reply_type: r.reply_type,
      created_at: r.created_at,
    })),
  });
});

export default app;
