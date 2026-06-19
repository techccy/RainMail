// =============================================================================
// 用户路由 —— /user/(inbox|settings)、/api/user/*
// =============================================================================
import { Hono } from 'hono';
import { and, desc, eq, inArray } from 'drizzle-orm';
import { db } from '../db/index.js';
import { users, messages, letterDeliveries, notifications } from '../db/schema.js';
import { getConfig } from '../config.js';
import { render } from '../views/nunjucks.js';
import { getClientIp } from '../lib/security.js';
import { getJsonBody } from '../lib/request.js';
import { getCaptchaProvider } from '../lib/captcha.js';
import { csrfProtect } from '../lib/csrf.js';
import { sessionGet } from '../lib/session.js';

const app = new Hono();

/** 用户登录校验中间件 */
function loginRequired(c: any): Response | null {
  if (!sessionGet(c, 'user_id')) {
    return c.json({ error: '请先登录', redirect: '/auth/login' }, 401);
  }
  return null;
}

// ----------------------------- 页面 -----------------------------
app.get('/user/inbox', (c) => {
  const guard = loginRequired(c);
  if (guard) return guard;
  const cfg = getConfig();
  const provider = getCaptchaProvider();
  return c.html(
    render(
      'user/inbox.html',
      {
        captcha_provider: provider,
        turnstile_site_key: provider === 'cloudflare' ? String(cfg.TURNSTILE_SITE_KEY ?? '') : '',
        recaptcha_site_key: provider === 'recaptcha' || provider === 'recaptcha_v3' ? String(cfg.RECAPTCHA_V3_SITE_KEY ?? '') : '',
      },
      c,
    ),
  );
});

app.get('/user/settings', (c) => {
  const guard = loginRequired(c);
  if (guard) return guard;
  return c.html(render('user/settings.html', {}, c));
});

// ----------------------------- 用户信息 -----------------------------
app.get('/api/user/profile', (c) => {
  const guard = loginRequired(c);
  if (guard) return guard;
  const userId = sessionGet(c, 'user_id');
  const user = db.select().from(users).where(eq(users.id, userId)).limit(1).all()[0];
  if (!user) return c.json({ error: '用户不存在' }, 404);
  return c.json({
    user: {
      id: user.id,
      email: user.email,
      username: user.username,
      city: user.city,
      is_verified: !!user.is_verified,
      created_at: user.created_at,
    },
  });
});

app.put('/api/user/profile', csrfProtect, async (c) => {
  const guard = loginRequired(c);
  if (guard) return guard;
  try {
    const data = await getJsonBody(c);
    const userId = sessionGet(c, 'user_id');
    const user = db.select().from(users).where(eq(users.id, userId)).limit(1).all()[0];
    if (!user) return c.json({ error: '用户不存在' }, 404);

    if ('username' in data) {
      db.update(users).set({ username: String(data.username ?? '').trim() }).where(eq(users.id, user.id)).run();
    }
    const updated = db.select().from(users).where(eq(users.id, user.id)).limit(1).all()[0]!;
    return c.json({
      success: true,
      message: '更新成功',
      user: {
        id: updated.id,
        email: updated.email,
        username: updated.username,
        city: updated.city,
        is_verified: !!updated.is_verified,
        created_at: updated.created_at,
      },
    });
  } catch (e) {
    console.error('[user] 更新用户信息错误:', e);
    return c.json({ error: '更新失败' }, 500);
  }
});

// ----------------------------- 收件箱 -----------------------------
app.get('/api/user/inbox', (c) => {
  const guard = loginRequired(c);
  if (guard) return guard;
  const userId = sessionGet(c, 'user_id');
  const user = db.select().from(users).where(eq(users.id, userId)).limit(1).all()[0];
  if (!user) return c.json({ error: '用户不存在' }, 404);

  const deliveries = db
    .select()
    .from(letterDeliveries)
    .where(eq(letterDeliveries.recipient_user_id, user.id))
    .all()
    .sort((a, b) => (a.created_at! < b.created_at! ? 1 : -1));

  const result = deliveries
    .map((d) => {
      const message = db.select().from(messages).where(eq(messages.id, d.message_id!)).limit(1).all()[0];
      if (!message) return null;
      return {
        id: d.id,
        message_id: message.id,
        sender_location: message.location,
        is_unlocked: d.delivery_status === 'delivered' || d.delivery_status === 'read',
        is_read: d.delivery_status === 'read',
        created_at: d.created_at,
        unlocked_at: d.unlocked_at,
      };
    })
    .filter(Boolean);

  return c.json({ letters: result });
});

// ----------------------------- 已发送 -----------------------------
app.get('/api/user/sent', (c) => {
  const guard = loginRequired(c);
  if (guard) return guard;
  const userId = sessionGet(c, 'user_id');
  const user = db.select().from(users).where(eq(users.id, userId)).limit(1).all()[0];
  if (!user) return c.json({ error: '用户不存在' }, 404);

  const rows = db.select().from(messages).where(eq(messages.sender_id, user.id)).all();
  rows.sort((a, b) => (a.created_at! < b.created_at! ? 1 : -1));
  return c.json({
    messages: rows.map((m) => ({
      id: m.id,
      content: m.content,
      created_at: m.created_at,
      location: m.location,
      unique_identifier: m.unique_identifier,
      delivery_type: m.delivery_type,
      is_anonymous: !!m.is_anonymous,
      hugs_count: m.hugs_count ?? 0,
    })),
  });
});

// ----------------------------- 通知 -----------------------------
app.get('/api/user/notifications', (c) => {
  const guard = loginRequired(c);
  if (guard) return guard;
  const userId = sessionGet(c, 'user_id');
  const rows = db
    .select()
    .from(notifications)
    .where(eq(notifications.user_id, userId))
    .all()
    .sort((a, b) => (a.created_at! < b.created_at! ? 1 : -1))
    .slice(0, 50);

  return c.json({
    notifications: rows.map((n) => ({
      id: n.id,
      type: n.notification_type,
      title: n.title,
      content: n.content,
      is_read: !!n.is_read,
      created_at: n.created_at,
    })),
  });
});

app.put('/api/user/notifications/:id', csrfProtect, (c) => {
  const guard = loginRequired(c);
  if (guard) return guard;
  const userId = sessionGet(c, 'user_id');
  const notifId = Number(c.req.param('id'));
  const n = db.select().from(notifications).where(eq(notifications.id, notifId)).limit(1).all()[0];
  if (!n || n.user_id !== userId) return c.json({ error: '通知不存在' }, 404);

  db.update(notifications).set({ is_read: true }).where(eq(notifications.id, n.id)).run();
  return c.json({ success: true });
});

// 避免未使用告警
void and;
void inArray;
void desc;
void getClientIp;
export { loginRequired };
export default app;
