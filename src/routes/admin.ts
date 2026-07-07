// =============================================================================
// 管理员路由 —— /{admin_prefix}/* 全部管理功能
// 包含登录、仪表盘、消息/用户管理（系统设置已移除，配置统一走 .env）
// =============================================================================
import { Hono } from 'hono';
import { and, eq, ne, like, or, sql, inArray } from 'drizzle-orm';
import { db } from '../db/index.js';
import { messages, users, letterDeliveries, notifications, messageReplies } from '../db/schema.js';
import { getConfig } from '../config.js';
import { render, flash, DateTime } from '../views/nunjucks.js';
import { getClientIp, checkHoneypot } from '../lib/security.js';
import { getFormBody, getJsonBody } from '../lib/request.js';
import { csrfProtect } from '../lib/csrf.js';
import { sessionGet, sessionSet } from '../lib/session.js';
import { verifyPassword, hashPassword } from '../lib/password.js';
import { checkLoginLocked, trackFailedLogin, resetFailedLogin } from '../lib/authLockout.js';
import { getDashboardData } from '../lib/weather.js';
import { createPrivateDelivery } from './letters.js';
import { pseudoContext } from '../lib/pseudoContext.js';

const app = new Hono();

const cfg = getConfig();
const ADMIN_PREFIX = String(cfg.admin_path_prefix ?? 'admin').replace(/^\/+|\/+$/g, '') || 'admin';
const ADMIN_USERNAME = String(cfg.admin_username ?? 'admin');
const ADMIN_PASSWORD = String(cfg.admin_password ?? '');

function prefix(p: string): string {
  return `/${ADMIN_PREFIX}/${p.replace(/^\/+/, '')}`;
}

/** 管理员权限中间件 */
function adminRequired(c: any): Response | null {
  if (!sessionGet(c, 'admin_logged_in')) {
    return c.redirect(prefix(''));
  }
  return null;
}

// ----------------------------- 裸前缀尾斜杠归一化 -----------------------------
// /techccyadmin → /techccyadmin/  （prefix('') 注册的登录路由带尾斜杠，
// 裸前缀无匹配会落到路由器尽头返回 404，这里补一条 301 重定向）
app.get(`/${ADMIN_PREFIX}`, (c) => c.redirect(prefix(''), 301));

// ----------------------------- 管理员登录 -----------------------------
// 登录速率限制已移除：由 Cloudflare（WAF / Rate Limiting Rules）在边缘层防护
app.get(prefix(''), (c) => {
  return c.html(render('admin_login.html', {}, c));
});

app.post(prefix(''), csrfProtect, async (c) => {
  const form = await getFormBody(c);

  // 蜜罐
  if (checkHoneypot(c, form)) {
    console.warn(`[admin] 蜜罐被触发，IP: ${getClientIp(c)}`);
    return c.html(render('admin_login.html', { error: '用户名或密码错误' }, c));
  }

  const userIp = getClientIp(c);
  const username = String(form.username ?? '');
  const password = String(form.password ?? '');

  // 账户/IP 锁定检查
  const [emailLocked, emailLockedUntil] = checkLoginLocked(username, 'email');
  if (emailLocked) {
    const t = emailLockedUntil ? formatHM(emailLockedUntil) : '';
    flash(c, 'error', `账户已被临时锁定，请 ${t}后再试`);
    return c.html(render('admin_login.html', { error: '账户已锁定', warning: getFlashesForTemplate(c) }, c));
  }
  const [ipLocked, ipLockedUntil] = checkLoginLocked(userIp, 'ip');
  if (ipLocked) {
    const t = ipLockedUntil ? formatHM(ipLockedUntil) : '';
    flash(c, 'error', `IP 地址已被临时锁定，请 ${t}后再试`);
    return c.html(render('admin_login.html', { error: 'IP 已锁定', warning: getFlashesForTemplate(c) }, c));
  }

  // 验证凭据
  if (username === ADMIN_USERNAME && verifyPassword(password, ADMIN_PASSWORD)) {
    sessionSet(c, 'admin_logged_in', true);
    resetFailedLogin(username, 'email');
    resetFailedLogin(userIp, 'ip');
    return c.redirect(prefix('dashboard'));
  }

  // 失败
  const [shouldLockEmail] = trackFailedLogin(username, 'email');
  const [shouldLockIp] = trackFailedLogin(userIp, 'ip');
  if (shouldLockIp) flash(c, 'error', '登录失败次数过多，IP 地址已被临时锁定30分钟');
  else if (!shouldLockEmail) flash(c, 'error', '用户名或密码错误');

  return c.html(render('admin_login.html', { error: '登录失败', warning: getFlashesForTemplate(c) }, c));
});

function formatHM(d: Date): string {
  const p = (n: number) => String(n).padStart(2, '0');
  return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}

function getFlashesForTemplate(c: any): string | undefined {
  // 合并所有 flash 消息为一段文本（用于 warning 区块）
  const arr = (c.get('__flash__') as [string, string][] | undefined) ?? [];
  if (arr.length === 0) return undefined;
  return arr.map(([, m]) => m).join('\n');
}

// ----------------------------- 仪表盘 -----------------------------
app.get(prefix('dashboard'), async (c) => {
  const guard = adminRequired(c);
  if (guard) return guard;
  // dashboard 模板大量使用内联 onclick（行内事件处理器），
  // 默认 CSP 不含 'unsafe-inline' 会被浏览器拦截（按钮点了没反应），
  // 故在此响应放宽 script-src。该页面受管理员登录保护。
  (c as any).set('cspAllowInline', true);
  const rows = db.select().from(messages).all().sort((a, b) => (a.created_at! < b.created_at! ? 1 : -1));
  const dashboard = await getDashboardData('广州');
  return c.html(render('admin_dashboard.html', { messages: rows.map((m) => ({ ...m, created_at: new DateTime(m.created_at) })), ...dashboard }, c));
});

// ----------------------------- 登出 -----------------------------
app.post(prefix('logout'), csrfProtect, (c) => {
  sessionSet(c, 'admin_logged_in', false);
  return c.redirect(prefix(''));
});

// ----------------------------- 删除消息 -----------------------------
app.post(prefix('delete_message/:id'), csrfProtect, (c) => {
  const guard = adminRequired(c);
  if (guard) return guard;
  const id = Number(c.req.param('id'));
  const message = db.select().from(messages).where(eq(messages.id, id)).limit(1).all()[0];
  if (!message) return c.json({ error: '消息不存在' }, 404);
  // 关联清理（外键约束开启，否则会报错）
  db.delete(messageReplies).where(eq(messageReplies.original_message_id, id)).run();
  db.delete(letterDeliveries).where(eq(letterDeliveries.message_id, id)).run();
  db.delete(messages).where(eq(messages.id, id)).run();
  return c.json({ success: true, message: '消息已删除' });
});

// ----------------------------- 人工复审：放行 -----------------------------
// 把 pending/rejected 置为 approved；幂等。
// 关键：放行一条 pending 的私信时，必须补跑原本被延迟到审核通过才执行的
// createPrivateDelivery，否则会出现"放行了但私信永远不投递"。仅在尚无
// letter_delivery 记录时创建，避免重复投递。
app.post(prefix('api/approve_message/:id'), csrfProtect, async (c) => {
  const guard = adminRequired(c);
  if (guard) return guard;
  const id = Number(c.req.param('id'));
  const message = db.select().from(messages).where(eq(messages.id, id)).limit(1).all()[0];
  if (!message) return c.json({ success: false, error: '消息不存在' }, 404);

  db.update(messages).set({ review_status: 'approved' }).where(eq(messages.id, id)).run();

  if (message.delivery_type === 'private') {
    const existing = db.select().from(letterDeliveries).where(eq(letterDeliveries.message_id, id)).limit(1).all()[0];
    if (!existing) {
      createPrivateDelivery(pseudoContext(), message, message.location ?? '广州');
    }
  }

  console.log(`[admin] 管理员放行消息 #${id}`);
  return c.json({ success: true, message: '消息已放行' });
});

// ----------------------------- 人工复审：拉黑 -----------------------------
// 把 approved/pending 置为 rejected；幂等。
// 注：已发出的投递/邮件无法撤回，拉黑只影响公开可见性（/m/<uid> 返回 404）。
app.post(prefix('api/reject_message/:id'), csrfProtect, (c) => {
  const guard = adminRequired(c);
  if (guard) return guard;
  const id = Number(c.req.param('id'));
  const message = db.select().from(messages).where(eq(messages.id, id)).limit(1).all()[0];
  if (!message) return c.json({ success: false, error: '消息不存在' }, 404);

  db.update(messages).set({ review_status: 'rejected' }).where(eq(messages.id, id)).run();

  console.warn(`[admin] 管理员拉黑消息 #${id}`);
  return c.json({ success: true, message: '消息已拉黑，公开页将显示404（已发出的投递/邮件无法撤回）' });
});

// ----------------------------- 批量删除消息 -----------------------------
app.post(prefix('api/delete_messages'), csrfProtect, async (c) => {
  const guard = adminRequired(c);
  if (guard) return guard;
  const data = await getJsonBody(c);
  const raw = Array.isArray(data.ids) ? data.ids : [];
  // 去重 + 仅保留正整数 + 上限 1000
  const ids = Array.from(new Set(raw.map((v: unknown) => Number(v)).filter((n: number) => Number.isInteger(n) && n > 0))).slice(0, 1000);
  if (ids.length === 0) return c.json({ success: false, error: '未选择有效消息' }, 400);
  db.delete(messageReplies).where(inArray(messageReplies.original_message_id, ids)).run();
  db.delete(letterDeliveries).where(inArray(letterDeliveries.message_id, ids)).run();
  const result = db.delete(messages).where(inArray(messages.id, ids)).run();
  return c.json({ success: true, message: `已删除 ${result.changes} 条消息`, deleted: result.changes });
});

// ----------------------------- 用户列表 -----------------------------
app.get(prefix('api/users'), (c) => {
  const guard = adminRequired(c);
  if (guard) return guard;
  const page = Number(c.req.query('page') ?? 1);
  const perPage = Number(c.req.query('per_page') ?? 20);
  const search = String(c.req.query('search') ?? '').trim();

  let query = db.select().from(users).$dynamic();
  if (search) {
    query = query.where(or(like(users.username, `%${search}%`), like(users.email, `%${search}%`)));
  }
  const all = query.all().sort((a, b) => (a.created_at! < b.created_at! ? 1 : -1));
  const total = all.length;
  const pages = Math.max(1, Math.ceil(total / perPage));
  const items = all.slice((page - 1) * perPage, page * perPage);

  return c.json({
    success: true,
    users: items.map((u) => ({
      id: u.id,
      username: u.username,
      email: u.email,
      city: u.city,
      is_verified: !!u.is_verified,
      created_at: u.created_at,
      last_login: u.last_login,
    })),
    total,
    pages,
    current_page: page,
  });
});

// ----------------------------- 手动验证用户 -----------------------------
app.post(prefix('api/verify_user/:id'), csrfProtect, (c) => {
  const guard = adminRequired(c);
  if (guard) return guard;
  const id = Number(c.req.param('id'));
  const user = db.select().from(users).where(eq(users.id, id)).limit(1).all()[0];
  if (!user) return c.json({ success: false, error: '用户不存在' }, 404);
  db.update(users).set({ is_verified: true, verification_token: null }).where(eq(users.id, user.id)).run();
  return c.json({ success: true, message: `用户 ${user.email} 已验证` });
});

// ----------------------------- 用户详情 -----------------------------
app.get(prefix('api/user/:id'), (c) => {
  const guard = adminRequired(c);
  if (guard) return guard;
  const id = Number(c.req.param('id'));
  const user = db.select().from(users).where(eq(users.id, id)).limit(1).all()[0];
  if (!user) return c.json({ success: false, error: '用户不存在' }, 404);
  return c.json({
    success: true,
    user: {
      id: user.id,
      username: user.username,
      email: user.email,
      city: user.city,
      is_verified: !!user.is_verified,
      created_at: user.created_at,
      last_login: user.last_login,
    },
  });
});

// ----------------------------- 更新用户 -----------------------------
app.put(prefix('api/update_user/:id'), csrfProtect, async (c) => {
  const guard = adminRequired(c);
  if (guard) return guard;
  const id = Number(c.req.param('id'));
  const user = db.select().from(users).where(eq(users.id, id)).limit(1).all()[0];
  if (!user) return c.json({ success: false, error: '用户不存在' }, 404);

  const data = await getJsonBody(c);
  const updates: Record<string, any> = {};
  if ('username' in data) updates.username = String(data.username ?? '').trim() || null;
  if ('city' in data) updates.city = String(data.city ?? '').trim() || '广州';
  if ('email' in data) {
    const email = String(data.email ?? '').trim();
    const existing = db.select().from(users).where(and(eq(users.email, email), ne(users.id, id))).limit(1).all()[0];
    if (existing) return c.json({ success: false, error: '邮箱已被使用' }, 400);
    updates.email = email;
  }
  if (Object.keys(updates).length > 0) db.update(users).set(updates).where(eq(users.id, user.id)).run();
  return c.json({ success: true, message: '用户信息已更新' });
});

// ----------------------------- 重置密码 -----------------------------
app.post(prefix('api/reset_password/:id'), csrfProtect, async (c) => {
  const guard = adminRequired(c);
  if (guard) return guard;
  const id = Number(c.req.param('id'));
  const user = db.select().from(users).where(eq(users.id, id)).limit(1).all()[0];
  if (!user) return c.json({ success: false, error: '用户不存在' }, 404);
  const data = await getJsonBody(c);
  const newPwd = String(data.password ?? '').trim();
  if (!newPwd || newPwd.length < 6) return c.json({ success: false, error: '密码长度至少6位' }, 400);
  db.update(users).set({ password_hash: hashPassword(newPwd) }).where(eq(users.id, user.id)).run();
  return c.json({ success: true, message: `用户 ${user.email} 的密码已重置` });
});

// ----------------------------- 删除用户 -----------------------------
app.post(prefix('api/delete_user/:id'), csrfProtect, (c) => {
  const guard = adminRequired(c);
  if (guard) return guard;
  const id = Number(c.req.param('id'));
  const user = db.select().from(users).where(eq(users.id, id)).limit(1).all()[0];
  if (!user) return c.json({ success: false, error: '用户不存在' }, 404);

  // 关联清理（与批量删除一致，外键约束开启）
  // 1) 该用户作为作者发表过的回复
  db.delete(messageReplies).where(eq(messageReplies.replier_user_id, id)).run();
  // 2) 该用户名下消息被别人回复过的回复（删消息前先清，避免 message_reply.original_message_id 外键报错）
  db.delete(messageReplies)
    .where(inArray(messageReplies.original_message_id, db.select({ id: messages.id }).from(messages).where(eq(messages.sender_id, id))))
    .run();
  db.delete(messages).where(eq(messages.sender_id, id)).run();
  db.delete(letterDeliveries).where(eq(letterDeliveries.recipient_user_id, id)).run();
  db.delete(notifications).where(eq(notifications.user_id, id)).run();
  db.delete(users).where(eq(users.id, id)).run();
  return c.json({ success: true, message: '用户已删除' });
});

// ----------------------------- 批量删除用户 -----------------------------
app.post(prefix('api/delete_users'), csrfProtect, async (c) => {
  const guard = adminRequired(c);
  if (guard) return guard;
  const data = await getJsonBody(c);
  const raw = Array.isArray(data.ids) ? data.ids : [];
  // 去重 + 仅保留正整数 + 上限 1000
  const ids = Array.from(new Set(raw.map((v: unknown) => Number(v)).filter((n: number) => Number.isInteger(n) && n > 0))).slice(0, 1000);
  if (ids.length === 0) return c.json({ success: false, error: '未选择有效用户' }, 400);
  // 关联清理（与单条删除一致，改用 inArray 批量）
  db.delete(messages).where(inArray(messages.sender_id, ids)).run();
  db.delete(messageReplies).where(inArray(messageReplies.replier_user_id, ids)).run();
  db.delete(letterDeliveries).where(inArray(letterDeliveries.recipient_user_id, ids)).run();
  db.delete(notifications).where(inArray(notifications.user_id, ids)).run();
  const result = db.delete(users).where(inArray(users.id, ids)).run();
  return c.json({ success: true, message: `已删除 ${result.changes} 个用户`, deleted: result.changes });
});

void and;
void sql;
export default app;
