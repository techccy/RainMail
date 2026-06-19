// =============================================================================
// 管理员路由 —— /{admin_prefix}/* 全部管理功能
// 包含登录、仪表盘、消息/用户管理、配置、强制降雨、邮件测试等
// =============================================================================
import { Hono } from 'hono';
import { and, eq, ne, like, or, sql } from 'drizzle-orm';
import { db, nowIso } from '../db/index.js';
import { messages, users, letterDeliveries, notifications } from '../db/schema.js';
import { getConfig } from '../config.js';
import { render, flash } from '../views/nunjucks.js';
import { getClientIp, rateLimit, checkHoneypot } from '../lib/security.js';
import { getFormBody, getJsonBody } from '../lib/request.js';
import {
  getCaptchaProvider,
  validateCaptcha,
  prepareChaQuestion,
} from '../lib/captcha.js';
import { csrfProtect } from '../lib/csrf.js';
import { sessionGet, sessionSet } from '../lib/session.js';
import { verifyPassword, hashPassword } from '../lib/password.js';
import { checkLoginLocked, trackFailedLogin, resetFailedLogin } from '../lib/authLockout.js';
import { getDashboardData, forceRain } from '../lib/weather.js';
import { sendTestEmail } from '../lib/mail.js';

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

function captchaTemplateVars() {
  const provider = getCaptchaProvider();
  return {
    captcha_provider: provider,
    turnstile_site_key: provider === 'cloudflare' ? String(cfg.TURNSTILE_SITE_KEY ?? '') : '',
    recaptcha_site_key: provider === 'recaptcha' || provider === 'recaptcha_v3' ? String(cfg.RECAPTCHA_V3_SITE_KEY ?? '') : '',
  };
}

function extractAdminCaptcha(provider: string, form: Record<string, any>): unknown {
  switch (provider) {
    case 'cloudflare':
      return form['cf-turnstile-response'];
    case 'recaptcha':
    case 'recaptcha_v3':
      return form.recaptcha_token;
    case 'cha':
      return form.cha_answer;
    case 'altcha':
      return form.cha_answer ?? form.altcha_payload;
    case 'none':
      return 'skip';
    default:
      return undefined;
  }
}

/**
 * 提交失败后生成一道新 CHA 题目（仅 cha 模式）。验证码一次性，
 * 上一次答案已在 validateCha 中销毁，必须换新题，否则重试必失败。
 */
function freshCha(c: any): string | undefined {
  return getCaptchaProvider() === 'cha' ? prepareChaQuestion(c).question : undefined;
}

// ----------------------------- 管理员登录 -----------------------------
app.get(prefix(''), rateLimit('5 per minute'), (c) => {
  const provider = getCaptchaProvider();
  const cha = provider === 'cha' || provider === 'altcha' ? prepareChaQuestion(c).question : undefined;
  return c.html(render('admin_login.html', { ...captchaTemplateVars(), cha_question: cha }, c));
});

app.post(prefix(''), rateLimit('5 per minute'), csrfProtect, async (c) => {
  const provider = getCaptchaProvider();
  const form = await getFormBody(c);

  // 蜜罐
  if (checkHoneypot(c, form)) {
    console.warn(`[admin] 蜜罐被触发，IP: ${getClientIp(c)}`);
    return c.html(render('admin_login.html', { ...captchaTemplateVars(), error: '用户名或密码错误', cha_question: freshCha(c) }, c));
  }

  const captchaResponse = extractAdminCaptcha(provider, form);
  const userIp = getClientIp(c);
  const username = String(form.username ?? '');
  const password = String(form.password ?? '');

  if (provider !== 'none' && !captchaResponse) {
    return c.html(render('admin_login.html', { ...captchaTemplateVars(), error: '请完成人机验证', cha_question: freshCha(c) }, c));
  }
  if (!(await validateCaptcha(captchaResponse, userIp, c))) {
    return c.html(render('admin_login.html', { ...captchaTemplateVars(), error: '人机验证失败，请刷新网页', cha_question: freshCha(c) }, c));
  }

  // 账户/IP 锁定检查
  const [emailLocked, emailLockedUntil] = checkLoginLocked(username, 'email');
  if (emailLocked) {
    const t = emailLockedUntil ? formatHM(emailLockedUntil) : '';
    flash(c, 'error', `账户已被临时锁定，请 ${t}后再试`);
    return c.html(render('admin_login.html', { ...captchaTemplateVars(), error: '账户已锁定', warning: getFlashesForTemplate(c), cha_question: freshCha(c) }, c));
  }
  const [ipLocked, ipLockedUntil] = checkLoginLocked(userIp, 'ip');
  if (ipLocked) {
    const t = ipLockedUntil ? formatHM(ipLockedUntil) : '';
    flash(c, 'error', `IP 地址已被临时锁定，请 ${t}后再试`);
    return c.html(render('admin_login.html', { ...captchaTemplateVars(), error: 'IP 已锁定', warning: getFlashesForTemplate(c), cha_question: freshCha(c) }, c));
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

  return c.html(render('admin_login.html', { ...captchaTemplateVars(), error: '登录失败', warning: getFlashesForTemplate(c), cha_question: freshCha(c) }, c));
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
  const rows = db.select().from(messages).all().sort((a, b) => (a.created_at! < b.created_at! ? 1 : -1));
  const dashboard = await getDashboardData('广州');
  return c.html(render('admin_dashboard.html', { messages: rows.map((m) => ({ ...m, created_at: m.created_at })), ...dashboard }, c));
});

// ----------------------------- 登出 -----------------------------
app.post(prefix('logout'), csrfProtect, (c) => {
  sessionSet(c, 'admin_logged_in', false);
  return c.redirect(prefix(''));
});

// ----------------------------- 强制降雨 -----------------------------
app.post(prefix('force_rain'), csrfProtect, (c) => {
  const guard = adminRequired(c);
  if (guard) return guard;
  const duration = Number(cfg.force_rain_duration ?? 40);
  const until = forceRain(duration);
  return c.json({ success: true, message: `已强制开启降雨模式 ${duration} 分钟`, until: until.until });
});

// ----------------------------- 删除消息 -----------------------------
app.post(prefix('delete_message/:id'), csrfProtect, (c) => {
  const guard = adminRequired(c);
  if (guard) return guard;
  const id = Number(c.req.param('id'));
  const message = db.select().from(messages).where(eq(messages.id, id)).limit(1).all()[0];
  if (!message) return c.json({ error: '消息不存在' }, 404);
  db.delete(messages).where(eq(messages.id, id)).run();
  return c.json({ success: true, message: '消息已删除' });
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

  // 关联清理
  db.delete(messages).where(eq(messages.sender_id, id)).run();
  db.delete(letterDeliveries).where(eq(letterDeliveries.recipient_user_id, id)).run();
  db.delete(notifications).where(eq(notifications.user_id, id)).run();
  db.delete(users).where(eq(users.id, id)).run();
  return c.json({ success: true, message: '用户已删除' });
});

// ----------------------------- 设置页 -----------------------------
app.get(prefix('settings'), (c) => {
  const guard = adminRequired(c);
  if (guard) return guard;
  return c.html(render('admin_settings.html', {}, c));
});

// ----------------------------- 配置安全检查 -----------------------------
app.get(prefix('config/security-check'), (c) => {
  const guard = adminRequired(c);
  if (guard) return guard;
  const issues: any[] = [];
  if (ADMIN_PASSWORD && !/^(scrypt:|pbkdf2:|sha256\$)/.test(ADMIN_PASSWORD)) {
    issues.push({ type: 'plaintext_password', severity: 'critical', message: '管理员密码为明文存储', fix: '请重新登录或手动迁移密码' });
  }
  return c.json({ has_issues: issues.length > 0, issues });
});

// ----------------------------- 配置（脱敏） -----------------------------
function mask(key: string, value: any): any {
  if (value === null || value === '') return value;
  const sensitive = ['HEFENG_KEY', 'TURNSTILE_SECRET_KEY', 'TURNSTILE_SITE_KEY', 'ALTCHA_HMAC_KEY', 'admin_password', 'MAIL_PASSWORD', 'API_KEY', 'IPINFO_TOKEN'];
  for (const s of sensitive) {
    if (key.includes(s)) {
      return typeof value === 'string' && value.length > 4 ? `****${value.slice(-4)}` : '****';
    }
  }
  return value;
}

app.get(prefix('api/config'), (c) => {
  const guard = adminRequired(c);
  if (guard) return guard;
  const ai = (cfg.AI_MODERATION ?? {}) as Record<string, any>;
  const categorized = {
    weather: {
      HEFENG_HOST1: cfg.HEFENG_HOST1 ?? '',
      HEFENG_HOST2: cfg.HEFENG_HOST2 ?? '',
      HEFENG_HOST3: cfg.HEFENG_HOST3 ?? '',
      HEFENG_HOST4: cfg.HEFENG_HOST4 ?? '',
      HEFENG_KEY1: mask('HEFENG_KEY1', cfg.HEFENG_KEY1 ?? ''),
      HEFENG_KEY2: mask('HEFENG_KEY2', cfg.HEFENG_KEY2 ?? ''),
      HEFENG_KEY3: mask('HEFENG_KEY3', cfg.HEFENG_KEY3 ?? ''),
      HEFENG_KEY4: mask('HEFENG_KEY4', cfg.HEFENG_KEY4 ?? ''),
      times: cfg.times ?? 3600,
    },
    captcha: {
      TURNSTILE_SECRET_KEY: mask('TURNSTILE_SECRET_KEY', cfg.TURNSTILE_SECRET_KEY ?? ''),
      TURNSTILE_SITE_KEY: mask('TURNSTILE_SITE_KEY', cfg.TURNSTILE_SITE_KEY ?? ''),
      CAPTCHA_PROVIDER: cfg.CAPTCHA_PROVIDER ?? 'altcha',
      ALTCHA_HMAC_KEY: mask('ALTCHA_HMAC_KEY', cfg.ALTCHA_HMAC_KEY ?? ''),
      ALTCHA_DIFFICULTY: cfg.ALTCHA_DIFFICULTY ?? 3,
      VERIFY_DURATION_MINUTES: cfg.VERIFY_DURATION_MINUTES ?? 15,
    },
    location: { LOCATION_NAME: cfg.LOCATION_NAME ?? '广州', LOCATION_ID: cfg.LOCATION_ID ?? 101280101 },
    admin: {
      admin_username: cfg.admin_username ?? 'admin',
      admin_password: mask('admin_password', cfg.admin_password ?? ''),
      force_rain_duration: cfg.force_rain_duration ?? 10,
    },
    mail: {
      MAIL_ENABLED: cfg.MAIL_ENABLED !== false,
      MAIL_SERVER: cfg.MAIL_SERVER ?? 'smtp.gmail.com',
      MAIL_PORT: cfg.MAIL_PORT ?? 587,
      MAIL_USE_TLS: cfg.MAIL_USE_TLS ?? true,
      MAIL_USERNAME: cfg.MAIL_USERNAME ?? '',
      MAIL_PASSWORD: mask('MAIL_PASSWORD', cfg.MAIL_PASSWORD ?? ''),
      MAIL_DEFAULT_SENDER: cfg.MAIL_DEFAULT_SENDER ?? 'RainMail <noreply@rainmail.dev>',
    },
    delivery: { PRIVATE_DELIVERY_REQUIRE_LOGIN: cfg.PRIVATE_DELIVERY_REQUIRE_LOGIN ?? false },
    ai_moderation: {
      API_KEY: mask('API_KEY', ai.API_KEY ?? ''),
      BASE_URL: ai.BASE_URL ?? '',
      MODEL: ai.MODEL ?? '',
      SYSTEM_PROMPT: ai.SYSTEM_PROMPT ?? '',
    },
  };
  return c.json({ success: true, config: categorized });
});

app.put(prefix('api/config'), csrfProtect, (c) => {
  const guard = adminRequired(c);
  if (guard) return guard;
  return c.json({ success: false, message: '配置现在从环境变量（.env 文件）加载，无法通过 API 修改。请编辑 .env 文件来修改配置。' }, 400);
});

app.get(prefix('api/config/export'), (c) => {
  const guard = adminRequired(c);
  if (guard) return guard;
  const body = JSON.stringify(cfg, null, 2);
  c.header('Content-Type', 'application/json');
  c.header('Content-Disposition', `attachment; filename=rainmail_config_${nowIso().replace(/[: ]/g, '')}.json`);
  return c.body(body);
});

app.post(prefix('api/config/import'), csrfProtect, (c) => {
  const guard = adminRequired(c);
  if (guard) return guard;
  return c.json({ success: false, message: '配置现在从环境变量（.env 文件）加载，无法通过 API 导入。' }, 400);
});

// ----------------------------- 测试邮件 -----------------------------
app.post(prefix('api/config/test-email'), csrfProtect, async (c) => {
  const guard = adminRequired(c);
  if (guard) return guard;
  try {
    const data = await getJsonBody(c);
    const testEmail = String(data.test_email ?? '');
    if (!testEmail) return c.json({ success: false, error: '请提供测试邮箱地址' }, 400);
    await sendTestEmail(testEmail);
    return c.json({ success: true, message: `测试邮件已发送至 ${testEmail}` });
  } catch (e) {
    return c.json({ success: false, error: `邮件发送失败: ${(e as Error).message}` }, 500);
  }
});

// ----------------------------- 修改密码 -----------------------------
app.post(prefix('change_password'), csrfProtect, async (c) => {
  const guard = adminRequired(c);
  if (guard) return guard;
  const form = await getFormBody(c);
  const newPwd = String(form.new_password ?? '');
  const confirm = String(form.confirm_password ?? '');
  if (!newPwd || newPwd !== confirm) return c.json({ success: false, error: '密码不匹配或为空' });
  return c.json({ success: true, message: '密码已更新（请在 .env 中手动更新）' });
});

void and;
void sql;
export default app;
