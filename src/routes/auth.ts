// =============================================================================
// 认证路由 —— /auth/(login|register)、/api/auth/*、/verify-email
// =============================================================================
import { Hono } from 'hono';
import crypto from 'node:crypto';
import { eq } from 'drizzle-orm';
import { db, nowIso } from '../db/index.js';
import { users } from '../db/schema.js';
import { getConfig } from '../config.js';
import { render } from '../views/nunjucks.js';
import { getClientIp, rateLimit } from '../lib/security.js';
import { getJsonBody } from '../lib/request.js';
import { getCityByIp } from '../lib/ipgeo.js';
import {
  getCaptchaProvider,
  validateCaptcha,
  generateChaQuestion,
  prepareChaQuestion,
  currentChaQuestion,
} from '../lib/captcha.js';
import { csrfProtect } from '../lib/csrf.js';
import { sessionSet, sessionPop } from '../lib/session.js';
import { hashPassword, verifyPassword } from '../lib/password.js';
import { checkLoginLocked, trackFailedLogin, resetFailedLogin } from '../lib/authLockout.js';
import { sendVerificationEmail } from '../lib/mail.js';

const app = new Hono();

/** 公共：构造登录/注册页模板变量 */
function captchaTemplateVars() {
  const cfg = getConfig();
  const provider = getCaptchaProvider();
  return {
    captcha_provider: provider,
    turnstile_site_key: provider === 'cloudflare' ? String(cfg.TURNSTILE_SITE_KEY ?? '') : '',
    recaptcha_site_key: provider === 'recaptcha' || provider === 'recaptcha_v3' ? String(cfg.RECAPTCHA_V3_SITE_KEY ?? '') : '',
  };
}

/** 公共：为 CHA/Altcha 移动端回退准备问题 */
function maybePrepareCha(c: any): string | undefined {
  const provider = getCaptchaProvider();
  if (provider === 'cha' || provider === 'altcha') {
    const q = prepareChaQuestion(c);
    return q.question;
  }
  return undefined;
}

/** 公共：从请求体按 provider 提取验证码响应 */
function extractCaptchaResponse(provider: string, data: Record<string, any>): unknown {
  switch (provider) {
    case 'cloudflare':
      return data.cf_token;
    case 'recaptcha':
    case 'recaptcha_v3':
      return data.recaptcha_token;
    case 'cha':
      return data.cha_answer;
    case 'altcha':
      return data.cha_answer ?? data.altcha_payload;
    case 'none':
      return 'skip';
    default:
      return undefined;
  }
}

// ----------------------------- 页面 -----------------------------
app.get('/auth/login', (c) => {
  const vars = captchaTemplateVars();
  const cha = maybePrepareCha(c);
  return c.html(render('auth/login.html', { ...vars, cha_question: cha }, c));
});

app.get('/auth/register', (c) => {
  const vars = captchaTemplateVars();
  const cha = maybePrepareCha(c);
  return c.html(render('auth/register.html', { ...vars, cha_question: cha }, c));
});

// ----------------------------- 注册 API -----------------------------
app.post('/api/auth/register', rateLimit('3 per hour'), async (c) => {
  try {
    const data = await getJsonBody(c);
    const email = String(data.email ?? '').trim().toLowerCase();
    const password = String(data.password ?? '');
    const username = String(data.username ?? '').trim();

    if (!email || !password) return c.json({ error: '邮箱和密码不能为空' }, 400);
    if (password.length < 6) return c.json({ error: '密码长度至少6位' }, 400);

    if (db.select().from(users).where(eq(users.email, email)).limit(1).all()[0]) {
      return c.json({ error: '该邮箱已被注册' }, 400);
    }

    const provider = getCaptchaProvider();
    const captchaResponse = extractCaptchaResponse(provider, data);
    const userIp = getClientIp(c);
    if (!(await validateCaptcha(captchaResponse, userIp, c))) {
      return c.json({ error: '人机验证失败' }, 400);
    }

    const userCity = await getCityByIp(userIp);
    const verificationToken = crypto.randomBytes(32).toString('base64url');
    const now = nowIso();

    db.insert(users)
      .values({
        email,
        password_hash: hashPassword(password),
        username: username || email.split('@')[0]!,
        city: userCity,
        is_verified: false,
        verification_token: verificationToken,
        created_at: now,
      })
      .run();

    const user = db.select().from(users).where(eq(users.email, email)).limit(1).all()[0]!;

    try {
      await sendVerificationEmail(c, { email: user.email, verification_token: user.verification_token });
    } catch (e) {
      console.error('[auth] 发送验证邮件失败:', e);
    }

    return c.json({
      success: true,
      message: '注册成功，请查收验证邮件',
      user: {
        id: user.id,
        email: user.email,
        username: user.username,
        city: user.city,
        is_verified: !!user.is_verified,
        created_at: user.created_at,
      },
    });
  } catch (e) {
    console.error('[auth] 注册错误:', e);
    return c.json({ error: '注册失败' }, 500);
  }
});

// ----------------------------- 邮箱验证 -----------------------------
app.post('/api/auth/verify-email', async (c) => {
  try {
    const data = await getJsonBody(c);
    const token = String(data.token ?? '');
    if (!token) return c.json({ error: '验证令牌不能为空' }, 400);

    const user = db.select().from(users).where(eq(users.verification_token, token)).limit(1).all()[0];
    if (!user) return c.json({ error: '无效的验证令牌' }, 400);

    db.update(users).set({ is_verified: true, verification_token: null }).where(eq(users.id, user.id)).run();
    return c.json({ success: true, message: '邮箱验证成功' });
  } catch (e) {
    console.error('[auth] 邮箱验证错误:', e);
    return c.json({ error: '验证失败' }, 500);
  }
});

app.get('/verify-email', (c) => {
  try {
    const token = c.req.query('token');
    if (!token) return c.redirect('/auth/login?error=invalid_token');
    const user = db.select().from(users).where(eq(users.verification_token, token)).limit(1).all()[0];
    if (!user) return c.redirect('/auth/login?error=invalid_token');

    db.update(users).set({ is_verified: true, verification_token: null }).where(eq(users.id, user.id)).run();
    return c.redirect('/auth/login?verified=1');
  } catch (e) {
    console.error('[auth] 邮箱验证错误:', e);
    return c.redirect('/auth/login?error=verification_failed');
  }
});

// ----------------------------- 登录 API -----------------------------
app.post('/api/auth/login', rateLimit('10 per minute'), async (c) => {
  try {
    const data = await getJsonBody(c);
    const email = String(data.email ?? '').trim().toLowerCase();
    const password = String(data.password ?? '');

    const provider = getCaptchaProvider();
    const captchaResponse = extractCaptchaResponse(provider, data);
    const userIp = getClientIp(c);
    if (!(await validateCaptcha(captchaResponse, userIp, c))) {
      return c.json({ error: '人机验证失败' }, 400);
    }

    const [emailLocked, emailLockedUntil] = checkLoginLocked(email, 'email');
    if (emailLocked) {
      return c.json({ error: '账户已被临时锁定', locked_until: emailLockedUntil?.toISOString() ?? null }, 429);
    }
    const [ipLocked, ipLockedUntil] = checkLoginLocked(userIp, 'ip');
    if (ipLocked) {
      return c.json({ error: 'IP 地址已被临时锁定', locked_until: ipLockedUntil?.toISOString() ?? null }, 429);
    }

    const user = db.select().from(users).where(eq(users.email, email)).limit(1).all()[0];
    if (!user || !verifyPassword(password, user.password_hash)) {
      const [shouldLock, remaining] = trackFailedLogin(email, 'email');
      trackFailedLogin(userIp, 'ip');
      const resp: Record<string, any> = { error: '邮箱或密码错误' };
      if (remaining > 0) resp.remaining_attempts = remaining;
      if (shouldLock) {
        resp.locked = true;
        resp.error = '登录失败次数过多，账户已被临时锁定30分钟';
      }
      return c.json(resp, 401);
    }

    db.update(users).set({ last_login: nowIso() }).where(eq(users.id, user.id)).run();
    sessionSet(c, 'user_id', user.id);
    sessionSet(c, 'user_email', user.email);
    resetFailedLogin(email, 'email');
    resetFailedLogin(userIp, 'ip');

    return c.json({
      success: true,
      message: '登录成功',
      user: {
        id: user.id,
        email: user.email,
        username: user.username,
        city: user.city,
        is_verified: !!user.is_verified,
        created_at: user.created_at,
      },
    });
  } catch (e) {
    console.error('[auth] 登录错误:', e);
    return c.json({ error: '登录失败' }, 500);
  }
});

// ----------------------------- 登出 -----------------------------
app.post('/api/auth/logout', csrfProtect, (c) => {
  sessionPop(c, 'user_id');
  sessionPop(c, 'user_email');
  return c.json({ success: true, message: '登出成功' });
});

// ----------------------------- 重发验证邮件 -----------------------------
app.post('/api/auth/resend-verification', csrfProtect, async (c) => {
  try {
    const data = await getJsonBody(c);
    const email = String(data.email ?? '').trim().toLowerCase();
    const user = db.select().from(users).where(eq(users.email, email)).limit(1).all()[0];
    if (!user) return c.json({ error: '用户不存在' }, 404);
    if (user.is_verified) return c.json({ error: '邮箱已验证' }, 400);

    const token = crypto.randomBytes(32).toString('base64url');
    db.update(users).set({ verification_token: token }).where(eq(users.id, user.id)).run();
    await sendVerificationEmail(c, { email: user.email, verification_token: token });
    return c.json({ success: true, message: '验证邮件已发送' });
  } catch (e) {
    console.error('[auth] 重发验证邮件错误:', e);
    return c.json({ error: '发送失败' }, 500);
  }
});

export { maybePrepareCha, currentChaQuestion, generateChaQuestion };
export default app;
