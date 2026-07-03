// =============================================================================
// API 路由 —— /api/messages、/api/weather(/meta)、/api/health、/api/form_token、
//            /api/csrf_token、/api/email-providers、/api/cha/question、/api/altcha/challenge
// =============================================================================
import { Hono } from 'hono';
import { eq } from 'drizzle-orm';
import fs from 'node:fs';
import path from 'node:path';
import { db, nowIso } from '../db/index.js';
import { messages } from '../db/schema.js';
import { PROJECT_ROOT, getConfig } from '../config.js';
import { generateCsrfToken } from '../lib/csrf.js';
import { generateFormToken, validateUserBehavior } from '../lib/behavior.js';
import {
  getCaptchaProvider,
  validateCaptcha,
  generateChaQuestion,
  generateAltchaChallenge,
} from '../lib/captcha.js';
import { detectSqlInjection, sanitizeInput, getClientIp, rateLimit } from '../lib/security.js';
import { getJsonBody } from '../lib/request.js';
import { getCityByIp } from '../lib/ipgeo.js';
import { getWeatherStatus, getDashboardData, getWeatherMeta } from '../lib/weather.js';
import { sessionSet } from '../lib/session.js';
import { createPrivateDelivery } from './letters.js';

const app = new Hono();

// ----------------------------- 健康检查 -----------------------------
app.get('/api/health', (c) => c.json({ status: 'healthy', timestamp: new Date().toISOString() }));

// ----------------------------- 前端启动配置 -----------------------------
// 返回 SPA 启动所需配置（替代模板 data-* 注入）
app.get('/api/bootstrap', (c) => {
  const cfg = getConfig();
  const provider = getCaptchaProvider();
  return c.json({
    captcha_provider: provider,
    turnstile_site_key: provider === 'cloudflare' ? String(cfg.TURNSTILE_SITE_KEY ?? '') : '',
    recaptcha_site_key:
      provider === 'recaptcha' || provider === 'recaptcha_v3' ? String(cfg.RECAPTCHA_V3_SITE_KEY ?? '') : '',
    app_name: String(cfg.APP_NAME ?? 'RainMail'),
    app_name_cn: String(cfg.APP_NAME_CN ?? '雨天信箱'),
  });
});

// ----------------------------- CSRF token -----------------------------
app.get('/api/csrf_token', (c) => c.json({ csrf_token: generateCsrfToken(c) }));

// ----------------------------- Form token（行为验证） -----------------------------
app.get('/api/form_token', (c) => c.json(generateFormToken()));

// ----------------------------- 天气 -----------------------------
app.get('/api/weather', async (c) => {
  const clientIp = getClientIp(c);
  const city = await getCityByIp(clientIp);
  return c.json(await getDashboardData(city));
});

app.get('/api/weather/meta', rateLimit('120 per hour', 'weather-meta'), async (c) => {
  const clientIp = getClientIp(c);
  const city = await getCityByIp(clientIp);
  return c.json(await getWeatherMeta(city));
});

// ----------------------------- 消息列表 (GET) -----------------------------
app.get('/api/messages', async (c) => {
  const clientIp = getClientIp(c);
  const city = await getCityByIp(clientIp);
  const weatherStatus = await getWeatherStatus(city);
  if (weatherStatus === 'sunny') {
    return c.json({ error: `${city} 模式下无法查看消息` }, 403);
  }
  const rows = db.select().from(messages).where(eq(messages.delivery_type, 'public')).all();
  // 仅展示已通过 AI 审核的消息（pending/rejected 不出现在公开列表）
  const visible = rows.filter((m) => (m.review_status ?? 'approved') === 'approved');
  visible.sort((a, b) => (a.created_at! < b.created_at! ? 1 : -1));
  return c.json({
    messages: visible.map((m) => ({
      id: m.id,
      content: m.content,
      created_at: m.created_at,
      location: m.location,
      unique_identifier: m.unique_identifier,
      delivery_type: m.delivery_type,
      is_anonymous: !!m.is_anonymous,
      hugs_count: m.hugs_count ?? 0,
    })),
    weather_status: weatherStatus,
    city,
  });
});

// ----------------------------- 邮箱服务商映射 -----------------------------
app.get('/api/email-providers', (c) => {
  const providers: Record<string, string> = {};
  const csvPath = path.join(PROJECT_ROOT, 'resources', 'email.csv');
  try {
    const content = fs.readFileSync(csvPath, 'utf-8').replace(/^\uFEFF/, '');
    const lines = content.split(/\r?\n/);
    for (let i = 1; i < lines.length; i++) {
      const cols = lines[i]!.split(',');
      if (cols.length >= 2 && cols[0] && cols[1]) {
        providers[cols[0].trim().toLowerCase()] = cols[1].trim();
      }
    }
  } catch (e) {
    console.error('[api] 读取邮箱服务商映射文件失败:', e);
  }
  return c.json(providers);
});

// ----------------------------- CHA 问题 -----------------------------
app.get('/api/cha/question', (c) => {
  const provider = getCaptchaProvider();
  if (provider !== 'cha') return c.json({ error: 'CHA 验证未启用' }, 400);
  const q = generateChaQuestion();
  sessionSet(c, 'cha_question', q.question);
  sessionSet(c, 'cha_answer', q.answer);
  sessionSet(c, 'cha_timestamp', Date.now() / 1000);
  return c.json({ question: q.question, timestamp: Date.now() / 1000 });
});

// ----------------------------- Altcha 挑战 -----------------------------
app.get('/api/altcha/challenge', (c) => {
  const provider = getCaptchaProvider();
  if (provider !== 'altcha') return c.json({ error: 'Altcha 验证未启用' }, 400);
  const cfg = getConfig();
  if (!cfg.ALTCHA_HMAC_KEY) return c.json({ error: 'Altcha 未配置' }, 500);
  return c.json(generateAltchaChallenge());
});

export { createPrivateDelivery };
export default app;
