// =============================================================================
// 页面路由 —— / /privacy-policy(-cn) /m/:unique_id
// =============================================================================
import { Hono } from 'hono';
import { eq } from 'drizzle-orm';
import { db } from '../db/index.js';
import { messages, messageReplies } from '../db/schema.js';
import { getConfig } from '../config.js';
import { render, wrapDates } from '../views/nunjucks.js';
import { getClientIp } from '../lib/security.js';
import { getCityByIp } from '../lib/ipgeo.js';
import { getDashboardData } from '../lib/weather.js';
import { getCaptchaProvider } from '../lib/captcha.js';

const app = new Hono();

// ----------------------------- 首页 -----------------------------
app.get('/', async (c) => {
  const cfg = getConfig();
  const clientIp = getClientIp(c);
  const city = await getCityByIp(clientIp);
  const dashboard = await getDashboardData(city);

  const provider = getCaptchaProvider();
  const turnstileSiteKey = provider === 'cloudflare' ? String(cfg.TURNSTILE_SITE_KEY ?? '') : '';
  const recaptchaSiteKey = provider === 'recaptcha' || provider === 'recaptcha_v3' ? String(cfg.RECAPTCHA_V3_SITE_KEY ?? '') : '';

  return c.html(
    render(
      'index.html',
      {
        ...dashboard,
        turnstile_site_key: turnstileSiteKey,
        recaptcha_site_key: recaptchaSiteKey,
        captcha_provider: provider,
        wechat_enabled: false,
      },
      c,
    ),
  );
});

// ----------------------------- 隐私政策 -----------------------------
app.get('/privacy-policy', (c) => c.html(render('privacy_policy.html', {}, c)));
app.get('/privacy-policy-cn', (c) => c.html(render('privacy_policy_cn.html', {}, c)));

// ----------------------------- 消息详情页 -----------------------------
app.get('/m/:unique_id', (c) => {
  const uniqueId = c.req.param('unique_id');
  const message = db.select().from(messages).where(eq(messages.unique_identifier, uniqueId)).limit(1).all()[0];
  if (!message) return c.html(render('error.html', { message: '消息不存在' }, c), 404);

  const replies = db
    .select()
    .from(messageReplies)
    .where(eq(messageReplies.original_message_id, message.id))
    .all()
    .sort((a, b) => (a.created_at! < b.created_at! ? 1 : -1));

  return c.html(
    render(
      'public/message.html',
      {
        message: wrapDates(message, ['created_at']),
        replies: replies.map((r) => wrapDates(r, ['created_at'])),
      },
      c,
    ),
  );
});

export default app;
