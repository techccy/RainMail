// =============================================================================
// 信件/消息路由 —— /letters/:token、/api/messages(POST)、/api/messages/:id/hug、
//                  /api/letters/:id/(unlock|read|reply)、createPrivateDelivery
// =============================================================================
import { Hono } from 'hono';
import crypto from 'node:crypto';
import { eq } from 'drizzle-orm';
import { db, nowIso } from '../db/index.js';
import { messages, users, letterDeliveries, messageReplies, notifications } from '../db/schema.js';
import type { Message, LetterDelivery } from '../db/schema.js';
import { getConfig } from '../config.js';
import { render, wrapDates } from '../views/nunjucks.js';
import { getClientIp, detectSqlInjection, sanitizeInput, rateLimit } from '../lib/security.js';
import { getJsonBody } from '../lib/request.js';
import { getCityByIp } from '../lib/ipgeo.js';
import { getCaptchaProvider, validateCaptcha } from '../lib/captcha.js';
import { validateUserBehavior } from '../lib/behavior.js';
import { basicKeywordCheck, aiModerationCheck } from '../lib/moderation.js';
import { csrfProtect } from '../lib/csrf.js';
import { sessionGet, sessionSet } from '../lib/session.js';
import { sendNewLetterNotification, sendReplyNotification } from '../lib/mail.js';

const app = new Hono();

function randomId(len: number): string {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  let out = '';
  const bytes = crypto.randomBytes(len);
  for (let i = 0; i < len; i++) out += chars[bytes[i]! % chars.length];
  return out;
}

/** 按 provider 提取消息提交的验证码响应 */
function extractCaptchaForMessage(provider: string, data: Record<string, any>): unknown {
  switch (provider) {
    case 'cloudflare':
      return data.cf_token;
    case 'recaptcha':
    case 'recaptcha_v3':
      return data.recaptcha_token;
    case 'cha':
      return data.cha_answer;
    case 'altcha':
      return data.altcha_payload;
    case 'none':
      return 'skip';
    default:
      return undefined;
  }
}

// ----------------------------- 创建私密投递记录 -----------------------------
export function createPrivateDelivery(c: any, message: Message, senderCity: string): LetterDelivery | null {
  const verified = db
    .select()
    .from(users)
    .where(eq(users.is_verified, true))
    .all();

  if (verified.length > 0) {
    const recipient = verified[Math.floor(Math.random() * verified.length)]!;
    const now = nowIso();
    const token = crypto.randomBytes(32).toString('base64url');
    db.insert(letterDeliveries)
      .values({
        message_id: message.id,
        recipient_user_id: recipient.id,
        recipient_city: recipient.city || '广州',
        unlock_token: token,
        delivery_status: 'pending',
        created_at: now,
      })
      .run();
    const delivery = db.select().from(letterDeliveries).where(eq(letterDeliveries.message_id, message.id)).limit(1).all()[0]!;
    sendNewLetterNotification(c, delivery);
    return delivery;
  }

  // 没有已验证用户时，按收件人邮箱投递
  const options = message.delivery_options ? safeParseJson(message.delivery_options) : {};
  const recipientEmail = options.recipient_email as string | undefined;
  if (recipientEmail) {
    const now = nowIso();
    const token = crypto.randomBytes(32).toString('base64url');
    db.insert(letterDeliveries)
      .values({
        message_id: message.id,
        recipient_email: recipientEmail,
        recipient_city: senderCity,
        unlock_token: token,
        delivery_status: 'pending',
        created_at: now,
      })
      .run();
    const delivery = db.select().from(letterDeliveries).where(eq(letterDeliveries.message_id, message.id)).limit(1).all()[0]!;
    sendNewLetterNotification(c, delivery);
    return delivery;
  }

  return null;
}

function safeParseJson(s: string | null): Record<string, any> {
  if (!s) return {};
  try {
    return JSON.parse(s);
  } catch {
    return {};
  }
}

// ----------------------------- 提交消息 POST /api/messages -----------------------------
app.post('/api/messages', rateLimit('10 per minute', 'msg'), csrfProtect, async (c) => {
  try {
    const data = await getJsonBody(c);

    // 用户行为验证
    const formToken = String(data.form_token ?? '');
    const pageStayTime = Number(data.page_stay_time ?? 0);
    const inputFocusCount = Number(data.input_focus_count ?? 0);
    const inputCharCount = Number(data.input_char_count ?? 0);

    const behavior = validateUserBehavior(formToken, pageStayTime, inputFocusCount, inputCharCount);
    if (!behavior.ok) {
      const ip = getClientIp(c);
      console.warn(`[BEHAVIOR] 用户行为验证失败，IP: ${ip}, 原因: ${behavior.message}`);
      return c.json({ error: `行为验证失败: ${behavior.message}` }, 400);
    }

    // 蜜罐检测
    if (data.website) {
      const ip = getClientIp(c);
      console.warn(`[HONEYPOT] 机器人IP被记录: ${ip}, 蜜罐值: ${data.website}`);
      return c.json({ error: '请先完成人机验证', redirect: '/verify' }, 429);
    }

    let content = String(data.content ?? '').trim();
    if (!content) return c.json({ error: '内容不能为空' }, 400);

    if (detectSqlInjection(content)) {
      const ip = getClientIp(c);
      console.warn(`[SECURITY] 拦截SQL注入尝试，IP: ${ip}`);
      return c.json({ error: '输入包含非法字符' }, 400);
    }

    const provider = getCaptchaProvider();
    const captchaResponse = extractCaptchaForMessage(provider, data);
    const userIp = getClientIp(c);
    if (provider !== 'none' && !captchaResponse) {
      return c.json({ error: '请完成人机验证' }, 400);
    }
    if (!(await validateCaptcha(captchaResponse, userIp, c))) {
      return c.json({ error: '人机验证失败，请刷新网页' }, 400);
    }

    if (basicKeywordCheck(content) || (await aiModerationCheck(content))) {
      console.warn(`[moderation] 内容拦截: ${content}`);
      return c.json({ error: '内容未通过系统安全审查', blocked: true }, 400);
    }

    content = sanitizeInput(content);

    const deliveryType = String(data.delivery_type ?? 'public');
    const deliveryOptions = data.delivery_options ?? {};
    const replyNotification = String(data.reply_notification ?? 'none');
    const isAnonymous = data.is_anonymous !== false; // 默认 true
    const senderEmail = String(data.sender_email ?? '').trim();
    const publicAfterReply = data.public_after_reply === true;

    if (senderEmail) {
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (!emailRegex.test(senderEmail)) return c.json({ error: '邮箱格式不正确' }, 400);
    }

    if (deliveryType === 'private' && getConfig().PRIVATE_DELIVERY_REQUIRE_LOGIN) {
      if (!sessionGet(c, 'user_id')) {
        return c.json({ error: '一对一投递需要先登录', require_login: true }, 403);
      }
    }

    const senderId = !isAnonymous ? sessionGet(c, 'user_id') ?? null : null;
    const senderCity = await getCityByIp(userIp);
    const now = nowIso();
    const uniqueIdentifier = randomId(16);

    db.insert(messages)
      .values({
        content,
        location: senderCity,
        unique_identifier: uniqueIdentifier,
        sender_id: senderId,
        delivery_type: deliveryType,
        delivery_options: typeof deliveryOptions === 'string' ? deliveryOptions : JSON.stringify(deliveryOptions),
        reply_notification: replyNotification,
        is_anonymous: isAnonymous,
        sender_email: senderEmail || null,
        public_after_reply: publicAfterReply,
        created_at: now,
      })
      .run();

    const message = db.select().from(messages).where(eq(messages.unique_identifier, uniqueIdentifier)).limit(1).all()[0]!;

    if (deliveryType === 'private') {
      createPrivateDelivery(c, message, senderCity);
    }

    const messageCount = db.select().from(messages).all().length;
    const host = c.req.header('host') ? `https://${c.req.header('host')}` : '';

    return c.json({
      success: true,
      message: '提交成功',
      share_data: {
        message_id: message.id,
        unique_identifier: message.unique_identifier,
        share_url: `/m/${message.unique_identifier}`,
        full_share_url: `${host}/m/${message.unique_identifier}`,
        total_messages: messageCount,
        created_at: message.created_at,
        weather_status: 'sunny',
        delivery_type: deliveryType,
      },
    });
  } catch (e) {
    console.error('[api] Message submission error:', e);
    return c.json({ error: '提交失败' }, 500);
  }
});

// ----------------------------- 查看信件页面 /letters/:token -----------------------------
// 邮件链接场景：:token 为 unlock_token（16 位随机串）→ SSR 渲染解锁/查看页。
// 收件箱场景：:token 为 delivery id（纯数字）→ 让出，交由 SPA fallback（React /letters/:id）。
// SPA 前端另经 /api/letters/:id（按 delivery id + 登录态校验）取详情。
app.get('/letters/:token', (c, next) => {
  const token = c.req.param('token');
  // 纯数字 = delivery id → 交给 SPA
  if (/^\d+$/.test(token)) return next();

  const delivery = db.select().from(letterDeliveries).where(eq(letterDeliveries.unlock_token, token)).limit(1).all()[0];
  if (!delivery) return c.html(render('error.html', { message: '信件不存在' }, c), 404);

  const message = db.select().from(messages).where(eq(messages.id, delivery.message_id!)).limit(1).all()[0];
  if (!message) return c.html(render('error.html', { message: '信件内容不存在' }, c), 404);

  const isUnlocked = delivery.delivery_status === 'delivered' || delivery.delivery_status === 'read';
  return c.html(
    render(
      'user/letter.html',
      {
        delivery: wrapDates(delivery, ['created_at', 'unlocked_at', 'read_at']),
        message: wrapDates(message, ['created_at']),
        is_unlocked: isUnlocked,
      },
      c,
    ),
  );
});

// ----------------------------- 信件详情 JSON（SPA 用，按 delivery id） -----------------------------
app.get('/api/letters/:id', (c) => {
  const id = Number(c.req.param('id'));
  const delivery = db.select().from(letterDeliveries).where(eq(letterDeliveries.id, id)).limit(1).all()[0];
  if (!delivery) return c.json({ error: '信件不存在' }, 404);

  // 登录态校验（仅 recipient_user_id 场景；邮件 token 场景走 /letters/:token SSR）
  const userId = sessionGet(c, 'user_id');
  if (delivery.recipient_user_id && (!userId || userId !== delivery.recipient_user_id)) {
    return c.json({ error: '无权访问此信件' }, 403);
  }

  const message = db.select().from(messages).where(eq(messages.id, delivery.message_id!)).limit(1).all()[0];
  if (!message) return c.json({ error: '信件内容不存在' }, 404);

  const isUnlocked = delivery.delivery_status === 'delivered' || delivery.delivery_status === 'read';

  // 已解锁才返回内容；未解锁只返回元信息
  return c.json({
    delivery_id: delivery.id,
    message_id: message.id,
    is_unlocked: isUnlocked,
    is_read: delivery.delivery_status === 'read',
    location: message.location,
    created_at: delivery.created_at,
    unlocked_at: delivery.unlocked_at,
    content: isUnlocked ? message.content : null,
    hugs_count: message.hugs_count ?? 0,
  });
});

// ----------------------------- 权限校验辅助 -----------------------------
function verifyLetterAccess(c: any, delivery: LetterDelivery): { ok: true } | { ok: false; error: any; status: 403 } {
  if (delivery.recipient_user_id) {
    const userId = sessionGet(c, 'user_id');
    if (!userId || userId !== delivery.recipient_user_id) {
      return { ok: false, error: { error: '无权访问此信件' }, status: 403 };
    }
  } else if (delivery.recipient_email) {
    const unlocked: number[] = sessionGet(c, 'unlocked_deliveries') ?? [];
    if (!unlocked.includes(delivery.id!)) {
      return { ok: false, error: { error: '此信件需要解锁后才能访问' }, status: 403 };
    }
  } else {
    return { ok: false, error: { error: '无效的信件记录' }, status: 403 };
  }
  return { ok: true };
}

// ----------------------------- 解锁 /api/letters/:id/unlock -----------------------------
app.post('/api/letters/:id/unlock', csrfProtect, async (c) => {
  const id = Number(c.req.param('id'));
  const delivery = db.select().from(letterDeliveries).where(eq(letterDeliveries.id, id)).limit(1).all()[0];
  if (!delivery) return c.json({ error: '信件不存在' }, 404);

  const data = await getJsonBody(c);
  const token = String(data.token ?? '');
  if (delivery.unlock_token !== token) return c.json({ valid: false });

  db.update(letterDeliveries)
    .set({ delivery_status: 'delivered', unlocked_at: nowIso() })
    .where(eq(letterDeliveries.id, delivery.id))
    .run();

  const unlocked: number[] = sessionGet(c, 'unlocked_deliveries') ?? [];
  unlocked.push(delivery.id!);
  sessionSet(c, 'unlocked_deliveries', unlocked);

  return c.json({ valid: true, unlocked: true, status: 'delivered' });
});

// ----------------------------- 标记已读 /api/letters/:id/read -----------------------------
app.post('/api/letters/:id/read', csrfProtect, (c) => {
  const id = Number(c.req.param('id'));
  const delivery = db.select().from(letterDeliveries).where(eq(letterDeliveries.id, id)).limit(1).all()[0];
  if (!delivery) return c.json({ error: '信件不存在' }, 404);

  const access = verifyLetterAccess(c, delivery);
  if (!access.ok) return c.json(access.error, access.status);

  if (delivery.delivery_status !== 'read') {
    db.update(letterDeliveries).set({ delivery_status: 'read', read_at: nowIso() }).where(eq(letterDeliveries.id, delivery.id)).run();
  }
  return c.json({ success: true });
});

// ----------------------------- 回复 /api/letters/:id/reply -----------------------------
app.post('/api/letters/:id/reply', csrfProtect, async (c) => {
  try {
    const id = Number(c.req.param('id'));
    const delivery = db.select().from(letterDeliveries).where(eq(letterDeliveries.id, id)).limit(1).all()[0];
    if (!delivery) return c.json({ error: '信件不存在' }, 404);

    const message = db.select().from(messages).where(eq(messages.id, delivery.message_id!)).limit(1).all()[0];
    if (!message) return c.json({ error: '原信件不存在' }, 404);

    if (delivery.delivery_status !== 'delivered' && delivery.delivery_status !== 'read') {
      return c.json({ error: '信件未解锁' }, 403);
    }

    const access = verifyLetterAccess(c, delivery);
    if (!access.ok) return c.json(access.error, access.status);

    const data = await getJsonBody(c);
    const replyContent = String(data.content ?? '').trim();
    const replyType = String(data.reply_type ?? 'text');
    const replierEmail = String(data.replier_email ?? '').trim();

    if (replyType === 'text' && !replyContent) return c.json({ error: '回复内容不能为空' }, 400);
    if (replyType === 'text' && (basicKeywordCheck(replyContent) || (await aiModerationCheck(replyContent)))) {
      console.warn(`[moderation] 回复内容拦截: ${replyContent}`);
      return c.json({ error: '回复内容未通过系统安全审查', blocked: true }, 400);
    }

    const userId = sessionGet(c, 'user_id');
    db.insert(messageReplies)
      .values({
        original_message_id: message.id,
        reply_content: replyType === 'text' ? replyContent : null,
        reply_type: replyType,
        replier_user_id: userId ?? null,
        replier_email: !userId ? replierEmail || null : null,
        created_at: nowIso(),
      })
      .run();

    if (delivery.delivery_status !== 'read') {
      db.update(letterDeliveries).set({ delivery_status: 'read', read_at: nowIso() }).where(eq(letterDeliveries.id, delivery.id)).run();
    }

    // 通知原发件人
    if (message.sender_id) {
      db.insert(notifications)
        .values({
          user_id: message.sender_id,
          notification_type: 'reply',
          title: '📨 你的信收到了回复',
          content: '有人回复了你之前发送的信件',
          created_at: nowIso(),
        })
        .run();
    }

    // 邮件通知（微信通知已移除）
    if (message.reply_notification === 'email' && message.sender_id) {
      const sender = db.select().from(users).where(eq(users.id, message.sender_id)).limit(1).all()[0];
      if (sender) {
        const reply = db.select().from(messageReplies).where(eq(messageReplies.original_message_id, message.id)).all().slice(-1)[0]!;
        await sendReplyNotification(c, sender, message, reply);
      }
    }

    // 被回复后公开
    if (message.public_after_reply) {
      db.update(messages).set({ delivery_type: 'public' }).where(eq(messages.id, message.id)).run();
      const firstDelivery = db.select().from(letterDeliveries).where(eq(letterDeliveries.message_id, message.id)).limit(1).all()[0];
      if (firstDelivery) {
        db.update(letterDeliveries).set({ delivery_status: 'public' }).where(eq(letterDeliveries.id, firstDelivery.id)).run();
      }
    }

    return c.json({ success: true, message: '回复成功' });
  } catch (e) {
    console.error('[letters] 回复信件错误:', e);
    return c.json({ error: '回复失败' }, 500);
  }
});

// ----------------------------- 拥抱 /api/messages/:id/hug -----------------------------
app.post('/api/messages/:id/hug', csrfProtect, (c) => {
  try {
    const id = Number(c.req.param('id'));
    const message = db.select().from(messages).where(eq(messages.id, id)).limit(1).all()[0];
    if (!message) return c.json({ error: '消息不存在' }, 404);

    const newCount = (message.hugs_count ?? 0) + 1;
    db.update(messages).set({ hugs_count: newCount }).where(eq(messages.id, message.id)).run();
    return c.json({ success: true, hugs_count: newCount });
  } catch (e) {
    console.error('[letters] 拥抱错误:', e);
    return c.json({ error: '操作失败' }, 500);
  }
});

export default app;
