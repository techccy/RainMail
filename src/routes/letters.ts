// =============================================================================
// 信件/消息路由 —— /letters/:token、/api/messages(POST)、/api/messages/:id/hug、
//                  /api/letters/:id/(unlock|read|reply)、createPrivateDelivery
// =============================================================================
import { Hono } from 'hono';
import crypto from 'node:crypto';
import { eq } from 'drizzle-orm';
import { db, nowIso } from '../db/index.js';
import { messages, users, letterDeliveries, messageReplies, notifications } from '../db/schema.js';
import type { Message, LetterDelivery, MessageReply } from '../db/schema.js';
import { getConfig } from '../config.js';
import { render, wrapDates } from '../views/nunjucks.js';
import { getClientIp, detectSqlInjection, sanitizeInput, rateLimit } from '../lib/security.js';
import { getJsonBody } from '../lib/request.js';
import { getCityByIp } from '../lib/ipgeo.js';
import { validateUserBehavior } from '../lib/behavior.js';
import { basicKeywordCheck } from '../lib/moderation.js';
import { csrfProtect } from '../lib/csrf.js';
import { sessionGet, sessionSet } from '../lib/session.js';
import { generateDeleteCode, formatDeleteCode, hashDeleteCode, verifyDeleteCode } from '../lib/delete-code.js';
import { sendNewLetterNotification, sendReplyNotification } from '../lib/mail.js';

const app = new Hono();

function randomId(len: number): string {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  let out = '';
  const bytes = crypto.randomBytes(len);
  for (let i = 0; i < len; i++) out += chars[bytes[i]! % chars.length];
  return out;
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

/**
 * 执行回复审核通过后的副作用：站内通知、回复邮件、被回复后公开翻转。
 * 同时供回复路由（直接 approved 路径）与审核队列 worker（异步通过后）复用。
 */
export async function runReplySideEffects(c: any, message: Message, reply: MessageReply): Promise<void> {
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
      return c.json({ error: '请求异常', redirect: '/verify' }, 429);
    }

    let content = String(data.content ?? '').trim();
    if (!content) return c.json({ error: '内容不能为空' }, 400);

    if (detectSqlInjection(content)) {
      const ip = getClientIp(c);
      console.warn(`[SECURITY] 拦截SQL注入尝试，IP: ${ip}`);
      return c.json({ error: '输入包含非法字符' }, 400);
    }

    const userIp = getClientIp(c);

    // 基础敏感词仍作为同步前置拦截（快速、不消耗 AI 配额）；命中即 400。
    // AI 审核已改为异步队列（见 workers/moderation-queue.ts），不再阻塞请求：
    // 消息以 pending 落库，审核通过后才进入公开列表/触发私信投递与邮件。
    if (basicKeywordCheck(content)) {
      console.warn(`[moderation] 内容拦截(敏感词): ${content}`);
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

    // 静默绑定：登录用户无论是否勾选匿名都写入 sender_id（用于登录后免安全码删除）；
    // is_anonymous 仍单独控制对外显示，二者解耦。
    const senderId = sessionGet(c, 'user_id') ?? null;
    const senderCity = await getCityByIp(userIp);
    const now = nowIso();
    const uniqueIdentifier = randomId(16);
    // 删除安全码：仅在 share_data 中明文返回一次；后台只落 HMAC 哈希。
    const securityCode = generateDeleteCode();
    const deleteCodeHash = hashDeleteCode(securityCode);

    // 配置了 AI 审核时以 pending 落库（由 worker 审核通过后再触发投递/通知）；
    // 未配置 AI 时直接 approved，保持"即写即发"的现状语义。
    const aiConfigured = !!(getConfig().AI_MODERATION as { API_KEY?: string } | undefined)?.API_KEY;
    const reviewStatus = aiConfigured ? 'pending' : 'approved';

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
        review_status: reviewStatus,
        delete_code_hash: deleteCodeHash,
      })
      .run();

    const message = db.select().from(messages).where(eq(messages.unique_identifier, uniqueIdentifier)).limit(1).all()[0]!;

    // 私信投递、邮件通知统一延迟到 worker 审核通过后触发（见 moderation-queue.ts）。
    // 未配置 AI 时（approved）在此立即投递，保持原行为。
    if (reviewStatus === 'approved' && deliveryType === 'private') {
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
        review_status: reviewStatus,
        security_code: formatDeleteCode(securityCode),
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
    // 基础敏感词同步拦截（命中即 400，不消耗 AI 配额）；
    // AI 审核改为异步队列：文本回复以 pending 落库，通过后再触发通知/邮件/公开翻转。
    if (replyType === 'text' && basicKeywordCheck(replyContent)) {
      console.warn(`[moderation] 回复内容拦截(敏感词): ${replyContent}`);
      return c.json({ error: '回复内容未通过系统安全审查', blocked: true }, 400);
    }

    const aiConfigured = !!(getConfig().AI_MODERATION as { API_KEY?: string } | undefined)?.API_KEY;
    // 仅文本回复需要 AI 审核；拥抱等非文本回复无需审核，直接 approved。
    const replyReviewStatus = replyType === 'text' && aiConfigured ? 'pending' : 'approved';

    const userId = sessionGet(c, 'user_id');
    db.insert(messageReplies)
      .values({
        original_message_id: message.id,
        reply_content: replyType === 'text' ? replyContent : null,
        reply_type: replyType,
        replier_user_id: userId ?? null,
        replier_email: !userId ? replierEmail || null : null,
        created_at: nowIso(),
        review_status: replyReviewStatus,
      })
      .run();

    if (delivery.delivery_status !== 'read') {
      db.update(letterDeliveries).set({ delivery_status: 'read', read_at: nowIso() }).where(eq(letterDeliveries.id, delivery.id)).run();
    }

    const reply = db
      .select()
      .from(messageReplies)
      .where(eq(messageReplies.original_message_id, message.id))
      .all()
      .slice(-1)[0]!;

    // 审核通过（含未配置 AI）才执行通知/邮件/公开翻转；pending 则交给 worker 审核通过后处理。
    if (replyReviewStatus === 'approved') {
      runReplySideEffects(c, message, reply);
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

// ----------------------------- 删除消息 /api/messages/:unique_id/delete -----------------------------
// 鉴权：一律凭安全码（verifyDeleteCode 常量时间比较，后台仅存哈希）。
// 配合速率限制抗爆破；失败返回统一错误，不泄露消息存在与否以外的信息。
app.post('/api/messages/:unique_id/delete', rateLimit('10 per minute', 'del'), csrfProtect, async (c) => {
  try {
    const uniqueId = c.req.param('unique_id');
    const message = db.select().from(messages).where(eq(messages.unique_identifier, uniqueId)).limit(1).all()[0];
    if (!message) return c.json({ error: '消息不存在' }, 404);

    const data = await getJsonBody(c);
    const codeOk = verifyDeleteCode(String(data.security_code ?? ''), message.delete_code_hash);

    if (!codeOk) {
      return c.json({ error: '安全码不正确' }, 403);
    }

    // 关联清理（与 admin 删除逻辑一致；外键约束开启）
    db.delete(messageReplies).where(eq(messageReplies.original_message_id, message.id)).run();
    db.delete(letterDeliveries).where(eq(letterDeliveries.message_id, message.id)).run();
    db.delete(messages).where(eq(messages.id, message.id)).run();

    return c.json({ success: true, message: '消息已删除' });
  } catch (e) {
    console.error('[letters] 删除消息错误:', e);
    return c.json({ error: '删除失败' }, 500);
  }
});

export default app;
