// =============================================================================
// 邮件 —— nodemailer + 队列
// 对齐 Python：is_mail_enabled / send_verification_email / send_new_letter_notification /
//             send_letter_unlocked_notification / send_reply_notification / api_test_email
// 队列入 email_queue 表，由 workers/email-queue.ts 异步发送
// =============================================================================
import nodemailer from 'nodemailer';
import { eq } from 'drizzle-orm';
import type { Context } from 'hono';
import { db, nowIso } from '../db/index.js';
import { emailQueue, users, type Message, type MessageReply, type LetterDelivery } from '../db/schema.js';
import { getConfig } from '../config.js';

export function isMailEnabled(): boolean {
  const cfg = getConfig();
  return cfg.MAIL_ENABLED !== false; // 默认 true
}

function smtpTransport(): nodemailer.Transporter | null {
  const cfg = getConfig();
  if (!cfg.MAIL_USERNAME) return null;
  const port = Number(cfg.MAIL_PORT ?? 587);
  return nodemailer.createTransport({
    host: String(cfg.MAIL_SERVER ?? 'smtp.gmail.com'),
    port,
    secure: Boolean(cfg.MAIL_USE_SSL),
    requireTLS: !cfg.MAIL_USE_SSL && cfg.MAIL_USE_TLS !== false,
    auth: { user: String(cfg.MAIL_USERNAME), pass: String(cfg.MAIL_PASSWORD ?? '') },
  });
}

/** 直接发送邮件（同步、立即） */
export async function sendMailNow(to: string, subject: string, html: string): Promise<void> {
  const transport = smtpTransport();
  if (!transport) throw new Error('SMTP 未配置');
  const cfg = getConfig();
  await transport.sendMail({
    from: String(cfg.MAIL_DEFAULT_SENDER ?? cfg.MAIL_USERNAME),
    to,
    subject,
    html,
  });
}

/** 入队（异步发送） */
function enqueue(recipientEmail: string, emailType: string, subject: string, bodyHtml: string): void {
  db.insert(emailQueue)
    .values({
      recipient_email: recipientEmail,
      email_type: emailType,
      subject,
      body_html: bodyHtml,
      status: 'pending',
      attempts: 0,
      created_at: nowIso(),
    })
    .run();
}

/** 构造当前请求的 base url（强制 https，对齐 Python） */
function baseUrl(c: Context): string {
  const host = c.req.header('host') || 'localhost:5024';
  return `https://${host}`;
}

// ----------------------------- 各类通知 -----------------------------

/** 验证邮件（同步发送，注册时调用） */
export async function sendVerificationEmail(c: Context, user: { email: string; verification_token: string | null }): Promise<void> {
  if (!isMailEnabled() || !getConfig().MAIL_USERNAME) {
    console.log('[mail] 邮件功能已禁用或未配置，跳过发送验证邮件');
    return;
  }
  const verifyUrl = `${baseUrl(c)}/verify-email?token=${user.verification_token}`;
  const appName = String(getConfig().APP_NAME ?? 'RainMail');
  const subject = String(getConfig().EMAIL_VERIFY_SUBJECT ?? '验证你的 RainMail 邮箱');
  const html = `
    <h2>欢迎加入 ${appName}</h2>
    <p>请点击下面的链接验证你的邮箱：</p>
    <p><a href="${verifyUrl}">验证邮箱</a></p>
    <p>如果链接无法点击，请复制以下 URL 到浏览器：</p>
    <p>${verifyUrl}</p>
    <p style="color: #e74c3c;"><strong>⚠️ 重要提示：</strong></p>
    <p style="color: #e74c3c;">请在注册后 <strong>1小时内</strong> 完成验证，否则您的账户将被自动删除以防止垃圾注册。</p>
    <hr>
    <p style="font-size: 12px; color: #7f8c8d;">此链接永久有效，验证后即可正常使用。</p>`;
  try {
    await sendMailNow(user.email, subject, html);
    console.log(`[mail] 验证邮件已发送至 ${user.email}`);
  } catch (e) {
    console.error(`[mail] 发送验证邮件失败:`, e);
    throw e;
  }
}

function recipientOf(delivery: LetterDelivery): { email: string | null; name: string } {
  if (delivery.recipient_user_id) {
    const u = db.select().from(users).where(eq(users.id, delivery.recipient_user_id)).limit(1).all()[0];
    if (u) return { email: u.email, name: u.username || u.email.split('@')[0] };
  } else if (delivery.recipient_email) {
    return { email: delivery.recipient_email, name: '朋友' };
  }
  return { email: null, name: '朋友' };
}

/** 新信件通知（入队） */
export function sendNewLetterNotification(c: Context, delivery: LetterDelivery): void {
  if (!isMailEnabled()) return;
  const { email, name } = recipientOf(delivery);
  if (!email) return;
  const viewUrl = `${baseUrl(c)}/letters/${delivery.unlock_token}`;
  const appNameCn = String(getConfig().APP_NAME_CN ?? '雨天信箱');
  const subject = String(getConfig().EMAIL_NEW_LETTER_SUBJECT ?? '📮 远方有一封信正在等你');
  const html = `
    <h2>🌧️ ${appNameCn}</h2>
    <p>亲爱的 ${name}，</p>
    <p>有一封来自远方的信正在等你。</p>
    <p>但这封信需要等待雨天才能解锁...</p>
    <p>当雨落下时，你将可以阅读这封信。</p>
    <p><a href="${viewUrl}">查看信件状态</a></p>
    <p>如果雨天已到，信件将自动解锁。</p>`;
  enqueue(email, 'new_letter', subject, html);
}

/** 信件解锁通知（入队） */
export function sendLetterUnlockedNotification(c: Context, delivery: LetterDelivery): void {
  if (!isMailEnabled()) return;
  const { email, name } = recipientOf(delivery);
  if (!email) return;
  const viewUrl = `${baseUrl(c)}/letters/${delivery.unlock_token}`;
  const appNameCn = String(getConfig().APP_NAME_CN ?? '雨天信箱');
  const subject = String(getConfig().EMAIL_UNLOCKED_SUBJECT ?? '🌧️ 雨来了，信已解锁');
  const html = `
    <h2>🌧️ ${appNameCn}</h2>
    <p>亲爱的 ${name}，</p>
    <p>雨天已至，你的信件已解锁！</p>
    <p><a href="${viewUrl}">点击阅读信件</a></p>`;
  enqueue(email, 'letter_unlocked', subject, html);
}

/** 回复通知（同步发送） */
export async function sendReplyNotification(
  c: Context,
  user: { email: string; username: string | null },
  originalMessage: Message,
  reply: MessageReply,
): Promise<void> {
  if (!isMailEnabled() || !getConfig().MAIL_USERNAME) return;
  const appNameCn = String(getConfig().APP_NAME_CN ?? '雨天信箱');
  const replyText = reply.reply_type === 'text' ? reply.reply_content : '🤗 发送了一个拥抱';
  const html = `
    <h2>📨 ${appNameCn}</h2>
    <p>亲爱的 ${user.username || user.email.split('@')[0]}，</p>
    <p>你之前发送的信件收到了回复！</p>
    <p><strong>原信件内容：</strong></p>
    <p>${originalMessage.content.substring(0, 100)}...</p>
    <p><strong>回复内容：</strong></p>
    <p>${replyText}</p>
    <p>登录${appNameCn}查看更多详情。</p>`;
  try {
    await sendMailNow(user.email, '📨 你的信收到了回复', html);
  } catch (e) {
    console.error('[mail] 发送回复通知邮件失败:', e);
  }
}

/** 测试邮件 */
export async function sendTestEmail(to: string): Promise<void> {
  const subject = String(getConfig().EMAIL_TEST_SUBJECT ?? '雨天信箱 - 邮件配置测试');
  const body = String(getConfig().EMAIL_TEST_BODY ?? '这是一封测试邮件，如果您收到此邮件，说明邮件配置正确。\n\n雨天信箱系统');
  await sendMailNow(to, subject, body.replace(/\n/g, '<br>'));
}
