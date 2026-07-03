// =============================================================================
// AI 内容审核队列 worker
// -----------------------------------------------------------------------------
// 用户提交消息/回复后立即以 pending 落库（见 routes/letters.ts），由本 worker
// 异步审核：按 env 配置的 RPM（每分钟最大请求数）节流调用 AI 服务，保证上游
// 正常返回、不超限。审核通过后执行被延迟的副作用（私信投递、邮件、通知、被
// 回复后公开翻转）；被拦截或重试耗尽则标记 rejected（隐藏）。
//
// 结构对齐 workers/email-queue.ts：SQLite 行作为任务 + setInterval 轮询。
// 单进程模型，内存中维护 RPM 滑动窗口即可（无需 Redis）。
// =============================================================================
import { eq, asc } from 'drizzle-orm';
import { db } from '../db/index.js';
import { messages, messageReplies } from '../db/schema.js';
import type { Message, MessageReply } from '../db/schema.js';
import { getConfig } from '../config.js';
import { aiModerationReview } from '../lib/moderation.js';
import { pseudoContext } from '../lib/pseudoContext.js';
import { createPrivateDelivery, runReplySideEffects } from '../routes/letters.js';

type AiConfig = {
  API_KEY?: string;
  RPM?: number;
  MAX_RETRIES?: number;
  QUEUE_INTERVAL_MS?: number;
};

function readAiConfig(): AiConfig {
  return (getConfig().AI_MODERATION as AiConfig | undefined) ?? {};
}

// ----------------------------- RPM 节流（滑动窗口） -----------------------------
// 记录最近 60s 内每次 AI 调用的时间戳；超过 RPM 配额则本周期跳过，等下个周期。
const callTimestamps: number[] = [];
const WINDOW_MS = 60_000;

/** 在 60s 滑动窗口内还能发起多少次 AI 调用 */
function remainingQuota(rpm: number): number {
  const now = Date.now();
  // 淘汰窗口外的时间戳
  while (callTimestamps.length > 0 && now - callTimestamps[0]! >= WINDOW_MS) {
    callTimestamps.shift();
  }
  return Math.max(0, rpm - callTimestamps.length);
}

function recordCall(): void {
  callTimestamps.push(Date.now());
}

// ----------------------------- 单条消息审核 -----------------------------
async function reviewMessage(message: Message, maxRetries: number): Promise<void> {
  const verdict = await aiModerationReview(message.content);

  if (verdict === 'pass') {
    db.update(messages).set({ review_status: 'approved' }).where(eq(messages.id, message.id)).run();
    console.log(`[ModerationQueue] 消息 ${message.id} 审核通过`);
    // 审核通过 → 触发被延迟的副作用：私密投递（创建 letter_delivery + 新信件邮件）
    if (message.delivery_type === 'private') {
      createPrivateDelivery(pseudoContext(), message, message.location ?? '广州');
    }
    return;
  }

  if (verdict === 'reject') {
    db.update(messages).set({ review_status: 'rejected' }).where(eq(messages.id, message.id)).run();
    console.warn(`[ModerationQueue] 消息 ${message.id} 审核拦截(REJECT)`);
    return;
  }

  // verdict === 'error'：网络/超时 → 重试，耗尽则隐藏
  const attempts = (message.review_attempts ?? 0) + 1;
  if (attempts >= maxRetries) {
    db.update(messages).set({ review_attempts: attempts, review_status: 'rejected' }).where(eq(messages.id, message.id)).run();
    console.warn(`[ModerationQueue] 消息 ${message.id} 审核 ${attempts} 次仍失败，标记 rejected`);
  } else {
    db.update(messages).set({ review_attempts: attempts }).where(eq(messages.id, message.id)).run();
    console.warn(`[ModerationQueue] 消息 ${message.id} 审核失败(error)，第 ${attempts}/${maxRetries} 次，待重试`);
  }
}

// ----------------------------- 单条回复审核 -----------------------------
async function reviewReply(reply: MessageReply, maxRetries: number): Promise<void> {
  // 仅文本回复进入队列（拥抱等已在提交时直接 approved）
  const verdict = await aiModerationReview(reply.reply_content ?? '');

  if (verdict === 'pass') {
    db.update(messageReplies).set({ review_status: 'approved' }).where(eq(messageReplies.id, reply.id)).run();
    console.log(`[ModerationQueue] 回复 ${reply.id} 审核通过`);
    // 审核通过 → 触发被延迟的副作用（通知/邮件/被回复后公开翻转）
    const message = db.select().from(messages).where(eq(messages.id, reply.original_message_id!)).limit(1).all()[0];
    if (message) {
      await runReplySideEffects(pseudoContext(), message, reply);
    }
    return;
  }

  if (verdict === 'reject') {
    db.update(messageReplies).set({ review_status: 'rejected' }).where(eq(messageReplies.id, reply.id)).run();
    console.warn(`[ModerationQueue] 回复 ${reply.id} 审核拦截(REJECT)`);
    return;
  }

  // verdict === 'error'：重试，耗尽则隐藏
  const attempts = (reply.review_attempts ?? 0) + 1;
  if (attempts >= maxRetries) {
    db.update(messageReplies)
      .set({ review_attempts: attempts, review_status: 'rejected' })
      .where(eq(messageReplies.id, reply.id))
      .run();
    console.warn(`[ModerationQueue] 回复 ${reply.id} 审核 ${attempts} 次仍失败，标记 rejected`);
  } else {
    db.update(messageReplies).set({ review_attempts: attempts }).where(eq(messageReplies.id, reply.id)).run();
    console.warn(`[ModerationQueue] 回复 ${reply.id} 审核失败(error)，第 ${attempts}/${maxRetries} 次，待重试`);
  }
}

// ----------------------------- 单次轮询 -----------------------------
async function runOnce(): Promise<void> {
  try {
    const cfg = readAiConfig();
    // 未配置 AI 不应进入本 worker（提交时已直接 approved），这里再防御一次
    if (!cfg.API_KEY) return;

    const rpm = Math.max(1, Number(cfg.RPM ?? 60));
    const maxRetries = Math.max(1, Number(cfg.MAX_RETRIES ?? 3));
    const quota = remainingQuota(rpm);
    if (quota <= 0) return; // 当前窗口配额已满，等下个周期

    // 取 pending 消息（按时间升序，先进先审），数量不超过剩余配额
    const pendingMessages = db
      .select()
      .from(messages)
      .where(eq(messages.review_status, 'pending'))
      .orderBy(asc(messages.created_at))
      .limit(quota)
      .all();

    // 取 pending 回复，数量不超过"扣减消息后"的剩余配额
    const remainingAfterMessages = Math.max(0, quota - pendingMessages.length);
    const pendingReplies =
      remainingAfterMessages > 0
        ? db
            .select()
            .from(messageReplies)
            .where(eq(messageReplies.review_status, 'pending'))
            .orderBy(asc(messageReplies.created_at))
            .limit(remainingAfterMessages)
            .all()
        : [];

    if (pendingMessages.length === 0 && pendingReplies.length === 0) return;

    for (const message of pendingMessages) {
      try {
        recordCall();
        await reviewMessage(message, maxRetries);
      } catch (e) {
        console.error(`[ModerationQueue] 审核消息 ${message.id} 出错:`, e);
      }
    }

    for (const reply of pendingReplies) {
      try {
        recordCall();
        await reviewReply(reply, maxRetries);
      } catch (e) {
        console.error(`[ModerationQueue] 审核回复 ${reply.id} 出错:`, e);
      }
    }
  } catch (e) {
    console.error('[ModerationQueue] 任务出错:', e);
  }
}

export function startModerationQueueWorker(): NodeJS.Timeout {
  const cfg = readAiConfig();
  const intervalMs = Math.max(500, Number(cfg.QUEUE_INTERVAL_MS ?? 2000));
  if (!cfg.API_KEY) {
    console.log('[ModerationQueue] 未配置 AI_MODERATION_API_KEY，审核队列 worker 不启动（消息即写即发）');
    // 返回一个空定时器占位，保持调用方签名一致
    return setInterval(() => {}, 1 << 30);
  }
  const rpm = Number(cfg.RPM ?? 60);
  console.log(`[ModerationQueue] 启动 AI 审核队列处理（RPM=${rpm}, 间隔=${intervalMs}ms, 最大重试=${cfg.MAX_RETRIES ?? 3}）`);
  return setInterval(() => {
    runOnce().catch((e) => console.error('[ModerationQueue] error:', e));
  }, intervalMs);
}
