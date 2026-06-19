// =============================================================================
// 邮件队列处理任务 —— 每 1 分钟运行一次
// 对齐 Python email_queue_worker：从 email_queue 表取出 pending 邮件并发送
// =============================================================================
import { eq } from 'drizzle-orm';
import { db, nowIso } from '../db/index.js';
import { emailQueue } from '../db/schema.js';
import { sendMailNow } from '../lib/mail.js';
import { getConfig } from '../config.js';

async function runOnce(): Promise<void> {
  try {
    const cfg = getConfig();
    const pending = db.select().from(emailQueue).where(eq(emailQueue.status, 'pending')).limit(50).all();
    if (pending.length === 0) return;

    for (const email of pending) {
      try {
        if (!cfg.MAIL_USERNAME) {
          console.warn('[EmailQueueWorker] 邮件未配置，跳过发送');
          db.update(emailQueue).set({ status: 'failed' }).where(eq(emailQueue.id, email.id)).run();
          continue;
        }
        await sendMailNow(email.recipient_email!, email.subject ?? '', email.body_html ?? '');
        db.update(emailQueue)
          .set({ status: 'sent', sent_at: nowIso() })
          .where(eq(emailQueue.id, email.id))
          .run();
        console.log(`[EmailQueueWorker] 邮件 ${email.id} 已发送至 ${email.recipient_email}`);
      } catch (e) {
        const attempts = (email.attempts ?? 0) + 1;
        const status = attempts >= 3 ? 'failed' : 'pending';
        db.update(emailQueue).set({ attempts, status }).where(eq(emailQueue.id, email.id)).run();
        console.error(`[EmailQueueWorker] 发送邮件 ${email.id} 失败:`, e);
      }
    }
  } catch (e) {
    console.error('[EmailQueueWorker] 任务出错:', e);
  }
}

export function startEmailQueueWorker(): NodeJS.Timeout {
  console.log('[EmailQueueWorker] 启动邮件队列处理');
  return setInterval(() => {
    runOnce().catch((e) => console.error('[EmailQueueWorker] error:', e));
  }, 60_000);
}
