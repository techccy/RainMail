// =============================================================================
// 未验证用户清理任务 —— 每 10 分钟运行一次
// 对齐 Python unverified_users_cleanup_worker
// =============================================================================
import { and, eq, lt } from 'drizzle-orm';
import { db } from '../db/index.js';
import { users } from '../db/schema.js';

function isoMinutesAgo(minutes: number): string {
  return new Date(Date.now() - minutes * 60_000).toISOString().replace('T', ' ').substring(0, 19);
}

async function runOnce(): Promise<void> {
  try {
    const cleanupMinutes = Number(process.env.UNVERIFIED_USER_CLEANUP_MINUTES ?? 60);
    const threshold = isoMinutesAgo(cleanupMinutes);

    const stale = db
      .select()
      .from(users)
      .where(and(eq(users.is_verified, false), lt(users.created_at, threshold)))
      .all();

    if (stale.length > 0) {
      for (const u of stale) {
        console.log(`[UnverifiedCleanupWorker] 删除未验证用户: ${u.email}`);
        db.delete(users).where(eq(users.id, u.id)).run();
      }
      console.log(`[UnverifiedCleanupWorker] 清理了 ${stale.length} 个未验证用户`);
    }
  } catch (e) {
    console.error('[UnverifiedCleanupWorker] 清理任务出错:', e);
  }
}

export function startCleanupWorker(): NodeJS.Timeout {
  console.log('[UnverifiedCleanupWorker] 启动未验证用户清理');
  return setInterval(() => {
    runOnce().catch((e) => console.error('[UnverifiedCleanupWorker] error:', e));
  }, 600_000);
}
