// =============================================================================
// 登录爆破防护 —— 对齐 Python track_failed_login / check_login_locked / reset_failed_login
// 基于 failed_login_attempt 表，阈值 5 次，锁定 30 分钟
// =============================================================================
import { and, eq } from 'drizzle-orm';
import { db, nowIso } from '../db/index.js';
import { failedLoginAttempts } from '../db/schema.js';

const BRUTE_FORCE_THRESHOLD = 5;
const LOCK_DURATION_MINUTES = 30;

function parseIso(v: string | null | undefined): Date | null {
  if (!v) return null;
  const d = new Date(v.includes('T') ? v : v.replace(' ', 'T') + 'Z');
  return isNaN(d.getTime()) ? null : d;
}

function lockUntilDate(): string {
  return new Date(Date.now() + LOCK_DURATION_MINUTES * 60_000).toISOString().replace('T', ' ').substring(0, 19);
}

/**
 * 记录一次登录失败
 * @returns [shouldLock, remainingAttempts]
 */
export function trackFailedLogin(identifier: string, identifierType: 'email' | 'ip' = 'email'): [boolean, number] {
  const existing = db
    .select()
    .from(failedLoginAttempts)
    .where(and(eq(failedLoginAttempts.identifier, identifier), eq(failedLoginAttempts.identifier_type, identifierType)))
    .limit(1)
    .all()[0];

  const now = nowIso();
  if (!existing) {
    db.insert(failedLoginAttempts)
      .values({
        identifier,
        identifier_type: identifierType,
        attempt_count: 1,
        last_attempt_at: now,
        is_locked: false,
        created_at: now,
      })
      .run();
    return [false, BRUTE_FORCE_THRESHOLD - 1];
  }

  const lockedUntil = parseIso(existing.locked_until);
  // 已在锁定期
  if (existing.is_locked && lockedUntil && lockedUntil > new Date()) {
    return [true, 0];
  }

  // 锁定已过期，重置
  if (existing.is_locked && lockedUntil && lockedUntil <= new Date()) {
    db.update(failedLoginAttempts)
      .set({ is_locked: false, attempt_count: 1, last_attempt_at: now })
      .where(eq(failedLoginAttempts.id, existing.id))
      .run();
    return [false, BRUTE_FORCE_THRESHOLD - 1];
  }

  const newCount = (existing.attempt_count ?? 0) + 1;
  const remaining = BRUTE_FORCE_THRESHOLD - newCount;

  if (newCount >= BRUTE_FORCE_THRESHOLD) {
    const until = lockUntilDate();
    db.update(failedLoginAttempts)
      .set({ is_locked: true, locked_until: until, attempt_count: newCount, last_attempt_at: now })
      .where(eq(failedLoginAttempts.id, existing.id))
      .run();
    console.warn(`[auth] 登录失败过多，锁定 ${identifierType}:${identifier} 直到 ${until}`);
    return [true, 0];
  }

  db.update(failedLoginAttempts)
    .set({ attempt_count: newCount, last_attempt_at: now })
    .where(eq(failedLoginAttempts.id, existing.id))
    .run();
  return [false, Math.max(0, remaining)];
}

/** 检查是否被锁定 [isLocked, lockedUntil] */
export function checkLoginLocked(identifier: string, identifierType: 'email' | 'ip' = 'email'): [boolean, Date | null] {
  const row = db
    .select()
    .from(failedLoginAttempts)
    .where(and(eq(failedLoginAttempts.identifier, identifier), eq(failedLoginAttempts.identifier_type, identifierType)))
    .limit(1)
    .all()[0];

  if (!row || !row.is_locked) return [false, null];
  const lockedUntil = parseIso(row.locked_until);
  if (lockedUntil && lockedUntil <= new Date()) {
    db.update(failedLoginAttempts).set({ is_locked: false }).where(eq(failedLoginAttempts.id, row.id)).run();
    return [false, null];
  }
  return [true, lockedUntil];
}

/** 登录成功后重置 */
export function resetFailedLogin(identifier: string, identifierType: 'email' | 'ip' = 'email'): void {
  db.delete(failedLoginAttempts)
    .where(and(eq(failedLoginAttempts.identifier, identifier), eq(failedLoginAttempts.identifier_type, identifierType)))
    .run();
}

export { BRUTE_FORCE_THRESHOLD, LOCK_DURATION_MINUTES };
