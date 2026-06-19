// =============================================================================
// CSRF 保护 —— 对齐原 csrf_protect 装饰器
// GET/HEAD/OPTIONS 放行；其余从 X-CSRF-Token 头 / 表单字段 / JSON 字段读取并校验
// 失败返回 {error:'CSRF token 验证失败'} + 403（前端 csrf.js 靠 "CSRF" 子串判断）
// =============================================================================
import crypto from 'node:crypto';
import type { Context, Next } from 'hono';
import { sessionGet, sessionSet } from './session.js';
import { getJsonBody, getFormBody } from './request.js';

/** 生成 CSRF token（若 session 中不存在则生成） */
export function generateCsrfToken(c: Context): string {
  let token = sessionGet(c, 'csrf_token');
  if (!token) {
    token = crypto.randomBytes(32).toString('hex');
    sessionSet(c, 'csrf_token', token);
  }
  return token;
}

/** 校验 token */
export function validateCsrfToken(c: Context, token: string | null | undefined): boolean {
  if (!token) return false;
  const sessionToken = sessionGet(c, 'csrf_token');
  if (!sessionToken) return false;
  try {
    const a = Buffer.from(String(token));
    const b = Buffer.from(String(sessionToken));
    if (a.length !== b.length) return false;
    return crypto.timingSafeEqual(a, b);
  } catch {
    return false;
  }
}

/**
 * CSRF 保护中间件
 * 仅作用于写方法（POST/PUT/PATCH/DELETE）
 */
export async function csrfProtect(c: Context, next: Next): Promise<Response | void> {
  const method = c.req.method.toUpperCase();
  if (method === 'GET' || method === 'HEAD' || method === 'OPTIONS') {
    await next();
    return;
  }

  // 优先从 header
  let token = c.req.header('X-CSRF-Token');
  if (!token) {
    // 再尝试请求体（JSON / 表单）
    const ct = c.req.header('content-type') || '';
    let body: Record<string, any> = {};
    try {
      if (ct.includes('application/json')) body = await getJsonBody(c);
      else if (ct.includes('application/x-www-form-urlencoded') || ct.includes('multipart/form-data')) body = await getFormBody(c);
    } catch {
      /* ignore */
    }
    token = body?.csrf_token;
  }

  if (!validateCsrfToken(c, token ?? null)) {
    return c.json({ error: 'CSRF token 验证失败' }, 403);
  }
  await next();
}
