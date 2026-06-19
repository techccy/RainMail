// =============================================================================
// 请求体解析辅助 —— 缓存 JSON / 表单解析结果，便于 CSRF 中间件复用
// =============================================================================
import type { Context } from 'hono';

/** 解析 JSON 请求体（缓存） */
export async function getJsonBody(c: Context): Promise<Record<string, any>> {
  const cached = (c as any)._jsonBody;
  if (cached !== undefined) return cached;
  let body: Record<string, any> = {};
  try {
    const ct = c.req.header('content-type') || '';
    if (ct.includes('application/json')) {
      body = (await c.req.json()) ?? {};
    } else if (ct.includes('application/x-www-form-urlencoded') || ct.includes('multipart/form-data')) {
      body = Object.fromEntries((await c.req.parseBody()) as any);
    }
  } catch {
    body = {};
  }
  (c as any)._jsonBody = body;
  (c.req as any).parsedBody = body; // 供 csrfProtect 读取
  return body;
}

/** 解析表单（multipart / urlencoded） */
export async function getFormBody(c: Context): Promise<Record<string, any>> {
  const cached = (c as any)._formBody;
  if (cached !== undefined) return cached;
  let body: Record<string, any> = {};
  try {
    body = Object.fromEntries((await c.req.parseBody()) as any);
  } catch {
    body = {};
  }
  (c as any)._formBody = body;
  (c.req as any).parsedBody = body;
  return body;
}
