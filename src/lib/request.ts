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
  // 兜底：parseBody 偶发返回空对象（如 body 流被读、或适配层对 urlencoded 解析失败）。
  // 此时手动读取原始 body 文本并解析 urlencoded，确保字段不丢失。
  if (Object.keys(body).length === 0) {
    try {
      const raw = await c.req.raw.text();
      if (raw) {
        const parsed = new URLSearchParams(raw);
        const fallback: Record<string, any> = {};
        parsed.forEach((v, k) => { fallback[k] = v; });
        if (Object.keys(fallback).length > 0) {
          console.warn(`[getFormBody] parseBody 返回空，手动解析 urlencoded 得到字段: [${Object.keys(fallback).join(',')}]`);
          body = fallback;
        }
      }
    } catch {
      /* ignore */
    }
  }
  (c as any)._formBody = body;
  (c.req as any).parsedBody = body;
  return body;
}
