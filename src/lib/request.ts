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

  // 先克隆请求，用 clone 探测 body 真实内容（不消费原始流）。
  // 这样无论 parseBody 是否成功，都能拿到原始 body 文本用于诊断 / 兜底。
  let rawText = '';
  try {
    const cloned = c.req.raw.clone();
    rawText = await cloned.text();
  } catch {
    /* clone 失败说明流已被消费 */
  }

  let body: Record<string, any> = {};
  try {
    body = Object.fromEntries((await c.req.parseBody()) as any);
  } catch {
    body = {};
  }

  // 兜底：parseBody 返回空，但原始 body 有内容 → 手动解析 urlencoded。
  // 原因：Hono 的 @hono/node-server 适配层对 application/x-www-form-urlencoded 的
  // parseBody 偶发返回空（见 honojs/hono#2695）。用 clone 探测原始 body 后手动解析。
  if (Object.keys(body).length === 0 && rawText) {
    try {
      const parsed = new URLSearchParams(rawText);
      const fallback: Record<string, any> = {};
      parsed.forEach((v, k) => { fallback[k] = v; });
      if (Object.keys(fallback).length > 0) {
        body = fallback;
      }
    } catch {
      /* ignore */
    }
  }
  (c as any)._formBody = body;
  (c.req as any).parsedBody = body;
  return body;
}
