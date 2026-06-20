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
  // 兜底 + 诊断：parseBody 返回空时，读原始 body 文本看实际内容。
  // body 流是一次性的，parseBody 读过后 raw.text() 会空；这里两个都打出来定位。
  if (Object.keys(body).length === 0) {
    let rawLen = -1;
    let rawSample = '';
    try {
      const raw = await c.req.raw.text();
      rawLen = raw.length;
      rawSample = raw.slice(0, 80);
      if (raw) {
        const parsed = new URLSearchParams(raw);
        const fallback: Record<string, any> = {};
        parsed.forEach((v, k) => { fallback[k] = v; });
        if (Object.keys(fallback).length > 0) {
          body = fallback;
        }
      }
    } catch (e: any) {
      rawSample = `读取异常: ${e?.message ?? String(e)}`;
    }
    console.warn(
      `[getFormBody] parseBody 返回空 rawLen=${rawLen}`,
      `rawSample=${rawSample ? JSON.stringify(rawSample) : '(空)'}`,
      `parsedKeys=${Object.keys(body).join(',')}`,
    );
  }
  (c as any)._formBody = body;
  (c.req as any).parsedBody = body;
  return body;
}
