// =============================================================================
// 图片白名单路由 —— GET /data/:name
// 仅暴露 static/ 下的少数固定图片，杜绝任意文件读取与路径穿越。
// 安全设计：
//   1. 白名单映射（name → 文件名），未命中一律 404
//   2. 即使白名单项被改错，再做 path.resolve 后的包含性校验（必须在 static/ 内）
//   3. Content-Type 仅按白名单扩展名给出（png），配合全局 nosniff 杜绝嗅探
//   4. 任何失败统一 404，不泄露文件存在性
// =============================================================================
import { Hono } from 'hono';
import fs from 'node:fs';
import path from 'node:path';
import { PROJECT_ROOT } from '../config.js';

const app = new Hono();

/** name → 文件名 的白名单。新增图片必须显式在此登记。 */
const ALLOWED_IMAGES: Record<string, string> = {
  donate: 'donate.png',
  techccy: 'techccy.png',
};

/** 扩展名 → Content-Type。仅放行图片类型。 */
const CONTENT_TYPES: Record<string, string> = {
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.gif': 'image/gif',
  '.webp': 'image/webp',
  '.svg': 'image/svg+xml',
};

const STATIC_DIR = path.resolve(PROJECT_ROOT, 'static');

app.get('/data/:name', async (c) => {
  const name = c.req.param('name');

  // 1. 白名单命中
  const filename = ALLOWED_IMAGES[name];
  if (!filename) return c.notFound();

  // 2. 解析后必须在 static/ 目录内（深度防御穿越）
  const resolved = path.resolve(STATIC_DIR, filename);
  const rel = path.relative(STATIC_DIR, resolved);
  if (rel.startsWith('..') || path.isAbsolute(rel)) return c.notFound();

  // 3. 扩展名白名单 → Content-Type（否则 404）
  const ext = path.extname(filename).toLowerCase();
  const contentType = CONTENT_TYPES[ext];
  if (!contentType) return c.notFound();

  // 4. 读取文件，失败统一 404
  let buf: Buffer;
  try {
    buf = await fs.promises.readFile(resolved);
  } catch {
    return c.notFound();
  }

  // 图片静态可缓存（与全局 HTML no-store 逻辑不冲突）
  return new Response(buf, {
    headers: {
      'Content-Type': contentType,
      'Cache-Control': 'public, max-age=86400',
    },
  });
});

export default app;
