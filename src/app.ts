// =============================================================================
// Hono 应用装配 —— 全局中间件 + 静态资源 + 路由挂载
// =============================================================================
import { Hono } from 'hono';
import { serveStatic } from '@hono/node-server/serve-static';
import type { Context, Next } from 'hono';
import fs from 'node:fs';
import path from 'node:path';
import { getConfig } from './config.js';
import { PROJECT_ROOT } from './config.js';
import { initSession, commitSession } from './lib/session.js';
import { securityHeadersMiddleware, defaultRateLimit } from './lib/security.js';
import { setAdminPrefix } from './views/nunjucks.js';

import pagesRoutes from './routes/pages.js';
import apiRoutes from './routes/api.js';
import authRoutes from './routes/auth.js';
import userRoutes from './routes/user.js';
import letterRoutes from './routes/letters.js';
import adminRoutes from './routes/admin.js';

export function createApp(): Hono {
  const cfg = getConfig();
  const adminPrefix = String(cfg.admin_path_prefix ?? 'admin').replace(/^\/+|\/+$/g, '') || 'admin';
  setAdminPrefix(adminPrefix);

  const app = new Hono();

  // 1. 会话初始化（最先执行）
  app.use('*', async (c: Context, next: Next) => {
    initSession(c);
    await next();
    // 请求结束时写回会话
    commitSession(c);
  });

  // 2. 安全响应头
  app.use('*', securityHeadersMiddleware());

  // 3. 全局默认限流（5000/day, 1000/hour）——仅作兜底，写接口有各自的路由级限流
  app.use('/api/*', defaultRateLimit());

  // 4. 静态资源
  app.use('/static/*', serveStatic({ root: './', rewriteRequestPath: (p) => p }));

  // 5. 路由挂载
  app.route('/', pagesRoutes);
  app.route('/', apiRoutes);
  app.route('/', authRoutes);
  app.route('/', userRoutes);
  app.route('/', letterRoutes);
  app.route('/', adminRoutes); // 内部使用 admin 前缀

  // 6. SPA fallback —— React 前端接管页面路由
  //    仅对「未匹配到后端路由 + GET + Accept:text/html + 非静态/非 API/非 admin」的请求
  //    返回 static/spa/index.html，由 react-router 客户端路由。
  const spaIndex = path.join(PROJECT_ROOT, 'static', 'spa', 'index.html');
  app.get('*', serveSpaIndex(spaIndex, adminPrefix));

  // 7. 全局错误兜底
  app.onError((err, c) => {
    console.error('[app] 未捕获错误:', err);
    return c.json({ error: '服务器内部错误' }, 500);
  });

  return app;
}

/**
 * SPA fallback 中间件工厂。
 * 判定规则：
 *   - 仅 GET 且 Accept 含 text/html
 *   - 路径不以 /api、/static、/admin（admin 前缀）、/letters（保留 SSR 资源路径）干扰
 *   - SPA index.html 存在时返回；否则放行（交由后续 404）
 *
 * 注意：react-router 的 SPA 路由（/、/auth/*、/user/*、/m/:id 等）均会被此前端接管。
 * 后端已有的精确路由（pages/api/auth/user/letters/admin）优先级更高，已在上一步注册。
 */
function serveSpaIndex(indexHtmlPath: string, adminPrefix: string) {
  return async (c: Context, next: Next) => {
    const url = new URL(c.req.url);
    const p = url.pathname;

    // 非 GET 或非页面请求直接放行
    if (c.req.method !== 'GET') return next();
    const accept = c.req.header('accept') ?? '';
    if (!accept.includes('text/html')) return next();

    // 明确排除的路径前缀：API、静态资源、admin、后端 SSR 资源目录、隐私政策(SSR 静态)
    const exclude = [
      '/api/',
      '/static/',
      `/${adminPrefix}/`,
      `/${adminPrefix}`,
      '/privacy-policy',
      '/privacy-policy-cn',
    ];
    if (exclude.some((x) => p === x || p.startsWith(x))) return next();

    // SPA index.html 不存在（前端未构建）→ 放行，返回 404
    try {
      await fs.promises.access(indexHtmlPath, fs.constants.R_OK);
    } catch {
      return next();
    }
    const html = await fs.promises.readFile(indexHtmlPath, 'utf-8');
    return c.html(html);
  };
}
