// =============================================================================
// Hono 应用装配 —— 全局中间件 + 静态资源 + 路由挂载
// =============================================================================
import { Hono } from 'hono';
import { serveStatic } from '@hono/node-server/serve-static';
import type { Context, Next } from 'hono';
import { getConfig } from './config.js';
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

  // 3. 全局默认限流（200/day, 50/hour）
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

  // 6. 全局错误兜底
  app.onError((err, c) => {
    console.error('[app] 未捕获错误:', err);
    return c.json({ error: '服务器内部错误' }, 500);
  });

  return app;
}
