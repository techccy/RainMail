// =============================================================================
// 应用入口 —— 配置加载 → 建表 → 启动 workers → 监听 5024
// 对齐原 Python run.py + app.py 启动逻辑
// =============================================================================
import { serve } from '@hono/node-server';
import { getConfig } from './config.js';
import { ensureSchema } from './db/migrate.js';
import { initWeather } from './lib/weather.js';
import { isHashed } from './lib/password.js';
import { createApp } from './app.js';
import { startWeatherUnlockWorker } from './workers/weather-unlock.js';
import { startEmailQueueWorker } from './workers/email-queue.js';
import { startCleanupWorker } from './workers/cleanup.js';

const PORT = Number(process.env.PORT ?? 5024);

function verifyAdminPasswordFormat(): void {
  const cfg = getConfig();
  const pwd = String(cfg.admin_password ?? '');
  if (!pwd) {
    console.warn('[WARN] 管理员密码为空（admin_password 未配置），管理员登录将不可用');
    return;
  }
  if (!isHashed(pwd)) {
    console.warn(
      '===========================================\n' +
        '安全警告：管理员密码不是哈希格式！\n' +
        '请使用以下命令生成 scrypt 哈希后填入 .env 的 ADMIN_PASSWORD：\n' +
        '  npm run -s -- gen-hash <your-password>  （或在 Node 中调用 hashPassword）\n' +
        '===========================================',
    );
  } else {
    console.log('[INFO] 管理员密码格式验证通过（哈希格式）');
  }
}

function main(): void {
  // 1. 配置（getConfig 内部首次加载会读 .env）
  getConfig();

  // 2. 建表
  ensureSchema();

  // 3. 天气 API 初始化
  initWeather();

  // 4. 启动期密码格式校验
  verifyAdminPasswordFormat();

  // 5. 启动后台任务
  try {
    startWeatherUnlockWorker();
    startEmailQueueWorker();
    startCleanupWorker();
    console.log('[BackgroundWorkers] 后台任务已启动');
  } catch (e) {
    console.error('[BackgroundWorkers] 启动后台任务失败:', e);
  }

  // 6. 启动 HTTP 服务
  const app = createApp();
  serve({ fetch: app.fetch, port: PORT, hostname: '0.0.0.0' }, (info) => {
    console.log('============================================================');
    console.log(`  📮 雨天信箱 (RainMail) 已启动`);
    console.log(`  监听: http://localhost:${info.port}`);
    console.log(`  健康检查: http://localhost:${info.port}/api/health`);
    console.log(`  按 Ctrl+C 停止服务`);
    console.log('============================================================');
  });
}

main();
