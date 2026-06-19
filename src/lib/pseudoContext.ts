// =============================================================================
// 伪 Context —— 后台 worker 调用 mail 通知时需要一个类似 Hono Context 的对象
// 以便 baseUrl() 读取 host 头。worker 不在 HTTP 请求内，使用 APP_URL 作为 host。
// =============================================================================
import type { Context } from 'hono';
import { getConfig } from '../config.js';

/** 创建一个仅供 mail.ts 使用的最小伪上下文 */
export function pseudoContext(): Context {
  const cfg = getConfig();
  const appUrl = String(cfg.APP_URL ?? 'https://rainmail.dev');
  const host = appUrl.replace(/^https?:\/\//, '');
  const fakeReq = {
    header: (name: string): string | undefined => {
      const lower = name.toLowerCase();
      if (lower === 'host') return host;
      return undefined;
    },
  };
  return {
    req: fakeReq as any,
  } as Context;
}
