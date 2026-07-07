// =============================================================================
// 安全相关：响应头、SQL 注入检测、XSS 过滤、蜜罐、限流、客户端 IP
// 对齐 Python：add_security_headers / detect_sql_injection / sanitize_input /
//             check_honeypot / get_client_ip / Limiter
// =============================================================================
import type { Context, MiddlewareHandler } from 'hono';
import { getConfig } from '../config.js';

// ----------------------------- 安全响应头 -----------------------------
export const DEFAULT_CSP = [
  "default-src 'self'",
  "script-src 'self' https://static.cloudflareinsights.com",
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data: https:",
  "connect-src 'self' https://static.cloudflareinsights.com",
  "font-src 'self'",
  "frame-src 'self'",
  "object-src 'none'",
  "base-uri 'self'",
  "form-action 'self'",
  "frame-ancestors 'none'",
  'upgrade-insecure-requests',
].join('; ');

/**
 * 给 CSP 的 script-src 指令追加 'unsafe-inline'。
 * 后台 dashboard 大量依赖内联 onclick（行内事件处理器），而 CSP 默认不含
 * 'unsafe-inline' 会被浏览器静默拦截（连确认框都不弹）。公共站点 / SPA 仍保持严格策略。
 * 只对 handler 显式 c.set('cspAllowInline', true) 的响应放宽，影响面最小。
 */
function withInlineScriptsAllowed(csp: string): string {
  // 命中 script-src 这一段并在其末尾（遇到下一个 ';' 或字符串结尾前）插入 'unsafe-inline'
  return csp.replace(/script-src[^;]*/i, (m) => (m.includes("'unsafe-inline'") ? m : `${m} 'unsafe-inline'`));
}

export function securityHeadersMiddleware(): MiddlewareHandler {
  return async (c, next) => {
    await next();
    const cfg = getConfig();
    // SSR 页面（登录页等）把 CSRF token 内嵌进 HTML 并与会话绑定，
    // 若被任何一层缓存（Cloudflare 边缘 / 浏览器启发式），下次 GET 命中缓存即不回源，
    // 提交的是旧会话的 token，会导致 CSRF 校验失败。因此对 HTML 响应强制禁缓存。
    const contentType = c.res.headers.get('content-type') || '';
    if (contentType.includes('text/html')) {
      c.header('Cache-Control', 'no-store, no-cache, must-revalidate');
      c.header('Pragma', 'no-cache');
    }
    const baseCsp = (cfg.CSP_POLICY as string) || DEFAULT_CSP;
    const csp = c.get('cspAllowInline') ? withInlineScriptsAllowed(baseCsp) : baseCsp;
    c.header('Content-Security-Policy', csp);
    c.header('X-Frame-Options', 'DENY');
    c.header('X-Content-Type-Options', 'nosniff');
    c.header('X-XSS-Protection', '1; mode=block');
    c.header('Referrer-Policy', 'strict-origin-when-cross-origin');
    c.header('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
  };
}

// ----------------------------- 客户端 IP -----------------------------
export function getClientIp(c: Context): string {
  const cf = c.req.header('CF-Connecting-IP');
  if (cf) return cf.split(',')[0]!.trim();
  const xff = c.req.header('X-Forwarded-For');
  if (xff) return xff.split(',')[0]!.trim();
  return c.env?.REMOTE_ADDR || '127.0.0.1';
}

// ----------------------------- SQL 注入检测 -----------------------------
const SQL_INJECTION_PATTERNS: RegExp[] = [
  /(%27)|(')|(--)|(#)|(;)/i,
  /\b(ALLOW|OR|AND)\b.*?(=|LIKE)/i,
  /(EXEC|EXECUTE|EXECUTEMANY|SP_|XP_)/i,
  /(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\s+/i,
  /(UNION\s+SELECT)/i,
  /\b(INFORMATION_SCHEMA|SYS|MYSQL)\b/i,
  /\b(GROUP_CONCAT|CONCAT|CONCAT_WS)\b.*?\(/i,
  /(WAITFOR\s+DELAY|SLEEP\()/i,
  /(BENCHMARK\s*\()/i,
  /\b(LOAD_FILE|INTO\s+OUTFILE)\b/i,
  /\b(CAST|CONVERT)\b.*\bAS\b/i,
  /\b(CHAR|ASCII|ORD|HEX)\s*\(/i,
  /(0x[0-9a-fA-F]+)/i,
  /(\|\||&&)/i,
  /(\bor\b|\bAND\b).*?\b\d+\b/i,
  /(\bor\b|\bAND\b).*?['"]/i,
  /(\bx\b\s*=\s*0x)/i,
];

export function detectSqlInjection(text: string): boolean {
  if (!text) return false;
  for (const pattern of SQL_INJECTION_PATTERNS) {
    if (pattern.test(text)) {
      console.warn(`[SECURITY] 检测到SQL注入模式，模式: ${pattern.source}, 输入: ${text.substring(0, 100)}`);
      return true;
    }
  }
  return false;
}

// ----------------------------- XSS 过滤 -----------------------------
export function sanitizeInput(text: string): string {
  if (!text) return '';
  let out = text.replace(/<script.*?>.*?<\/script>/gis, '');
  out = out.replace(/<.*?>/g, '');
  out = out.replace(/"/g, '"').replace(/'/g, '&#39;');
  out = out.replace(/</g, '&lt;').replace(/>/g, '&gt;');
  return out.trim();
}

// ----------------------------- 蜜罐检测 -----------------------------
export function checkHoneypot(c: Context, data: Record<string, any>): boolean {
  const value = String(data?.website_confirm ?? '').trim();
  if (value) {
    console.warn(`[HONEYPOT] 机器人IP被记录: ${getClientIp(c)}, 填充值: ${value}`);
    return true;
  }
  return false;
}

// ----------------------------- 内存限流 -----------------------------
interface RateBucket {
  count: number;
  resetAt: number; // epoch ms
}

interface RateLimitOpts {
  limit: number;
  windowMs: number;
}

const buckets = new Map<string, RateBucket>();

/** 解析 "10 per minute" / "3 per hour" / "200 per day" */
export function parseRate(spec: string): RateLimitOpts {
  const m = spec.match(/(\d+)\s*per\s*(minute|hour|day|second)/i);
  if (!m) return { limit: 100, windowMs: 60_000 };
  const n = parseInt(m[1]!, 10);
  const unit = m[2]!.toLowerCase();
  const mult = unit === 'second' ? 1000 : unit === 'minute' ? 60_000 : unit === 'hour' ? 3_600_000 : 86_400_000;
  return { limit: n, windowMs: mult };
}

/**
 * 限流中间件工厂
 * @param keyTag 路由标签，用于隔离不同接口的计数桶。若多个路由共用空 tag，
 *               它们会共享同一个 `${tag}:${ip}` 桶（登录与投递会互相消耗额度）。
 *               每个限流路由都应传入唯一 tag，例如 'msg' / 'login' / 'register'。
 * @example rateLimit('10 per minute', 'msg')
 */
export function rateLimit(spec: string, keyTag = ''): MiddlewareHandler {
  const { limit, windowMs } = parseRate(spec);
  return async (c, next) => {
    const id = getClientIp(c);
    const key = `${keyTag}:${id}`;
    const now = Date.now();
    let bucket = buckets.get(key);
    if (!bucket || bucket.resetAt <= now) {
      bucket = { count: 0, resetAt: now + windowMs };
      buckets.set(key, bucket);
    }
    bucket.count++;
    if (bucket.count > limit) {
      const retryAfter = Math.ceil((bucket.resetAt - now) / 1000);
      console.warn(
        `[RATELIMIT] tag=${keyTag || '(none)'} IP=${id} count=${bucket.count}/${limit} windowMs=${windowMs} retryAfter=${retryAfter}s`,
      );
      c.header('Retry-After', String(retryAfter));
      return c.json({ error: '请求过于频繁，请稍后再试' }, 429);
    }
    await next();
  };
}

/** 全局默认限流 ——可选启用
 *
 * 阈值需高于前端自身的后台轮询频率，否则长时间停留页面会被正常轮询打爆：
 *   - 主页 /api/weather/meta 每 1 分钟轮询一次 → 60 次/小时
 *   - /api/weather 每 5 分钟轮询一次 → 12 次/小时
 *   - 页面加载时还会拉 /api/form_token、/api/csrf_token 等
 * 旧阈值（50/hour、200/day）远低于上述合计，导致停留约 25 分钟即触发 429。
 * 现放宽至 1000/hour、5000/day，仍可拦截真正的刷量，且不影响被动轮询。
 * 注意：写接口（POST /api/messages、login、register 等）均有各自更严格的路由级限流，
 *       全局限流仅作为兜底，不应拦截合法的后台刷新请求。
 */
export function defaultRateLimit(): MiddlewareHandler {
  return async (c, next) => {
    const id = getClientIp(c);
    const now = Date.now();
    const dayKey = `gday:${id}`;
    const hourKey = `ghour:${id}`;
    const day = buckets.get(dayKey);
    const hour = buckets.get(hourKey);
    const dayReset = day && day.resetAt > now ? day : (() => {
      const b = { count: 0, resetAt: now + 86_400_000 };
      buckets.set(dayKey, b);
      return b;
    })();
    const hourReset = hour && hour.resetAt > now ? hour : (() => {
      const b = { count: 0, resetAt: now + 3_600_000 };
      buckets.set(hourKey, b);
      return b;
    })();
    dayReset.count++;
    hourReset.count++;
    if (dayReset.count > 5000 || hourReset.count > 1000) {
      console.warn(
        `[RATELIMIT] tag=global IP=${id} day=${dayReset.count}/5000 hour=${hourReset.count}/1000`,
      );
      return c.json({ error: '请求过于频繁，请稍后再试' }, 429);
    }
    await next();
  };
}
