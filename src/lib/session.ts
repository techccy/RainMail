// =============================================================================
// 会话 —— HMAC 签名的 Cookie 会话（复刻 Flask session 语义）
// 结构：base64url(JSON) + "." + base64url(HMAC-SHA256(payload))
// 所有读写通过 Context 的 Variables 传递，响应阶段写回 Cookie
// =============================================================================
import crypto from 'node:crypto';
import type { Context } from 'hono';
import { getConfig } from '../config.js';

const COOKIE_NAME = 'session';

export type SessionData = Record<string, any>;

function getSecret(): string {
  return String(getConfig().SECRET_KEY ?? 'rainmail_secret_key_2024');
}

function b64url(input: Buffer | string): string {
  return Buffer.from(input).toString('base64url');
}

function fromB64url(input: string): Buffer {
  return Buffer.from(input, 'base64url');
}

/** 签发 payload */
function sign(payload: SessionData): string {
  const body = b64url(JSON.stringify(payload));
  const sig = crypto.createHmac('sha256', getSecret()).update(body).digest();
  return `${body}.${sig.toString('base64url')}`;
}

/** 校验并解析（失败返回空对象） */
function verifyAndParse(raw: string | undefined): SessionData {
  if (!raw) return {};
  const dot = raw.lastIndexOf('.');
  if (dot < 1) return {};
  const body = raw.substring(0, dot);
  const sig = raw.substring(dot + 1);
  const expected = crypto.createHmac('sha256', getSecret()).update(body).digest('base64url');
  // 恒定时间比较
  const a = Buffer.from(sig);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return {};
  try {
    const parsed = JSON.parse(fromB64url(body).toString('utf8'));
    return parsed && typeof parsed === 'object' ? parsed : {};
  } catch {
    return {};
  }
}

/** 为请求初始化会话变量（在全局中间件最前面调用） */
export function initSession(c: Context): void {
  const cookie = getCookie(c, COOKIE_NAME);
  const data = verifyAndParse(cookie);
  // 暂存原始快照，便于响应阶段判断是否需要写回
  c.set('session', data);
  c.set('sessionOriginal', JSON.stringify(data));
}

function getCookie(c: Context, name: string): string | undefined {
  const header = c.req.header('cookie');
  if (!header) return undefined;
  for (const part of header.split(';')) {
    const eq = part.indexOf('=');
    if (eq < 0) continue;
    const k = part.substring(0, eq).trim();
    if (k === name) return part.substring(eq + 1).trim();
  }
  return undefined;
}

function getCached(c: Context): SessionData {
  const s = c.get('session');
  if (!s) throw new Error('session 未初始化');
  return s;
}

/** 读取会话值 */
export function sessionGet(c: Context, key: string): any {
  return getCached(c)[key];
}

/** 设置会话值 */
export function sessionSet(c: Context, key: string, value: any): void {
  getCached(c)[key] = value;
}

/** 弹出会话值，返回原值 */
export function sessionPop(c: Context, key: string): any {
  const s = getCached(c);
  const v = s[key];
  delete s[key];
  return v;
}

/** 判断 key 是否存在 */
export function sessionHas(c: Context, key: string): boolean {
  return key in getCached(c);
}

/** 把会话写回响应 Cookie（在请求结束时调用） */
export function commitSession(c: Context): void {
  const data = c.get('session');
  const original = c.get('sessionOriginal');
  if (!data) return;
  if (JSON.stringify(data) === original) return; // 未变化，不写回

  const cfg = getConfig();
  const secure = cfg.SESSION_COOKIE_SECURE === true;
  const value = sign(data);
  const parts = [
    `${COOKIE_NAME}=${value}`,
    'Path=/',
    'HttpOnly',
    `SameSite=${secure ? 'None' : 'Lax'}`,
    'Max-Age=86400', // 24h
  ];
  if (secure) parts.push('Secure');
  c.header('Set-Cookie', parts.join('; '), { append: true });
}

export { COOKIE_NAME as SESSION_COOKIE_NAME };
