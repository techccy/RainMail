// =============================================================================
// 用户行为轨迹分析 —— 对齐 Python UserBehaviorTracker
// form_token = base64( timestamp:random_hex:hmac_sha256_hex )
// 校验签名 + 时效；validateUserBehavior 进一步检查停留时间/聚焦/输入字符
// =============================================================================
import crypto from 'node:crypto';
import type { Context } from 'hono';
import { getConfig } from '../config.js';

const MIN_PAGE_TIME = 8;
const MIN_INPUT_FOCUS = 1;
const MIN_INPUT_CHARS = 1;
const TOKEN_EXPIRY = 600;

function secretKey(): Buffer {
  return Buffer.from(String(getConfig().SECRET_KEY ?? 'rainmail_secret_key_2024'), 'utf8');
}

export interface FormTokenData {
  form_token: string;
  generated_at: number;
  expires_at: number;
}

/** 生成加密 Form_Token */
export function generateFormToken(): FormTokenData {
  const timestamp = Math.floor(Date.now() / 1000);
  const randomStr = crypto.randomBytes(16).toString('hex');
  const data = `${timestamp}:${randomStr}`;
  const signature = crypto.createHmac('sha256', secretKey()).update(data, 'utf8').digest('hex');
  const token = Buffer.from(`${data}:${signature}`, 'utf8').toString('base64');
  return {
    form_token: token,
    generated_at: timestamp,
    expires_at: timestamp + TOKEN_EXPIRY,
  };
}

/** 验证 Form_Token，成功返回时间戳（number） */
export function verifyFormToken(formToken: string): { ok: true; timestamp: number } | { ok: false; message: string } {
  try {
    const decoded = Buffer.from(formToken, 'base64').toString('utf8');
    const parts = decoded.split(':');
    if (parts.length !== 3) return { ok: false, message: 'Token格式错误' };

    const [timestampStr, randomStr, signature] = parts;
    const data = `${timestampStr}:${randomStr}`;
    const expectedSig = crypto.createHmac('sha256', secretKey()).update(data, 'utf8').digest('hex');
    const a = Buffer.from(signature!, 'utf8');
    const b = Buffer.from(expectedSig, 'utf8');
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
      return { ok: false, message: 'Token签名无效' };
    }

    const tokenTime = parseInt(timestampStr!, 10);
    const currentTime = Math.floor(Date.now() / 1000);
    if (isNaN(tokenTime)) return { ok: false, message: 'Token时间无效' };
    if (currentTime - tokenTime > TOKEN_EXPIRY) return { ok: false, message: 'Token已过期' };
    if (tokenTime > currentTime) return { ok: false, message: 'Token时间无效' };

    return { ok: true, timestamp: tokenTime };
  } catch (e) {
    console.error('[behavior] Form token验证错误:', e);
    return { ok: false, message: 'Token验证失败' };
  }
}

/** 验证用户行为（停留时间/聚焦/字符数） */
export function validateUserBehavior(
  formToken: string,
  pageStayTime: number,
  inputFocusCount: number,
  inputCharCount: number,
): { ok: true } | { ok: false; message: string } {
  const r = verifyFormToken(formToken);
  if (!r.ok) return { ok: false, message: r.message };

  const currentTime = Math.floor(Date.now() / 1000);
  const maxStayTime = currentTime - r.timestamp;

  if (pageStayTime < MIN_PAGE_TIME) return { ok: false, message: `页面停留时间不足${MIN_PAGE_TIME}秒` };
  if (pageStayTime > maxStayTime + 60) return { ok: false, message: '页面停留时间异常' };
  if (inputFocusCount < MIN_INPUT_FOCUS) return { ok: false, message: '未检测到输入框交互' };
  if (inputCharCount < MIN_INPUT_CHARS) return { ok: false, message: '未检测到输入内容' };

  return { ok: true };
}

/** 在 Context 上记录行为验证日志（占位，保留以备扩展） */
export function _ctx(c: Context): void {
  void c;
}
