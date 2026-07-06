// =============================================================================
// 删除安全码 —— 未登录用户凭码删除消息的凭证
//
// 安全设计：
//   1. 仅在消息发布时返回一次明文（随存票展示给作者本人）；
//   2. 后台只存 HMAC-SHA-256(code, SECRET_KEY)，绝不落明文；
//   3. 校验走常量时间比较（timingSafeEqual），长度不等直接 false；
//   4. 密钥复用 session.ts 的 SECRET_KEY，无需额外配置。
//
// 字符集：A–Z / a–z / 0–9 共 62 字符（16 位 ≈ 95 bit 熵），
// 展示形态：4 位一段空格隔开，如 "aB3d E5fG 7hIj K9lM"。
// =============================================================================
import crypto from 'node:crypto';
import { getConfig } from '../config.js';

const CODE_LENGTH = 16;
const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

function getSecret(): string {
  return String(getConfig().SECRET_KEY ?? 'rainmail_secret_key_2024');
}

/** 生成 16 位原始安全码（crypto.randomBytes 取模，杜绝 Math.random） */
export function generateDeleteCode(): string {
  const bytes = crypto.randomBytes(CODE_LENGTH);
  let out = '';
  for (let i = 0; i < CODE_LENGTH; i++) out += ALPHABET[bytes[i]! % ALPHABET.length];
  return out;
}

/** 格式化为 "XXXX XXXX XXXX XXXX"（仅用于展示 / 复制） */
export function formatDeleteCode(raw: string): string {
  const clean = raw.replace(/\s+/g, '');
  return clean.match(/.{1,4}/g)?.join(' ') ?? clean;
}

/**
 * 规范化用户输入：去空格 / 去分隔符，仅保留字母数字。
 * 大小写敏感保留（62 字符集区分大小写）。
 */
export function normalizeDeleteCode(input: string): string {
  return String(input ?? '').replace(/[^A-Za-z0-9]/g, '');
}

/** HMAC-SHA-256(code, SECRET_KEY) → hex（落库用） */
export function hashDeleteCode(raw: string): string {
  return crypto.createHmac('sha256', getSecret()).update(raw).digest('hex');
}

/**
 * 校验提交的安全码是否匹配已存储的哈希。
 * - 输入规范化后再哈希再比对，避免空格 / 大小写导致的误判；
 * - 长度不等直接 false，相等走 timingSafeEqual（常量时间）；
 * - storedHash 为 null（历史行 / 无码消息）一律视为不通过。
 */
export function verifyDeleteCode(input: string, storedHash: string | null | undefined): boolean {
  if (!storedHash) return false;
  const normalized = normalizeDeleteCode(input);
  if (normalized.length !== CODE_LENGTH) return false;
  const candidate = hashDeleteCode(normalized);
  try {
    const a = Buffer.from(candidate);
    const b = Buffer.from(storedHash);
    if (a.length !== b.length) return false;
    return crypto.timingSafeEqual(a, b);
  } catch {
    return false;
  }
}
