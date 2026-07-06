// =============================================================================
// Altcha 人机验证 —— HMAC 签名 + SHA-256 工作量证明（PoW）
//
// 纯本地、零外部依赖：无需调用任何第三方 API，不受 CSP 限制。
// 启用条件：配置了 ALTCHA_HMAC_KEY 即开启（见 .env）。
//
// 流程：
//   1. 后端 generateAltchaChallenge() 签发 {challenge, salt, signature, target_prefix, max_number}
//   2. 前端求解 i ∈ [0, max_number]，使 sha256(challenge + i) 以 target_prefix 开头
//   3. 前端回传 {challenge, number, salt, signature, hash_result} 的 JSON
//   4. 后端 validateAltcha() 三步校验：签名 → 前缀 → 哈希一致性
// =============================================================================
import crypto from 'node:crypto';
import { getConfig } from '../config.js';

/** Altcha 挑战响应（签发给前端） */
export interface AltchaChallenge {
  challenge: string;
  salt: string;
  signature: string;
  /** 目标前缀（难度 = 该前缀的 hex 位数） */
  target_prefix: string;
  /** 求解上限 */
  max_number: number;
}

/** 是否启用 Altcha（配置了 ALTCHA_HMAC_KEY 即视为启用） */
export function isAltchaEnabled(): boolean {
  return !!getConfig().ALTCHA_HMAC_KEY;
}

/** 读取难度（1-5，默认 5；数值越大求解越慢越安全） */
function getDifficulty(): number {
  const n = Number(getConfig().ALTCHA_DIFFICULTY ?? 5);
  if (!Number.isFinite(n) || n < 1) return 5;
  return Math.min(n, 5);
}

/**
 * 签发 Altcha 挑战。
 * - challenge：随机 16 字节 hex
 * - salt：随机 8 字节 hex（参与 target_prefix 派生，防止预计算）
 * - signature：HMAC-SHA256(key, challenge)，前端原样回传，后端校验一致性
 * - target_prefix：HMAC-SHA256(key, challenge+salt) 的前 N 位 hex
 */
export function generateAltchaChallenge(): AltchaChallenge {
  const hmacKey = String(getConfig().ALTCHA_HMAC_KEY ?? '');
  const challenge = crypto.randomBytes(16).toString('hex');
  const salt = crypto.randomBytes(8).toString('hex');
  const signature = crypto
    .createHmac('sha256', Buffer.from(hmacKey, 'utf8'))
    .update(challenge, 'utf8')
    .digest('hex');
  const targetSeed = crypto
    .createHmac('sha256', Buffer.from(hmacKey, 'utf8'))
    .update(`${challenge}${salt}`, 'utf8')
    .digest('hex');
  return {
    challenge,
    salt,
    signature,
    target_prefix: targetSeed.substring(0, getDifficulty()),
    max_number: 1000000,
  };
}

/**
 * 校验前端回传的 PoW payload（JSON 字符串）。
 * 三步全过才有效，任何一步失败均拒绝：
 *   1. signature == HMAC-SHA256(key, challenge)  —— 挑战确由本服务签发
 *   2. hash_result 以 target_prefix 开头           —— 确实做了工作量
 *   3. hash_result == SHA-256(challenge + number)  —— 哈希值未被伪造
 */
export function validateAltcha(payload: string): boolean {
  const hmacKey = String(getConfig().ALTCHA_HMAC_KEY ?? '');
  if (!hmacKey) {
    console.error('[altcha] ALTCHA_HMAC_KEY 未配置');
    return false;
  }

  let data: Record<string, unknown>;
  try {
    data = JSON.parse(payload);
  } catch (e) {
    console.error('[altcha] payload JSON 解析失败:', e);
    return false;
  }

  const required = ['challenge', 'number', 'salt', 'signature', 'hash_result'];
  for (const f of required) {
    if (data[f] === undefined || data[f] === null || data[f] === '') {
      console.error(`[altcha] 响应缺少必需字段: ${f}`);
      return false;
    }
  }

  const challenge = String(data.challenge);
  const number = String(data.number);
  const salt = String(data.salt);
  const signature = String(data.signature);
  const hashResult = String(data.hash_result);

  // 1. 验证签名 —— 确认挑战由本服务签发
  const expectedSig = crypto
    .createHmac('sha256', Buffer.from(hmacKey, 'utf8'))
    .update(challenge, 'utf8')
    .digest('hex');
  if (signature !== expectedSig) {
    console.error('[altcha] 签名验证失败');
    return false;
  }

  // 2. 目标前缀 —— 确认完成了相应难度的工作量
  const targetSeed = crypto
    .createHmac('sha256', Buffer.from(hmacKey, 'utf8'))
    .update(`${challenge}${salt}`, 'utf8')
    .digest('hex');
  const targetPrefix = targetSeed.substring(0, getDifficulty());
  if (!hashResult.startsWith(targetPrefix)) {
    console.error('[altcha] 哈希结果不满足目标前缀');
    return false;
  }

  // 3. 哈希一致性 —— 确认 hash_result 确由 challenge + number 计算得出
  const expectedHash = crypto
    .createHash('sha256')
    .update(`${challenge}${number}`, 'utf8')
    .digest('hex');
  if (hashResult !== expectedHash) {
    console.error('[altcha] 哈希结果与计算值不匹配');
    return false;
  }

  console.info(`[altcha] 验证成功: ${hashResult.substring(0, 10)}...`);
  return true;
}
