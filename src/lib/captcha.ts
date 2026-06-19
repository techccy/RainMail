// =============================================================================
// 人机验证 —— 统一入口 + 5 种提供商
// cloudflare(Turnstile) / recaptcha(v3) / cha(数学题) / altcha(工作量证明) / none
// 对齐 Python validate_captcha / validate_turnstile / validate_recaptcha_v3 /
//        validate_cha / generate_cha_question / validate_altcha
// =============================================================================
import crypto from 'node:crypto';
import type { Context } from 'hono';
import { getConfig } from '../config.js';
import { sessionGet, sessionSet, sessionPop } from './session.js';

function cfg() {
  return getConfig();
}

// ----------------------------- Cloudflare Turnstile -----------------------------
async function validateTurnstile(token: string, userIp?: string): Promise<boolean> {
  const secret = cfg().TURNSTILE_SECRET_KEY as string | undefined;
  if (!secret) {
    console.error('[captcha] TURNSTILE_SECRET_KEY 未配置');
    return false;
  }
  const body = new URLSearchParams({ secret, response: token });
  if (userIp) body.set('remoteip', userIp);
  try {
    const resp = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST',
      body,
      signal: AbortSignal.timeout(10000),
    });
    const data = (await resp.json()) as { success?: boolean };
    return data.success === true;
  } catch (e) {
    console.error('[captcha] Turnstile 验证请求失败:', e);
    return false;
  }
}

// ----------------------------- Google reCAPTCHA v3 -----------------------------
async function validateRecaptchaV3(token: string, userIp?: string): Promise<boolean> {
  const secret = cfg().RECAPTCHA_V3_SECRET_KEY as string | undefined;
  if (!secret) {
    console.error('[captcha] RECAPTCHA_V3_SECRET_KEY 未配置');
    return false;
  }
  const body = new URLSearchParams({ secret, response: token });
  if (userIp) body.set('remoteip', userIp);
  try {
    const resp = await fetch('https://www.google.com/recaptcha/api/siteverify', {
      method: 'POST',
      body,
      signal: AbortSignal.timeout(10000),
    });
    const data = (await resp.json()) as { success?: boolean; score?: number };
    if (!data.success) return false;
    const score = data.score ?? 0;
    const threshold = (cfg().RECAPTCHA_V3_THRESHOLD as number) || 0.5;
    if (score >= threshold) return true;
    console.warn(`[captcha] reCAPTCHA v3 分数过低: ${score} < ${threshold}`);
    return false;
  } catch (e) {
    console.error('[captcha] reCAPTCHA v3 验证请求失败:', e);
    return false;
  }
}

// ----------------------------- CHA 数学题 -----------------------------
export interface ChaQuestion {
  question: string;
  answer: number;
}

export function generateChaQuestion(): ChaQuestion {
  const num1 = 1 + Math.floor(Math.random() * 10);
  const num2 = 1 + Math.floor(Math.random() * 10);
  const ops = ['+', '-', '*'] as const;
  const op = ops[Math.floor(Math.random() * ops.length)]!;
  if (op === '+') return { question: `${num1} + ${num2} = ?`, answer: num1 + num2 };
  if (op === '-') return { question: `${num1} - ${num2} = ?`, answer: num1 - num2 };
  return { question: `${num1} × ${num2} = ?`, answer: num1 * num2 };
}

/**
 * CHA 校验（接受字符串答案或 JSON body）
 * 对齐 Python validate_cha(captcha_response, session_obj)：从 session 读取并销毁，
 * 校验答案 + 2 分钟时效
 */
function validateCha(c: Context, submitted: unknown): boolean {
  const answer = typeof submitted === 'object' && submitted !== null
    ? (submitted as Record<string, any>).cha_answer
    : submitted;
  if (answer === undefined || answer === null || answer === '') {
    console.warn('[captcha] CHA verification missing answer');
    return false;
  }

  const storedAnswer = sessionGet(c, 'cha_answer');
  const timestamp = sessionGet(c, 'cha_timestamp');

  // 一次性：销毁避免重放
  sessionPop(c, 'cha_answer');
  sessionPop(c, 'cha_timestamp');

  if (storedAnswer === undefined || timestamp === undefined) {
    console.warn('[captcha] CHA verification data missing in session');
    return false;
  }

  if (String(storedAnswer).trim() !== String(answer).trim()) {
    console.info(`[captcha] CHA verification failed: expected ${storedAnswer}, got ${answer}`);
    return false;
  }

  const elapsed = Date.now() / 1000 - Number(timestamp);
  if (elapsed > 120) {
    console.info(`[captcha] CHA verification timeout: ${elapsed.toFixed(1)}s elapsed`);
    return false;
  }
  return true;
}

// ----------------------------- Altcha 工作量证明 -----------------------------
function validateAltcha(payload: string): boolean {
  const hmacKey = cfg().ALTCHA_HMAC_KEY as string | undefined;
  if (!hmacKey) {
    console.error('[captcha] ALTCHA_HMAC_KEY 未配置');
    return false;
  }
  let data: any;
  try {
    data = JSON.parse(payload);
  } catch (e) {
    console.error('[captcha] Altcha JSON 解析失败:', e);
    return false;
  }

  const required = ['challenge', 'number', 'salt', 'signature', 'hash_result'];
  for (const f of required) {
    if (!(f in data)) {
      console.error(`[captcha] Altcha 响应缺少必需字段: ${f}`);
      return false;
    }
  }

  const { challenge, number, salt, signature, hash_result } = data as Record<string, string>;
  const difficulty = Number(cfg().ALTCHA_DIFFICULTY ?? 5);

  // 1. 验证签名
  const expectedSig = crypto.createHmac('sha256', Buffer.from(hmacKey, 'utf8')).update(challenge!, 'utf8').digest('hex');
  if (signature !== expectedSig) {
    console.error('[captcha] Altcha 签名验证失败');
    return false;
  }

  // 2. 目标前缀
  const targetSeed = crypto
    .createHmac('sha256', Buffer.from(hmacKey, 'utf8'))
    .update(`${challenge}${salt}`, 'utf8')
    .digest('hex');
  const targetPrefix = targetSeed.substring(0, difficulty);
  if (!hash_result!.startsWith(targetPrefix)) {
    console.error(`[captcha] Altcha 哈希结果不满足目标前缀`);
    return false;
  }

  // 3. 校验哈希确实由 challenge + number 计算
  const expectedHash = crypto.createHash('sha256').update(`${challenge}${number}`, 'utf8').digest('hex');
  if (hash_result !== expectedHash) {
    console.error('[captcha] Altcha 哈希结果与计算值不匹配');
    return false;
  }

  console.info(`[captcha] Altcha 验证成功: ${hash_result!.substring(0, 10)}...`);
  return true;
}

// ----------------------------- 统一入口 -----------------------------
export type CaptchaProvider = 'cloudflare' | 'recaptcha' | 'recaptcha_v3' | 'cha' | 'altcha' | 'none' | string;

export function getCaptchaProvider(): CaptchaProvider {
  return String(cfg().CAPTCHA_PROVIDER ?? 'cloudflare').toLowerCase();
}

/**
 * 统一校验
 * @param captchaResponse 客户端提交的答案（字符串/对象/undefined）
 * @param userIp
 * @param c 用于 cha 模式读取 session
 */
export async function validateCaptcha(
  captchaResponse: unknown,
  userIp: string | undefined,
  c: Context,
): Promise<boolean> {
  const provider = getCaptchaProvider();
  if (provider === 'none') return true;
  if (provider === 'cloudflare') return validateTurnstile(String(captchaResponse ?? ''), userIp);
  if (provider === 'recaptcha' || provider === 'recaptcha_v3') {
    return validateRecaptchaV3(String(captchaResponse ?? ''), userIp);
  }
  if (provider === 'cha') return validateCha(c, captchaResponse);
  if (provider === 'altcha') return validateAltcha(String(captchaResponse ?? ''));
  console.error(`[captcha] 未知的验证提供商: ${provider}`);
  return false;
}

/** 为 CHA/Altcha 回退场景在 session 中放入新问题 */
export function prepareChaQuestion(c: Context): ChaQuestion {
  const q = generateChaQuestion();
  sessionSet(c, 'cha_question', q.question);
  sessionSet(c, 'cha_answer', q.answer);
  sessionSet(c, 'cha_timestamp', Date.now() / 1000);
  return q;
}

/** 从 session 读取当前 CHA 问题（用于模板渲染） */
export function currentChaQuestion(c: Context): string | undefined {
  return sessionGet(c, 'cha_question');
}

// ----------------------------- Altcha 挑战签发 -----------------------------
export function generateAltchaChallenge(): {
  challenge: string;
  salt: string;
  signature: string;
  target_prefix: string;
  max_number: number;
} {
  const hmacKey = String(cfg().ALTCHA_HMAC_KEY ?? '');
  const challenge = crypto.randomBytes(16).toString('hex');
  const salt = crypto.randomBytes(8).toString('hex');
  const signature = crypto.createHmac('sha256', Buffer.from(hmacKey, 'utf8')).update(challenge, 'utf8').digest('hex');
  const difficulty = Number(cfg().ALTCHA_DIFFICULTY ?? 5);
  const targetSeed = crypto
    .createHmac('sha256', Buffer.from(hmacKey, 'utf8'))
    .update(`${challenge}${salt}`, 'utf8')
    .digest('hex');
  const target_prefix = targetSeed.substring(0, difficulty);
  return { challenge, salt, signature, target_prefix, max_number: 1000000 };
}

// 避免未使用告警
void sessionGet;
