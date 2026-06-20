// =============================================================================
// 验证码抽象 —— 5 provider 统一处理
// none / cloudflare(Turnstile) / recaptcha|recaptcha_v3 / cha(数学题) / altcha(PoW)
// 对齐后端 src/routes/letters.ts、auth.ts 的字段提取：
//   cf_token / recaptcha_token / cha_answer / altcha_payload
// =============================================================================
import { api } from '@/lib/api';
import type { AltchaChallenge, ChaQuestion } from '@/types/api';

/** 验证码字段：提交时合并进 body 的 {field, value} */
export interface CaptchaField {
  field: string;
  value: string;
}

// ----------------------------- cha（数学题） -----------------------------
/** 拉取一道 cha 题目 */
export async function fetchChaQuestion(): Promise<ChaQuestion | null> {
  const res = await api<ChaQuestion>('/api/cha/question');
  return res.ok ? res.data : null;
}

// ----------------------------- altcha（工作量证明） -----------------------------
/** 拉取 altcha 挑战 */
export async function fetchAltchaChallenge(): Promise<AltchaChallenge | null> {
  const res = await api<AltchaChallenge>('/api/altcha/challenge');
  return res.ok ? res.data : null;
}

async function sha256Hex(input: string): Promise<string> {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(input));
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Altcha PoW 求解：寻找 i 使 sha256(challenge + str(i)) 以 target_prefix 开头。
 * 每 500 次迭代让出一次事件循环（避免阻塞 UI）。
 * 移植自 static/js/init.js 的 solveAltchaChallenge。
 */
export async function solveAltcha(challenge: AltchaChallenge, onProgress?: (pct: number) => void): Promise<string | null> {
  const { challenge: ch, salt, signature, target_prefix, max_number } = challenge;
  for (let i = 0; i <= max_number; i++) {
    const hash = await sha256Hex(ch + String(i));
    if (hash.startsWith(target_prefix)) {
      return JSON.stringify({ challenge: ch, number: i, salt, signature, hash_result: hash });
    }
    if (i % 500 === 0) {
      onProgress?.(Math.round((i / max_number) * 100));
      // 让出事件循环
      await new Promise((r) => setTimeout(r, 0));
    }
  }
  return null;
}

/** 根据 provider 名得到提交 body 的字段名 */
export function captchaFieldName(provider: string): string | null {
  switch (provider) {
    case 'cloudflare':
      return 'cf_token';
    case 'recaptcha':
    case 'recaptcha_v3':
      return 'recaptcha_token';
    case 'cha':
      return 'cha_answer';
    case 'altcha':
      return 'altcha_payload';
    default:
      return null;
  }
}

// ----------------------------- 第三方脚本动态加载 -----------------------------
const loadedScripts = new Set<string>();

export function loadScript(src: string): Promise<void> {
  if (loadedScripts.has(src)) return Promise.resolve();
  return new Promise((resolve) => {
    const existing = document.querySelector(`script[src="${src}"]`);
    if (existing) {
      loadedScripts.add(src);
      resolve();
      return;
    }
    const s = document.createElement('script');
    s.src = src;
    s.async = true;
    s.defer = true;
    s.onload = () => {
      loadedScripts.add(src);
      resolve();
    };
    s.onerror = () => resolve();
    document.head.appendChild(s);
  });
}

// Cloudflare Turnstile / Google reCAPTCHA 的全局类型声明
declare global {
  interface Window {
    turnstile?: {
      render: (el: string | HTMLElement, opts: Record<string, unknown>) => string;
      reset: (id?: string) => void;
      getResponse: (id?: string) => string;
      remove: (id?: string) => void;
    };
    grecaptcha?: {
      ready: (cb: () => void) => void;
      execute: (siteKey: string, opts: { action: string }) => Promise<string>;
      render: (el: HTMLElement | string, opts: Record<string, unknown>) => number;
      reset: (id?: number) => void;
      getResponse: (id?: number) => string;
    };
  }
}
