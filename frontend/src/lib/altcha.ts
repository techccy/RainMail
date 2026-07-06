// =============================================================================
// Altcha 人机验证 —— 前端求解器（工作量证明）
//
// 流程：GET /api/altcha/challenge 拉取挑战 → 浏览器内 SHA-256 暴力求解 →
//       回传 {challenge, number, salt, signature, hash_result} JSON 给后端校验。
// 纯本地计算，零外部依赖（Web Crypto API）。
// =============================================================================
import { apiFetch } from '@/lib/api';
import type { AltchaChallenge } from '@/types/api';

/** 拉取 Altcha 挑战（未启用时后端返回 404，这里返回 null） */
export async function fetchAltchaChallenge(): Promise<AltchaChallenge | null> {
  try {
    const resp = (await apiFetch('/api/altcha/challenge', { csrf: false })) as unknown as Response;
    if (!resp.ok) return null;
    return (await resp.json()) as AltchaChallenge;
  } catch {
    return null;
  }
}

async function sha256Hex(input: string): Promise<string> {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(input));
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * 求解 PoW：寻找 i ∈ [0, max_number] 使 sha256(challenge + i) 以 target_prefix 开头。
 * 命中即返回 payload JSON 字符串；未命中返回 null。
 * 每 500 次迭代让出一次事件循环，避免阻塞 UI。
 */
export async function solveAltchaPoW(
  challenge: AltchaChallenge,
  onProgress?: (pct: number) => void,
): Promise<string | null> {
  const { challenge: ch, salt, signature, target_prefix, max_number } = challenge;
  for (let i = 0; i <= max_number; i++) {
    const hash = await sha256Hex(ch + String(i));
    if (hash.startsWith(target_prefix)) {
      return JSON.stringify({ challenge: ch, number: i, salt, signature, hash_result: hash });
    }
    if (i % 500 === 0) {
      onProgress?.(Math.round((i / max_number) * 100));
      await new Promise((r) => setTimeout(r, 0));
    }
  }
  return null;
}
