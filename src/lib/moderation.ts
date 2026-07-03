// =============================================================================
// AI 内容审核 + 基础敏感词过滤
// 对齐 Python ai_moderation_check / basic_keyword_check / BASE_SENSITIVE_KEYWORDS
// =============================================================================
import { getConfig } from '../config.js';

const BASE_SENSITIVE_KEYWORDS = [
  '赌博', '彩票', '博彩', '充值', '代打',
  '加微信', '加QQ', '兼职刷单',
];

export function basicKeywordCheck(content: string): boolean {
  const lower = content.toLowerCase();
  for (const kw of BASE_SENSITIVE_KEYWORDS) {
    if (lower.includes(kw.toLowerCase())) {
      console.warn(`[moderation] 触发敏感词拦截: ${kw}`);
      return true;
    }
  }
  return false;
}

const DEFAULT_SYSTEM_PROMPT = `你是一个内容安全审核助手。请判断用户输入是否包含以下内容：
1. 违法、暴力、色情内容
2. 垃圾广告或恶意链接
3. 政治敏感或极端言论
4. 人身攻击或歧视性言论

请严格按照以下 JSON 格式回复，不要添加任何其他文字：
{"decision": "REJECT"}  表示内容不安全，应该拦截
{"decision": "PASS"}    表示内容安全，可以通过
`;

export type AiModerationConfig = {
  API_KEY?: string;
  BASE_URL?: string;
  MODEL?: string;
  SYSTEM_PROMPT?: string;
};

/** AI 审核三元结果：'pass' 通过 / 'reject' 拦截 / 'error' 网络/超时可重试 */
export type AiModerationVerdict = 'pass' | 'reject' | 'error';

/**
 * AI 内容审核（队列 worker 用）。
 *
 * 返回三元结果，让队列区分：
 *   - 'pass'   → 放行（AI 明确 PASS）
 *   - 'reject' → 拦截（AI 明确 REJECT；或决策不明/JSON 解析失败 → 仍按拦截，与原 fail-closed 语义一致）
 *   - 'error'  → 网络/超时异常，可重试（区别于原同步版本"异常默认放行"的 fail-open 语义；
 *                队列场景下用重试+耗尽兜底处理，而非直接放行）
 *
 * 未配置 API_KEY 时返回 'pass'（跳过审核，对齐原行为）。
 */
export async function aiModerationReview(content: string): Promise<AiModerationVerdict> {
  const ai = getConfig().AI_MODERATION as AiModerationConfig | undefined;
  if (!ai || !ai.API_KEY) return 'pass';

  const headers: Record<string, string> = {
    Authorization: `Bearer ${ai.API_KEY}`,
    'Content-Type': 'application/json',
  };
  const payload = {
    model: ai.MODEL || 'deepseek-chat',
    messages: [
      { role: 'system', content: ai.SYSTEM_PROMPT || DEFAULT_SYSTEM_PROMPT },
      { role: 'user', content: `请审核以下内容：\n\n${content}` },
    ],
    temperature: 0.0,
    max_tokens: 100,
    response_format: { type: 'json_object' }, // 强制 JSON 输出，避免思考型模型在 content 里输出思考过程
  };

  try {
    const resp = await fetch(`${ai.BASE_URL}/chat/completions`, {
      method: 'POST',
      headers,
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(5000),
    });
    const data = (await resp.json()) as { choices?: { message?: { content?: string } }[] };
    const raw = (data.choices?.[0]?.message?.content ?? '').trim();
    console.info(`[moderation] AI Raw Response: [${raw}]`);

    try {
      const result = JSON.parse(raw) as { decision?: string };
      const decision = (result.decision ?? '').toUpperCase();
      if (decision === 'REJECT') {
        console.info('[moderation] AI 判别结果：拦截');
        return 'reject';
      }
      if (decision === 'PASS') {
        console.info('[moderation] AI 判别结果：通过');
        return 'pass';
      }
      console.warn(`[moderation] AI 返回了不明确的决策: ${decision}，默认拦截`);
      return 'reject';
    } catch {
      console.warn(`[moderation] AI 响应 JSON 解析失败: [${raw}]，默认拦截`);
      return 'reject';
    }
  } catch (e) {
    console.error('[moderation] AI 审计请求异常:', e);
    // 网络/超时 → 可重试错误（队列场景）
    return 'error';
  }
}
