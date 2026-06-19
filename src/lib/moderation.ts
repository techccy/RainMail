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

/**
 * AI 内容审核
 * @returns true 表示应拦截，false 表示放行
 * 行为对齐 Python：解析失败默认拦截，请求异常默认放行
 */
export async function aiModerationCheck(content: string): Promise<boolean> {
  const ai = getConfig().AI_MODERATION as { API_KEY?: string; BASE_URL?: string; MODEL?: string; SYSTEM_PROMPT?: string } | undefined;
  if (!ai || !ai.API_KEY) return false;

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
        return true;
      }
      if (decision === 'PASS') {
        console.info('[moderation] AI 判别结果：通过');
        return false;
      }
      console.warn(`[moderation] AI 返回了不明确的决策: ${decision}，默认拦截`);
      return true;
    } catch {
      console.warn(`[moderation] AI 响应 JSON 解析失败: [${raw}]，默认拦截`);
      return true;
    }
  } catch (e) {
    console.error('[moderation] AI 审计请求异常:', e);
    // 异常默认放行
    return false;
  }
}
