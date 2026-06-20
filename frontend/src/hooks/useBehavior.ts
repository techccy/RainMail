// =============================================================================
// 行为验证 hook —— 移植自 static/js/behavior-tracker.js
//   - mount 记录 pageLoadTime
//   - 计数首次 focus 的输入框、累计字符
//   - 提供 validate()（停留≥4s、focus≥1、char≥1），文案逐字对齐原版
//   - getBehaviorData() 返回 form_token + 4 个字段，供 POST /api/messages 合并
// form_token 为页面级单例（GET /api/form_token），提交后可复用（对齐原 app.js 不调 reset 的行为）
// =============================================================================
import { useCallback, useEffect, useRef, useState } from 'react';

const MIN_STAY_TIME = 4; // 秒

interface BehaviorData {
  form_token: string;
  page_stay_time: number;
  input_focus_count: number;
  input_char_count: number;
}

export function useBehavior() {
  const pageLoadTimeRef = useRef<number>(Date.now());
  const focusCountRef = useRef(0);
  const charCountRef = useRef(0);
  const focusedSetRef = useRef<Set<string>>(new Set());
  const [formToken, setFormToken] = useState<string>('');

  // 拉取 form_token（页面级单例）
  const fetchFormToken = useCallback(async () => {
    try {
      const res = await fetch('/api/form_token', { credentials: 'same-origin' });
      const d = (await res.json()) as { form_token?: string };
      if (d.form_token) setFormToken(d.form_token);
    } catch {
      // 忽略
    }
  }, []);

  useEffect(() => {
    void fetchFormToken();
  }, [fetchFormToken]);

  /** textarea/input 的 onFocus 回调：仅首次 focus 计数 */
  const handleFocus = useCallback((id: string) => {
    if (!focusedSetRef.current.has(id)) {
      focusedSetRef.current.add(id);
      focusCountRef.current += 1;
    }
  }, []);

  /** 累计字符变化（每次 input 调用，传当前 value 长度增量） */
  const handleInput = useCallback((addedChars: number) => {
    if (addedChars > 0) charCountRef.current += addedChars;
  }, []);

  /** 校验，返回 null 或错误文案（逐字对齐 behavior-tracker.js） */
  const validate = useCallback((): string | null => {
    const pageStayTime = Math.floor((Date.now() - pageLoadTimeRef.current) / 1000);
    if (pageStayTime < MIN_STAY_TIME) {
      return `请在页面停留至少${MIN_STAY_TIME}秒后再提交（当前：${pageStayTime}秒）`;
    }
    if (focusCountRef.current < 1) return '请先在输入框中输入内容';
    if (charCountRef.current < 1) return '请输入有效内容';
    return null;
  }, []);

  /** 组装提交用的行为字段（form_token 缺失时返回 null） */
  const getBehaviorData = useCallback((): BehaviorData | null => {
    if (!formToken) return null;
    return {
      form_token: formToken,
      page_stay_time: Math.floor((Date.now() - pageLoadTimeRef.current) / 1000),
      input_focus_count: focusCountRef.current,
      input_char_count: charCountRef.current,
    };
  }, [formToken]);

  /** 重新拉取 form_token（可选，原版提交后不调用） */
  const reset = useCallback(() => {
    focusCountRef.current = 0;
    charCountRef.current = 0;
    focusedSetRef.current.clear();
    void fetchFormToken();
  }, [fetchFormToken]);

  return { handleFocus, handleInput, validate, getBehaviorData, reset };
}
