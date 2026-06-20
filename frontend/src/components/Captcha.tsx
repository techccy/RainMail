// =============================================================================
// Captcha 组件 —— 按 captcha_provider 渲染，通过 ref 暴露 getToken()
// provider: none（空）/ cloudflare(Turnstile) / recaptcha|recaptcha_v3(invisible)
//           / cha(数学题) / altcha(PoW)
// 提交后调用 refresh() 刷新一次性 token。
// =============================================================================
import { forwardRef, useEffect, useImperativeHandle, useRef, useState } from 'react';
import { Input } from '@/components/ui/input';
import { getBootstrap } from '@/lib/config';
import {
  captchaFieldName,
  fetchAltchaChallenge,
  fetchChaQuestion,
  loadScript,
  solveAltcha,
  type CaptchaField,
} from '@/lib/captcha';
import type { ChaQuestion } from '@/types/api';

export interface CaptchaHandle {
  /** 获取当前验证码 token（失败抛错），返回 {field, value} 或 null（none/未启用） */
  getToken: () => Promise<CaptchaField | null>;
  /** 提交后刷新一次性 token（成功或失败都调） */
  refresh: () => Promise<void>;
}

interface Props {
  /** reCAPTCHA action（home=submit / login=login / register=register） */
  action: string;
}

const TURNSTILE_SCRIPT = 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit';

export const Captcha = forwardRef<CaptchaHandle, Props>(function Captcha({ action }, ref) {
  const provider = getBootstrap()?.captcha_provider ?? 'none';
  const turnstileSiteKey = getBootstrap()?.turnstile_site_key ?? '';
  const recaptchaSiteKey = getBootstrap()?.recaptcha_site_key ?? '';

  const [cha, setCha] = useState<ChaQuestion | null>(null);
  const [chaAnswer, setChaAnswer] = useState('');
  const [altchaPayload, setAltchaPayload] = useState<string | null>(null);
  const [altchaProgress, setAltchaProgress] = useState(0);

  const containerRef = useRef<HTMLDivElement>(null);
  const turnstileIdRef = useRef<string | null>(null);
  const recaptchaTokenRef = useRef<string>('');

  // ---- cloudflare turnstile 渲染 ----
  useEffect(() => {
    if (provider !== 'cloudflare' || !turnstileSiteKey || !containerRef.current) return;
    let cancelled = false;
    void loadScript(TURNSTILE_SCRIPT).then(() => {
      if (cancelled || !containerRef.current || !window.turnstile) return;
      if (turnstileIdRef.current) return;
      turnstileIdRef.current = window.turnstile.render(containerRef.current, {
        sitekey: turnstileSiteKey,
        callback: () => {},
      });
    });
    return () => {
      cancelled = true;
    };
  }, [provider, turnstileSiteKey]);

  // ---- recaptcha invisible：提交时 execute ----
  useEffect(() => {
    if (!(provider === 'recaptcha' || provider === 'recaptcha_v3') || !recaptchaSiteKey) return;
    void loadScript(`https://www.google.com/recaptcha/api.js?render=${recaptchaSiteKey}`);
  }, [provider, recaptchaSiteKey]);

  // ---- cha：加载题目 ----
  const loadCha = async () => {
    if (provider !== 'cha') return;
    const q = await fetchChaQuestion();
    if (q) {
      setCha(q);
      setChaAnswer('');
    }
  };
  useEffect(() => {
    void loadCha();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [provider]);

  // ---- altcha：加载挑战并求解 ----
  const loadAltcha = async () => {
    if (provider !== 'altcha') return;
    const challenge = await fetchAltchaChallenge();
    if (!challenge) return;
    setAltchaPayload(null);
    setAltchaProgress(0);
    const payload = await solveAltcha(challenge, setAltchaProgress);
    if (payload) setAltchaPayload(payload);
  };
  useEffect(() => {
    void loadAltcha();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [provider]);

  const refresh = async () => {
    if (provider === 'cloudflare' && turnstileIdRef.current && window.turnstile) {
      window.turnstile.reset(turnstileIdRef.current);
    } else if (provider === 'recaptcha' || provider === 'recaptcha_v3') {
      recaptchaTokenRef.current = '';
    } else if (provider === 'cha') {
      await loadCha();
    } else if (provider === 'altcha') {
      await loadAltcha();
    }
  };

  const getToken = async (): Promise<CaptchaField | null> => {
    const field = captchaFieldName(provider);
    if (!field) return null; // none

    if (provider === 'cloudflare') {
      const v = turnstileIdRef.current && window.turnstile ? window.turnstile.getResponse(turnstileIdRef.current) : '';
      return { field, value: v };
    }
    if (provider === 'recaptcha' || provider === 'recaptcha_v3') {
      // invisible：执行获取 token
      if (!recaptchaSiteKey || !window.grecaptcha) {
        return { field, value: '' };
      }
      const token = await window.grecaptcha.execute(recaptchaSiteKey, { action });
      recaptchaTokenRef.current = token;
      return { field, value: token };
    }
    if (provider === 'cha') {
      return { field, value: chaAnswer.trim() };
    }
    if (provider === 'altcha') {
      return { field, value: altchaPayload ?? '' };
    }
    return null;
  };

  useImperativeHandle(ref, () => ({ getToken, refresh }), [provider, action, chaAnswer, altchaPayload]);

  if (provider === 'none') return null;

  if (provider === 'cloudflare') {
    return <div ref={containerRef} className="min-h-[65px]" />;
  }

  if (provider === 'recaptcha' || provider === 'recaptcha_v3') {
    return <p className="text-xs text-muted-foreground">受 reCAPTCHA 保护（提交时自动验证）</p>;
  }

  if (provider === 'cha') {
    return (
      <div className="space-y-2">
        <p className="text-sm font-medium">{cha?.question ?? '加载验证题...'}</p>
        <Input
          value={chaAnswer}
          onChange={(e) => setChaAnswer(e.target.value)}
          placeholder="输入答案"
          autoComplete="off"
        />
      </div>
    );
  }

  if (provider === 'altcha') {
    return (
      <div className="space-y-1">
        {altchaPayload ? (
          <p className="text-xs text-muted-foreground">✓ 已完成工作量验证</p>
        ) : (
          <p className="text-xs text-muted-foreground">正在计算工作量证明... {altchaProgress}%</p>
        )}
      </div>
    );
  }

  return null;
});
