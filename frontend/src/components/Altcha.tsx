// =============================================================================
// Altcha —— 工作量证明人机验证组件
//
// 行为：
//   - 挂载时读取 bootstrap.altcha_enabled 判断是否启用
//   - 启用则后台拉取挑战并预计算 PoW（用户填表期间已求解，UX 无感）
//   - 通过 ref 暴露 getPayload()（取已算好的 payload）与 refresh()（换新挑战重算）
//   - 未启用（altcha_enabled=false）渲染 null，getPayload 返回 null
// =============================================================================
import { forwardRef, useEffect, useImperativeHandle, useRef, useState } from 'react';
import { loadBootstrap } from '@/lib/config';
import { fetchAltchaChallenge, solveAltchaPoW } from '@/lib/altcha';

export interface AltchaHandle {
  /** 取已求解的 payload（未启用或未就绪时返回 null） */
  getPayload: () => string | null;
  /** 提交后换新挑战并重算（PoW 一次性，无论成功失败都应调用） */
  refresh: () => Promise<void>;
}

export const Altcha = forwardRef<AltchaHandle>(function Altcha(_props, ref) {
  const [enabled, setEnabled] = useState<boolean | null>(null); // null = 未确定
  const [progress, setProgress] = useState(0);
  const [payload, setPayload] = useState<string | null>(null);
  const [failed, setFailed] = useState(false);

  // 用 ref 持有最新 payload，避免 useImperativeHandle 依赖频繁刷新
  const payloadRef = useRef<string | null>(null);

  const solve = async () => {
    setPayload(null);
    payloadRef.current = null;
    setProgress(0);
    setFailed(false);
    const challenge = await fetchAltchaChallenge();
    if (!challenge) {
      setFailed(true);
      return;
    }
    const result = await solveAltchaPoW(challenge, setProgress);
    if (result) {
      setPayload(result);
      payloadRef.current = result;
    } else {
      setFailed(true);
    }
  };

  // 判定启用状态；启用则自动预求解
  useEffect(() => {
    let cancelled = false;
    void loadBootstrap().then((cfg) => {
      if (cancelled) return;
      const on = !!cfg.altcha_enabled;
      setEnabled(on);
      if (on) void solve();
    });
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const refresh = async () => {
    if (enabled) await solve();
  };

  useImperativeHandle(ref, () => ({ getPayload: () => payloadRef.current, refresh }), [enabled]);

  // 未启用或未确定时不渲染
  if (!enabled) return null;

  if (failed) {
    return (
      <button
        type="button"
        onClick={() => void solve()}
        className="text-xs text-destructive underline hover:text-destructive/80"
      >
        人机验证加载失败，点击重试
      </button>
    );
  }

  if (payload) {
    return <p className="text-xs text-muted-foreground">✓ 已完成人机验证</p>;
  }

  return <p className="text-xs text-muted-foreground">正在计算人机验证... {progress}%</p>;
});
