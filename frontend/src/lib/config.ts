// =============================================================================
// 启动配置 —— GET /api/bootstrap，全局单例
// =============================================================================
import type { BootstrapConfig, CaptchaProvider } from '@/types/api';

let bootstrapCache: BootstrapConfig | null = null;
let bootstrapPromise: Promise<BootstrapConfig> | null = null;

const FALLBACK: BootstrapConfig = {
  captcha_provider: 'none',
  turnstile_site_key: '',
  recaptcha_site_key: '',
  app_name: 'RainMail',
  app_name_cn: '雨天信箱',
};

export async function loadBootstrap(force = false): Promise<BootstrapConfig> {
  if (bootstrapCache && !force) return bootstrapCache;
  if (bootstrapPromise && !force) return bootstrapPromise;
  bootstrapPromise = fetch('/api/bootstrap', { credentials: 'same-origin' })
    .then((r) => r.json())
    .then((d: Partial<BootstrapConfig>) => {
      bootstrapCache = { ...FALLBACK, ...d } as BootstrapConfig;
      bootstrapPromise = null;
      return bootstrapCache;
    })
    .catch(() => {
      bootstrapCache = FALLBACK;
      bootstrapPromise = null;
      return FALLBACK;
    });
  return bootstrapPromise;
}

export function getBootstrap(): BootstrapConfig | null {
  return bootstrapCache;
}

export function getCaptchaProvider(): CaptchaProvider {
  return bootstrapCache?.captcha_provider ?? 'none';
}
