// =============================================================================
// API 基础层 —— CSRF 单例 + apiFetch（403-CSRF 自动重试一次）
// 移植自 static/js/csrf.js 的 fetchWithCSRF，行为逐字对齐：
//   - header 名 X-CSRF-Token
//   - 首次 lazy 取 token，模块级单例缓存
//   - 遇 HTTP 403 且 error 含 "CSRF" → 重新取 token + 原请求重试一次（不循环）
// =============================================================================
import type { ApiError } from '@/types/api';

let csrfToken: string | null = null;
let csrfPromise: Promise<string> | null = null;

async function fetchCsrfToken(): Promise<string> {
  if (csrfPromise) return csrfPromise;
  csrfPromise = fetch('/api/csrf_token', { credentials: 'same-origin' })
    .then((r) => r.json())
    .then((d: { csrf_token?: string }) => {
      csrfToken = d.csrf_token ?? null;
      csrfPromise = null;
      return d.csrf_token ?? '';
    })
    .catch((e) => {
      csrfPromise = null;
      throw e;
    });
  return csrfPromise;
}

/** 取当前 CSRF token（lazy 拉取） */
export async function getCsrfToken(): Promise<string> {
  if (!csrfToken) await fetchCsrfToken();
  return csrfToken ?? '';
}

export interface ApiFetchOptions extends RequestInit {
  /** 是否附带 CSRF 头，默认 true */
  csrf?: boolean;
  /** JSON 请求体（自动 stringify + Content-Type） */
  json?: unknown;
}

/**
 * 统一 fetch 封装。默认 same-origin（携带 session cookie）+ CSRF 头。
 * 遇 CSRF 过期会自动重试一次。
 */
export async function apiFetch<T = unknown>(
  url: string,
  options: ApiFetchOptions = {},
): Promise<T> {
  const { csrf = true, json, headers, body, ...rest } = options;

  const finalHeaders: Record<string, string> = {
    ...(headers as Record<string, string> | undefined),
  };
  let finalBody = body;
  if (json !== undefined) {
    finalHeaders['Content-Type'] = 'application/json';
    finalBody = JSON.stringify(json);
  }
  if (csrf) {
    finalHeaders['X-CSRF-Token'] = await getCsrfToken();
  }

  const doFetch = () =>
    fetch(url, {
      credentials: 'same-origin',
      ...rest,
      headers: finalHeaders,
      body: finalBody,
    });

  let response = await doFetch();

  // CSRF 过期 → 重取 + 重试一次（仅当 403 且 error 含 "CSRF"）
  if (response.status === 403 && csrf) {
    try {
      const data = (await response.clone().json()) as ApiError;
      if (typeof data.error === 'string' && data.error.includes('CSRF')) {
        csrfToken = null;
        csrfPromise = null;
        finalHeaders['X-CSRF-Token'] = await getCsrfToken();
        response = await doFetch();
      }
    } catch {
      // 非 JSON 响应，忽略
    }
  }

  return response as unknown as T;
}

/**
 * 解析 JSON 响应，附带 HTTP 状态码。
 * 失败时抛出带 { status, error } 的对象，便于调用方按状态/字段分支处理。
 */
export async function apiJson<T = unknown>(
  url: string,
  options: ApiFetchOptions = {},
): Promise<{ status: number; data: T }> {
  const response = (await apiFetch<Response>(url, options)) as unknown as Response;
  let data: unknown = null;
  const text = await response.text();
  if (text) {
    try {
      data = JSON.parse(text);
    } catch {
      data = text;
    }
  }
  return { status: response.status, data: data as T };
}

export type ApiResult<T> = { ok: true; status: number; data: T } | { ok: false; status: number; data: ApiError };

/** 便捷封装：ok/err 二分，err 含完整错误体（含 require_login/blocked/locked_until 等额外字段） */
export async function api<T = unknown>(url: string, options: ApiFetchOptions = {}): Promise<ApiResult<T>> {
  const { status, data } = await apiJson<T & ApiError>(url, options);
  if (status >= 200 && status < 300) return { ok: true, status, data: data as T };
  return { ok: false, status, data: (data as ApiError) ?? { error: '请求失败' } };
}
