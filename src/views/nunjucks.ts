// =============================================================================
// Nunjucks 渲染层 —— 复用 templates/ 下的 12 个 Jinja2 模板
// 注册兼容 Jinja2 的全局/过滤器：url_for / csrf_token / config /
//   get_flashed_messages / DateTime 包装（支持 .strftime）
// =============================================================================
import nunjucks from 'nunjucks';
import path from 'node:path';
import type { Context } from 'hono';
import { PROJECT_ROOT } from '../config.js';
import { generateCsrfToken } from '../lib/csrf.js';

const env = new nunjucks.Environment(new nunjucks.FileSystemLoader(path.join(PROJECT_ROOT, 'templates')), {
  autoescape: true,
  throwOnUndefined: false,
});

// ----------------------------- DateTime 包装 -----------------------------
// 模板里有 5 处 x.created_at.strftime('%Y-%m-%d %H:%M')，
// 用包装对象支持 strftime 调用，避免改模板
export class DateTime {
  constructor(public readonly raw: Date | string | null) {}

  private toDate(): Date | null {
    if (!this.raw) return null;
    if (this.raw instanceof Date) return this.raw;
    const v = this.raw.includes('T') ? this.raw : this.raw.replace(' ', 'T') + 'Z';
    const d = new Date(v);
    return isNaN(d.getTime()) ? null : d;
  }

  strftime(fmt: string): string {
    const d = this.toDate();
    if (!d) return '';
    // 简化版 strftime，覆盖模板用到的 %Y %m %d %H %M %S
    const p = (n: number) => String(n).padStart(2, '0');
    const map: Record<string, string> = {
      '%Y': String(d.getFullYear()),
      '%m': p(d.getMonth() + 1),
      '%d': p(d.getDate()),
      '%H': p(d.getHours()),
      '%M': p(d.getMinutes()),
      '%S': p(d.getSeconds()),
    };
    return fmt.replace(/%[YmdHMS]/g, (m) => map[m] ?? m);
  }

  toString(): string {
    const d = this.toDate();
    if (!d) return '';
    const p = (n: number) => String(n).padStart(2, '0');
    return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
  }
}

/** 把行对象里的时间字段包装成 DateTime（递归一层） */
export function wrapDates<T extends Record<string, any>>(row: T, dateFields: (keyof T)[] = []): T {
  const out: any = { ...row };
  for (const f of dateFields) {
    if (out[f] !== undefined && out[f] !== null && !(out[f] instanceof DateTime)) {
      out[f] = new DateTime(out[f]);
    }
  }
  return out;
}

// ----------------------------- 路由名 -> 路径映射 -----------------------------
// 对齐 Flask url_for('endpoint_name')。注意 admin 路径带可配置前缀
let adminPrefix = 'admin';
export function setAdminPrefix(p: string): void {
  adminPrefix = p || 'admin';
}

const ROUTE_MAP: Record<string, () => string> = {
  index: () => '/',
  login_page: () => '/auth/login',
  register_page: () => '/auth/register',
  user_settings: () => '/user/settings',
  admin_login: () => `/${adminPrefix}/`,
  admin_dashboard: () => `/${adminPrefix}/dashboard`,
  admin_logout: () => `/${adminPrefix}/logout`,
};

function urlFor(name: string, opts?: Record<string, string>): string {
  if (name === 'static') {
    return `/static/${opts?.filename ?? ''}`;
  }
  const fn = ROUTE_MAP[name];
  return fn ? fn() : '#';
}

// ----------------------------- flash 消息 -----------------------------
// 基于 Context 的临时存储（一次请求内有效）
const FLASH_KEY = '__flash__';

type FlashEntry = [string, string]; // [category, message]

export function flash(c: Context, category: string, message: string): void {
  const arr = (c.get(FLASH_KEY) as FlashEntry[] | undefined) ?? [];
  arr.push([category, message]);
  c.set(FLASH_KEY, arr);
}

function getFlashedMessages(c: Context, opts?: { with_categories?: boolean }): FlashEntry[] | string[] {
  const arr = (c.get(FLASH_KEY) as FlashEntry[] | undefined) ?? [];
  if (opts?.with_categories) return arr;
  return arr.map(([, m]) => m);
}

// ----------------------------- 渲染入口 -----------------------------
export interface RenderOpts {
  c?: Context; // 传入则注入 csrf_token / flash / config
}

/**
 * 渲染模板
 * @param name 模板相对路径，如 'index.html' / 'auth/login.html'
 * @param ctx 模板变量
 * @param honoCtx Hono 上下文（用于 csrf_token / flash）
 */
export function render(name: string, ctx: Record<string, any> = {}, honoCtx?: Context): string {
  const data: Record<string, any> = { ...ctx };

  if (honoCtx) {
    data.csrf_token = () => generateCsrfToken(honoCtx);
    data.get_flashed_messages = (opts?: { with_categories?: boolean }) => getFlashedMessages(honoCtx, opts);
  } else {
    data.csrf_token = () => '';
    data.get_flashed_messages = () => [];
  }
  data.url_for = urlFor;
  data.config = { ADMIN_PATH_PREFIX: adminPrefix };
  data.admin_path_prefix = adminPrefix;
  data.current_year = new Date().getFullYear();

  return env.render(name, data);
}

// 便于外部引用
export { env as nunjucksEnv };
