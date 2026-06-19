// =============================================================================
// 配置加载：从环境变量（.env）读取所有配置
// 对应原 Python 版 config_loader.py
// =============================================================================
import dotenv from 'dotenv';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
// src/ -> 项目根
export const PROJECT_ROOT = path.resolve(__dirname, '..');

/** 智能转换环境变量值类型（布尔/数字/字符串），对齐 convert_env_value */
function convertEnvValue(value: string): unknown {
  const lower = value.toLowerCase();
  if (lower === 'true' || lower === 'yes' || lower === '1') return true;
  if (lower === 'false' || lower === 'no' || lower === '0') return false;
  // 数字
  if (/^-?\d+\.\d+$/.test(value)) return parseFloat(value);
  if (/^-?\d+$/.test(value)) return parseInt(value, 10);
  return value;
}

/** 在 config 对象上写入嵌套键，如 "AI_MODERATION.API_KEY" */
function setNestedKey(config: Record<string, any>, key: string, value: unknown): void {
  if (key.includes('.')) {
    const parts = key.split('.');
    let obj = config;
    for (const part of parts.slice(0, -1)) {
      if (typeof obj[part] !== 'object' || obj[part] === null) obj[part] = {};
      obj = obj[part];
    }
    obj[parts[parts.length - 1]!] = value;
  } else {
    config[key] = value;
  }
}

// 环境变量名 -> 配置键（对齐 Python ENV_MAPPINGS，移除全部 WECHAT_*）
const ENV_MAPPINGS: Record<string, string> = {
  // Flask / 通用
  SECRET_KEY: 'SECRET_KEY',

  // 邮件
  MAIL_SERVER: 'MAIL_SERVER',
  MAIL_PORT: 'MAIL_PORT',
  MAIL_USE_TLS: 'MAIL_USE_TLS',
  MAIL_USE_SSL: 'MAIL_USE_SSL',
  MAIL_USERNAME: 'MAIL_USERNAME',
  MAIL_PASSWORD: 'MAIL_PASSWORD',
  MAIL_DEFAULT_SENDER: 'MAIL_DEFAULT_SENDER',
  MAIL_ENABLED: 'MAIL_ENABLED',

  // 人机验证
  CAPTCHA_PROVIDER: 'CAPTCHA_PROVIDER',
  TURNSTILE_SITE_KEY: 'TURNSTILE_SITE_KEY',
  TURNSTILE_SECRET_KEY: 'TURNSTILE_SECRET_KEY',
  RECAPTCHA_V3_SITE_KEY: 'RECAPTCHA_V3_SITE_KEY',
  RECAPTCHA_V3_SECRET_KEY: 'RECAPTCHA_V3_SECRET_KEY',
  RECAPTCHA_V3_THRESHOLD: 'RECAPTCHA_V3_THRESHOLD',
  ALTCHA_HMAC_KEY: 'ALTCHA_HMAC_KEY',
  ALTCHA_DIFFICULTY: 'ALTCHA_DIFFICULTY',
  VERIFY_DURATION_MINUTES: 'VERIFY_DURATION_MINUTES',

  // 和风天气
  HEFENG_HOST1: 'HEFENG_HOST1',
  HEFENG_HOST2: 'HEFENG_HOST2',
  HEFENG_HOST3: 'HEFENG_HOST3',
  HEFENG_HOST4: 'HEFENG_HOST4',
  HEFENG_KEY1: 'HEFENG_KEY1',
  HEFENG_KEY2: 'HEFENG_KEY2',
  HEFENG_KEY3: 'HEFENG_KEY3',
  HEFENG_KEY4: 'HEFENG_KEY4',

  // 位置
  LOCATION_ID: 'LOCATION_ID',
  LOCATION_NAME: 'LOCATION_NAME',

  // 管理员
  ADMIN_USERNAME: 'admin_username',
  ADMIN_PASSWORD: 'admin_password',
  ADMIN_PATH_PREFIX: 'admin_path_prefix',

  // AI 审核
  AI_MODERATION_API_KEY: 'AI_MODERATION.API_KEY',
  AI_MODERATION_BASE_URL: 'AI_MODERATION.BASE_URL',
  AI_MODERATION_MODEL: 'AI_MODERATION.MODEL',
  AI_MODERATION_SYSTEM_PROMPT: 'AI_MODERATION.SYSTEM_PROMPT',

  // 邮件模板
  EMAIL_VERIFY_SUBJECT: 'EMAIL_VERIFY_SUBJECT',
  EMAIL_NEW_LETTER_SUBJECT: 'EMAIL_NEW_LETTER_SUBJECT',
  EMAIL_UNLOCKED_SUBJECT: 'EMAIL_UNLOCKED_SUBJECT',
  EMAIL_TEST_SUBJECT: 'EMAIL_TEST_SUBJECT',
  EMAIL_TEST_BODY: 'EMAIL_TEST_BODY',

  // 应用通知模板
  NOTIFICATION_LETTER_UNLOCKED_TITLE: 'NOTIFICATION_LETTER_UNLOCKED_TITLE',
  NOTIFICATION_LETTER_UNLOCKED_CONTENT: 'NOTIFICATION_LETTER_UNLOCKED_CONTENT',

  // 应用配置
  APP_NAME: 'APP_NAME',
  APP_NAME_CN: 'APP_NAME_CN',
  APP_URL: 'APP_URL',

  // 数据库
  DATABASE_PATH: 'DATABASE_PATH',

  // 其他
  TIMES: 'times',
  FORCE_RAIN_DURATION: 'force_rain_duration',
  PRIVATE_DELIVERY_REQUIRE_LOGIN: 'PRIVATE_DELIVERY_REQUIRE_LOGIN',
  IPINFO_TOKEN: 'IPINFO_TOKEN',
  SESSION_COOKIE_SECURE: 'SESSION_COOKIE_SECURE',
  CSP_POLICY: 'CSP_POLICY',
};

export type AppConfig = Record<string, any>;

function loadConfigFromEnv(): AppConfig {
  // 1. 若 .env 存在则加载（否则依赖已注入的环境变量）
  const envPath = path.join(PROJECT_ROOT, '.env');
  if (fs.existsSync(envPath)) {
    dotenv.config({ path: envPath });
  }

  // 2. 必需变量
  const REQUIRED = ['SECRET_KEY'];
  const missing = REQUIRED.filter((v) => !process.env[v]);
  if (missing.length > 0) {
    throw new Error(`缺少必需的环境变量: ${missing.join(', ')}`);
  }

  const config: AppConfig = {};

  // 3. 逐项映射
  for (const [envKey, configKey] of Object.entries(ENV_MAPPINGS)) {
    const raw = process.env[envKey];
    if (raw !== undefined && raw !== null) {
      setNestedKey(config, configKey, convertEnvValue(raw));
    }
  }

  return config;
}

let cachedConfig: AppConfig | null = null;

/** 获取全局配置（单例） */
export function getConfig(): AppConfig {
  if (cachedConfig) return cachedConfig;
  cachedConfig = loadConfigFromEnv();
  console.log('[INFO] 配置已从环境变量加载');
  return cachedConfig;
}

// 不可编辑的配置（来自环境变量），对齐 READ_ONLY_CONFIG_KEYS
export const READ_ONLY_CONFIG_KEYS = new Set<string>([
  'SECRET_KEY',
  'admin_password',
  'HEFENG_KEY1',
  'HEFENG_KEY2',
  'HEFENG_KEY3',
  'HEFENG_KEY4',
  'TURNSTILE_SECRET_KEY',
  'RECAPTCHA_V3_SECRET_KEY',
  'ALTCHA_HMAC_KEY',
  'MAIL_PASSWORD',
  'AI_MODERATION.API.KEY',
  'IPINFO_TOKEN',
]);
