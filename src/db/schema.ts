// =============================================================================
// Drizzle ORM Schema —— 对齐原 Flask/SQLAlchemy 模型
// 表名、列名与原 SQLite 完全一致，保证可直接读取旧库 / 兼容 migrate_db 历史
// 日期列以 TEXT 存 ISO-8601 字符串（与 SQLAlchemy 在 SQLite 上的默认一致）
// 已移除微信相关表 WeChatBinding
// =============================================================================
import { sql } from 'drizzle-orm';
import { sqliteTable, text, integer, index, uniqueIndex } from 'drizzle-orm/sqlite-core';

/** 当前 UTC ISO-8601 字符串（默认值用） */
const nowIso = () => sql`(datetime('now'))`;

// ----------------------------- message -----------------------------
// 注意：reply_to_id 自引用使用无返回类型推断的 () => messages.id，
// 需先声明以避免循环类型推断（TS7022）。这里改用普通 integer + 手动外键语义。
export const messages = sqliteTable('message', {
  id: integer('id').primaryKey({ autoIncrement: true }),
  content: text('content').notNull(),
  created_at: text('created_at').default(nowIso()),
  location: text('location').default('广州'),
  unique_identifier: text('unique_identifier'),
  // 情感投递系统字段
  sender_id: integer('sender_id'),
  delivery_type: text('delivery_type').default('public'), // 'public' | 'private'
  delivery_options: text('delivery_options'), // JSON 字符串
  reply_notification: text('reply_notification').default('none'), // 'none' | 'email'
  is_anonymous: integer('is_anonymous', { mode: 'boolean' }).default(true),
  reply_to_id: integer('reply_to_id'),
  hugs_count: integer('hugs_count').default(0),
  sender_email: text('sender_email'),
  public_after_reply: integer('public_after_reply', { mode: 'boolean' }).default(false),
  // 删除安全码的 HMAC-SHA-256 哈希（绝不存明文）；用于未登录场景凭码删除。
  // 密钥复用 getConfig().SECRET_KEY；历史行 NULL = 无法凭码删除。
  delete_code_hash: text('delete_code_hash'),
  // AI 审核队列字段
  // 'pending' = 等待 AI 审核；'approved' = 已通过（默认，未配置 AI 时即写即发）；'rejected' = 已拦截/重试耗尽
  review_status: text('review_status').default('approved'),
  review_attempts: integer('review_attempts').default(0),
});

// ----------------------------- location_weather_cache -----------------------------
export const locationWeatherCache = sqliteTable(
  'location_weather_cache',
  {
    id: integer('id').primaryKey({ autoIncrement: true }),
    city: text('city').notNull().unique(),
    weather_status: text('weather_status').notNull(), // 'sunny' | 'rainy'
    weather_text: text('weather_text'),
    icon_code: text('icon_code'),
    raw_weather_data: text('raw_weather_data'),
    last_updated: text('last_updated').default(nowIso()),
    last_used_api_index: integer('last_used_api_index').default(0),
  },
);

// ----------------------------- ip_location_cache -----------------------------
export const ipLocationCache = sqliteTable(
  'ip_location_cache',
  {
    id: integer('id').primaryKey({ autoIncrement: true }),
    ip_address: text('ip_address').notNull().unique(),
    city: text('city').notNull(),
    created_at: text('created_at').default(nowIso()),
    updated_at: text('updated_at').default(nowIso()),
  },
);

// ----------------------------- user -----------------------------
export const users = sqliteTable('user', {
  id: integer('id').primaryKey({ autoIncrement: true }),
  email: text('email').notNull().unique(),
  password_hash: text('password_hash').notNull(),
  username: text('username'),
  city: text('city').default('广州'),
  is_verified: integer('is_verified', { mode: 'boolean' }).default(false),
  verification_token: text('verification_token'),
  created_at: text('created_at').default(nowIso()),
  last_login: text('last_login'),
});

// ----------------------------- letter_delivery -----------------------------
export const letterDeliveries = sqliteTable(
  'letter_delivery',
  {
    id: integer('id').primaryKey({ autoIncrement: true }),
    message_id: integer('message_id').references(() => messages.id),
    recipient_email: text('recipient_email'),
    recipient_user_id: integer('recipient_user_id').references(() => users.id),
    recipient_city: text('recipient_city'),
    delivery_status: text('delivery_status').default('pending'), // pending/delivered/read/public
    unlock_token: text('unlock_token'),
    unlocked_at: text('unlocked_at'),
    read_at: text('read_at'),
    created_at: text('created_at').default(nowIso()),
  },
);

// ----------------------------- message_reply -----------------------------
export const messageReplies = sqliteTable('message_reply', {
  id: integer('id').primaryKey({ autoIncrement: true }),
  original_message_id: integer('original_message_id').references(() => messages.id),
  reply_content: text('reply_content'),
  reply_type: text('reply_type').default('text'), // 'text' | 'hug'
  replier_user_id: integer('replier_user_id').references(() => users.id),
  replier_email: text('replier_email'),
  created_at: text('created_at').default(nowIso()),
  // AI 审核队列字段（语义同 message）
  review_status: text('review_status').default('approved'),
  review_attempts: integer('review_attempts').default(0),
});

// ----------------------------- failed_login_attempt -----------------------------
export const failedLoginAttempts = sqliteTable(
  'failed_login_attempt',
  {
    id: integer('id').primaryKey({ autoIncrement: true }),
    identifier: text('identifier').notNull(),
    identifier_type: text('identifier_type').notNull(), // 'email' | 'ip'
    attempt_count: integer('attempt_count').default(1),
    last_attempt_at: text('last_attempt_at').default(nowIso()),
    is_locked: integer('is_locked', { mode: 'boolean' }).default(false),
    locked_until: text('locked_until'),
    created_at: text('created_at').default(nowIso()),
  },
  (t) => ({
    identifierIdx: index('ix_failed_login_attempt_identifier').on(t.identifier),
  }),
);

// ----------------------------- notification -----------------------------
export const notifications = sqliteTable('notification', {
  id: integer('id').primaryKey({ autoIncrement: true }),
  user_id: integer('user_id').references(() => users.id),
  email: text('email'),
  notification_type: text('notification_type'),
  title: text('title'),
  content: text('content'),
  related_id: integer('related_id'),
  is_read: integer('is_read', { mode: 'boolean' }).default(false),
  created_at: text('created_at').default(nowIso()),
});

// ----------------------------- email_queue -----------------------------
export const emailQueue = sqliteTable('email_queue', {
  id: integer('id').primaryKey({ autoIncrement: true }),
  recipient_email: text('recipient_email'),
  email_type: text('email_type'),
  subject: text('subject'),
  body_html: text('body_html'),
  status: text('status').default('pending'),
  attempts: integer('attempts').default(0),
  sent_at: text('sent_at'),
  created_at: text('created_at').default(nowIso()),
});

// ----------------------------- 类型导出（便于路由使用） -----------------------------
export type Message = typeof messages.$inferSelect;
export type NewMessage = typeof messages.$inferInsert;
export type User = typeof users.$inferSelect;
export type NewUser = typeof users.$inferInsert;
export type LetterDelivery = typeof letterDeliveries.$inferSelect;
export type MessageReply = typeof messageReplies.$inferSelect;
export type Notification = typeof notifications.$inferSelect;
export type EmailQueueRow = typeof emailQueue.$inferSelect;
export type FailedLoginAttempt = typeof failedLoginAttempts.$inferSelect;
export type LocationWeatherCache = typeof locationWeatherCache.$inferSelect;
export type IpLocationCache = typeof ipLocationCache.$inferSelect;
