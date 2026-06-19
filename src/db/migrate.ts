// =============================================================================
// 启动期建表 —— 等价于原 Flask `db.create_all()`
// 直接用 DDL 显式创建所有表（IF NOT EXISTS），不依赖 drizzle-kit generate，
// 这样全新部署和读取旧库都无需额外步骤。
// =============================================================================
import { sqlite } from './index.js';

const DDL_STATEMENTS: string[] = [
  `CREATE TABLE IF NOT EXISTS message (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    content TEXT NOT NULL,
    created_at DATETIME DEFAULT (datetime('now')),
    location TEXT DEFAULT '广州',
    unique_identifier TEXT,
    sender_id INTEGER REFERENCES message(id),
    delivery_type TEXT DEFAULT 'public',
    delivery_options TEXT,
    reply_notification TEXT DEFAULT 'none',
    is_anonymous BOOLEAN DEFAULT 1,
    reply_to_id INTEGER REFERENCES message(id),
    hugs_count INTEGER DEFAULT 0,
    sender_email TEXT,
    public_after_reply BOOLEAN DEFAULT 0
  )`,
  `CREATE TABLE IF NOT EXISTS location_weather_cache (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    city TEXT NOT NULL UNIQUE,
    weather_status TEXT NOT NULL,
    weather_text TEXT,
    icon_code TEXT,
    raw_weather_data TEXT,
    last_updated DATETIME DEFAULT (datetime('now')),
    last_used_api_index INTEGER DEFAULT 0
  )`,
  `CREATE TABLE IF NOT EXISTS ip_location_cache (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT NOT NULL UNIQUE,
    city TEXT NOT NULL,
    created_at DATETIME DEFAULT (datetime('now')),
    updated_at DATETIME DEFAULT (datetime('now'))
  )`,
  `CREATE TABLE IF NOT EXISTS user (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    username TEXT,
    city TEXT DEFAULT '广州',
    is_verified BOOLEAN DEFAULT 0,
    verification_token TEXT,
    created_at DATETIME DEFAULT (datetime('now')),
    last_login DATETIME
  )`,
  `CREATE TABLE IF NOT EXISTS letter_delivery (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    message_id INTEGER REFERENCES message(id),
    recipient_email TEXT,
    recipient_user_id INTEGER REFERENCES user(id),
    recipient_city TEXT,
    delivery_status TEXT DEFAULT 'pending',
    unlock_token TEXT,
    unlocked_at DATETIME,
    read_at DATETIME,
    created_at DATETIME DEFAULT (datetime('now'))
  )`,
  `CREATE TABLE IF NOT EXISTS message_reply (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    original_message_id INTEGER REFERENCES message(id),
    reply_content TEXT,
    reply_type TEXT DEFAULT 'text',
    replier_user_id INTEGER REFERENCES user(id),
    replier_email TEXT,
    created_at DATETIME DEFAULT (datetime('now'))
  )`,
  `CREATE TABLE IF NOT EXISTS failed_login_attempt (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    identifier TEXT NOT NULL,
    identifier_type TEXT NOT NULL,
    attempt_count INTEGER DEFAULT 1,
    last_attempt_at DATETIME DEFAULT (datetime('now')),
    is_locked BOOLEAN DEFAULT 0,
    locked_until DATETIME,
    created_at DATETIME DEFAULT (datetime('now'))
  )`,
  `CREATE INDEX IF NOT EXISTS ix_failed_login_attempt_identifier ON failed_login_attempt (identifier)`,
  `CREATE TABLE IF NOT EXISTS notification (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER REFERENCES user(id),
    email TEXT,
    notification_type TEXT,
    title TEXT,
    content TEXT,
    related_id INTEGER,
    is_read BOOLEAN DEFAULT 0,
    created_at DATETIME DEFAULT (datetime('now'))
  )`,
  `CREATE TABLE IF NOT EXISTS email_queue (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    recipient_email TEXT,
    email_type TEXT,
    subject TEXT,
    body_html TEXT,
    status TEXT DEFAULT 'pending',
    attempts INTEGER DEFAULT 0,
    sent_at DATETIME,
    created_at DATETIME DEFAULT (datetime('now'))
  )`,
];

/** 创建所有表（幂等） */
export function ensureSchema(): void {
  const tx = sqlite.transaction(() => {
    for (const stmt of DDL_STATEMENTS) sqlite.exec(stmt);
  });
  tx();
  console.log('[INFO] 数据库表已就绪');
}

// 作为脚本直接运行时（npm run db:migrate）
const isMain = (() => {
  try {
    return process.argv[1] && import.meta.url.endsWith(process.argv[1].replace(/.*\//, '')) === false
      ? false
      : false;
  } catch {
    return false;
  }
})();

// 简单的 main 检测：通过环境变量标记
if (process.env.RUN_DB_MIGRATE === '1') {
  ensureSchema();
  console.log('[OK] 迁移完成');
  process.exit(0);
}

void isMain;
