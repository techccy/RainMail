// =============================================================================
// Drizzle 实例 + 数据库文件路径解析
// 对齐原 app.py：DATABASE_PATH 默认 sqlite:///instance/rainmail.db
// =============================================================================
import Database from 'better-sqlite3';
import { drizzle, type BetterSQLite3Database } from 'drizzle-orm/better-sqlite3';
import fs from 'node:fs';
import path from 'node:path';
import { PROJECT_ROOT, getConfig } from '../config.js';
import * as schema from './schema.js';

/**
 * 解析数据库文件绝对路径（兼容 SQLAlchemy/Flask 的 sqlite URI 约定）：
 *   sqlite:///path   （3 个斜杠）= 相对路径 path
 *   sqlite:////path  （4 个斜杠）= 绝对路径 /path
 *   path / /abs/path            = 直接使用
 */
export function resolveDbPath(): string {
  const cfg = getConfig();
  const raw = (cfg.DATABASE_PATH as string | undefined) || 'sqlite:///instance/rainmail.db';

  let stripped = raw;
  if (stripped.startsWith('sqlite:///')) {
    // 4 斜杠（绝对）：sqlite:////abs -> /abs ；3 斜杠（相对）：sqlite:///rel -> rel
    if (stripped.startsWith('sqlite:////')) {
      stripped = stripped.slice('sqlite:///'.length); // 保留开头的 '/'
    } else {
      stripped = stripped.slice('sqlite:///'.length); // 去掉前缀，得到相对路径
    }
  }

  let dbFile: string;
  if (path.isAbsolute(stripped)) {
    dbFile = stripped;
  } else {
    dbFile = path.join(PROJECT_ROOT, stripped);
  }

  // 确保目录存在（对齐原 app.py 启动期 mkdir）
  const dir = path.dirname(dbFile);
  if (dir && !fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }

  return dbFile;
}

const dbFile = resolveDbPath();
console.log(`[INFO] 数据库路径: sqlite:///${path.relative(PROJECT_ROOT, dbFile) || dbFile}`);

// better-sqlite3 需开启外键约束（SQLite 默认关闭）
const sqlite = new Database(dbFile);
sqlite.pragma('journal_mode = WAL');
sqlite.pragma('foreign_keys = ON');

export const db: BetterSQLite3Database<typeof schema> = drizzle(sqlite, { schema });
export { sqlite };

/** 将任意 Date / ISO 字符串 / 时间戳 格式化为 'YYYY-MM-DD HH:MM:SS'（对齐 Python strftime） */
export function fmtDateTime(value: Date | string | number | null | undefined): string | null {
  if (value === null || value === undefined) return null;
  const d = value instanceof Date ? value : new Date(value);
  if (isNaN(d.getTime())) return null;
  const p = (n: number) => String(n).padStart(2, '0');
  return (
    `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ` +
    `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`
  );
}

/** 当前 ISO-8601 字符串（用于写入 created_at 等） */
export function nowIso(): string {
  return new Date().toISOString().replace('T', ' ').substring(0, 19);
}
