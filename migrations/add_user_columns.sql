-- 数据库迁移脚本：为user表添加新增的列
-- 执行方式：sqlite3 your_database.db < migrations/add_user_columns.sql
-- 注意：执行前请先备份数据库！

-- 添加 username 列
ALTER TABLE user ADD COLUMN username VARCHAR(50);

-- 添加 city 列
ALTER TABLE user ADD COLUMN city VARCHAR(100) DEFAULT '广州';

-- 添加 is_verified 列
ALTER TABLE user ADD COLUMN is_verified BOOLEAN DEFAULT 0;

-- 添加 verification_token 列
ALTER TABLE user ADD COLUMN verification_token VARCHAR(128);

-- 添加 last_login 列
ALTER TABLE user ADD COLUMN last_login DATETIME;
