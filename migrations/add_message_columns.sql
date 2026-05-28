-- 数据库迁移脚本：为message表添加新字段
-- 执行方式：sqlite3 instance/rainmail.db < migrations/add_message_columns.sql
-- 注意：执行前请先备份数据库！

-- 添加 sender_email 列（存储未登录用户的邮箱）
ALTER TABLE message ADD COLUMN sender_email VARCHAR(120);

-- 添加 public_after_reply 列（被回复后是否公开）
ALTER TABLE message ADD COLUMN public_after_reply BOOLEAN DEFAULT 0;
