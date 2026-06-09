-- 数据库迁移脚本：扩展unique_identifier字段长度
-- 执行方式：sqlite3 instance/rainmail.db < migrations/extend_unique_identifier.sql
-- 注意：执行前请先备份数据库！

-- SQLite不支持直接修改列长度，需要重建表
BEGIN TRANSACTION;

-- 1. 创建新表
CREATE TABLE message_new (
    id INTEGER PRIMARY KEY,
    content TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    location VARCHAR(50) DEFAULT '广州',
    unique_identifier VARCHAR(16),
    sender_id INTEGER REFERENCES user(id),
    delivery_type VARCHAR(20) DEFAULT 'public',
    delivery_options JSON,
    reply_notification VARCHAR(20) DEFAULT 'none',
    is_anonymous BOOLEAN DEFAULT 1,
    reply_to_id INTEGER REFERENCES message(id),
    hugs_count INTEGER DEFAULT 0,
    sender_email VARCHAR(120),
    public_after_reply BOOLEAN DEFAULT 0
);

-- 2. 复制数据
INSERT INTO message_new SELECT * FROM message;

-- 3. 删除旧表
DROP TABLE message;

-- 4. 重命名新表
ALTER TABLE message_new RENAME TO message;

-- 5. 重建索引
CREATE INDEX ix_message_sender_id ON message(sender_id);
CREATE INDEX ix_message_reply_to_id ON message(reply_to_id);

COMMIT;
