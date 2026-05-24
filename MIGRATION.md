# 数据库迁移说明

## 背景

新版本的 RainMail 增加了更多功能字段，导致旧数据库 `rainmail2.db` 的表结构不兼容。本迁移工具可将旧数据迁移到新数据库 `rainmail.db`。

## 迁移内容

### Message 表字段变化

| 旧字段 | 新字段 | 默认值 |
|--------|--------|--------|
| - | sender_id | NULL |
| - | delivery_type | 'public' |
| - | delivery_options | NULL |
| - | reply_notification | 'none' |
| - | is_anonymous | 1 (True) |
| - | reply_to_id | NULL |
| - | hugs_count | 0 |

## 使用方法

### 方法一：自动部署（推荐）

在服务器上拉取最新代码后，运行：

```bash
./deploy.sh
```

脚本会自动：
1. 备份现有的 rainmail.db（如果存在）
2. 将 rainmail2.db 的数据迁移到 rainmail.db
3. 提示如何启动服务

### 方法二：手动迁移

```bash
# 1. 激活虚拟环境
source venv/bin/activate

# 2. 运行迁移脚本
python3 migrate_db.py

# 3. 确认迁移提示，输入 y
```

### 方法三：直接 SQL 迁移

如果 Python 环境不可用，可以使用 sqlite3 命令：

```bash
# 备份新数据库
cp instance/rainmail.db instance/rainmail.db.backup

# 迁移 message 表
sqlite3 instance/rainmail2.db <<EOF | sqlite3 instance/rainmail.db
.mode insert message
SELECT * FROM message;
EOF

# 注意：手动 SQL 迁移需要处理新字段的默认值
```

## 验证迁移

迁移完成后，检查数据：

```bash
sqlite3 instance/rainmail.db "SELECT COUNT(*) FROM message;"
sqlite3 instance/rainmail.db "SELECT COUNT(*) FROM user;"
```

## 回滚

如果迁移出现问题，可以恢复备份：

```bash
cp instance/rainmail.db.backup instance/rainmail.db
```

## 注意事项

1. 迁移脚本会跳过已存在的记录（通过 ID 判断），可以安全地重复运行
2. 旧数据库 `rainmail2.db` 不会被修改
3. 建议在部署前先在测试环境验证迁移
