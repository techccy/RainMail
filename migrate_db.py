#!/usr/bin/env python3
"""
数据库迁移脚本：从 rainmail2.db 迁移数据到 rainmail.db
保留旧数据库的原有数据，兼容新表结构
"""
import sqlite3
import os
import json
from datetime import datetime

# 数据库路径 —— 锚定项目根，与 app.py 使用的 instance 目录保持一致
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
INSTANCE_DIR = os.path.join(BASE_DIR, 'instance')
OLD_DB = os.path.join(INSTANCE_DIR, 'rainmail2.db')
NEW_DB = os.path.join(INSTANCE_DIR, 'rainmail.db')
BACKUP_DB = os.path.join(INSTANCE_DIR, 'rainmail.db.backup')

def backup_new_database():
    """备份新数据库"""
    if os.path.exists(NEW_DB):
        print(f"[INFO] 备份现有数据库到 {BACKUP_DB}")
        import shutil
        shutil.copy2(NEW_DB, BACKUP_DB)
    else:
        print(f"[WARN] 新数据库不存在，将创建新数据库")

def migrate_data():
    """执行数据迁移"""
    if not os.path.exists(OLD_DB):
        print(f"[ERROR] 旧数据库不存在: {OLD_DB}")
        return False

    # 连接两个数据库
    old_conn = sqlite3.connect(OLD_DB)
    new_conn = sqlite3.connect(NEW_DB)

    old_conn.row_factory = sqlite3.Row
    new_conn.row_factory = sqlite3.Row

    old_cur = old_conn.cursor()
    new_cur = new_conn.cursor()

    try:
        # 1. 迁移 message 表（旧表字段少，需要填充新字段的默认值）
        print("[MIGRATE] 迁移 message 表...")
        old_cur.execute("SELECT * FROM message")
        old_messages = old_cur.fetchall()

        for msg in old_messages:
            # 检查是否已存在（避免重复迁移）
            new_cur.execute("SELECT id FROM message WHERE id = ?", (msg['id'],))
            if new_cur.fetchone():
                print(f"  [SKIP] message id={msg['id']} 已存在，跳过")
                continue

            # 插入消息，为新字段设置默认值
            new_cur.execute("""
                INSERT INTO message (
                    id, content, created_at, location, unique_identifier,
                    sender_id, delivery_type, delivery_options, reply_notification,
                    is_anonymous, reply_to_id, hugs_count
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                msg['id'],
                msg['content'],
                msg['created_at'],
                msg['location'],
                msg['unique_identifier'],
                None,                    # sender_id (旧数据没有)
                'public',                 # delivery_type (默认公开)
                None,                     # delivery_options (JSON)
                'none',                   # reply_notification (默认不通知)
                1,                        # is_anonymous (默认匿名)
                None,                     # reply_to_id
                0                         # hugs_count (默认0)
            ))
            print(f"  [OK] 迁移 message id={msg['id']}")

        migrated_messages = len(old_messages)
        print(f"[DONE] message 表迁移完成，共 {migrated_messages} 条")

        # 2. 迁移 user 表（字段兼容）
        print("[MIGRATE] 迁移 user 表...")
        old_cur.execute("SELECT * FROM user")
        old_users = old_cur.fetchall()

        for user in old_users:
            new_cur.execute("SELECT id FROM user WHERE id = ?", (user['id'],))
            if new_cur.fetchone():
                print(f"  [SKIP] user id={user['id']} 已存在，跳过")
                continue

            new_cur.execute("""
                INSERT INTO user (
                    id, email, password_hash, username, is_verified,
                    verification_token, created_at, last_login
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                user['id'],
                user['email'],
                user['password_hash'],
                user['username'],
                user['is_verified'],
                user['verification_token'],
                user['created_at'],
                user['last_login']
            ))
            print(f"  [OK] 迁移 user id={user['id']}")

        print(f"[DONE] user 表迁移完成")

        # 3. 迁移 location_weather_cache 表（字段兼容）
        print("[MIGRATE] 迁移 location_weather_cache 表...")
        old_cur.execute("SELECT * FROM location_weather_cache")
        old_caches = old_cur.fetchall()

        for cache in old_caches:
            # 使用 UPSERT：如果存在则更新，否则插入
            new_cur.execute("""
                INSERT INTO location_weather_cache (
                    id, city, weather_status, weather_text, icon_code,
                    raw_weather_data, last_updated, last_used_api_index
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(city) DO UPDATE SET
                    weather_status = excluded.weather_status,
                    weather_text = excluded.weather_text,
                    icon_code = excluded.icon_code,
                    raw_weather_data = excluded.raw_weather_data,
                    last_updated = excluded.last_updated,
                    last_used_api_index = excluded.last_used_api_index
            """, (
                cache['id'],
                cache['city'],
                cache['weather_status'],
                cache['weather_text'],
                cache['icon_code'],
                cache['raw_weather_data'],
                cache['last_updated'],
                cache['last_used_api_index']
            ))
            print(f"  [OK] 迁移/更新 weather_cache city={cache['city']}")

        print(f"[DONE] location_weather_cache 表迁移完成")

        # 4. 迁移 ip_location_cache 表（字段兼容）
        print("[MIGRATE] 迁移 ip_location_cache 表...")
        old_cur.execute("SELECT * FROM ip_location_cache")
        old_ips = old_cur.fetchall()

        for ip in old_ips:
            new_cur.execute("""
                INSERT INTO ip_location_cache (
                    id, ip_address, city, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(ip_address) DO UPDATE SET
                    city = excluded.city,
                    updated_at = excluded.updated_at
            """, (
                ip['id'],
                ip['ip_address'],
                ip['city'],
                ip['created_at'],
                ip['updated_at']
            ))
            print(f"  [OK] 迁移 IP cache {ip['ip_address']}")

        print(f"[DONE] ip_location_cache 表迁移完成")

        # 5. 迁移 letter_delivery 表（字段兼容）
        print("[MIGRATE] 迁移 letter_delivery 表...")
        old_cur.execute("SELECT * FROM letter_delivery")
        old_deliveries = old_cur.fetchall()

        for delivery in old_deliveries:
            new_cur.execute("SELECT id FROM letter_delivery WHERE id = ?", (delivery['id'],))
            if new_cur.fetchone():
                continue

            new_cur.execute("""
                INSERT INTO letter_delivery (
                    id, message_id, recipient_email, recipient_user_id,
                    recipient_city, delivery_status, unlock_token,
                    unlocked_at, read_at, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                delivery['id'],
                delivery['message_id'],
                delivery['recipient_email'],
                delivery['recipient_user_id'],
                delivery['recipient_city'],
                delivery['delivery_status'],
                delivery['unlock_token'],
                delivery['unlocked_at'],
                delivery['read_at'],
                delivery['created_at']
            ))

        print(f"[DONE] letter_delivery 表迁移完成")

        # 6. 迁移 message_reply 表（字段兼容）
        print("[MIGRATE] 迁移 message_reply 表...")
        old_cur.execute("SELECT * FROM message_reply")
        old_replies = old_cur.fetchall()

        for reply in old_replies:
            new_cur.execute("SELECT id FROM message_reply WHERE id = ?", (reply['id'],))
            if new_cur.fetchone():
                continue

            new_cur.execute("""
                INSERT INTO message_reply (
                    id, original_message_id, reply_content, reply_type,
                    replier_user_id, replier_email, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                reply['id'],
                reply['original_message_id'],
                reply['reply_content'],
                reply['reply_type'],
                reply['replier_user_id'],
                reply['replier_email'],
                reply['created_at']
            ))

        print(f"[DONE] message_reply 表迁移完成")

        # 7. 迁移 notification 表（字段兼容）
        print("[MIGRATE] 迁移 notification 表...")
        old_cur.execute("SELECT * FROM notification")
        old_notifications = old_cur.fetchall()

        for notif in old_notifications:
            new_cur.execute("SELECT id FROM notification WHERE id = ?", (notif['id'],))
            if new_cur.fetchone():
                continue

            new_cur.execute("""
                INSERT INTO notification (
                    id, user_id, email, notification_type, title,
                    content, related_id, is_read, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                notif['id'],
                notif['user_id'],
                notif['email'],
                notif['notification_type'],
                notif['title'],
                notif['content'],
                notif['related_id'],
                notif['is_read'],
                notif['created_at']
            ))

        print(f"[DONE] notification 表迁移完成")

        # 8. 迁移 email_queue 表（字段兼容）
        print("[MIGRATE] 迁移 email_queue 表...")
        old_cur.execute("SELECT * FROM email_queue")
        old_emails = old_cur.fetchall()

        for email in old_emails:
            new_cur.execute("SELECT id FROM email_queue WHERE id = ?", (email['id'],))
            if new_cur.fetchone():
                continue

            new_cur.execute("""
                INSERT INTO email_queue (
                    id, recipient_email, email_type, subject, body_html,
                    status, attempts, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                email['id'],
                email['recipient_email'],
                email['email_type'],
                email['subject'],
                email['body_html'],
                email['status'],
                email['attempts'],
                email['created_at']
            ))

        print(f"[DONE] email_queue 表迁移完成")

        # 9. 迁移 we_chat_binding 表（字段兼容）
        print("[MIGRATE] 迁移 we_chat_binding 表...")
        old_cur.execute("SELECT * FROM we_chat_binding")
        old_bindings = old_cur.fetchall()

        for binding in old_bindings:
            new_cur.execute("SELECT id FROM we_chat_binding WHERE id = ?", (binding['id'],))
            if new_cur.fetchone():
                continue

            new_cur.execute("""
                INSERT INTO we_chat_binding (id, user_id, wechat_openid, created_at)
                VALUES (?, ?, ?, ?)
            """, (
                binding['id'],
                binding['user_id'],
                binding['wechat_openid'],
                binding['created_at']
            ))

        print(f"[DONE] we_chat_binding 表迁移完成")

        # 提交所有更改
        new_conn.commit()
        print("\n[SUCCESS] 数据迁移完成！")
        print(f"[INFO] 旧数据库备份: {BACKUP_DB}")

        # 显示迁移后的统计
        print("\n[STATS] 迁移后的数据统计：")
        for table in ['message', 'user', 'location_weather_cache', 'ip_location_cache',
                      'letter_delivery', 'message_reply', 'notification', 'email_queue', 'we_chat_binding']:
            new_cur.execute(f"SELECT COUNT(*) FROM {table}")
            count = new_cur.fetchone()[0]
            print(f"  {table}: {count} 条")

        return True

    except Exception as e:
        new_conn.rollback()
        print(f"[ERROR] 迁移失败: {e}")
        import traceback
        traceback.print_exc()
        return False

    finally:
        old_conn.close()
        new_conn.close()

if __name__ == '__main__':
    print("=" * 50)
    print("RainMail 数据库迁移工具")
    print(f"旧数据库: {OLD_DB}")
    print(f"新数据库: {NEW_DB}")
    print("=" * 50)

    # 确认操作
    response = input("\n是否继续迁移？(y/n): ")
    if response.lower() != 'y':
        print("已取消")
        exit(0)

    backup_new_database()
    migrate_data()
