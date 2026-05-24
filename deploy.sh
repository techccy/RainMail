#!/bin/bash
# RainMail 服务器部署脚本
# 用于迁移旧数据库并启动新版本服务

set -e

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR"

echo "================================"
echo "RainMail 部署迁移工具"
echo "================================"
echo ""

# 检查虚拟环境
if [ ! -d "venv" ]; then
    echo "[ERROR] 未找到虚拟环境 venv/"
    echo "请先运行: python3 -m venv venv"
    exit 1
fi

# 激活虚拟环境
source venv/bin/activate

# 检查旧数据库是否存在
if [ ! -f "instance/rainmail2.db" ]; then
    echo "[WARN] 未找到旧数据库 instance/rainmail2.db"
    echo "将使用全新的 rainmail.db"
fi

# 运行迁移
echo "[INFO] 开始数据库迁移..."
python3 migrate_db.py <<EOF
y
EOF

echo ""
echo "================================"
echo "[SUCCESS] 部署准备完成！"
echo ""
echo "启动服务请运行:"
echo "  ./run.sh"
echo ""
echo "或者手动启动:"
echo "  source venv/bin/activate"
echo "  python3 app.py"
echo "================================"
