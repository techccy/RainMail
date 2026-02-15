#!/bin/bash
# 雨天信箱安装脚本

echo "雨天信箱安装程序"
echo "===================="

# 检查Python是否安装
if ! command -v python3 &> /dev/null; then
    echo "错误: 未找到Python3，请先安装Python 3.8+"
    exit 1
fi

# 检查pip是否安装
if ! command -v pip3 &> /dev/null; then
    echo "错误: 未找到pip3，请先安装pip"
    exit 1
fi

echo "✓ 检查Python和pip... 通过"

# 安装依赖
echo "安装Python依赖..."
pip3 install -r requirements.txt

if [ $? -eq 0 ]; then
    echo "✓ 依赖安装完成"
else
    echo "✗ 依赖安装失败"
    exit 1
fi

# 检查配置文件
if [ ! -f "config.yaml" ]; then
    echo "创建默认配置文件..."
    cat > config.yaml << EOL
API_KEY: "请在此处填写和风天气API_KEY"
times: 2
EOL
    echo "⚠ 请编辑 config.yaml 文件配置API密钥"
fi

# 创建数据库
echo "初始化数据库..."
python3 -c "
from app import app, db
with app.app_context():
    db.create_all()
    print('数据库初始化完成')
"

echo ""
echo "安装完成！"
echo "启动应用: python run.py"
echo "访问地址: http://localhost:5000"
echo ""
echo "下一步:"
echo "1. 编辑 config.yaml 配置天气API密钥"
echo "2. 运行 python run.py 启动应用"
echo "3. 打开浏览器访问 http://localhost:5000"