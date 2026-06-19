#!/bin/bash
# 雨天信箱安装脚本（Node.js 版）

echo "雨天信箱安装程序"
echo "===================="

# 检查 Node.js 是否安装
if ! command -v node &> /dev/null; then
    echo "错误: 未找到 Node.js，请先安装 Node.js 20+"
    exit 1
fi

# 检查 npm 是否安装
if ! command -v npm &> /dev/null; then
    echo "错误: 未找到 npm，请先安装 npm"
    exit 1
fi

NODE_VERSION=$(node -p "process.versions.node.split('.')[0]")
if [ "$NODE_VERSION" -lt 20 ]; then
    echo "错误: Node.js 版本过低（当前 $NODE_VERSION），需要 20+"
    exit 1
fi

echo "✓ 检查 Node.js ($(node -v)) 和 npm ($(npm -v))... 通过"

# 安装依赖
echo "安装 Node 依赖..."
npm install --no-audit --no-fund

if [ $? -eq 0 ]; then
    echo "✓ 依赖安装完成"
else
    echo "✗ 依赖安装失败"
    exit 1
fi

# 编译 TypeScript
echo "编译 TypeScript..."
npm run build

if [ $? -eq 0 ]; then
    echo "✓ 编译完成"
else
    echo "✗ 编译失败"
    exit 1
fi

# 检查配置文件
if [ ! -f ".env" ]; then
    echo "创建配置文件..."
    cp .env.example .env
    echo "⚠ 请编辑 .env 文件填入实际配置（特别是 SECRET_KEY、天气 API 密钥、管理员密码哈希）"
fi

echo ""
echo "安装完成！"
echo "启动应用: npm start"
echo "  开发模式: npm run dev"
echo "访问地址: http://localhost:5024"
echo ""
echo "下一步:"
echo "1. 编辑 .env 文件配置实际参数（SECRET_KEY、天气 API 密钥、ADMIN_PASSWORD 哈希等）"
echo "2. 生成管理员密码哈希: npm run gen-hash <你的密码>，将输出填入 .env 的 ADMIN_PASSWORD"
echo "3. 运行 npm start 启动应用"
echo "4. 打开浏览器访问 http://localhost:5024"
