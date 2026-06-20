FROM node:20-slim

WORKDIR /app

# 设置时区
ENV TZ=Asia/Shanghai
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

RUN sed -i 's/deb.debian.org/mirrors.tuna.tsinghua.edu.cn/g' /etc/apt/sources.list.d/debian.sources 2>/dev/null || sed -i 's/deb.debian.org/mirrors.tuna.tsinghua.edu.cn/g' /etc/apt/sources.list

# 安装系统依赖（curl 用于健康检查）
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/*

# 复制依赖清单并安装（包含 dev 依赖，构建时需要 tsc）
COPY package*.json ./
RUN npm ci

# 复制项目源码与资源
COPY tsconfig.json ./
COPY drizzle.config.ts ./
COPY src/ ./src/
COPY templates/ ./templates/
COPY static/ ./static/
COPY resources/ ./resources/
COPY .env.example ./

# 编译 TypeScript
RUN npm run build

# 编译完成后移除 dev 依赖，保持最终镜像精简
RUN npm prune --omit=dev

# 创建非 root 用户
RUN useradd -m -u 1000 rainmail && \
    chown -R rainmail:rainmail /app

# 创建数据库目录并设置权限（数据库文件位于 instance 目录）
RUN mkdir -p /app/instance && \
    chown -R rainmail:rainmail /app/instance

USER rainmail

EXPOSE 5024

# 健康检查
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:5024/api/health || exit 1

# 启动应用
CMD ["node", "dist/index.js"]
