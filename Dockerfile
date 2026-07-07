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
COPY about.md ./
COPY .env.example ./

# 构建前端 SPA（产物输出到 static/spa/，随 static/ 一并由 Hono 服务）
COPY frontend/ ./frontend/
RUN cd frontend && npm ci && npm run build && cd .. && rm -rf frontend/node_modules

# 编译 TypeScript 后端
RUN npm run build

# 编译完成后移除 dev 依赖，保持最终镜像精简
RUN npm prune --omit=dev

# 复用基础镜像中已存在的非 root 用户 node（UID 1000），避免 UID 冲突
RUN chown -R node:node /app

# 创建数据库目录并设置权限（数据库文件位于 instance 目录）
RUN mkdir -p /app/instance && \
    chown -R node:node /app/instance

USER node

EXPOSE 5024

# 健康检查
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:5024/api/health || exit 1

# 启动应用
CMD ["node", "dist/index.js"]
