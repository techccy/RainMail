# 雨天信箱 - The RainMail

体验项目--->https://rm.techccy.com

一个基于天气状态的匿名社交树洞应用，当**访问者**城市下雨时解锁所有秘密。

> 让雨水滋润秘密的生长，让阳光守护内心的宁静。

## 特性

### 核心功能
- **天气感应**：通过和风天气 API 自动检测对应城市的天气状态
- **状态切换**：晴天只能投递，雨天可以查看所有秘密
- **毛玻璃设计**：赛博禅意风格的现代化 UI（React + Tailwind）
- **定时轮询**：前端定时刷新天气状态与元信息，秒级感知晴雨切换

### 用户系统
- **注册登录**：支持邮箱验证的用户注册
- **情感投递**：发送私密情感信件到指定城市，附带解锁 token
- **消息分类**：支持普通消息、私密投递、情感信件三种类型
- **消息互动**：拥抱、回复等社交互动功能

### 消息分享
- **公开分享**：每条消息生成唯一的 16 位标识符
- **分享链接**：通过 `/m/<unique_id>` 公开访问消息详情
- **二维码 / 截图卡片**：前端使用 `qrcode` + `html-to-image` 生成分享卡片，便于移动端传播

### 管理后台
- **登录防护**：蜜罐、账户/IP 爆破锁定（30 分钟）
- **系统概览**：消息总数、降雨概率、CPU 温度等
- **消息管理**：查看 / 单条删除 / **批量删除**消息（单次上限 1000）
- **用户管理**：分页搜索、查看 / 编辑用户、重置密码、手动通过验证、单条删除 / **批量删除**（单次上限 1000）
- **僵尸用户清理**：定时清理未在有效期内完成验证的注册账户
- **配置统一走 `.env`**：已移除原系统设置 UI，所有配置通过环境变量管理

### 后台任务
- **天气解锁**：定时拉取天气并刷新解锁状态
- **邮件队列**：异步 SMTP 发送（Nodemailer），避免请求阻塞
- **僵尸用户清理**：每 10 分钟扫描，删除超过 `UNVERIFIED_USER_CLEANUP_MINUTES`（默认 60）未验证的用户
- **AI 审核队列**：对消息 / 回复做内容审核，按 `AI_MODERATION_RPM` 滑窗限速，失败重试 `AI_MODERATION_MAX_RETRIES` 次，pending → approved / rejected 状态机驱动

### 安全特性
- **XSS 防护**：输入内容过滤和转义
- **SQL 注入防护**：Drizzle ORM 参数化查询
- **AI 内容审查**：OpenAI 兼容接口（默认 NVIDIA / deepseek-r1-distill-llama-8b）
- **密码安全**：scrypt 哈希存储，格式与 Werkzeug 兼容
- **CSRF / 会话**：签名的会话 Cookie、CSRF Token（SPA 命中 403 自动刷新）
- **安全文档**：详细的 Cloudflare WAF 防护配置（参见 [Cloudflare.md](Cloudflare.md)）

## 技术栈

| 层 | 技术 |
|----|------|
| 运行时 | Node.js ≥ 20（ESM） |
| 后端 | TypeScript、[Hono](https://hono.dev/) + `@hono/node-server`、[Drizzle ORM](https://orm.drizzle.team/)、`better-sqlite3`、Nunjucks、Nodemailer、Zod |
| 前端 | React 19、React Router 7、Vite 7、Tailwind CSS 4、Radix UI、`lucide-react`、`html-to-image` / `qrcode` |
| 模板 | Nunjucks（兼容 Jinja2 语法，仅用于管理后台 SSR + 隐私政策页） |
| 外部服务 | 和风天气 API（最多 4 组 Key 轮换）、AI 内容审核（OpenAI 兼容） |
| 数据库 | SQLite（持久化在 `instance/rainmail.db`） |

前端为独立的 `frontend/` 包，Vite 构建产物输出到 `static/spa/`，由同一个 Hono 服务在 5024 端口统一托管（**单端口部署**）。

## 快速开始（Docker）

> 完整部署指引见 [DEPLOYMENT.md](DEPLOYMENT.md)。

### 第一步（可选）：网络隔离加固

`docker-compose.yml` 会自动创建一个名为 `isolated_net` 的 bridge 网络，并通过
`com.docker.network.bridge.name: br-rainmail` 把宿主机上的虚拟网卡名**固定为 `br-rainmail`**，
方便你写死 iptables 规则，无需再手动 `docker network create` 或推算 `br-<id>`。

如果你想阻止该容器访问宿主机内网，可在宿主机执行（假设内网网段是 `192.168.1.0/24`）：

```bash
iptables -I DOCKER-USER -i br-rainmail -d 192.168.1.0/24 -j DROP
```

*如有多个内网网段（如 `10.0.0.0/8`），重复上述命令替换 `-d` 后的网段即可。*

### 第二步：获取和风天气 API 密钥

1. 访问 [和风天气开发者平台](https://dev.qweather.com/) 并注册账号
2. 在[开发者设置页](https://console.qweather.com/setting)找到 API Host（形如 `*****.re.qweatherapi.com`），填入 `HEFENG_HOST1`
3. 在[项目管理](https://console.qweather.com/project)创建项目并新建凭据，**选择 API_KEY**，填入 `HEFENG_KEY1`
4. 支持配置多组密钥轮换（最多 4 组 `HEFENG_HOST2..4` / `HEFENG_KEY2..4`），提高请求额度

### 第三步：环境变量配置

```bash
cp .env.example .env
nano .env
```

**关键环境变量说明：**

```bash
# 应用配置（必需）
SECRET_KEY=your-secret-key-here           # 会话签名密钥，openssl rand -hex 32 生成
APP_NAME=RainMail                          # 应用名（英文）
APP_NAME_CN=雨天信箱                       # 应用名（中文）
APP_URL=https://rainmail.dev               # 应用主页 URL

# 邮件配置
MAIL_SERVER=smtp.gmail.com                # SMTP 服务器
MAIL_PORT=587                             # 587=TLS, 465=SSL
MAIL_USE_TLS=true                         # 与 MAIL_USE_SSL 互斥
MAIL_USE_SSL=false
MAIL_USERNAME=your-email@gmail.com
MAIL_PASSWORD=your-app-password           # Gmail 需用应用专用密码
MAIL_DEFAULT_SENDER=RainMail <noreply@rainmail.dev>
MAIL_ENABLED=true                         # 设为 false 可禁用邮件发送

# 邮箱验证配置
VERIFY_DURATION_MINUTES=15                # 邮箱验证有效期（分钟）

# 和风天气 API 配置（支持多组轮换，至少配一组）
HEFENG_HOST1=your-hefeng-host1
HEFENG_KEY1=your-api-key1
HEFENG_HOST2=                             # 备用（可选）
HEFENG_KEY2=

# 位置配置
LOCATION_ID=101280101                     # 和风天气位置 ID（101280101=广州）
LOCATION_NAME=广州

# 管理员配置
ADMIN_PATH_PREFIX=admin                   # 管理后台路径前缀，建议改成不易猜测的字符串
ADMIN_USERNAME=admin
ADMIN_PASSWORD=your-scrypt-hash-here      # 必须是哈希，不能明文！
# 生成哈希：npm run gen-hash your-password
# 哈希格式与 Werkzeug 兼容：scrypt:N:r:p$salt$hash

# AI 内容审核配置
AI_MODERATION_API_KEY=your-ai-api-key
AI_MODERATION_BASE_URL=https://integrate.api.nvidia.com/v1
AI_MODERATION_MODEL=deepseek-ai/deepseek-r1-distill-llama-8b
AI_MODERATION_RPM=60                      # 上游每分钟最大请求数，审核队列据此限速
AI_MODERATION_MAX_RETRIES=3               # 网络/超时失败重试次数，耗尽标记 rejected
AI_MODERATION_QUEUE_INTERVAL_MS=2000      # 审核队列轮询周期（毫秒）

# 其他配置
TIMES=3600                                # 天气缓存时间（秒）
FORCE_RAIN_DURATION=10                    # 强制降雨持续时间（分钟，仅内部 helper 使用）
PRIVATE_DELIVERY_REQUIRE_LOGIN=false      # 私密投递是否需要登录
IPINFO_TOKEN=your-ipinfo-token            # IPInfo.io 令牌（可选，用于 IP 定位）
SESSION_COOKIE_SECURE=false               # 生产环境建议 true
CSP_POLICY=default-src 'self'; ...        # 内容安全策略
UNVERIFIED_USER_CLEANUP_MINUTES=60        # 僵尸用户清理阈值（分钟）
```

### 第五步：启动应用

```bash
docker compose up -d --build
```

### 第六步：访问应用

打开浏览器访问：http://localhost:5024

## 开发模式

项目由根目录的后端（Hono）与 `frontend/` 的前端（Vite）两部分组成。

**后端**（端口 5024，热重载）：
```bash
npm install
npm run dev           # tsx watch src/index.ts
```

**前端**（端口 5173，自动代理 `/api`、`/auth` 到 5024）：
```bash
cd frontend
npm install
npm run dev           # Vite dev server
```

**生产构建 / 启动**：
```bash
npm run build         # tsc → dist/
cd frontend && npm run build   # Vite → static/spa/
cd ..
npm start             # node dist/index.js
```

**常用脚本**：
- `npm run gen-hash <密码>` — 生成管理员密码的 scrypt 哈希
- `npm run db:migrate` — 执行启动期建表（正常情况下 `index.ts` 启动时已自动执行）
- `npm run db:generate` — 通过 drizzle-kit 由 schema 生成迁移
- `npm run typecheck` — 类型检查

## 项目结构

```
RainMail/
├── .env.example               # 环境变量配置模板
├── Dockerfile                 # Docker 部署配置（node:20-slim）
├── docker-compose.yml         # Docker Compose 编排（isolated_net + br-rainmail）
├── install.sh                 # 安装脚本（npm）
├── package.json               # 后端依赖与脚本
├── tsconfig.json              # TypeScript 配置
├── drizzle.config.ts          # Drizzle ORM 配置
├── Cloudflare.md              # Cloudflare 安全防护配置文档
├── DEPLOYMENT.md              # 部署指南（Node.js 版，现行）
├── LICENSE                    # MIT 许可证
├── README.md                  # 项目文档
├── src/                       # 后端源码（TypeScript / Hono + Drizzle）
│   ├── index.ts               # 应用入口（启动 + 后台任务）
│   ├── app.ts                 # Hono 装配（中间件 + 路由 + SPA fallback）
│   ├── config.ts              # 环境变量 → 配置对象（单例）
│   ├── db/
│   │   ├── schema.ts          # Drizzle 表定义
│   │   ├── index.ts           # better-sqlite3 连接 + 工具函数
│   │   └── migrate.ts         # 启动期建表
│   ├── lib/                   # 业务库（密码 / 会话 / CSRF / 天气 / 邮件 / 审核 / 爆破锁定 / IP 定位 …）
│   ├── routes/                # 路由（pages / api / auth / user / letters / admin）
│   ├── views/nunjucks.ts      # Nunjucks 模板渲染（兼容 Jinja2）
│   ├── workers/               # 后台任务（天气解锁 / 邮件队列 / 僵尸用户清理 / AI 审核队列）
│   └── scripts/gen-hash.ts    # 生成管理员密码哈希的 CLI
├── frontend/                  # 前端 SPA（React 19 + Vite 7 + Tailwind 4）
│   ├── package.json
│   ├── vite.config.ts
│   └── src/
│       ├── App.tsx
│       ├── pages/             # Home / PublicMessage / Login / Register / VerifyEmail / Inbox / Letter / Settings …
│       ├── components/        # MessageForm / MessageWall / ShareCardModal / WeatherBackground / RequireAuth …
│       └── hooks/             # useAuth / useWeather / useBehavior
├── instance/                  # 数据库目录（SQLite 持久化）
│   └── rainmail.db
├── resources/
│   └── email.csv              # 邮箱服务商 → 登录入口映射
├── static/                    # 静态资源（由 Hono 统一托管）
│   ├── techccy.png            # Logo
│   ├── css/style.css
│   ├── spa/                   # 前端 Vite 构建产物（生产用）
│   └── js/                    # auth.js / csrf.js / motion.js / gsap/
└── templates/                 # Nunjucks HTML 模板
    ├── admin_dashboard.html   # 管理后台面板
    ├── admin_login.html       # 管理后台登录
    ├── error.html             # 错误页
    ├── privacy_policy.html    # 隐私条款（英文）
    ├── privacy_policy_cn.html # 隐私条款（中文）
    └── legacy/                # 旧 SSR 页面（已弃用，仅留档参考）
```

## 公网访问

### 使用 Cloudflare Tunnel

1. 安装 Cloudflare Tunnel
   ```bash
   brew install cloudflared
   ```
2. 登录 Cloudflare
   ```bash
   cloudflared tunnel login
   ```
3. 创建隧道
   ```bash
   cloudflared tunnel create rainmail
   ```
4. 配置路由
   ```bash
   cloudflared tunnel route dns rainmail your-domain.example.com
   ```
5. 启动隧道
   ```bash
   cloudflared tunnel run rainmail
   ```

### 使用 cpolar

1. 安装 cpolar
   ```bash
   brew install cpolar
   ```
2. 启动内网穿透
   ```bash
   cpolar http 5024
   ```

## API 接口

> 管理后台路径前缀由 `ADMIN_PATH_PREFIX` 控制，下文以默认 `admin` 为例。所有写操作需带 `X-CSRF-Token`。

### 天气
```
GET /api/weather         # {"weather_status": "sunny"|"rainy", "precip_prob": 60}
GET /api/weather/meta    # 天气元信息（限流 120/h）
```

### 消息管理
```
GET  /api/messages              # 获取消息列表（仅雨天返回，晴天 403）
POST /api/messages              # 提交新消息
     Body: {"content": "...", "message_type": "normal"}
GET  /api/messages/:unique_id   # 按唯一标识符获取消息详情
```

### 消息互动
```
POST /api/messages/:id/hug      # 给消息一个拥抱
```

### 情感信件
```
GET  /letters/:token            # 凭 token 打开信件
GET  /api/letters/:id           # 获取信件详情
POST /api/letters/:id/unlock    # 解锁信件
POST /api/letters/:id/read      # 标记已读
POST /api/letters/:id/reply     # 回复信件
```

### 公开页面
```
GET /m/<unique_id>              # 公开访问消息详情页（同 /api/messages/:unique_id）
GET /api/email-providers        # 邮箱服务商 → 登录入口映射
GET /privacy-policy             # 隐私条款（英文）
GET /privacy-policy-cn          # 隐私条款（中文）
```

### 用户认证
```
POST /api/auth/register               # 注册（限流 3/h）
POST /api/auth/verify-email           # 校验邮箱验证码
GET  /verify-email                    # 验证邮箱落地页
POST /api/auth/resend-verification    # 重新发送验证邮件
POST /api/auth/login                  # 登录（限流 10/min）
POST /api/auth/logout                 # 登出
```
> 登录状态由 `GET /api/user/profile` 体现，无独立的 `/api/auth/status`。

### 用户功能
```
GET  /api/user/profile           # 获取用户资料（同时反映登录状态）
PUT  /api/user/profile           # 更新用户资料
GET  /api/user/inbox             # 收件箱（收到的情感信件）
GET  /api/user/sent              # 已发送消息
GET  /api/user/notifications     # 通知列表
PUT  /api/user/notifications/:id # 更新通知（如标记已读）
```

### 管理员 API（前缀为 `/<ADMIN_PATH_PREFIX>`，默认 `/admin`）
```
GET  /admin/                              # 管理员登录页
POST /admin/                              # 登录提交（蜜罐 + 爆破锁定）
GET  /admin/dashboard                     # 仪表盘
POST /admin/logout                        # 登出
POST /admin/delete_message/:id            # 单条删除消息
POST /admin/api/delete_messages           # 批量删除消息（Body: {"ids":[...]}, 上限 1000）
GET  /admin/api/users                     # 用户列表（支持 page/per_page/search 分页搜索）
GET  /admin/api/user/:id                  # 用户详情
PUT  /admin/api/update_user/:id           # 更新用户信息
POST /admin/api/reset_password/:id        # 重置用户密码
POST /admin/api/verify_user/:id           # 手动通过用户邮箱验证
POST /admin/api/delete_user/:id           # 单条删除用户
POST /admin/api/delete_users              # 批量删除用户（Body: {"ids":[...]}, 上限 1000）
```

### 健康检查
```
GET /api/health
返回: {"status": "healthy", "timestamp": "ISO时间"}
```

## 界面预览

### 主页
- **晴天模式**：浅色背景，云雾动效，只能投递
- **雨天模式**：深色背景，雨滴动效，可查看所有秘密
- **响应式设计**：支持移动端和桌面端
- **实时感知**：前端定时轮询刷新天气

### 用户界面
- **情感投递**：给指定城市投递匿名情感信件
- **收件箱**：查看收到的情感信件
- **消息互动**：拥抱、回复等社交功能

### 管理后台
- **系统概览**：消息总数、降雨概率、CPU 温度等
- **用户管理**：搜索、编辑、重置密码、删除用户（支持批量）
- **验证管理**：批准用户邮箱验证
- **消息审核**：查看和删除违规消息（支持批量）

## 安全特性

### 输入安全
- XSS 输入过滤和转义
- SQL 注入防护（Drizzle 参数化查询）
- AI 智能内容审查（消息 + 回复，带 RPM 限速与重试）
- 敏感词过滤

### 认证安全
- 密码哈希存储（scrypt，兼容 Werkzeug 格式）
- 邮箱验证机制
- 会话 Cookie 签名、CSRF Token 保护
- 账户 / IP 爆破锁定（30 分钟）

### 系统安全
- 天气 API 请求超时处理
- 错误状态缓存机制
- 管理员操作确认与蜜罐
- CSP 安全响应头

### 数据隐私
- 匿名投递机制
- 私密消息隔离
- 用户数据隔离

## 许可证

[MIT License](LICENSE)

## 可以请我喝杯咖啡～
![donate_qr_code](static/donate.png)

---

*让雨水滋润秘密的生长，让阳光守护内心的宁静。*

![logo](static/techccy.png)
