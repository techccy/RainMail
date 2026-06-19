# 雨天信箱 - The RainMail

体验项目--->https://dropbox.techccy.dpdns.org

一个基于天气状态的匿名社交树洞应用，当**访问者**城市下雨时解锁所有秘密。

## 特性

### 核心功能
- **天气感应**：自动检测对应城市天气状态
- **状态切换**：晴天只能投递，雨天可以查看所有秘密
- **毛玻璃设计**：赛博禅意风格的现代化UI
- **实时同步**：WebSocket风格的天气状态更新

### 用户系统
- **注册登录**：支持邮箱验证的用户注册
- **情感投递**：发送私密情感信件到指定城市
- **消息分类**：支持普通消息、私密投递、情感信件三种类型
- **消息互动**：点赞、拥抱、回复等社交互动功能

### 消息分享
- **公开分享**：每条消息生成唯一的 16 位标识符
- **分享链接**：通过 `/m/<unique_id>` 公开访问消息详情
- **二维码**：自动生成消息二维码，便于移动端分享
- **社交传播**：支持将秘密分享到社交媒体

### 管理功能
- **用户管理**：管理员可编辑用户信息、重置密码、删除用户
- **验证管理**：管理员可批准用户邮箱验证
- **僵尸用户清理**：清理未验证的僵尸用户
- **消息审核**：删除违规消息
- **系统监控**：统计信息、CPU温度、降雨概率等
- **强制降雨**：可手动开启60分钟雨天模式

### 安全特性
- **XSS防护**：输入内容过滤和转义
- **SQL注入防护**：参数化查询
- **AI内容审查**：集成AI智能内容审核，支持消息和回复内容审核
- **多种验证**：支持Cloudflare Turnstile、Altcha、自定义数学验证，可选禁用
- **密码安全**：哈希存储，邮箱验证机制
- **安全文档**：详细的 Cloudflare WAF 防护配置（参见 [Cloudflare.md](Cloudflare.md)）

## 快速开始（docker）

### 第一步：为该容器创建一个专属网络

创建一个新的 bridge 网络，专门给这个需要被隔离的容器使用。

```bash
# 创建一个名为 isolated_net 的网络
docker network create isolated_net

```

### 第二步：找出这个专属网络对应的宿主机网卡名称

Docker 创建自定义网络时，会在宿主机上生成一个对应的虚拟网桥接口（网卡），名称通常为 `br-<网络ID的前缀>`。

```bash
# 1. 查看 isolated_net 的 Network ID
docker network ls | grep isolated_net
# 假设输出类似： 8a9b2c3d4e5f   isolated_net   bridge    local

# 2. 前缀是 8a9b2c3d4e5f，所以对应的网卡名字通常是 br-8a9b2c3d4e5f
# 你可以通过 ip a 命令验证这个网卡是否存在
ip a | grep br-8a9b2c3d4e5f

```

### 第三步：在 DOCKER-USER 链中仅针对该网卡添加拦截规则

假设你宿主机的内网网段是 `192.168.1.0/24`，现在我们只丢弃从 `br-8a9b2c3d4e5f`（即那个特定网络）发往内网的数据包：

```bash
iptables -I DOCKER-USER -i br-8a9b2c3d4e5f -d 192.168.1.0/24 -j DROP

```

*如果你有多个内网网段（如 `10.0.0.0/8` 等），可以重复执行上述命令替换 `-d` 后面的 IP 段。*


### 获取天气API密钥

1. 访问 [和风天气开发者平台](https://dev.qweather.com/)
2. 注册账号
3. 在[开发者设置页](https://console.qweather.com/setting)中，找到 API Host 一项，通常为``*****.re.qweatherapi.com``，填入配置文件中的``HEFENG_HOST1``
4. 在[项目管理](https://console.qweather.com/project)中，创建项目，其他随便设置，新建项目凭据，**选择API_KEY**，把API_KEY填入配置文件中的``HEFENG_KEY1``
5. 支持配置多组API密钥轮换使用（最多4组），提高请求额度

### 配置人机验证

项目支持三种验证方式：

1. **Cloudflare Turnstile** (推荐)
   - 访问 [Cloudflare Dashboard](https://dash.cloudflare.com/)
   - 创建 Turnstile Widget
   - 获取 Site Key 和 Secret Key
   - 填入配置文件中的 `TURNSTILE_SITE_KEY` 和 `TURNSTILE_SECRET_KEY`
   - 设置 `CAPTCHA_PROVIDER: "cloudflare"`

2. **CHA (Custom Human Authentication)** (自定义数学验证)
   - 无需额外配置
   - 自动生成简单的数学验证题
   - 设置 `CAPTCHA_PROVIDER: "cha"`

3. **Altcha (工作量证明验证)** (无隐私问题，推荐)
   - 完全客户端验证，无第三方依赖
   - 使用 SHA-256 工作量证明算法
   - 设置 `CAPTCHA_PROVIDER: "altcha"`
   - 配置 `ALTCHA_HMAC_KEY`（建议使用至少32个字符的随机字符串）
   - 配置 `ALTCHA_DIFFICULTY`（默认为3，数值越大计算越难）
   - 生成密钥示例：`openssl rand -base64 32`

### 环境变量配置

使用 `.env` 文件进行配置，复制模板并填入实际值：

```bash
cp .env.example .env
# 编辑 .env 文件，填入实际配置值
nano .env
```

**关键环境变量说明：**

```bash
# 应用配置（必需）
SECRET_KEY=your-secret-key-here           # 会话签名密钥，可通过 openssl rand -hex 32 生成

# 邮件配置
MAIL_SERVER=smtp.gmail.com                # SMTP服务器地址
MAIL_PORT=587                             # SMTP端口（587=TLS, 465=SSL）
MAIL_USE_TLS=true                         # 是否使用TLS
MAIL_USERNAME=your-email@gmail.com        # SMTP用户名
MAIL_PASSWORD=your-app-password           # SMTP密码（Gmail需使用应用专用密码）
MAIL_DEFAULT_SENDER=RainMail <noreply@rainmail.dev>  # 默认发件人

# 人机验证配置
CAPTCHA_PROVIDER=altcha                   # 验证方式: altcha, cloudflare, recaptcha, cha, none
TURNSTILE_SITE_KEY=your-site-key         # Cloudflare Turnstile Site Key
TURNSTILE_SECRET_KEY=your-secret-key     # Cloudflare Turnstile Secret Key
ALTCHA_HMAC_KEY=your-hmac-key             # Altcha HMAC 密钥
ALTCHA_DIFFICULTY=3                       # Altcha 难度（1-5）

# 和风天气 API 配置（支持多组轮换）
HEFENG_HOST1=your-hefeng-host1           # 和风天气API主机地址1
HEFENG_KEY1=your-api-key1                # 和风天气API密钥1
HEFENG_HOST2=your-hefeng-host2            # 备用API（可选）
HEFENG_KEY2=your-api-key2                # 备用API密钥（可选）

# 位置配置
LOCATION_ID=101280101                    # 和风天气位置ID（101280101=广州）
LOCATION_NAME=广州                        # 城市名称

# 管理员配置
ADMIN_PATH_PREFIX=admin                  # 管理员路径前缀（建议修改为不易猜测的字符串）
ADMIN_USERNAME=admin                     # 管理员用户名
ADMIN_PASSWORD=your-scrypt-hash-here     # 管理员密码（必须是哈希格式，不能是明文）
# 生成哈希方法：npm run gen-hash your-password （生成 Werkzeug 兼容的 scrypt 哈希）

# AI 内容审查配置
AI_MODERATION_API_KEY=your-ai-api-key    # AI服务API密钥
AI_MODERATION_BASE_URL=https://integrate.api.nvidia.com/v1  # AI服务基础URL
AI_MODERATION_MODEL=deepseek-ai/deepseek-r1-distill-llama-8b  # AI模型名称

# 其他配置
TIMES=3600                               # 天气缓存时间（秒）
FORCE_RAIN_DURATION=10                   # 强制降雨持续时间（分钟）
VERIFY_DURATION_MINUTES=15               # 邮箱验证码有效期（分钟）
```

**2. 启动应用**
```bash
docker compose up -d --build

```

3. **访问应用**
   打开浏览器访问: http://localhost:5024

## 项目结构

```
RainMail/
├── .gitignore
├── .env.example               # 环境变量配置模板
├── Dockerfile                 # Docker 部署配置（node:20-slim）
├── docker-compose.yml         # Docker Compose 编排
├── LICENSE                    # 许可证文件
├── README.md                  # 项目文档
├── Cloudflare.md              # Cloudflare 安全防护配置文档
├── DEPLOYMENT.md              # 部署指南
├── install.sh                 # 安装脚本（npm）
├── package.json               # Node 依赖与脚本
├── tsconfig.json              # TypeScript 配置
├── drizzle.config.ts          # Drizzle ORM 配置
├── src/                       # 后端源码（TypeScript / Hono + Drizzle）
│   ├── index.ts               # 应用入口（启动 + 后台任务）
│   ├── app.ts                 # Hono 装配（中间件 + 路由）
│   ├── config.ts              # 环境变量 → 配置对象
│   ├── db/                    # 数据库（Drizzle + better-sqlite3）
│   │   ├── schema.ts          # 表定义
│   │   ├── index.ts           # 连接 + 工具函数
│   │   └── migrate.ts         # 启动期建表
│   ├── lib/                   # 业务库（密码/会话/CSRF/验证码/天气/邮件/审核…）
│   ├── routes/                # 路由（pages/api/auth/user/letters/admin）
│   ├── views/nunjucks.ts      # Nunjucks 模板渲染（兼容 Jinja2）
│   └── workers/               # 后台任务（天气解锁/邮件队列/清理）
├── instance/                  # 数据库目录
│   └── rainmail.db            # SQLite 数据库
├── resources/                 # 资源
│   └── email.csv              # 邮箱服务商映射
├── static/                    # 前端静态资源
│   ├── techccy.png            # Logo
│   ├── css/
│   │   └── style.css          # 样式表
│   └── js/
│       ├── app.js             # 前端逻辑
│       ├── html2canvas.min.js # 截图库
│       └── qrcode.min.js      # 二维码生成
└── templates/                 # HTML 模板（Nunjucks/Jinja2 语法）
    ├── index.html             # 主页
    ├── admin_dashboard.html   # 管理员面板
    ├── admin_login.html       # 管理员登录
    ├── admin_settings.html    # 管理员设置
    ├── error.html             # 错误页
    ├── auth/                  # 用户认证
    │   ├── login.html         # 登录页
    │   └── register.html      # 注册页
    ├── user/                  # 用户功能
    │   ├── inbox.html         # 收件箱
    │   ├── letter.html        # 情感投递页
    │   └── settings.html      # 用户设置
    ├── public/                # 公开页面
    │   └── message.html       # 公开消息详情页
    ├── privacy_policy.html    # 隐私条款（英文）
    └── privacy_policy_cn.html # 隐私条款（中文）
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

## API接口

### 获取天气状态
```
GET /api/weather
返回: {"weather_status": "sunny"|"rainy", "precip_prob": 60}
```

### 消息管理
```
GET /api/messages              # 获取消息列表（仅雨天）
POST /api/messages            # 提交新消息
Body: {"content": "消息内容", "message_type": "normal"}
```

### 消息互动
```
POST /api/messages/<id>/like    # 点赞消息
POST /api/messages/<id>/hug     # 拥抱消息
POST /api/messages/<id>/reply   # 回复消息
```

### 公开消息
```
GET /m/<unique_id>              # 公开访问消息详情（通过唯一标识符）
```

### 用户认证
```
POST /api/auth/register     # 用户注册
POST /api/auth/login        # 用户登录
POST /api/auth/logout       # 用户登出
GET /api/auth/status        # 获取登录状态
POST /api/auth/verify       # 发送验证码
POST /api/auth/confirm      # 确认验证码
```

### 用户功能
```
GET /api/user/profile       # 获取用户资料
GET /api/user/inbox         # 获取收件箱（情感信件）
GET /api/user/sent          # 获取已发送消息
GET /api/user/notifications # 获取通知列表
```

### 管理员API
```
GET /admin/api/users                # 获取用户列表（支持分页搜索）
PUT /admin/api/update_user/<id>     # 更新用户信息
POST /admin/api/reset_password/<id> # 重置用户密码
POST /admin/api/delete_user/<id>    # 删除用户
POST /admin/api/verify_user/<id>    # 批准用户验证
POST /admin/force_rain              # 强制降雨60分钟
POST /admin/delete_message/<id>     # 删除消息
GET /admin/api/config                # 获取系统配置
PUT /admin/api/config                # 更新系统配置
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
- **实时监控**：数秒刷新天气

### 用户界面
- **情感投递**：给指定城市投递匿名情感信件
- **收件箱**：查看收到的情感信件
- **消息互动**：点赞、拥抱、回复等社交功能

### 管理后台
- **系统概览**：消息总数、降雨概率、CPU温度等
- **用户管理**：搜索、编辑、重置密码、删除用户
- **验证管理**：批准用户邮箱验证
- **消息审核**：查看和删除违规消息

## 安全特性

### 输入安全
- XSS输入过滤和转义
- SQL注入防护（参数化查询）
- AI智能内容审查
- 敏感词过滤

### 认证安全
- 密码哈希存储（scrypt，兼容 Werkzeug 格式）
- 邮箱验证机制
- 人机验证（Cloudflare Turnstile / Altcha / 数学验证）
- 会话管理

### 系统安全
- 天气API请求超时处理
- 错误状态缓存机制
- 爆破防护和警告
- 管理员操作确认

### 数据隐私
- 匿名投递机制
- 私密消息隔离
- 用户数据隔离

## 许可证

MIT License

---

*让雨水滋润秘密的生长，让阳光守护内心的宁静。*

![logo](static/techccy.png)
