# 雨天信箱 - The RainMail

体验项目--->https://dropbox.techccy.dpdns.org

一个基于天气状态的匿名社交树洞应用，当**访问者**城市下雨时解锁所有秘密。

## 特性

- **天气感应**：自动检测对应城市天气状态
- **状态切换**：晴天只能投递，雨天可以查看所有秘密
- **毛玻璃设计**：赛博禅意风格的现代化UI
- **安全匿名**：XSS防护和内容过滤
- **分享功能**：生成精美的存票卡片
- **实时同步**：WebSocket风格的天气状态更新
- **用户系统**：支持注册登录，情感投递功能
- **AI内容审查**：集成AI智能内容审核
- **多种验证**：支持Cloudflare Turnstile、Altcha、自定义数学验证

## 快速开始

### 环境要求

- Python 3.8+
- pip
- 网络连接（用于天气API）

### 安装运行

1. **安装依赖**
   ```bash
   pip install -r requirements.txt
   ```

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
   - 生成密钥示例：`python -c "import secrets; print(secrets.token_urlsafe(32))"`

### 基础配置

配置文件支持 `config.json`（优先）和 `config.yaml` 两种格式。

复制模板并修改配置文件：

```bash
cp config_model.yaml config.yaml
# 或者转换为 JSON 格式
cp config_model.yaml config.json
```

**配置文件示例：**

```yaml
# 和风天气API配置（支持1-4组轮换）
HEFENG_HOST1: "a"  # 和风天气API主机地址1
HEFENG_HOST2: "b"  # 和风天气API主机地址2（可选）
HEFENG_HOST3: "c"  # 和风天气API主机地址3（可选）
HEFENG_HOST4: "d"  # 和风天气API主机地址4（可选）
HEFENG_KEY1: "APIKEY1"  # 和风天气API密钥1
HEFENG_KEY2: "APIKEY2"  # 和风天气API密钥2（可选）
HEFENG_KEY3: "APIKEY3"  # 和风天气API密钥3（可选）
HEFENG_KEY4: "APIKEY4"  # 和风天气API密钥4（可选）

times: 60  # 请求频率，单位为秒

# 人机验证配置
TURNSTILE_SECRET_KEY: "0x"  # Cloudflare Turnstile Secret Key
TURNSTILE_SITE_KEY: "0x"  # Cloudflare Turnstile Site Key
CAPTCHA_PROVIDER: "altcha"  # 验证方式: cloudflare, cha, altcha
ALTCHA_HMAC_KEY: "your-hmac-key-here"  # Altcha HMAC 密钥
ALTCHA_DIFFICULTY: 1  # Altcha 难度（1-10）

# 位置配置
LOCATION_NAME: "广州"  # 服务器所在地
LOCATION_ID: 101280101  # 和风天气位置ID

# 管理员配置
admin_username: techccy  # 管理员登录账号
admin_password: ""  # 管理员登录密码
force_rain_duration: 10  # 强制降雨持续时间（分钟）
totp_decrypt_password: "password"  # TOTP密钥加密密码

# 邮件配置（情感投递系统）
MAIL_SERVER: "smtp.gmail.com"  # SMTP服务器地址
MAIL_PORT: 587  # SMTP端口
MAIL_USE_TLS: true  # 是否使用TLS
MAIL_USERNAME: "your-email@gmail.com"  # SMTP用户名
MAIL_PASSWORD: "your-app-password"  # SMTP密码
MAIL_DEFAULT_SENDER: "RainMail <noreply@rainmail.dev>"  # 默认发件人
VERIFY_DURATION_MINUTES: 15  # 邮箱验证码有效期（分钟）

# AI 内容审查配置
AI_MODERATION:
  API_KEY: "YOUR_API_KEY"  # AI审核API密钥
  BASE_URL: "YOUR_BASE_URL"  # AI审核API base url
  MODEL: "MODEL"  # AI审核模型（推荐使用 deepseek 等国内小型模型）
  SYSTEM_PROMPT: >
    你是一个内容审查助手。请分析用户提交的内容是否包含暴力、色情、政治敏感或人身攻击。
    如果内容违规，请只返回 "True"；
    如果内容安全，请只返回 "False"。
    不要返回任何其他文字。

# 微信配置（预留功能，暂未实现）
WECHAT_APP_ID: ""  # 微信公众号 AppID
WECHAT_APP_SECRET: ""  # 微信公众号 AppSecret
```

2. **启动应用**
   ```bash
   nohup python run.py &
   nohup python curl.py &
   ```

3. **访问应用**
   打开浏览器访问: http://localhost:5024

## 使用Docker运行

```bash
# 构建镜像
docker build -t rainmail .

# 运行容器
docker run -p 5024:5024 rainmail
```

## 项目结构

```
RainMail/
├── .gitignore
├── .claude/                  # Claude Code 配置
├── Dockerfile                # Docker 部署配置
├── LICENSE                   # 许可证文件
├── README.md                 # 项目文档
├── app.py                    # Flask 主应用文件
├── config_model.yaml         # 配置文件模板
├── config.yaml               # YAML 配置文件
├── config.json               # JSON 配置文件（优先）
├── config.json.backup        # 配置备份
├── install.sh                # 安装脚本
├── requirements.txt          # Python 依赖列表
├── run.py                    # 启动脚本
├── curl.py                   # 天气检查脚本
├── test_app.py               # 功能测试文件
├── totp_secret.json          # TOTP 密钥存储
├── instance/                 # 数据库目录
│   └── rainmail.db           # SQLite 数据库
├── resources/                # 静态资源
│   └── all.csv               # 敏感词库
├── static/                   # 前端静态资源
│   ├── techccy.png           # Logo
│   ├── css/
│   │   └── style.css         # 样式表
│   └── js/
│       ├── app.js            # 前端逻辑
│       ├── html2canvas.min.js # 截图库
│       └── qrcode.min.js     # 二维码生成
└── templates/                # HTML 模板
    ├── index.html            # 主页
    ├── admin_dashboard.html  # 管理员面板
    ├── admin_login.html      # 管理员登录
    ├── admin_settings.html   # 管理员设置
    ├── auth/                 # 用户认证
    │   ├── login.html        # 登录页
    │   └── register.html     # 注册页
    ├── user/                 # 用户功能
    │   └── letter.html       # 情感投递页
    ├── privacy_policy.html   # 隐私条款（英文）
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
返回: {"weather_status": "sunny"|"rainy"}
```

### 消息管理
```
GET /api/messages        # 获取消息列表（仅雨天）
POST /api/messages       # 提交新消息
Body: {"content": "消息内容"}
```

### 用户认证
```
POST /api/auth/register  # 用户注册
POST /api/auth/login     # 用户登录
POST /api/auth/logout    # 用户登出
GET /api/auth/status     # 获取登录状态
```

### 健康检查
```
GET /api/health
返回: {"status": "healthy", "timestamp": "ISO时间"}
```

## 界面预览

- **晴天模式**：浅色背景，云雾动效，只能投递
- **雨天模式**：深色背景，雨滴动效，可查看所有秘密
- **响应式设计**：支持移动端和桌面端
- **实时监控**：数秒刷新天气

## 安全特性

- XSS输入过滤
- SQL注入防护
- 天气API请求超时处理
- 错误状态缓存机制
- AI智能内容审查
- 密码哈希存储
- 邮箱验证机制

## 许可证

MIT License

---

*让雨水滋润秘密的生长，让阳光守护内心的宁静。*

![logo](static/techccy.png)
