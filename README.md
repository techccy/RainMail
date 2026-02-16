# 雨天信箱 - The RainMail

体验项目--->https://dropbox.techccy.dpdns.org

一个基于天气状态的匿名社交树洞应用，当广州城市下雨时解锁所有秘密。

## 特性

- **天气感应**：自动检测实时天气状态
- **状态切换**：晴天只能投递，雨天可以查看所有秘密
- **毛玻璃设计**：赛博禅意风格的现代化UI
- **安全匿名**：XSS防护和内容过滤
- **分享功能**：生成精美的存票卡片
- **实时同步**：WebSocket风格的天气状态更新

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
3. 在[开发者设置页](https://console.qweather.com/setting)中，找到 API Host 一项，通常为``*****.re.qweatherapi.com``，填入[config.yaml](config.yaml)中的``HEFENG_HOST``
4. 在[项目管理](https://console.qweather.com/project)中，创建项目，其他随便设置，新建项目凭据，**选择API_KEY**，把API_KEY填入[config.yaml](config.yaml)中的``HEFENG_KEY``

### 基础配置

复制并修改 `config.yaml` 文件：

```bash
cp config_model.yaml config.yaml

```

```yaml
HEFENG_HOST1: "a"  # 替换为你的和风天气API主机地址1，设计为两个轮换使用，若只有一个可以填相同的
HEFENG_HOST2: "b"  # 替换为你的和风天气API主机地址2
HEFENG_KEY1: "APIKEY1" # 替换为你的和风天气API密钥1，设计为两个轮换使用，若只有一个可以填相同的
HEFENG_KEY2: "APIKEY2" # 替换为你的和风天气API密钥2
times: 60 # 请求频率，单位为秒，和风天气免费API额度每分钟请求一次刚刚好
TURNSTILE_SECRET_KEY: "0x"  # 替换为你的 Cloudflare Turnstile Secret Key
TURNSTILE_SITE_KEY: "0x" # 替换成你自己的 Site Key
LOCATION_NAME: "广州"  # 替换为服务器所在地，用于前端展示
LOCATION_ID: 101280101  # 广东广州的和风天气位置ID
admin_username: techccy # 管理员登录账号
admin_password: "" # 管理员登录密码
force_rain_duration: 10   # 强制降雨持续时间（分钟）
totp_decrypt_password: "password" #用于加密管理员登录时二次验证器密钥的密码

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
├── Dockerfile             # Docker部署
├── LICENSE                # 许可证文件
├── README.md              # 项目简介
├── app.py                 # Flask主应用文件，包含核心逻辑、路由和天气API轮换
├── config_model.yaml      # 配置文件模板，存放API Key、检查间隔等
├── install.sh             # 安装脚本
├── logo.png
├── requirements.txt       # Python依赖列表
├── run.py                 # 启动脚本，负责检查依赖、初始化数据库并启动Flask应用和后台任务
├── test_app.py            # 功能测试文件
├── url.jpg
├── instance/              # 用于存放数据库
│   └── rainmail.db
├── resources/             # 用于存放静态资源或配置模板
│   └── all.csv            # 敏感词库
├── static/                # 存放前端静态资源
│   ├── css/
│   │   └── style.css      # 样式表文件
│   └── js/
│       └── app.js         # 前端JavaScript逻辑，处理UI切换、倒计时、消息提交等
└── templates/             # 存放HTML模板
    └── index.html         # 主页模板
```

## 外网访问

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


## 许可证

MIT License


---

*让雨水滋润秘密的生长，让阳光守护内心的宁静。*


![logo](logo.png)
