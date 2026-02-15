# 雨天信箱 - The Raindrop Box

一个基于天气状态的匿名社交树洞应用，当设定城市下雨时解锁所有秘密。

## 🌟 特性

- **天气感应**：自动检测实时天气状态
- **状态切换**：晴天只能投递，雨天可以查看所有秘密
- **毛玻璃设计**：赛博禅意风格的现代化UI
- **安全匿名**：XSS防护和内容过滤
- **分享功能**：生成精美的存票卡片
- **实时同步**：WebSocket风格的天气状态更新

## 🚀 快速开始

### 环境要求

- Python 3.8+
- pip
- 网络连接（用于天气API）

### 安装运行

1. **安装依赖**
   ```bash
   pip install -r requirements.txt
   ```

2. **启动应用**
   ```bash
   python run.py
   # 或者直接运行
   python app.py
   ```

3. **访问应用**
   打开浏览器访问: http://localhost:5024

### 使用Docker运行

```bash
# 构建镜像
docker build -t rainmail .

# 运行容器
docker run -p 5024:5000 rainmail
```

## 📁 项目结构

```
rainmail/
├── app.py                 # Flask主应用
├── run.py                # 启动脚本
├── test_app.py           # 功能测试
├── config.yaml           # 配置文件
├── requirements.txt      # Python依赖
├── rainmail.db           # SQLite数据库（自动生成）
├── templates/            # HTML模板
│   └── index.html
├── static/              # 静态资源
│   ├── css/
│   │   └── style.css
│   └── js/
│       └── app.js
└── README.md            # 项目文档
```

## ⚙️ 配置说明

编辑 `config.yaml` 文件：

```yaml
API_KEY: your_qweather_api_key  # 和风天气API密钥
times: 3                        # 天气检查间隔（分钟）
```

### 获取天气API密钥

1. 访问 [和风天气开发者平台](https://dev.qweather.com/)
2. 注册账号并创建应用
3. 获取API Key并配置到config.yaml
4. 如需更改城市，请更改[app.py](app.py)第98行 ''        url = f"https://devapi.qweather.com/v7/weather/now?location=101240310&key={config['API_KEY']}"''中的location，位置代码参考［官方的位置代码仓库］(https://github.com/qwd/LocationList)

## 🌐 外网访问

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
   cpolar http 5000
   ```

## 🧪 测试验证

运行功能测试：

```bash
python test_app.py
```

测试内容包括：
- 天气同步功能
- 数据隔离保护
- 消息提交功能
- XSS防护验证
- 健康检查接口

## 🔧 API接口

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

## 🎨 界面预览

- **晴天模式**：浅色背景，云雾动效，只能投递
- **雨天模式**：深色背景，雨滴动效，可查看所有秘密
- **响应式设计**：支持移动端和桌面端
- **毛玻璃效果**：现代化玻璃形态设计

## 📊 性能指标

- 单机支持50+并发用户
- 天气状态每2分钟更新一次
- 前端每10秒检查天气状态
- SQLite数据库，轻量高效

## 🔒 安全特性

- XSS输入过滤
- SQL注入防护
- 天气API请求超时处理
- 错误状态缓存机制

## 🐛 故障排除

### 常见问题

1. **天气API请求失败**
   - 检查网络连接
   - 验证API密钥配置

2. **数据库初始化失败**
   - 检查文件写入权限
   - 确认SQLite支持

3. **端口占用**
   - 更换端口：`app.run(port=5001)`

### 日志查看

应用日志输出在控制台，包含：
- 天气API调用状态
- 数据库操作记录
- 错误异常信息

## 📄 许可证

MIT License - 详见 LICENSE 文件


## 📞 支持联系

如有问题请提交 Issue 或联系开发团队。

---

*让雨水滋润秘密的生长，让阳光守护内心的宁静。*