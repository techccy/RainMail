# RainMail Cloudflare 安全防护方案

## 项目概述

RainMail（雨天信箱）是一个基于 Flask 的匿名社交信箱应用，具有天气解锁机制。项目使用 Docker 部署，包含 71 个 HTTP 端点。

**主要技术栈：**
- 后端：Python Flask + SQLite
- 前端：Vanilla JavaScript + Jinja2 模板
- 部署：Docker + Docker Compose

**应用端口：** 5024

---

## 需要保护的 URI 端点分类

### 🔴 高优先级 - 强制托管质询 (Managed Challenge)

这些端点是攻击者的主要目标，需要强制 Cloudflare 托管质询。

#### 1. 认证端点

| URI | HTTP 方法 | 保护措施 | 说明 |
|-----|----------|---------|------|
| `/api/auth/login` | POST | 托管质询 | 登录接口，防暴力破解 |
| `/api/auth/register` | POST | 托管质验 | 注册接口，防批量注册 |
| `/api/auth/verify-email` | POST | 托管质询 | 邮箱验证，防滥用 |
| `/api/auth/resend-verification` | POST | 托管质询 + 速率限制 | 重发验证邮件，防邮件轰炸 |
| `/auth/login` | GET | Bot 保护 | 登录页面，防爬虫扫描 |
| `/auth/register` | GET | Bot 保护 | 注册页面，防爬虫扫描 |

#### 2. 管理员端点（所有 `/admin/*` 路径）

**注意：管理员路径前缀可通过 `ADMIN_PATH_PREFIX` 环境变量配置（默认 `admin`）**

| URI | HTTP 方法 | 保护措施 | 说明 |
|-----|----------|---------|------|
| `/admin` | GET/POST | 托管质验 + IP 限制 | 管理员登录，最关键端点 |
| `/admin/dashboard` | GET | 托管质验 | 管理面板 |
| `/admin/api/users` | GET | 托管质验 | 用户列表 |
| `/admin/api/user/<id>` | GET | 托管质验 | 用户详情 |
| `/admin/api/update_user/<id>` | PUT | 托管质验 | 更新用户 |
| `/admin/api/reset_password/<id>` | POST | 托管质验 | 重置用户密码 |
| `/admin/api/delete_user/<id>` | POST | 托管质验 | 删除用户 |
| `/admin/api/config` | GET/PUT | 托管质验 | 配置管理 |
| `/admin/api/config/import` | POST | 托管质验 | 导入配置 |
| `/admin/force_rain` | POST | 托管质验 | 强制雨天模式 |
| `/admin/delete_message/<id>` | POST | 托管质验 | 删除消息 |

**推荐 Cloudflare 规则：**
```
(http.request.uri.path regex "^/admin/.*") or (http.request.uri.path eq "/admin")
→ Managed Challenge
+ IP Access Rules（仅允许管理员 IP）
```

#### 3. API 提交端点

| URI | HTTP 方法 | 保护措施 | 说明 |
|-----|----------|---------|------|
| `/api/messages` | POST | 托管质询 + 速率限制 | 消息提交，应用已有 10/min 限制 |
| `/api/letters/<id>/reply` | POST | 托管质询 + 速率限制 | 信件回复 |
| `/api/messages/<id>/hug` | POST | 托管质询 + 速率限制 | 拥抱消息 |

---

### 🟡 中优先级 - 速率限制 (Rate Limiting)

这些端点不需要强制质询，但需要速率限制防止滥用。

#### 1. 查询类 API

| URI | HTTP 方法 | 速率限制 | 说明 |
|-----|----------|---------|------|
| `/api/weather` | GET | 60/分钟 | 天气查询，应用已有 120/小时限制 |
| `/api/weather/meta` | GET | 60/分钟 | 天气元数据 |
| `/api/csrf_token` | GET | 60/分钟 | CSRF Token 获取 |
| `/api/user/profile` | GET | 60/分钟 | 用户资料 |
| `/api/user/inbox` | GET | 60/分钟 | 收件箱 |
| `/api/user/sent` | GET | 60/分钟 | 已发送 |
| `/api/user/notifications` | GET | 60/分钟 | 通知列表 |

#### 2. 公开内容页面

| URI | HTTP 方法 | 速率限制 | 说明 |
|-----|----------|---------|------|
| `/m/<unique_id>` | GET | 100/分钟 | 公开消息查看 |
| `/letters/<token>` | GET | 100/分钟 | 信件查看 |
| `/api/letters/<id>/unlock` | POST | 30/分钟 | 解锁信件 |

#### 3. 静态资源

| URI | HTTP 方法 | 速率限制 | 说明 |
|-----|----------|---------|------|
| `/static/*` | GET | 缓存 + 速率限制 | 静态文件，建议 Cloudflare 缓存 |
| `/` | GET | 60/分钟 | 首页 |

---

### 🟢 低优先级 - 跳过或轻量保护

这些端点风险较低，可使用轻量保护。

| URI | HTTP 方法 | 保护措施 | 说明 |
|-----|----------|---------|------|
| `/privacy-policy` | GET | 无 | 隐私政策页面 |
| `/privacy-policy-cn` | GET | 无 | 中文隐私政策 |
| `/api/health` | GET | 无或 IP 白名单 | 健康检查，建议内部 IP |
| `/wechat` | GET/POST | 签名验证 | 微信回调，有微信签名保护 |

---

## Cloudflare 配置建议

### 1. WAF 自定义规则（推荐配置）

#### 规则 A：管理员面板保护（最高优先级）
```
名称: Admin Panel Protection
表达式: (http.request.uri.path regex "^/admin/.*") or (http.request.uri.path eq "/admin")
操作: Managed Challenge
+ 如果可能，添加 IP 限制
```

#### 规则 B：认证端点保护
```
名称: Auth Endpoints Protection
表达式: http.request.uri.path regex "^/api/auth/.*"
操作: Managed Challenge
```

#### 规则 C：API 提交保护
```
名称: API Submission Protection
表达式: (http.request.uri.path eq "/api/messages" and http.request.method eq "POST") or
        http.request.uri.path regex "^/api/letters/[^/]+/reply$"
操作: Managed Challenge
```

#### 规则 D：API 速率限制
```
名称: API Rate Limiting
表达式: http.request.uri.path regex "^/api/.*"
操作: Rate Limit (100 requests per 5 minutes per IP)
```

#### 规则 E：Bot 检测跳过
```
名称: Skip Challenge for Static Assets
表达式: http.request.uri.path regex "^/static/.*"
操作: Skip (Allow)
```

#### 规则 F：健康检查跳过
```
名称: Skip for Health Check
表达式: http.request.uri.path eq "/api/health"
操作: Skip，建议使用 IP Access Rules 限制访问
```

### 2. Bot Fight Mode

建议启用 **Bot Fight Mode** 或 **Super Bot Fight Mode**：
- 自动检测并挑战机器爬虫
- 减少对 API 的恶意扫描

### 3. 安全级别

建议配置：
- **Security Level**: Medium 或 High
- **Browser Integrity Check**: 启用

### 4. 防 DDoS 设置

- **Under Attack Mode**: 仅在遭受攻击时启用
- **HTTP/3 支持**: 启用（减少 DDoS 影响）

### 5. IP 访问规则（针对管理员）

```
类型: Allow
值: <管理员 IP 地址>
备注: RainMail Admin Access

类型: Block
值: (all)
适用于: /admin/*
```

---

## 应用已有安全措施

RainMail 应用已实现以下安全措施，Cloudflare 防护与之互补：

| 措施 | 实现位置 | 说明 |
|-----|---------|------|
| CSRF 保护 | `app.py:290-327` | 所有状态变更操作 |
| 速率限制 | Flask-Limiter | 消息 10/min，注册 3/hour |
| 暴力破解保护 | `app.py:765-776` | 5 次失败锁定 30 分钟 |
| XSS 保护 | `app.py:1009-1017` | 输入清理 + CSP 头 |
| Session 安全 | `app.py:75-79` | HttpOnly + SameSite=Lax |
| 内容审核 | AI + 关键词过滤 | 敏感内容检测 |
| Honeypot | `app.py:1312-1323` | Bot 检测 |

---

## 关键文件位置

| 文件/路径 | 说明 |
|----------|------|
| `/Users/ccy/Project/rainmail/app.py` | 主应用文件（所有路由和逻辑） |
| `/Users/ccy/Project/rainmail/run.py` | 启动入口 |
| `/Users/ccy/Project/rainmail/config_loader.py` | 配置加载 |
| `/Users/ccy/Project/rainmail/.env` | 环境配置（包含 ADMIN_PATH_PREFIX） |
| `/Users/ccy/Project/rainmail/Dockerfile` | Docker 配置 |
| `/Users/ccy/Project/rainmail/docker-compose.yml` | Docker 编排 |

---

## 验证步骤

1. **Cloudflare Dashboard 设置**
   - 登录 Cloudflare Dashboard
   - 选择域名
   - 进入 Security > WAF > Custom Rules
   - 按上述规则创建 WAF 规则

2. **测试验证**
   - 访问 `/admin` - 应显示质询页面
   - 尝试频繁请求 `/api/weather` - 应被速率限制
   - 正常访问首页 - 应正常加载

3. **监控**
   - Cloudflare Analytics > Traffic
   - 查看被拦截的请求
   - 调整规则严格程度

---

## 注意事项

1. **管理员路径可变**：`ADMIN_PATH_PREFIX` 环境变量可修改管理面板路径，需要相应更新 Cloudflare 规则

2. **微信端点**：`/wechat` 用于接收微信服务器回调，已有签名验证，Cloudflare 建议跳过或仅轻度保护

3. **健康检查**：`/api/health` 建议通过 Cloudflare IP Access Rules 限制，避免暴露给公网

4. **静态资源**：建议启用 Cloudflare CDN 缓存，减轻源站压力
