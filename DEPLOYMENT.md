# RainMail 部署指南

本项目支持两种部署方式：Docker 部署和直接运行（本地开发/调试）。

## 前置要求

两种部署方式都需要：

1. Python 3.9+
2. 复制配置文件：
   ```bash
   cp .env.example .env
   ```
3. 编辑 `.env` 文件，填入实际的配置值（特别是 `SECRET_KEY`、天气 API 密钥等）

## 方式一：Docker 部署（推荐生产环境）

### 特点
- 完全隔离的运行环境
- 自动创建数据卷用于数据持久化
- 内置健康检查
- 资源限制保护

### 部署步骤

```bash
# 构建镜像
docker-compose build

# 启动服务
docker-compose up -d

# 查看日志
docker-compose logs -f rainmail

# 停止服务
docker-compose down
```

### 数据存储
Docker 部署使用以下数据卷：
- `rainmail_instance`: 实例文件夹，持久化数据库文件 `instance/rainmail.db`

### 访问地址
http://localhost:5024

## 方式二：直接运行（适合开发/调试）

### 特点
- 快速启动，便于调试
- 与 Docker 部署使用相同的数据库路径（`instance/rainmail.db`），便于切换
- 支持热重载（如需调试模式）

### 安装依赖

```bash
pip install -r requirements.txt
```

### 启动应用

```bash
python run.py
```

或使用测试脚本（推荐首次使用）：

```bash
python test_local.py
```

### 调试模式

如需启用调试模式，编辑 `run.py`，将 `debug=False` 改为 `debug=True`：

```python
app.run(host='0.0.0.0', port=5024, debug=True)
```

### 数据存储
直接运行时，数据存储在项目目录下的 `./instance/` 文件夹中：
- 数据库文件：`./instance/rainmail.db`

### 访问地址
http://localhost:5024

## 数据库路径说明

两种部署方式**统一使用 `instance/rainmail.db` 作为数据库路径**，由 `.env` 里的 `DATABASE_PATH` 控制：

| 环境 | 数据库路径 | 说明 |
|------|-----------|------|
| Docker | `/app/instance/rainmail.db` | 容器内路径，通过 `rainmail_instance` 数据卷持久化 |
| 本地 | `./instance/rainmail.db` | 项目根的 instance 目录，首次运行自动创建 |

两种环境 `.env` 里 `DATABASE_PATH` 都设为 `sqlite:///instance/rainmail.db`：
- Docker 容器 `WORKDIR=/app`，相对路径解析为 `/app/instance/rainmail.db`，与卷挂载一致
- 本地运行时，应用基于自身位置锚定项目根，相对路径解析为项目根的 `instance/rainmail.db`

如需自定义数据库位置，修改 `.env` 中的 `DATABASE_PATH` 即可（绝对路径用 4 个斜杠：`sqlite:////abs/path/db.db`）。

## 注意事项

### Docker 部署
- 确保端口 5024 未被占用
- 数据卷会自动创建并挂载
- 停止容器后数据仍然保留（数据卷持久化）

### 本地运行
- 首次运行会自动创建 `./instance` 目录
- 确保当前用户有写入权限
- 如需清空数据，删除 `./instance/rainmail.db` 即可

### 配置文件
- `.env` 文件包含敏感信息，不应提交到版本控制
- `.env.example` 提供了配置模板和说明

## 故障排除

### 问题：本地运行提示 "缺少依赖"
**解决**：运行 `pip install -r requirements.txt`

### 问题：Docker 启动失败
**解决**：检查 Docker 是否正常运行，端口是否被占用

### 问题：数据库初始化失败
**解决**：
- 本地：检查 `./instance` 目录权限（首次运行会自动创建）
- Docker：检查 `rainmail_instance` 数据卷是否正常挂载

### 问题：天气功能不可用
**解决**：检查 `.env` 文件中的 `HEFENG_HOST*` 和 `HEFENG_KEY*` 配置

## 开发建议

1. 本地开发和调试使用直接运行方式
2. 测试和生产环境使用 Docker 部署
3. 两种方式使用相同的配置文件格式（`.env`）
4. 数据库路径由 `.env` 中的 `DATABASE_PATH` 控制，两种方式默认一致，无需手动修改

## 性能调优

### Docker 部署
默认资源限制：
- CPU: 最大 1.0 核心
- 内存: 最大 512MB

可根据需要调整 `docker-compose.yml` 中的资源限制配置。

### 本地运行
- 生产环境建议使用 `debug=False`
- 开发环境可使用 `debug=True` 启用热重载

## 安全建议

1. 定期更新依赖：`pip install --upgrade -r requirements.txt`
2. 使用强密码作为 `SECRET_KEY`
3. 生产环境设置 `SESSION_COOKIE_SECURE=true`
4. 启用 HTTPS
5. 定期备份数据库文件
