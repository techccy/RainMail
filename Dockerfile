FROM python:3.9-slim

WORKDIR /app

# 设置时区
ENV TZ=Asia/Shanghai
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

# 安装系统依赖
RUN apt-get update && apt-get install -y \
    sqlite3 \
    && rm -rf /var/lib/apt/lists/*

# 复制项目文件
COPY requirements.txt .
COPY config.yaml .
COPY app.py .
COPY run.py .
COPY templates/ ./templates/
COPY static/ ./static/

# 安装Python依赖
RUN pip install --no-cache-dir -r requirements.txt

# 创建数据库目录
RUN mkdir -p /data && chmod 777 /data

# 暴露端口
EXPOSE 5024

# 健康检查
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:5024/api/health || exit 1

# 启动应用
CMD ["python", "run.py"]