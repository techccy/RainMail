# RainMail 远端 Linux 服务器部署指南

## 1. 准备工作

### 在本地（Mac）

```bash
# 进入项目目录
cd /Users/ccy/Project/rainmail

# 打包项目（排除不必要的文件）
tar czf rainmail.tar.gz \
    --exclude='.git' \
    --exclude='__pycache__' \
    --exclude='*.pyc' \
    --exclude='.DS_Store' \
    --exclude='venv' \
    .
```

### 传输到服务器

```bash
# 替换 USER 和 SERVER_IP 为你的实际值
scp rainmail.tar.gz USER@SERVER_IP:~/
```

---

## 2. 服务器端部署

### 登录服务器

```bash
ssh USER@SERVER_IP
```

### 解压并准备

```bash
# 解压
mkdir -p ~/rainmail
tar xzf rainmail.tar.gz -C ~/rainmail
cd ~/rainmail
```

---

## 3. 配置 iptables 网络隔离

### 设置规则（阻止容器访问内网）

```bash
# 添加 iptables 规则
sudo iptables -I DOCKER-USER -i docker0 -d 10.0.0.0/8 -j DROP
sudo iptables -I DOCKER-USER -i docker0 -d 172.16.0.0/12 -j DROP
sudo iptables -I DOCKER-USER -i docker0 -d 192.168.0.0/16 -j DROP
```

### 验证规则

```bash
sudo iptables -L DOCKER-USER -n -v
```

应该看到类似输出：

```
Chain DOCKER-USER (1 references)
pkts bytes target     prot opt in     out     source               destination
    0     0 DROP       all  --  docker0 *       0.0.0.0/0            192.168.0.0/16
    0     0 DROP       all  --  docker0 *       0.0.0.0/0            172.16.0.0/12
    0     0 DROP       all  --  docker0 *       0.0.0.0/0            10.0.0.0/8
    0     0 RETURN     all  --  *      *       0.0.0.0/0            0.0.0.0/0
```

### 持久化 iptables 规则

**Ubuntu/Debian:**

```bash
# 安装持久化工具
sudo apt-get update
sudo apt-get install -y iptables-persistent

# 保存当前规则
sudo netfilter-persistent save
```

**CentOS/RHEL:**

```bash
# 安装服务
sudo yum install -y iptables-services

# 保存规则
sudo service iptables save
```

### 验证重启后规则仍然有效

```bash
# 查看保存的规则
sudo cat /etc/iptables/rules.v4    # Debian/Ubuntu
# 或
sudo cat /etc/sysconfig/iptables   # CentOS/RHEL
```

---

## 4. 构建并启动服务

```bash
cd ~/rainmail

# 构建镜像
docker-compose build

# 启动服务（后台运行）
docker-compose up -d

# 查看日志
docker-compose logs -f
```

---

## 5. 验证部署

### 检查服务状态

```bash
# 查看容器状态
docker-compose ps

# 查看健康检查
docker inspect rainmail | grep -A 5 Health
```

### 测试网络隔离

```bash
# 进入容器
docker exec -it rainmail sh

# 在容器内测试（应该失败）
ping -c 1 192.168.1.1      # 私网 IP
ping -c 1 172.16.0.1       # 私网 IP
ping -c 1 10.0.0.1         # 私网 IP

# 测试公网（应该成功）
ping -c 1 8.8.8.8

# 退出容器
exit
```

---

## 6. 常用管理命令

```bash
# 停止服务
docker-compose down

# 重启服务
docker-compose restart

# 查看日志
docker-compose logs -f

# 更新代码后重新部署
cd ~/rainmail
# 上传新代码后...
docker-compose down
docker-compose build
docker-compose up -d
```

---

## 7. 故障排查

### 容器无法启动

```bash
# 查看详细日志
docker-compose logs rainmail

# 检查容器状态
docker ps -a
```

### iptables 规则丢失

```bash
# 重新加载保存的规则
sudo netfilter-persistent reload   # Debian/Ubuntu
sudo systemctl reload iptables      # CentOS/RHEL
```

### 网络隔离不生效

```bash
# 检查 DOCKER-USER 链
sudo iptables -L DOCKER-USER -n -v

# 确认规则顺序（DROP 规则应在 RETURN 之前）
# 如果顺序错误，重新添加规则
```

---

## 8. 防火墙端口开放（如需要）

如果服务器启用了 ufw/firewalld，需要开放端口 5024：

**Ubuntu (ufw):**

```bash
sudo ufw allow 5024/tcp
sudo ufw reload
```

**CentOS (firewalld):**

```bash
sudo firewall-cmd --permanent --add-port=5024/tcp
sudo firewall-cmd --reload
```
