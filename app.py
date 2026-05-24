from curses import flash
import threading
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, send_from_directory, make_response, flash
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message as EmailMessage
import requests
import yaml
import time
import logging
from datetime import datetime, timedelta
import re
import psutil
import os
import hashlib
import csv
import secrets
import base64
import json
import random
import string
from werkzeug.security import generate_password_hash, check_password_hash

# 用于防止并发请求天气API的锁
weather_request_lock = threading.Lock()
# 临时存储正在进行的天气请求的结果
pending_weather_result = None

app = Flask(__name__)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

# --- 新增：加载配置文件 ---
config_path = os.path.join(os.path.dirname(__file__), 'config.json')
config_yaml_path = os.path.join(os.path.dirname(__file__), 'config.yaml')

def migrate_yaml_to_json():
    """将YAML配置迁移到JSON格式"""
    if not os.path.exists(config_path) and os.path.exists(config_yaml_path):
        import yaml
        try:
            with open(config_yaml_path, 'r', encoding='utf-8') as f:
                yaml_config = yaml.safe_load(f)
            with open(config_path, 'w', encoding='utf-8') as f:
                json.dump(yaml_config, f, ensure_ascii=False, indent=2)
            print(f"[INFO] 已将 config.yaml 迁移至 config.json")
            return yaml_config
        except Exception as e:
            print(f"[ERROR] YAML迁移失败: {e}")
            return {}

def load_config():
    """加载JSON配置文件，如果不存在则尝试从YAML迁移"""
    if os.path.exists(config_path):
        with open(config_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    else:
        # 尝试从YAML迁移
        config = migrate_yaml_to_json()
        if config:
            return config
        return {}

config = load_config()
app.config.update(config)
app.secret_key = 'rainmail_secret_key_2024'
TURNSTILE_SECRET_KEY = app.config.get('TURNSTILE_SECRET_KEY')
TURNSTILE_SITE_KEY = app.config.get('TURNSTILE_SITE_KEY')
ALTCHA_HMAC_KEY = app.config.get('ALTCHA_HMAC_KEY', '')
ALTCHA_DIFFICULTY = app.config.get('ALTCHA_DIFFICULTY', 5)  # 默认难度为5
ASK_TIMES = app.config.get('TIMES', 900) # 请求频率 (900秒)
LOCATION_ID = app.config.get('LOCATION_ID', 101280101)  # 广东广州的和风天气位置ID
LOCATION_NAME = app.config.get('LOCATION_NAME', '广州') # 服务器所在位置名称
SENSITIVE_WORDS_SET = set()
IPINFO_TOKEN = app.config.get('IPINFO_TOKEN') # ipinfo.io 访问令牌

# --- 修改：动态加载多组API配置 ---
API_PAIRS = []
api_index = 1
while True:
    host_key = app.config.get(f'HEFENG_HOST{api_index}')
    api_key = app.config.get(f'HEFENG_KEY{api_index}')
    if host_key and api_key:
        API_PAIRS.append((host_key, api_key))
        print(f"[INFO] Loaded API Pair {api_index}: {host_key[:20]}.../{api_key[:5]}...")
        api_index += 1
    else:
        break

if not API_PAIRS:
    print("[ERROR] config.yaml 中未找到任何有效的 HEFENG_HOST*/HEFENG_KEY* 配置，天气功能将不可用。")
    API_AVAILABLE = False
else:
    API_AVAILABLE = True
    print(f"[INFO] 总共加载了 {len(API_PAIRS)} 组天气API。")

# 数据库配置
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///rainmail.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# 邮件配置
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', app.config.get('MAIL_SERVER', 'smtp.gmail.com'))
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', app.config.get('MAIL_PORT', 587)))
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', app.config.get('MAIL_USE_TLS', True))
app.config['MAIL_USE_SSL'] = os.environ.get('MAIL_USE_SSL', app.config.get('MAIL_USE_SSL', False))
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME', app.config.get('MAIL_USERNAME', ''))
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD', app.config.get('MAIL_PASSWORD', ''))
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER', app.config.get('MAIL_DEFAULT_SENDER', 'RainMail <noreply@rainmail.dev>'))
mail = Mail(app)

# def load_sensitive_words_from_csv(file_path):
#     """
#     从 all.csv 文件中加载标记为敏感词 (_sensitivewords=1) 的词到集合中
#     :param file_path: all.csv 文件路径
#     """
#     global SENSITIVE_WORDS_SET
#     try:
#         # Use 'utf-8-sig' to automatically handle the BOM character
#         with open(file_path, 'r', encoding='utf-8-sig') as csvfile:
#             reader = csv.DictReader(csvfile)
#             # With utf-8-sig, the column names should now be clean without BOM
#             words_from_csv = {
#                 row['keyword'].strip() # Now this should work correctly
#                 for row in reader
#                 if row.get('_sensitivewords') == '1' and row.get('keyword', '').strip()
#             }

#         SENSITIVE_WORDS_SET = words_from_csv
#         print(f"成功从 all.csv 加载 {len(SENSITIVE_WORDS_SET)} 个标记为敏感的唯一词语。")

#     except FileNotFoundError:
#         print(f"错误：未找到敏感词 CSV 文件 {file_path}")
#         SENSITIVE_WORDS_SET = set()
#     except KeyError as e:
#         print(f"错误：CSV 文件 {file_path} 中缺少必要的列: {e}")
#         SENSITIVE_WORDS_SET = set()

def ai_moderation_check(content):
    ai_config = app.config.get('AI_MODERATION')
    if not ai_config or not ai_config.get('API_KEY'):
        return False

    headers = {
        "Authorization": f"Bearer {ai_config['API_KEY']}",
        "Content-Type": "application/json"
    }

    payload = {
        "model": ai_config.get('MODEL', 'deepseek-chat'),
        "messages": [
            {"role": "system", "content": ai_config['SYSTEM_PROMPT']},
            {"role": "user", "content": content}
        ],
        "temperature": 0.0,
        "max_tokens": 800 # 稍微给一点空间让它输出结果
    }

    try:
        response = requests.post(
            f"{ai_config['BASE_URL']}/chat/completions",
            headers=headers,
            json=payload,
            timeout=5
        )
        res_data = response.json()
        raw_output = res_data['choices'][0]['message']['content'].upper()

        app.logger.info(f"AI Raw Response: [{raw_output}]")

        # 从后往前找 True 和 False 出现的位置
        pos_true = raw_output.rfind("TRUE")
        pos_false = raw_output.rfind("FALSE")

        # 逻辑判断：
        # 1. 如果都没找到，说明敏感词中了
        if pos_true == -1 and pos_false == -1:
            app.logger.warning("AI未返回明确指令，默认放行")
            return True

        # 2. 谁的位置索引（Index）更大，说明谁更靠后出现
        if pos_true > pos_false:
            app.logger.info("判别结果：拦截 (True 靠后)")
            return True
        else:
            app.logger.info("判别结果：通过 (False 靠后)")
            return False

    except Exception as e:
        app.logger.error(f"AI 审计请求异常: {e}")
        return False

# 定义消息模型
class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now)
    location = db.Column(db.String(50), default='广州')
    unique_identifier = db.Column(db.String(8), nullable=True)

    # 新增字段：情感投递系统
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)  # 可为空保持匿名
    delivery_type = db.Column(db.String(20), default='public')  # 'public' 或 'private'
    delivery_options = db.Column(db.JSON, nullable=True)  # 存储投递选项
    reply_notification = db.Column(db.String(20), default='none')  # 'none', 'email', 'wechat'
    is_anonymous = db.Column(db.Boolean, default=True)
    reply_to_id = db.Column(db.Integer, db.ForeignKey('message.id'), nullable=True)
    hugs_count = db.Column(db.Integer, default=0)

    def to_dict(self):
        return {
            'id': self.id,
            'content': self.content,
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            'location': self.location,
            'unique_identifier': self.unique_identifier,
            'delivery_type': self.delivery_type,
            'is_anonymous': self.is_anonymous,
            'hugs_count': self.hugs_count
        }

# --- 新增：天气缓存模型 ---
class LocationWeatherCache(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    city = db.Column(db.String(100), nullable=False, unique=True) # 城市名
    weather_status = db.Column(db.String(10), nullable=False) # 'sunny' or 'rainy'
    weather_text = db.Column(db.String(50)) # 天气描述，可选
    icon_code = db.Column(db.String(10))   # 图标代码，可选
    raw_weather_data = db.Column(db.Text) # 存储原始的 now_data (JSON字符串)
    last_updated = db.Column(db.DateTime, default=datetime.now) # 上次更新时间
    last_used_api_index = db.Column(db.Integer, default=0) # 记录上次使用的API索引

# --- 新增：IP位置缓存模型 ---
class IPLocationCache(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), nullable=False, unique=True) # IPv4: 15 chars, IPv6: up to 39 chars, + buffer
    city = db.Column(db.String(100), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now)
    updated_at = db.Column(db.DateTime, default=datetime.now, onupdate=datetime.now)

# --- 新增：用户模型 ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    username = db.Column(db.String(50))
    is_verified = db.Column(db.Boolean, default=False)
    verification_token = db.Column(db.String(128))
    created_at = db.Column(db.DateTime, default=datetime.now)
    last_login = db.Column(db.DateTime)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def to_dict(self):
        return {
            'id': self.id,
            'email': self.email,
            'username': self.username,
            'is_verified': self.is_verified,
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S')
        }

# --- 新增：信件投递记录模型 ---
class LetterDelivery(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    message_id = db.Column(db.Integer, db.ForeignKey('message.id'))
    recipient_email = db.Column(db.String(120))  # 未登录用户邮箱
    recipient_user_id = db.Column(db.Integer, db.ForeignKey('user.id'))  # 登录用户
    recipient_city = db.Column(db.String(100))
    delivery_status = db.Column(db.String(20), default='pending')  # pending/delivered/read
    unlock_token = db.Column(db.String(64))  # 匿名收件人的解锁令牌
    unlocked_at = db.Column(db.DateTime)
    read_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.now)

# --- 新增：回复模型 ---
class MessageReply(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    original_message_id = db.Column(db.Integer, db.ForeignKey('message.id'))
    reply_content = db.Column(db.Text)
    reply_type = db.Column(db.String(20), default='text')  # 'text' 或 'hug'
    replier_user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    replier_email = db.Column(db.String(120))  # 匿名回复者邮箱
    created_at = db.Column(db.DateTime, default=datetime.now)

# --- 新增：通知模型 ---
class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    email = db.Column(db.String(120))  # 非登录用户
    notification_type = db.Column(db.String(50))
    title = db.Column(db.String(100))
    content = db.Column(db.Text)
    related_id = db.Column(db.Integer)
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.now)

# --- 新增：邮件队列表 ---
class EmailQueue(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    recipient_email = db.Column(db.String(120))
    email_type = db.Column(db.String(50))
    subject = db.Column(db.String(200))
    body_html = db.Column(db.Text)
    status = db.Column(db.String(20), default='pending')
    attempts = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.now)

# --- 新增：微信绑定表（预留）---
class WeChatBinding(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    wechat_openid = db.Column(db.String(100), unique=True)
    created_at = db.Column(db.DateTime, default=datetime.now)

# 初始化数据库
with app.app_context():
    db.create_all()

# sensitive_words_csv_file = os.path.join(os.path.dirname(__file__), 'resources', 'all.csv')
# load_sensitive_words_from_csv(sensitive_words_csv_file)

# 全局状态变量
force_rain_until = None  # 强制降雨结束时间

def hash_password(password):
    """密码哈希函数"""
    return hashlib.sha256(password.encode()).hexdigest()

def sanitize_input(text):
    """基本的XSS过滤"""
    # 移除HTML标签
    text = re.sub(r'<script.*?>.*?</script>', '', text, flags=re.DOTALL)
    text = re.sub(r'<.*?>', '', text)
    # 移除危险字符
    text = text.replace('"', '"').replace("'", '&#39;')
    text = text.replace('<', '<').replace('>', '>')
    return text.strip()

# 获取用户位置IP地址的函数
def get_client_ip():
    # 优先使用 Cloudflare 提供的头
    if request.headers.getlist("CF-Connecting-IP"):
        ip = request.headers.getlist("CF-Connecting-IP")[0]
    # 否则尝试 X-Forwarded-For
    elif request.headers.getlist("X-Forwarded-For"):
        ip = request.headers.getlist("X-Forwarded-For")[0].split(',')[0]
    # 最后使用 remote_addr
    else:
        ip = request.remote_addr
    return ip

def get_city_by_ip(ip_address):
    """
    根据 IP 地址获取城市名，优先从数据库缓存获取。
    """
    cache_entry = IPLocationCache.query.filter_by(ip_address=ip_address).first()

    # 定义缓存过期时间（例如，1个月 = 30天 * 24小时 * 3600秒）
    cache_expiry_seconds = 30 * 24 * 3600

    if cache_entry:
        # 检查缓存是否过期
        time_diff = (datetime.now() - cache_entry.updated_at).total_seconds()
        if time_diff < cache_expiry_seconds:
            print(f"[INFO] Resolved {ip_address} to '{cache_entry.city}' from cache.")
            return cache_entry.city
        else:
            print(f"[INFO] Cache for {ip_address} is expired, fetching fresh data...")

    # 缓存未命中或已过期，调用 API 查询
    try:
        print(f"[DEBUG] Attempting to get city for {ip_address} using ip-api.com")
        # 使用 HTTPS，并确保参数正确
        response = requests.get(
            f"http://ip-api.com/json/{ip_address}",
            params={'fields': 'status,message,country,regionName,city'},
            timeout=10
        )
        data = response.json()

        if data.get('status') == 'success':
            # 优先返回 city，其次 regionName，最后 country
            city = data.get('city')
            region = data.get('regionName')
            country = data.get('country')

            if city and city.lower() != 'unknown':
                result = city
            elif region and region.lower() != 'unknown':
                result = region
            elif country and country.lower() != 'unknown':
                result = country
            else:
                result = 'Unknown'

            print(f"[INFO] Resolved {ip_address} to '{result}' via ip-api.com")

            # 更新或创建缓存记录
            if cache_entry:
                cache_entry.city = result
                cache_entry.updated_at = datetime.now()
            else:
                cache_entry = IPLocationCache(ip_address=ip_address, city=result)
            db.session.add(cache_entry)
            db.session.commit() # 提交数据库更改

            return result
        else:
            # 如果 ip-api.com 失败，记录日志
            app.logger.warning(f"ip-api.com failed for {ip_address}: {data.get('message', 'Unknown error')}")
            # 可以选择返回默认值，或者尝试其他 API（如果已集成）
            # 这里先返回默认值 '广州'
            default_city = app.config.get('LOCATION_NAME', '广州')
            print(f"[INFO] Falling back to default city: {default_city} for {ip_address} after API failure.")
            # 即使 API 失败，也可以选择性地缓存失败结果（例如，缓存为 'Unknown' 或特定标记），
            # 以避免立即重试。这里为了简单，不缓存失败结果，每次都尝试。
            # 如果要缓存失败结果，可以创建一个新记录或更新现有记录为 'Unknown' 等。
            # 例如： cache_entry.city = 'Unknown'
            # 但需要一个机制区分是 API 临时失败还是 IP 确实未知。
            # 这里我们只缓存成功的查询结果。
            return default_city

    except Exception as e:
        app.logger.error(f"Error getting city for IP {ip_address} using ip-api.com: {e}")
        # 同样，返回默认值
        default_city = app.config.get('LOCATION_NAME', '广州')
        print(f"[INFO] Error resolving {ip_address}, falling back to default city: {default_city}")
        # 不缓存错误结果
        return default_city

def generate_unique_id(length=8):
    """生成指定长度的随机大写字母和数字组合"""
    characters = string.ascii_uppercase + string.digits # 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
    return ''.join(random.choices(characters, k=length))

def validate_turnstile(turnstile_response, user_ip):
    """
    验证 Cloudflare Turnstile Token
    """
    secret_key = app.config.get('TURNSTILE_SECRET_KEY')
    if not secret_key:
        app.logger.error("TURNSTILE_SECRET_KEY 未在 config.yaml 中配置！")
        return False

    payload = {
        'secret': secret_key,
        'response': turnstile_response,
        'remoteip': user_ip
    }
    try:
        response = requests.post('https://challenges.cloudflare.com/turnstile/v0/siteverify', data=payload, timeout=10)
        result = response.json()
        return result.get('success', False)
    except requests.RequestException as e:
        app.logger.error(f"Turnstile 验证请求失败: {e}")
        return False
    except ValueError as e: # JSON 解析错误
        app.logger.error(f"Turnstile 验证响应解析失败: {e}")
        return False

def validate_cha(cha_response, session):
    """
    验证 CHA (Custom Human Authentication) 验证码
    """
    expected_answer = session.get('cha_answer')
    timestamp = session.get('cha_timestamp')
    
    if not expected_answer or not timestamp:
        app.logger.error("CHA 验证信息丢失")
        return False
    
    # 检查验证码是否过期 (5分钟)
    if time.time() - timestamp > 300:
        app.logger.error("CHA 验证码已过期")
        return False
    
    # 验证答案
    if str(cha_response) != str(expected_answer):
        app.logger.error(f"CHA 验证失败: 输入 {cha_response}, 期望 {expected_answer}")
        return False
    
    return True

def generate_cha_question():
    """
    生成 CHA 验证问题 (简单的数学运算)
    """
    num1 = random.randint(1, 10)
    num2 = random.randint(1, 10)
    operators = ['+', '-', '*']
    operator = random.choice(operators)
    
    if operator == '+':
        answer = num1 + num2
        question = f"{num1} + {num2} = ?"
    elif operator == '-':
        answer = num1 - num2
        question = f"{num1} - {num2} = ?"
    else:  # '*'
        answer = num1 * num2
        question = f"{num1} × {num2} = ?"
    
    return question, answer

def validate_captcha(captcha_response, user_ip=None, session=None):
    """
    统一的验证函数，根据配置选择验证方式
    """
    captcha_provider = app.config.get('CAPTCHA_PROVIDER', 'cloudflare').lower()

    if captcha_provider == 'cloudflare':
        return validate_turnstile(captcha_response, user_ip)
    elif captcha_provider == 'cha':
        return validate_cha(captcha_response, session)
    elif captcha_provider == 'altcha':
        return validate_altcha(captcha_response)
    else:
        app.logger.error(f"未知的验证提供商: {captcha_provider}")
        return False

def validate_altcha(payload):
    """
    验证 Altcha 工作量证明响应
    """
    if not ALTCHA_HMAC_KEY:
        app.logger.error("ALTCHA_HMAC_KEY 未在 config.yaml 中配置！")
        return False

    try:
        import hmac

        data = json.loads(payload)

        # 验证必需字段
        required_fields = ['challenge', 'number', 'salt', 'signature', 'hash_result']
        if not all(field in data for field in required_fields):
            app.logger.error(f"Altcha 响应缺少必需字段，已有字段: {list(data.keys())}")
            return False

        challenge = data['challenge']
        number = data['number']
        salt = data['salt']
        signature = data['signature']
        hash_result = data['hash_result']

        # 1. 验证签名（防止伪造挑战）
        expected_signature = hmac.new(
            ALTCHA_HMAC_KEY.encode(),
            challenge.encode(),
            hashlib.sha256
        ).hexdigest()

        if signature != expected_signature:
            app.logger.error("Altcha 签名验证失败")
            return False

        # 2. 重新计算目标前缀（基于服务器端的难度配置）
        # 这确保客户端必须满足服务器端要求的难度
        target_seed = hmac.new(
            ALTCHA_HMAC_KEY.encode(),
            f"{challenge}{salt}".encode(),
            hashlib.sha256
        ).hexdigest()
        target_prefix = target_seed[:ALTCHA_DIFFICULTY]

        # 3. 验证哈希结果是否以目标前缀开头
        if not hash_result.startswith(target_prefix):
            app.logger.error(f"Altcha 哈希结果不满足目标前缀: 期望 {target_prefix}...，得到 {hash_result[:ALTCHA_DIFFICULTY]}...")
            return False

        # 4. 验证哈希结果确实是由 challenge + number 计算得出
        test_string = f"{challenge}{number}"
        expected_hash = hashlib.sha256(test_string.encode()).hexdigest()

        if hash_result != expected_hash:
            app.logger.error("Altcha 哈希结果与计算值不匹配")
            return False

        app.logger.info(f"Altcha 验证成功: {hash_result[:10]}...")
        return True

    except json.JSONDecodeError as e:
        app.logger.error(f"Altcha JSON 解析失败: {e}")
        return False
    except Exception as e:
        app.logger.error(f"Altcha 验证异常: {e}")
        return False

def check_honeypot(request_data):
    """
    检查蜜罐字段，如果被填充则记录IP并返回True
    蜜罐字段对浏览器隐藏，但脚本机器人会填充
    """
    honeypot_value = request_data.get('website_confirm', '').strip()
    if honeypot_value:
        # 蜜罐被触发，记录IP
        user_ip = request.headers.get('CF-Connecting-IP', request.remote_addr)
        app.logger.warning(f"[HONEYPOT] 机器人IP被记录: {user_ip}, 填充值: {honeypot_value}")
        return True
    return False

def get_cpu_temperature():
    """获取CPU温度（macOS）"""
    try:
        # macOS获取温度的方法
        result = os.popen('powermetrics --samplers smc -n 1 -i 1000 | grep "CPU die temperature"').read()
        if result:
            temp = float(result.split(':')[1].split(' C')[0].strip())
            return temp
        return 45.0  # 默认值
    except:
        return 45.0  # 默认值

# --- 修改：get_weather_status 函数，接受城市参数，使用LocationWeatherCache和API轮换 ---
def get_weather_status(city='广州'): # 默认为广州
    global force_rain_until # 保留强制降雨功能

    # 检查强制降雨状态
    if force_rain_until and datetime.now() < force_rain_until:
        # 如果是强制降雨，更新缓存为雨天（如果存在）
        cache_entry = LocationWeatherCache.query.filter_by(city=city).first()
        if cache_entry:
            cache_entry.weather_status = 'rainy'
            cache_entry.weather_text = '强制降雨'
            cache_entry.icon_code = '300' # 随意一个雨天图标
            cache_entry.last_updated = datetime.now()
            db.session.commit()
        return 'rainy' # 直接返回雨天

    # 检查缓存
    cache_entry = LocationWeatherCache.query.filter_by(city=city).first()

        # 定义一个内部函数来使用 API 更新天气缓存
    def update_weather_cache(city_to_update, api_pairs):
        nonlocal cache_entry # 声明使用外层函数的 cache_entry
        num_apis = len(api_pairs)
        if num_apis == 0:
            print(f"[ERROR] No API pairs available for {city_to_update}")
            return 'sunny', 'API配置缺失', '999', 'null', last_idx
        # 获取上次使用的API索引
        start_index = cache_entry.last_used_api_index if cache_entry else 0
        # 从下一个API开始轮换
        current_api_index = (start_index + 1) % num_apis

        # 尝试使用列表中的 API 对
        for i in range(num_apis):
            idx = (start_index + 1 + i) % num_apis # 轮换索引
            host, key = api_pairs[idx]
            try:
                print(f"[INFO] Trying API {idx+1} for {city_to_update}: {host[:20]}.../{key[:5]}...")
                # 需要根据城市名获取和风天气的 Location ID
                # 使用 v2 API 查找城市 ID
                geo_url = f"https://{host}/geo/v2/city/lookup"
                geo_params = {'location': city_to_update, 'key': key}
                geo_response = requests.get(geo_url, params=geo_params, timeout=10)
                if geo_response.status_code == 200:
                    geo_data = geo_response.json()
                    if geo_data.get('code') == '200' and geo_data.get('location'):
                        location_id = geo_data['location'][0]['id'] # 假设取第一个匹配结果
                        print(f"[INFO] Found location ID {location_id} for {city_to_update}")
                    else:
                        print(f"[WARN] Geo lookup failed for {city_to_update} using API {idx+1} ({host}), response: {geo_data.get('code')}, {geo_data.get('message')}. Trying next API pair.")
                        continue # 尝试下一组 API
                else:
                    print(f"[WARN] Geo lookup request failed for {city_to_update} using API {idx+1} ({host}), status {geo_response.status_code}. Trying next API pair.")
                    continue # 尝试下一组 API

                # 使用获取到的 location_id 请求天气
                weather_url = f"https://{host}/v7/weather/now"
                weather_params = {'location': location_id, 'key': key}
                weather_response = requests.get(weather_url, params=weather_params, timeout=10)

                if weather_response.status_code == 200:
                    weather_data = weather_response.json()
                    if weather_data.get('code') == '200':
                        now_info = weather_data['now']
                        weather_text = now_info.get('text', '')
                        icon_code = now_info.get('icon', '')
                        is_rainy = ('雨' in weather_text) or (icon_code.startswith('3'))
                        new_weather_status = 'rainy' if is_rainy else 'sunny'
                        print(f"[INFO] Successfully fetched weather for {city_to_update} from API {idx+1} ({host}): {weather_text} (状态: {new_weather_status})")
                        # 序列化原始数据
                        import json
                        raw_data_json = json.dumps(now_info)
                        return new_weather_status, weather_text, icon_code, raw_data_json, idx
                    else:
                        print(f"[WARN] Weather API returned error for {city_to_update} using API {idx+1} ({host}): {weather_data.get('code')}, {weather_data.get('message', 'No message')}. Trying next API pair.")
                        continue # 尝试下一组 API
                elif weather_response.status_code == 429:
                    print(f"[WARN] API {idx+1} ({host}) rate limited (429) for {city_to_update}. Trying next API pair.")
                    continue # 尝试下一组 API
                else:
                    print(f"[WARN] Weather API request failed for {city_to_update} using API {idx+1} ({host}), status {weather_response.status_code}. Trying next API pair.")
                    continue # 尝试下一组 API

            except requests.exceptions.RequestException as e:
                print(f"[ERROR] Request failed for {city_to_update} using API {idx+1} ({host}/{key[:5]}...): {e}. Trying next API pair.")
                continue # 尝试下一组 API
            except (ValueError, KeyError) as e:
                print(f"[ERROR] Parsing response failed for {city_to_update} using API {idx+1} ({host}/{key[:5]}...): {e}. Trying next API pair.")
                continue # 尝试下一组 API

        # 如果所有 API 对都失败了
        print(f"[ERROR] All {num_apis} API pairs failed to fetch weather for {city_to_update}.")
        # 返回一个默认值，并保持上次使用的API索引不变
        last_idx = cache_entry.last_used_api_index if cache_entry else 0
        return 'sunny', '获取失败', '999', 'null', last_idx # 返回默认值和上次使用的索引


    # 检查城市缓存是否需要更新 (1小时)
    if cache_entry and (datetime.now() - cache_entry.last_updated).total_seconds() < ASK_TIMES: # 1 hour
        print(f"[INFO] Cache for {city} is fresh (< {ASK_TIMES/60} mins), returning cached status: {cache_entry.weather_status}")
        return cache_entry.weather_status
    else:
        print(f"[INFO] Cache for {city} is stale or missing, updating...")
        # 更新城市缓存
        new_status, new_text, new_icon, new_raw_data, used_api_index = update_weather_cache(city, API_PAIRS)
        if cache_entry:
            cache_entry.weather_status = new_status
            cache_entry.weather_text = new_text
            cache_entry.icon_code = new_icon
            cache_entry.raw_weather_data = new_raw_data # 存储原始数据
            cache_entry.last_updated = datetime.now()
            cache_entry.last_used_api_index = used_api_index
        else:
            cache_entry = LocationWeatherCache(
                city=city,
                weather_status=new_status,
                weather_text=new_text,
                icon_code=new_icon,
                raw_weather_data=new_raw_data, # 存储原始数据
                last_updated=datetime.now(),
                last_used_api_index=used_api_index
            )
            db.session.add(cache_entry)
        db.session.commit()
        print(f"[INFO] Updated cache for {city}: {new_text} (状态: {new_status}), using API {used_api_index+1}")
        return new_status

# --- END 修改 ---

def get_dashboard_data(city='广州'): # 默认为广州
    weather_status = get_weather_status(city) # 传入城市，这会确保缓存被更新

    # 从缓存中获取该城市的完整天气数据
    cache_entry = LocationWeatherCache.query.filter_by(city=city).first()
    if cache_entry and cache_entry.raw_weather_data:
        try:
            import json
            raw_data = json.loads(cache_entry.raw_weather_data)
            precip_prob = raw_data.get('precip', '0') # 从缓存的原始数据中获取 precip
        except (json.JSONDecodeError, AttributeError):
            # 如果解析失败或 raw_weather_data 不是字符串
            precip_prob = '0'
    else:
        # 如果缓存不存在或没有原始数据
        precip_prob = '0'

    # 获取CPU温度
    cpu_temp = get_cpu_temperature()

    # 获取消息数量
    message_count = Message.query.count()

    return {
        'weather_status': weather_status,
        'precip_prob': precip_prob,
        'cpu_temp': round(cpu_temp, 1),
        'message_count': message_count,
        'city': city # 添加城市信息
    }

def admin_required(f):
    """管理员权限装饰器"""
    def wrapper(*args, **kwargs):
        if not session.get('admin_logged_in'):
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    wrapper.__name__ = f.__name__
    return wrapper

@app.route('/')
def index():
    """首页路由"""
    client_ip = get_client_ip()
    city = get_city_by_ip(client_ip)
    dashboard_data = get_dashboard_data(city) # 传递城市
    
    captcha_provider = app.config.get('CAPTCHA_PROVIDER', 'cloudflare').lower()
    site_key = app.config.get('TURNSTILE_SITE_KEY', '') if captcha_provider == 'cloudflare' else ''
    
    return render_template('index.html', **dashboard_data, turnstile_site_key=site_key, captcha_provider=captcha_provider)

@app.route('/api/messages', methods=['GET', 'POST'])
def handle_messages():
    if request.method == 'POST':
        # 提交新消息
        try:
            # 蜜罐检测 - 检查JSON中是否包含蜜罐字段
            if request.json and 'website' in request.json:
                user_ip = request.headers.get('CF-Connecting-IP', request.remote_addr)
                app.logger.warning(f"[HONEYPOT] 机器人IP被记录: {user_ip}, 蜜罐值: {request.json.get('website')}")
                # 返回成功响应但实际不保存，迷惑攻击者
                return jsonify({'error': '请先完成人机验证', 'redirect': '/verify'}), 429

            content = request.json.get('content', '').strip()
            if not content:
                return jsonify({'error': '内容不能为空'}), 400

            captcha_provider = app.config.get('CAPTCHA_PROVIDER', 'cloudflare').lower()
            if captcha_provider == 'cloudflare':
                captcha_response = request.json.get('cf_token')
            elif captcha_provider == 'cha':
                captcha_response = request.json.get('cha_answer')
            elif captcha_provider == 'altcha':
                captcha_response = request.json.get('altcha_payload')
            else:
                captcha_response = None

            user_ip = request.headers.get('CF-Connecting-IP', request.remote_addr)

            if not captcha_response:
                return jsonify({"error": "请完成人机验证"}), 400

            if not validate_captcha(captcha_response, user_ip, session):
                return jsonify({"error": "人机验证失败，请刷新网页"}), 400

            if ai_moderation_check(content):
              app.logger.warning(f"AI 语义拦截: {content}")
              return jsonify({"error": "内容未通过系统安全审查", "blocked": True}), 400

            # 过滤XSS
            content = sanitize_input(content)

            # 获取投递选项
            delivery_type = request.json.get('delivery_type', 'public')  # 'public' 或 'private'
            delivery_options = request.json.get('delivery_options', {})
            reply_notification = request.json.get('reply_notification', 'none')
            is_anonymous = request.json.get('is_anonymous', True)

            # 获取发送者信息
            sender_id = session.get('user_id') if not is_anonymous else None

            # 获取发送者位置
            sender_city = get_city_by_ip(user_ip)

            # 创建新消息
            message = Message(
                content=content,
                location=sender_city,
                sender_id=sender_id,
                delivery_type=delivery_type,
                delivery_options=delivery_options,
                reply_notification=reply_notification,
                is_anonymous=is_anonymous
            )
            message.unique_identifier = generate_unique_id()
            db.session.add(message)
            db.session.commit()

            # 如果是私发，创建投递记录
            if delivery_type == 'private':
                create_private_delivery(message, sender_city)

            # 生成分享卡片信息
            message_count = Message.query.count()
            share_data = {
                'message_id': message.id,
                'total_messages': message_count,
                'created_at': message.created_at.strftime('%Y-%m-%d %H:%M:%S'),
                'weather_status': 'sunny',
                'unique_identifier': message.unique_identifier,
                'delivery_type': delivery_type
            }

            return jsonify({
                'success': True,
                'message': '提交成功',
                'share_data': share_data
            })

        except Exception as e:
            logger.error(f"Message submission error: {str(e)}")
            return jsonify({'error': '提交失败'}), 500

    else:
        # 获取消息列表 (GET)
        # 获取访问者城市
        client_ip = get_client_ip()
        city = get_city_by_ip(client_ip)
        # 根据城市获取天气状态
        weather_status = get_weather_status(city)
        # 只有雨天才返回消息
        if weather_status == 'sunny':
            return jsonify({'error': f'{city} 模式下无法查看消息'}), 403

        # 只返回公开的消息
        messages = Message.query.filter_by(delivery_type='public').order_by(Message.created_at.desc()).all()
        return jsonify({
            'messages': [msg.to_dict() for msg in messages],
            'weather_status': weather_status,
            'city': city
        })

@app.route('/api/weather')
def weather_api():
    """天气状态API"""
    client_ip = get_client_ip()
    city = get_city_by_ip(client_ip)
    dashboard_data = get_dashboard_data(city) # 传递城市
    return jsonify(dashboard_data)

@app.route('/api/health')
def health_check():
    """健康检查接口"""
    return jsonify({'status': 'healthy', 'timestamp': datetime.now().isoformat()})

@app.route('/api/cha/question')
def get_cha_question():
    """获取 CHA 验证问题"""
    captcha_provider = app.config.get('CAPTCHA_PROVIDER', 'cloudflare').lower()

    # 检测是否为移动设备
    user_agent = request.headers.get('User-Agent', '')
    is_mobile = bool(re.search(r'Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini', user_agent, re.IGNORECASE))

    # 允许移动设备在 Altcha 模式下使用 CHA
    if captcha_provider != 'cha' and not (captcha_provider == 'altcha' and is_mobile):
        return jsonify({'error': 'CHA 验证未启用'}), 400

    question, answer = generate_cha_question()
    session['cha_answer'] = answer
    session['cha_timestamp'] = time.time()

    return jsonify({
        'question': question,
        'timestamp': session['cha_timestamp']
    })

@app.route('/api/altcha/challenge')
def get_altcha_challenge():
    """获取 Altcha 挑战"""
    captcha_provider = app.config.get('CAPTCHA_PROVIDER', 'cloudflare').lower()

    if captcha_provider != 'altcha':
        return jsonify({'error': 'Altcha 验证未启用'}), 400

    if not ALTCHA_HMAC_KEY:
        return jsonify({'error': 'Altcha 未配置'}), 500

    import hmac

    # 生成随机挑战字符串
    challenge = secrets.token_hex(16)

    # 生成随机盐值，使每个挑战的目标都不同
    challenge_salt = secrets.token_hex(8)

    # 使用 HMAC 生成签名（用于验证挑战的有效性）
    signature = hmac.new(
        ALTCHA_HMAC_KEY.encode(),
        challenge.encode(),
        hashlib.sha256
    ).hexdigest()

    # 生成目标哈希前缀
    # 这是客户端需要满足的条件：SHA256(challenge + number) 必须以此前缀开头
    # 使用 challenge_salt 确保每个挑战的目标都不同
    # 使用 HMAC 确保客户端无法伪造目标
    target_seed = hmac.new(
        ALTCHA_HMAC_KEY.encode(),
        f"{challenge}{challenge_salt}".encode(),
        hashlib.sha256
    ).hexdigest()

    # 根据难度取前N位作为目标前缀
    # 例如：难度5，target_seed='abc123...'，则 target_prefix='abc12'
    target_prefix = target_seed[:ALTCHA_DIFFICULTY]

    # 返回挑战信息
    # 注意：不直接返回难度值，而是返回签名后的目标前缀
    return jsonify({
        'challenge': challenge,
        'salt': challenge_salt,
        'signature': signature,
        'target_prefix': target_prefix,  # 客户端需要匹配的哈希前缀
        'max_number': 1000000  # 客户端最大尝试次数
    })

# 管理员路由
@app.route('/admin', methods=['GET', 'POST'])
def admin_login():
    """管理员登录"""
    captcha_provider = app.config.get('CAPTCHA_PROVIDER', 'cloudflare').lower()
    
    if request.method == 'POST':
        # --- 蜜罐检测 ---
        if check_honeypot(request.form):
            # 蜜罐被触发，假装登录成功但实际不登录
            site_key = app.config.get('TURNSTILE_SITE_KEY', '') if captcha_provider == 'cloudflare' else ''
            cha_question = session.get('cha_question') if captcha_provider == 'cha' else None
            return render_template('admin_login.html', error='用户名或密码错误', turnstile_site_key=site_key, captcha_provider=captcha_provider, cha_question=cha_question)

        # --- 新增：管理员登录人机验证 ---
        if captcha_provider == 'cloudflare':
            captcha_response = request.form.get('cf-turnstile-response')
        elif captcha_provider == 'cha':
            captcha_response = request.form.get('cha_answer')
        elif captcha_provider == 'altcha':
            captcha_response = request.form.get('altcha_payload')
        else:
            captcha_response = None

        user_ip = request.headers.get('CF-Connecting-IP', request.remote_addr) # 获取真实 IP
        username = request.form.get('username')
        password = request.form.get('password')

        if not captcha_response:
            # --- 修改：不再返回 JSON，而是渲染模板 ---
            site_key = app.config.get('TURNSTILE_SITE_KEY', '') if captcha_provider == 'cloudflare' else ''
            cha_question = session.get('cha_question') if captcha_provider == 'cha' else None
            return render_template('admin_login.html', error='请完成人机验证', turnstile_site_key=site_key, captcha_provider=captcha_provider, cha_question=cha_question)

        if not validate_captcha(captcha_response, user_ip, session):
            site_key = app.config.get('TURNSTILE_SITE_KEY', '') if captcha_provider == 'cloudflare' else ''
            cha_question = session.get('cha_question') if captcha_provider == 'cha' else None
            return render_template('admin_login.html', error='人机验证失败，请刷新网页', turnstile_site_key=site_key, captcha_provider=captcha_provider, cha_question=cha_question)
        # --- 结束新增 ---

        # --- 修正：统一从 config 获取管理员凭据 ---
        admin_username_from_config = app.config.get('admin_username')
        admin_password_from_config = app.config.get('admin_password')

        # 验证用户名和密码（已移除TOTP验证）
        if username == admin_username_from_config and password == admin_password_from_config:
            session['admin_logged_in'] = True
            return redirect(url_for('admin_dashboard'))
        else:
            # 提供更模糊的错误信息以增强安全性
            flash('登录凭据无效或双重认证失败')
            site_key = app.config.get('TURNSTILE_SITE_KEY', '') if captcha_provider == 'cloudflare' else ''
            cha_question = session.get('cha_question') if captcha_provider == 'cha' else None
            return render_template('admin_login.html', error='用户名或密码错误', turnstile_site_key=site_key, captcha_provider=captcha_provider, cha_question=cha_question)

    site_key = app.config.get('TURNSTILE_SITE_KEY', '') if captcha_provider == 'cloudflare' else ''
    
    # 为 CHA 验证生成新问题
    if captcha_provider == 'cha':
        question, answer = generate_cha_question()
        session['cha_question'] = question
        session['cha_answer'] = answer
        session['cha_timestamp'] = time.time()
        cha_question = question
    else:
        cha_question = None
    
    return render_template('admin_login.html', turnstile_site_key=site_key, captcha_provider=captcha_provider, cha_question=cha_question)

@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    """管理员仪表盘"""
    messages = Message.query.order_by(Message.created_at.desc()).all()
    # 为管理员页面获取一个基准城市（例如广州）的天气数据
    dashboard_data = get_dashboard_data(city='广州') # 使用广州作为管理员页面的基准

    return render_template('admin_dashboard.html',
                         messages=messages,
                         **dashboard_data)

@app.route('/admin/force_rain', methods=['POST'])
@admin_required
def admin_force_rain():
    """强制降雨"""
    global force_rain_until

    duration = config.get('force_rain_duration', 40)
    force_rain_until = datetime.now() + timedelta(minutes=duration)
    # 强制降雨后，可以考虑清空所有城市的缓存，或者让缓存逻辑自然更新
    # 这里我们不清空，因为 get_weather_status 会处理 force_rain_until

    return jsonify({
        'success': True,
        'message': f'已强制开启降雨模式 {duration} 分钟',
        'until': force_rain_until.strftime('%Y-%m-%d %H:%M:%S')
    })

@app.route('/admin/delete_message/<int:message_id>', methods=['POST'])
@admin_required
def admin_delete_message(message_id):
    """删除消息"""
    message = Message.query.get_or_404(message_id)
    db.session.delete(message)
    db.session.commit()

    return jsonify({'success': True, 'message': '消息已删除'})

@app.route('/admin/change_password', methods=['POST'])
@admin_required
def admin_change_password():
    """更改管理员密码"""
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')

    if not new_password or new_password != confirm_password:
        return jsonify({'success': False, 'error': '密码不匹配或为空'})

    # 这里应该更新配置文件，简化处理
    return jsonify({
        'success': True,
        'message': '密码已更新（请在config.yaml中手动更新）'
    })

@app.route('/admin/logout')
def admin_logout():
    """管理员登出"""
    session.pop('admin_logged_in', None)
    return redirect(url_for('admin_login'))

@app.route('/admin/settings')
@admin_required
def admin_settings():
    """管理员设置页面"""
    return render_template('admin_settings.html')

# 敏感字段列表（用于脱敏显示）
SENSITIVE_FIELDS = [
    'HEFENG_KEY', 'TURNSTILE_SECRET_KEY', 'TURNSTILE_SITE_KEY',
    'ALTCHA_HMAC_KEY', 'admin_password', 'MAIL_PASSWORD',
    'API_KEY', 'WECHAT_APP_SECRET', 'IPINFO_TOKEN'
]

def mask_sensitive_value(key, value):
    """对敏感字段进行脱敏处理"""
    if value is None or value == '':
        return value
    for sensitive in SENSITIVE_FIELDS:
        if sensitive in key:
            if isinstance(value, str) and len(value) > 4:
                return f'****{value[-4:]}'
            else:
                return '****'
    return value

@app.route('/admin/api/config')
@admin_required
def api_get_config():
    """获取配置（敏感字段脱敏）"""
    config_path = os.path.join(os.path.dirname(__file__), 'config.json')
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            config = json.load(f)

        # 构建分类配置
        categorized_config = {
            'weather': {
                'HEFENG_HOST1': config.get('HEFENG_HOST1', ''),
                'HEFENG_HOST2': config.get('HEFENG_HOST2', ''),
                'HEFENG_HOST3': config.get('HEFENG_HOST3', ''),
                'HEFENG_HOST4': config.get('HEFENG_HOST4', ''),
                'HEFENG_KEY1': mask_sensitive_value('HEFENG_KEY1', config.get('HEFENG_KEY1', '')),
                'HEFENG_KEY2': mask_sensitive_value('HEFENG_KEY2', config.get('HEFENG_KEY2', '')),
                'HEFENG_KEY3': mask_sensitive_value('HEFENG_KEY3', config.get('HEFENG_KEY3', '')),
                'HEFENG_KEY4': mask_sensitive_value('HEFENG_KEY4', config.get('HEFENG_KEY4', '')),
                'times': config.get('times', 3600)
            },
            'captcha': {
                'TURNSTILE_SECRET_KEY': mask_sensitive_value('TURNSTILE_SECRET_KEY', config.get('TURNSTILE_SECRET_KEY', '')),
                'TURNSTILE_SITE_KEY': mask_sensitive_value('TURNSTILE_SITE_KEY', config.get('TURNSTILE_SITE_KEY', '')),
                'CAPTCHA_PROVIDER': config.get('CAPTCHA_PROVIDER', 'altcha'),
                'ALTCHA_HMAC_KEY': mask_sensitive_value('ALTCHA_HMAC_KEY', config.get('ALTCHA_HMAC_KEY', '')),
                'ALTCHA_DIFFICULTY': config.get('ALTCHA_DIFFICULTY', 3),
                'VERIFY_DURATION_MINUTES': config.get('VERIFY_DURATION_MINUTES', 15)
            },
            'location': {
                'LOCATION_NAME': config.get('LOCATION_NAME', '广州'),
                'LOCATION_ID': config.get('LOCATION_ID', 101280101)
            },
            'admin': {
                'admin_username': config.get('admin_username', 'admin'),
                'admin_password': mask_sensitive_value('admin_password', config.get('admin_password', '')),
                'force_rain_duration': config.get('force_rain_duration', 10)
            },
            'mail': {
                'MAIL_SERVER': config.get('MAIL_SERVER', 'smtp.gmail.com'),
                'MAIL_PORT': config.get('MAIL_PORT', 587),
                'MAIL_USE_TLS': config.get('MAIL_USE_TLS', True),
                'MAIL_USERNAME': config.get('MAIL_USERNAME', ''),
                'MAIL_PASSWORD': mask_sensitive_value('MAIL_PASSWORD', config.get('MAIL_PASSWORD', '')),
                'MAIL_DEFAULT_SENDER': config.get('MAIL_DEFAULT_SENDER', 'RainMail <noreply@rainmail.dev>')
            },
            'ai_moderation': {
                'API_KEY': mask_sensitive_value('API_KEY', config.get('AI_MODERATION', {}).get('API_KEY', '')),
                'BASE_URL': config.get('AI_MODERATION', {}).get('BASE_URL', ''),
                'MODEL': config.get('AI_MODERATION', {}).get('MODEL', ''),
                'SYSTEM_PROMPT': config.get('AI_MODERATION', {}).get('SYSTEM_PROMPT', '')
            },
            'wechat': {
                'WECHAT_APP_ID': config.get('WECHAT_APP_ID', ''),
                'WECHAT_APP_SECRET': mask_sensitive_value('WECHAT_APP_SECRET', config.get('WECHAT_APP_SECRET', ''))
            }
        }

        return jsonify({'success': True, 'config': categorized_config})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/admin/api/config', methods=['PUT'])
@admin_required
def api_update_config():
    """更新配置"""
    config_path = os.path.join(os.path.dirname(__file__), 'config.json')
    backup_path = config_path + '.backup'

    try:
        # 备份当前配置
        if os.path.exists(config_path):
            with open(config_path, 'r', encoding='utf-8') as f:
                backup_content = f.read()
            with open(backup_path, 'w', encoding='utf-8') as f:
                f.write(backup_content)

        # 读取当前配置
        with open(config_path, 'r', encoding='utf-8') as f:
            config = json.load(f)

        # 获取提交的配置
        data = request.get_json()
        updates = data.get('config', {})

        # 更新天气配置
        if 'weather' in updates:
            weather = updates['weather']
            for i in range(1, 5):
                host_key = f'HEFENG_HOST{i}'
                key_key = f'HEFENG_KEY{i}'
                if host_key in weather:
                    config[host_key] = weather[host_key]
                # 如果密码值以****开头，说明用户没有修改，保留原值
                if key_key in weather:
                    if weather[key_key] and not str(weather[key_key]).startswith('****'):
                        config[key_key] = weather[key_key]
            if 'times' in weather:
                config['times'] = int(weather['times'])

        # 更新人机验证配置
        if 'captcha' in updates:
            captcha = updates['captcha']
            for key in ['TURNSTILE_SECRET_KEY', 'TURNSTILE_SITE_KEY', 'CAPTCHA_PROVIDER',
                       'ALTCHA_HMAC_KEY', 'ALTCHA_DIFFICULTY', 'VERIFY_DURATION_MINUTES']:
                if key in captcha:
                    value = captcha[key]
                    # 敏感字段脱敏检查
                    if key in ['TURNSTILE_SECRET_KEY', 'TURNSTILE_SITE_KEY', 'ALTCHA_HMAC_KEY']:
                        if value and not str(value).startswith('****'):
                            config[key] = value
                    elif key in ['ALTCHA_DIFFICULTY']:
                        config[key] = int(value) if value else 3
                    elif key in ['VERIFY_DURATION_MINUTES']:
                        config[key] = int(value) if value else 15
                    else:
                        config[key] = value

        # 更新位置配置
        if 'location' in updates:
            location = updates['location']
            if 'LOCATION_NAME' in location:
                config['LOCATION_NAME'] = location['LOCATION_NAME']
            if 'LOCATION_ID' in location:
                config['LOCATION_ID'] = int(location['LOCATION_ID'])

        # 更新管理员配置
        if 'admin' in updates:
            admin = updates['admin']
            if 'admin_username' in admin:
                config['admin_username'] = admin['admin_username']
            if 'admin_password' in admin:
                password = admin['admin_password']
                if password and not str(password).startswith('****'):
                    config['admin_password'] = password
            if 'force_rain_duration' in admin:
                config['force_rain_duration'] = int(admin['force_rain_duration'])

        # 更新邮件配置
        if 'mail' in updates:
            mail = updates['mail']
            for key in ['MAIL_SERVER', 'MAIL_PORT', 'MAIL_USE_TLS',
                       'MAIL_USERNAME', 'MAIL_PASSWORD', 'MAIL_DEFAULT_SENDER']:
                if key in mail:
                    value = mail[key]
                    if key == 'MAIL_PASSWORD':
                        if value and not str(value).startswith('****'):
                            config[key] = value
                    elif key == 'MAIL_PORT':
                        config[key] = int(value) if value else 587
                    elif key == 'MAIL_USE_TLS':
                        config[key] = bool(value)
                    else:
                        config[key] = value

        # 更新AI审查配置
        ai_mod = config.get('AI_MODERATION', {})
        if 'ai_moderation' in updates:
            ai = updates['ai_moderation']
            if 'API_KEY' in ai:
                api_key = ai['API_KEY']
                if api_key and not str(api_key).startswith('****'):
                    ai_mod['API_KEY'] = api_key
            if 'BASE_URL' in ai:
                ai_mod['BASE_URL'] = ai['BASE_URL']
            if 'MODEL' in ai:
                ai_mod['MODEL'] = ai['MODEL']
            if 'SYSTEM_PROMPT' in ai:
                ai_mod['SYSTEM_PROMPT'] = ai['SYSTEM_PROMPT']
        config['AI_MODERATION'] = ai_mod

        # 更新微信配置
        if 'wechat' in updates:
            wechat = updates['wechat']
            if 'WECHAT_APP_ID' in wechat:
                config['WECHAT_APP_ID'] = wechat['WECHAT_APP_ID']
            if 'WECHAT_APP_SECRET' in wechat:
                secret = wechat['WECHAT_APP_SECRET']
                if secret and not str(secret).startswith('****'):
                    config['WECHAT_APP_SECRET'] = secret

        # 写入配置文件（JSON格式）
        with open(config_path, 'w', encoding='utf-8') as f:
            json.dump(config, f, ensure_ascii=False, indent=2)

        return jsonify({'success': True, 'message': '配置已保存，部分更改需要重启服务后生效'})

    except Exception as e:
        # 恢复备份
        if os.path.exists(backup_path):
            with open(backup_path, 'r', encoding='utf-8') as f:
                backup_content = f.read()
            with open(config_path, 'w', encoding='utf-8') as f:
                f.write(backup_content)
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/admin/api/config/export')
@admin_required
def api_export_config():
    """导出配置为 JSON 文件（与后端config.json格式一致）"""
    config_path = os.path.join(os.path.dirname(__file__), 'config.json')
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            config = json.load(f)

        # 直接导出配置，与后端config.json格式完全一致
        response = make_response(json.dumps(config, ensure_ascii=False, indent=2))
        response.headers['Content-Type'] = 'application/json'
        response.headers['Content-Disposition'] = f'attachment; filename=rainmail_config_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
        return response

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/admin/api/config/import', methods=['POST'])
@admin_required
def api_import_config():
    """导入配置 JSON 文件（与导出格式一致）"""
    config_path = os.path.join(os.path.dirname(__file__), 'config.json')
    backup_path = config_path + '.backup'

    try:
        # 备份当前配置
        if os.path.exists(config_path):
            with open(config_path, 'r', encoding='utf-8') as f:
                backup_content = f.read()
            with open(backup_path, 'w', encoding='utf-8') as f:
                f.write(backup_content)

        # 检查文件上传
        if 'file' not in request.files:
            return jsonify({'success': False, 'error': '未找到上传文件'}), 400

        file = request.files['file']
        if file.filename == '':
            return jsonify({'success': False, 'error': '未选择文件'}), 400

        if not file.filename.endswith('.json'):
            return jsonify({'success': False, 'error': '只支持 JSON 格式文件'}), 400

        # 读取并解析 JSON
        content = file.read().decode('utf-8')
        imported_config = json.loads(content)

        # 如果是旧格式（包含config字段），提取config
        if 'config' in imported_config:
            imported_config = imported_config['config']

        # 写入配置文件
        with open(config_path, 'w', encoding='utf-8') as f:
            json.dump(imported_config, f, ensure_ascii=False, indent=2)

        return jsonify({
            'success': True,
            'message': f'配置已导入，备份已保存至 {backup_path}。部分更改需要重启服务后生效'
        })

    except json.JSONDecodeError:
        return jsonify({'success': False, 'error': 'JSON 解析失败'}), 400
    except Exception as e:
        # 恢复备份
        if os.path.exists(backup_path):
            with open(backup_path, 'r', encoding='utf-8') as f:
                backup_content = f.read()
            with open(config_path, 'w', encoding='utf-8') as f:
                f.write(backup_content)
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/admin/api/config/test-email', methods=['POST'])
@admin_required
def api_test_email():
    """测试邮件配置"""
    try:
        data = request.get_json()
        test_email = data.get('test_email')

        if not test_email:
            return jsonify({'success': False, 'error': '请提供测试邮箱地址'}), 400

        # 创建测试邮件
        msg = EmailMessage(
            subject='雨天信箱 - 邮件配置测试',
            recipients=[test_email],
            body='这是一封测试邮件，如果您收到此邮件，说明邮件配置正确。\n\n雨天信箱系统'
        )

        # 发送邮件
        mail.send(msg)

        return jsonify({'success': True, 'message': f'测试邮件已发送至 {test_email}'})

    except Exception as e:
        return jsonify({'success': False, 'error': f'邮件发送失败: {str(e)}'}), 500

@app.route('/api/weather/meta')
def weather_meta():
    """返回天气元信息：上次更新时间、地点、天气文本、倒计时等"""
    # 获取访问者城市
    client_ip = get_client_ip()
    city = get_city_by_ip(client_ip)

    # 查询缓存表获取该城市的天气信息和更新时间
    cache_entry = LocationWeatherCache.query.filter_by(city=city).first()

    if cache_entry:
        last_update_time = cache_entry.last_updated.timestamp()
        elapsed = time.time() - last_update_time
        remaining_for_cache = max(0, ASK_TIMES - elapsed) # 统一缓存时间
        remaining_for_cache_minutes = int(remaining_for_cache // 60)

        return jsonify({
            'location': city,
            'weather_text': cache_entry.weather_text,
            'last_update': datetime.fromtimestamp(last_update_time).strftime('%Y-%m-%d %H:%M:%S'),
            'next_refresh_in_seconds': int(remaining_for_cache), # 实际剩余缓存时间
            'next_refresh_in_minutes': remaining_for_cache_minutes, # 实际剩余缓存时间 (分钟)
            'next_refresh_desc': f"最快 {ASK_TIMES/3600:.0f} 小时后刷新", # 描述性文字
            'current_state': cache_entry.weather_status,
            'city_specific': True # 标识城市特定
        })
    else:
        # 如果城市没有缓存记录（理论上在访问时会被创建，但首次访问或查询失败时可能为空）
        return jsonify({
            'location': city,
            'weather_text': '未知',
            'last_update': None,
            'next_refresh_in_seconds': 0,
            'next_refresh_desc': f"最快 {ASK_TIMES/3600:.0f} 小时后刷新",
            'current_state': 'sunny', # 默认状态
            'city_specific': True
        })

@app.route('/privacy-policy')
def privacy():
    return render_template('privacy_policy.html')

@app.route('/privacy-policy-cn')
def privacycn():
    return render_template('privacy_policy_cn.html')

@app.context_processor
def inject_year():
    """向所有模板注入当前年份"""
    from datetime import datetime
    return {'current_year': datetime.now().year}

# ==================== 用户认证相关路由 ====================

def login_required_user(f):
    """用户登录装饰器"""
    def wrapper(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': '请先登录', 'redirect': '/auth/login'}), 401
        return f(*args, **kwargs)
    wrapper.__name__ = f.__name__
    return wrapper

@app.route('/auth/login')
def login_page():
    """用户登录页面"""
    captcha_provider = app.config.get('CAPTCHA_PROVIDER', 'cloudflare').lower()
    site_key = app.config.get('TURNSTILE_SITE_KEY', '') if captcha_provider == 'cloudflare' else ''

    # 为 CHA 验证生成新问题 (CHA 或 Altcha 移动端回退都需要)
    if captcha_provider in ('cha', 'altcha'):
        question, answer = generate_cha_question()
        session['cha_question'] = question
        session['cha_answer'] = answer
        session['cha_timestamp'] = time.time()
        cha_question = question
    else:
        cha_question = None

    return render_template('auth/login.html',
                          turnstile_site_key=site_key,
                          captcha_provider=captcha_provider,
                          cha_question=cha_question)

@app.route('/auth/register')
def register_page():
    """用户注册页面"""
    captcha_provider = app.config.get('CAPTCHA_PROVIDER', 'cloudflare').lower()
    site_key = app.config.get('TURNSTILE_SITE_KEY', '') if captcha_provider == 'cloudflare' else ''

    # 为 CHA 验证生成新问题 (CHA 或 Altcha 移动端回退都需要)
    if captcha_provider in ('cha', 'altcha'):
        question, answer = generate_cha_question()
        session['cha_question'] = question
        session['cha_answer'] = answer
        session['cha_timestamp'] = time.time()
        cha_question = question
    else:
        cha_question = None

    return render_template('auth/register.html',
                          turnstile_site_key=site_key,
                          captcha_provider=captcha_provider,
                          cha_question=cha_question)

@app.route('/user/inbox')
@login_required_user
def user_inbox_page():
    """用户收件箱页面"""
    captcha_provider = app.config.get('CAPTCHA_PROVIDER', 'cloudflare').lower()
    site_key = app.config.get('TURNSTILE_SITE_KEY', '') if captcha_provider == 'cloudflare' else ''

    return render_template('user/inbox.html',
                          captcha_provider=captcha_provider,
                          turnstile_site_key=site_key)

@app.route('/user/settings')
@login_required_user
def user_settings_page():
    """用户设置页面"""
    return render_template('user/settings.html')

@app.route('/api/auth/register', methods=['POST'])
def api_register():
    """用户注册 API"""
    try:
        data = request.get_json()
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        username = data.get('username', '').strip()

        # 验证输入
        if not email or not password:
            return jsonify({'error': '邮箱和密码不能为空'}), 400

        if len(password) < 6:
            return jsonify({'error': '密码长度至少6位'}), 400

        # 检查邮箱是否已存在
        if User.query.filter_by(email=email).first():
            return jsonify({'error': '该邮箱已被注册'}), 400

        # 验证 CAPTCHA
        captcha_provider = app.config.get('CAPTCHA_PROVIDER', 'cloudflare').lower()
        if captcha_provider == 'cloudflare':
            captcha_response = data.get('cf_token')
        elif captcha_provider == 'cha':
            captcha_response = data.get('cha_answer')
        elif captcha_provider == 'altcha':
            captcha_response = data.get('altcha_payload')
        else:
            captcha_response = None

        user_ip = get_client_ip()
        if not validate_captcha(captcha_response, user_ip, session):
            return jsonify({'error': '人机验证失败'}), 400

        # 创建用户
        user = User(
            email=email,
            username=username if username else email.split('@')[0]
        )
        user.set_password(password)

        # 生成验证令牌
        import secrets
        user.verification_token = secrets.token_urlsafe(32)

        db.session.add(user)
        db.session.commit()

        # 发送验证邮件
        try:
            send_verification_email(user)
        except Exception as e:
            app.logger.error(f"发送验证邮件失败: {e}")
            # 即使邮件发送失败，也允许注册成功

        return jsonify({
            'success': True,
            'message': '注册成功，请查收验证邮件',
            'user': user.to_dict()
        })

    except Exception as e:
        app.logger.error(f"注册错误: {e}")
        return jsonify({'error': '注册失败'}), 500

@app.route('/api/auth/verify-email', methods=['POST'])
def api_verify_email():
    """邮箱验证 API"""
    try:
        data = request.get_json()
        token = data.get('token')

        if not token:
            return jsonify({'error': '验证令牌不能为空'}), 400

        user = User.query.filter_by(verification_token=token).first()
        if not user:
            return jsonify({'error': '无效的验证令牌'}), 400

        user.is_verified = True
        user.verification_token = None
        db.session.commit()

        return jsonify({
            'success': True,
            'message': '邮箱验证成功'
        })

    except Exception as e:
        app.logger.error(f"邮箱验证错误: {e}")
        return jsonify({'error': '验证失败'}), 500

@app.route('/api/auth/login', methods=['POST'])
def api_login():
    """用户登录 API"""
    try:
        data = request.get_json()
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')

        # 验证 CAPTCHA
        captcha_provider = app.config.get('CAPTCHA_PROVIDER', 'cloudflare').lower()
        if captcha_provider == 'cloudflare':
            captcha_response = data.get('cf_token')
        elif captcha_provider == 'cha':
            captcha_response = data.get('cha_answer')
        elif captcha_provider == 'altcha':
            captcha_response = data.get('altcha_payload')
        else:
            captcha_response = None

        user_ip = get_client_ip()
        if not validate_captcha(captcha_response, user_ip, session):
            return jsonify({'error': '人机验证失败'}), 400

        # 查找用户
        user = User.query.filter_by(email=email).first()
        if not user or not user.check_password(password):
            return jsonify({'error': '邮箱或密码错误'}), 401

        # 更新最后登录时间
        user.last_login = datetime.now()
        db.session.commit()

        # 设置会话
        session['user_id'] = user.id
        session['user_email'] = user.email

        return jsonify({
            'success': True,
            'message': '登录成功',
            'user': user.to_dict()
        })

    except Exception as e:
        app.logger.error(f"登录错误: {e}")
        return jsonify({'error': '登录失败'}), 500

@app.route('/api/auth/logout', methods=['POST'])
def api_logout():
    """用户登出 API"""
    session.pop('user_id', None)
    session.pop('user_email', None)
    return jsonify({'success': True, 'message': '登出成功'})

@app.route('/api/auth/resend-verification', methods=['POST'])
def api_resend_verification():
    """重发验证邮件 API"""
    try:
        data = request.get_json()
        email = data.get('email', '').strip().lower()

        user = User.query.filter_by(email=email).first()
        if not user:
            return jsonify({'error': '用户不存在'}), 404

        if user.is_verified:
            return jsonify({'error': '邮箱已验证'}), 400

        # 重新生成验证令牌
        user.verification_token = secrets.token_urlsafe(32)
        db.session.commit()

        # 发送验证邮件
        send_verification_email(user)

        return jsonify({
            'success': True,
            'message': '验证邮件已发送'
        })

    except Exception as e:
        app.logger.error(f"重发验证邮件错误: {e}")
        return jsonify({'error': '发送失败'}), 500

# ==================== 用户相关路由 ====================

@app.route('/api/user/profile')
@login_required_user
def api_user_profile():
    """获取用户信息"""
    user = User.query.get(session['user_id'])
    if not user:
        return jsonify({'error': '用户不存在'}), 404

    return jsonify({'user': user.to_dict()})

@app.route('/api/user/profile', methods=['PUT'])
@login_required_user
def api_update_profile():
    """更新用户信息"""
    try:
        data = request.get_json()
        user = User.query.get(session['user_id'])

        if not user:
            return jsonify({'error': '用户不存在'}), 404

        if 'username' in data:
            user.username = data['username'].strip()

        db.session.commit()

        return jsonify({
            'success': True,
            'message': '更新成功',
            'user': user.to_dict()
        })

    except Exception as e:
        app.logger.error(f"更新用户信息错误: {e}")
        return jsonify({'error': '更新失败'}), 500

@app.route('/api/user/inbox')
@login_required_user
def api_user_inbox():
    """获取用户收件箱"""
    user = User.query.get(session['user_id'])

    # 获取发给该用户的信件
    deliveries = LetterDelivery.query.filter_by(
        recipient_user_id=user.id
    ).order_by(LetterDelivery.created_at.desc()).all()

    result = []
    for delivery in deliveries:
        message = Message.query.get(delivery.message_id)
        if message:
            result.append({
                'id': delivery.id,
                'message_id': message.id,
                'sender_location': message.location,
                'is_unlocked': delivery.delivery_status in ['delivered', 'read'],
                'is_read': delivery.delivery_status == 'read',
                'created_at': delivery.created_at.strftime('%Y-%m-%d %H:%M:%S'),
                'unlocked_at': delivery.unlocked_at.strftime('%Y-%m-%d %H:%M:%S') if delivery.unlocked_at else None
            })

    return jsonify({'letters': result})

@app.route('/api/user/sent')
@login_required_user
def api_user_sent():
    """获取用户发送的消息"""
    user = User.query.get(session['user_id'])

    messages = Message.query.filter_by(
        sender_id=user.id
    ).order_by(Message.created_at.desc()).all()

    return jsonify({
        'messages': [msg.to_dict() for msg in messages]
    })

@app.route('/api/user/notifications')
@login_required_user
def api_user_notifications():
    """获取用户通知"""
    user = User.query.get(session['user_id'])

    notifications = Notification.query.filter_by(
        user_id=user.id
    ).order_by(Notification.created_at.desc()).limit(50).all()

    return jsonify({
        'notifications': [{
            'id': n.id,
            'type': n.notification_type,
            'title': n.title,
            'content': n.content,
            'is_read': n.is_read,
            'created_at': n.created_at.strftime('%Y-%m-%d %H:%M:%S')
        } for n in notifications]
    })

@app.route('/api/user/notifications/<int:notif_id>', methods=['PUT'])
@login_required_user
def api_mark_notification_read(notif_id):
    """标记通知为已读"""
    notification = Notification.query.get(notif_id)
    if not notification or notification.user_id != session['user_id']:
        return jsonify({'error': '通知不存在'}), 404

    notification.is_read = True
    db.session.commit()

    return jsonify({'success': True})

# ==================== 信件相关路由 ====================

@app.route('/letters/<token>')
def view_letter(token):
    """查看信件页面"""
    delivery = LetterDelivery.query.filter_by(unlock_token=token).first()

    if not delivery:
        return render_template('error.html', message='信件不存在'), 404

    message = Message.query.get(delivery.message_id)
    if not message:
        return render_template('error.html', message='信件内容不存在'), 404

    # 检查是否已解锁
    is_unlocked = delivery.delivery_status in ['delivered', 'read']

    return render_template('user/letter.html',
                          delivery=delivery,
                          message=message,
                          is_unlocked=is_unlocked)

@app.route('/api/letters/<int:delivery_id>/unlock')
def api_check_unlock(delivery_id):
    """检查信件是否已解锁"""
    delivery = LetterDelivery.query.get_or_404(delivery_id)

    return jsonify({
        'unlocked': delivery.delivery_status in ['delivered', 'read'],
        'status': delivery.delivery_status
    })

@app.route('/api/letters/<int:delivery_id>/read', methods=['POST'])
def api_mark_letter_read(delivery_id):
    """标记信件为已读"""
    delivery = LetterDelivery.query.get_or_404(delivery_id)

    # 检查权限
    if delivery.recipient_user_id:
        if 'user_id' not in session or session['user_id'] != delivery.recipient_user_id:
            return jsonify({'error': '无权访问此信件'}), 403

    if delivery.delivery_status != 'read':
        delivery.delivery_status = 'read'
        delivery.read_at = datetime.now()
        db.session.commit()

    return jsonify({'success': True})

@app.route('/api/letters/<int:delivery_id>/reply', methods=['POST'])
def api_reply_letter(delivery_id):
    """回复信件"""
    try:
        delivery = LetterDelivery.query.get_or_404(delivery_id)
        message = Message.query.get(delivery.message_id)

        if not message:
            return jsonify({'error': '原信件不存在'}), 404

        # 检查是否已解锁
        if delivery.delivery_status not in ['delivered', 'read']:
            return jsonify({'error': '信件未解锁'}), 403

        # 检查权限
        if delivery.recipient_user_id:
            if 'user_id' not in session or session['user_id'] != delivery.recipient_user_id:
                return jsonify({'error': '无权访问此信件'}), 403

        data = request.get_json()
        reply_content = data.get('content', '').strip()
        reply_type = data.get('reply_type', 'text')
        replier_email = data.get('replier_email', '').strip()

        if reply_type == 'text' and not reply_content:
            return jsonify({'error': '回复内容不能为空'}), 400

        # 创建回复
        reply = MessageReply(
            original_message_id=message.id,
            reply_content=reply_content if reply_type == 'text' else None,
            reply_type=reply_type,
            replier_user_id=session.get('user_id'),
            replier_email=replier_email if not session.get('user_id') else None
        )
        db.session.add(reply)

        # 标记信件为已读
        if delivery.delivery_status != 'read':
            delivery.delivery_status = 'read'
            delivery.read_at = datetime.now()

        # 通知原发件人
        if message.sender_id:
            notification = Notification(
                user_id=message.sender_id,
                notification_type='reply',
                title='📨 你的信收到了回复',
                content=f'有人回复了你之前发送的信件',
                related_id=reply.id
            )
            db.session.add(notification)

        # 如果发件人选择了邮件通知
        if message.reply_notification == 'email' and message.sender_id:
            sender = User.query.get(message.sender_id)
            if sender:
                # 发送回复通知邮件
                send_reply_notification(sender, message, reply)

        db.session.commit()

        return jsonify({
            'success': True,
            'message': '回复成功'
        })

    except Exception as e:
        app.logger.error(f"回复信件错误: {e}")
        return jsonify({'error': '回复失败'}), 500

@app.route('/api/messages/<int:message_id>/hug', methods=['POST'])
def api_hug_message(message_id):
    """给信件发送拥抱"""
    try:
        message = Message.query.get_or_404(message_id)

        # 增加拥抱计数
        message.hugs_count = (message.hugs_count or 0) + 1

        # 如果是回复，通知原消息发送者
        db.session.commit()

        return jsonify({
            'success': True,
            'hugs_count': message.hugs_count
        })

    except Exception as e:
        app.logger.error(f"拥抱错误: {e}")
        return jsonify({'error': '操作失败'}), 500

def send_reply_notification(user, original_message, reply):
    """发送回复通知邮件"""
    if not app.config.get('MAIL_USERNAME'):
        return

    msg = EmailMessage(
        subject='📨 你的信收到了回复',
        recipients=[user.email],
        html=f'''
        <h2>📨 雨天信箱</h2>
        <p>亲爱的 {user.username or user.email.split('@')[0]}，</p>
        <p>你之前发送的信件收到了回复！</p>
        <p><strong>原信件内容：</strong></p>
        <p>{original_message.content[:100]}...</p>
        <p><strong>回复内容：</strong></p>
        <p>{reply.reply_content if reply.reply_type == 'text' else '🤗 发送了一个拥抱'}</p>
        <p>登录雨天信箱查看更多详情。</p>
        '''
    )

    try:
        mail.send(msg)
    except Exception as e:
        app.logger.error(f"发送回复通知邮件失败: {e}")

# ==================== 邮件辅助函数 ====================

def create_private_delivery(message, sender_city):
    """
    创建私发投递记录，随机选择收件人
    """
    # 优先选择已验证的注册用户
    verified_users = User.query.filter_by(is_verified=True).all()

    if verified_users:
        # 随机选择一个已验证用户
        recipient_user = random.choice(verified_users)
        delivery = LetterDelivery(
            message_id=message.id,
            recipient_user_id=recipient_user.id,
            recipient_city=recipient_user.email.split('@')[-1],  # 简化：使用邮箱域名作为城市
            unlock_token=secrets.token_urlsafe(32)
        )
        db.session.add(delivery)
        db.session.commit()

        # 发送新信件通知
        send_new_letter_notification(delivery)

        return delivery
    else:
        # 没有已验证用户，信件进入等待池
        # 可以从请求中获取收件人邮箱，或者让信件等待
        recipient_email = message.delivery_options.get('recipient_email') if message.delivery_options else None

        if recipient_email:
            delivery = LetterDelivery(
                message_id=message.id,
                recipient_email=recipient_email,
                recipient_city=sender_city,  # 使用发送者城市作为默认
                unlock_token=secrets.token_urlsafe(32)
            )
            db.session.add(delivery)
            db.session.commit()

            # 发送新信件通知
            send_new_letter_notification(delivery)

            return delivery

    # 如果没有收件人，返回 None（信件进入等待池）
    return None

def send_verification_email(user):
    """发送验证邮件"""
    if not app.config.get('MAIL_USERNAME'):
        app.logger.warning("邮件未配置，跳过发送验证邮件")
        return

    # 构建验证链接
    verify_url = f"{request.host_url}api/auth/verify-email?token={user.verification_token}"

    # 创建邮件
    msg = EmailMessage(
        subject='验证你的 RainMail 邮箱',
        recipients=[user.email],
        html=f'''
        <h2>欢迎加入 RainMail</h2>
        <p>请点击下面的链接验证你的邮箱：</p>
        <p><a href="{verify_url}">验证邮箱</a></p>
        <p>如果链接无法点击，请复制以下 URL 到浏览器：</p>
        <p>{verify_url}</p>
        <p>此链接将在 24 小时后失效。</p>
        '''
    )

    try:
        mail.send(msg)
        app.logger.info(f"验证邮件已发送至 {user.email}")
    except Exception as e:
        app.logger.error(f"发送验证邮件失败: {e}")
        raise

def send_new_letter_notification(delivery):
    """发送新信件通知"""
    recipient_email = None
    recipient_name = "朋友"

    if delivery.recipient_user_id:
        user = User.query.get(delivery.recipient_user_id)
        if user:
            recipient_email = user.email
            recipient_name = user.username or user.email.split('@')[0]
    elif delivery.recipient_email:
        recipient_email = delivery.recipient_email

    if not recipient_email:
        return

    # 构建查看链接
    view_url = f"{request.host_url}letters/{delivery.unlock_token}"

    msg = EmailMessage(
        subject='📮 远方有一封信正在等你',
        recipients=[recipient_email],
        html=f'''
        <h2>🌧️ 雨天信箱</h2>
        <p>亲爱的 {recipient_name}，</p>
        <p>有一封来自远方的信正在等你。</p>
        <p>但这封信需要等待雨天才能解锁...</p>
        <p>当雨落下时，你将可以阅读这封信。</p>
        <p><a href="{view_url}">查看信件状态</a></p>
        <p>如果雨天已到，信件将自动解锁。</p>
        '''
    )

    # 添加到邮件队列
    email_queue = EmailQueue(
        recipient_email=recipient_email,
        email_type='new_letter',
        subject=msg.subject,
        body_html=msg.html
    )
    db.session.add(email_queue)
    db.session.commit()

def send_letter_unlocked_notification(delivery):
    """发送信件解锁通知"""
    recipient_email = None
    recipient_name = "朋友"

    if delivery.recipient_user_id:
        user = User.query.get(delivery.recipient_user_id)
        if user:
            recipient_email = user.email
            recipient_name = user.username or user.email.split('@')[0]
    elif delivery.recipient_email:
        recipient_email = delivery.recipient_email

    if not recipient_email:
        return

    # 构建查看链接
    view_url = f"{request.host_url}letters/{delivery.unlock_token}"

    msg = EmailMessage(
        subject='🌧️ 雨来了，信已解锁',
        recipients=[recipient_email],
        html=f'''
        <h2>🌧️ 雨天信箱</h2>
        <p>亲爱的 {recipient_name}，</p>
        <p>雨天已至，你的信件已解锁！</p>
        <p><a href="{view_url}">点击阅读信件</a></p>
        '''
    )

    # 添加到邮件队列
    email_queue = EmailQueue(
        recipient_email=recipient_email,
        email_type='letter_unlocked',
        subject=msg.subject,
        body_html=msg.html
    )
    db.session.add(email_queue)
    db.session.commit()

# ==================== 后台任务 ====================

def weather_unlock_worker():
    """天气解锁后台任务 - 每5分钟运行一次"""
    app.logger.info("[WeatherUnlockWorker] 启动天气解锁检查")

    while True:
        try:
            # 获取所有待解锁的信件
            pending_deliveries = LetterDelivery.query.filter_by(
                delivery_status='pending'
            ).all()

            if not pending_deliveries:
                app.logger.debug("[WeatherUnlockWorker] 没有待解锁的信件")

            unlocked_count = 0
            for delivery in pending_deliveries:
                try:
                    # 获取收件人城市天气
                    city = delivery.recipient_city or '广州'
                    weather = get_weather_status(city)

                    # 解锁条件：下雨或下雪
                    if weather in ['rainy', 'snowy']:
                        delivery.delivery_status = 'delivered'
                        delivery.unlocked_at = datetime.now()

                        # 创建应用内通知
                        if delivery.recipient_user_id:
                            notification = Notification(
                                user_id=delivery.recipient_user_id,
                                notification_type='letter_unlocked',
                                title='🌧️ 信件已解锁',
                                content='雨天已至，你有一封来自远方的信已解锁，快去查看吧！',
                                related_id=delivery.message_id
                            )
                            db.session.add(notification)

                        # 发送解锁通知邮件
                        send_letter_unlocked_notification(delivery)

                        unlocked_count += 1
                        app.logger.info(f"[WeatherUnlockWorker] 信件 {delivery.id} 已解锁（城市：{city}，天气：{weather}）")

                except Exception as e:
                    app.logger.error(f"[WeatherUnlockWorker] 解锁信件 {delivery.id} 时出错: {e}")

            if unlocked_count > 0:
                db.session.commit()
                app.logger.info(f"[WeatherUnlockWorker] 本次解锁了 {unlocked_count} 封信件")

        except Exception as e:
            app.logger.error(f"[WeatherUnlockWorker] 天气解锁任务出错: {e}")

        # 等待5分钟
        time.sleep(300)

def email_queue_worker():
    """邮件队列处理任务 - 每1分钟运行一次"""
    app.logger.info("[EmailQueueWorker] 启动邮件队列处理")

    while True:
        try:
            # 获取待发送的邮件
            pending_emails = EmailQueue.query.filter_by(
                status='pending'
            ).limit(50).all()

            if not pending_emails:
                app.logger.debug("[EmailQueueWorker] 没有待发送的邮件")

            for email in pending_emails:
                try:
                    # 检查邮件配置
                    if not app.config.get('MAIL_USERNAME'):
                        app.logger.warning("[EmailQueueWorker] 邮件未配置，跳过发送")
                        email.status = 'failed'
                        db.session.commit()
                        continue

                    # 发送邮件
                    msg = EmailMessage(
                        subject=email.subject,
                        recipients=[email.recipient_email],
                        html=email.body_html
                    )

                    mail.send(msg)
                    email.status = 'sent'
                    email.sent_at = datetime.now()

                    app.logger.info(f"[EmailQueueWorker] 邮件 {email.id} 已发送至 {email.recipient_email}")

                except Exception as e:
                    email.attempts += 1
                    if email.attempts >= 3:
                        email.status = 'failed'
                    app.logger.error(f"[EmailQueueWorker] 发送邮件 {email.id} 失败: {e}")

            db.session.commit()

        except Exception as e:
            app.logger.error(f"[EmailQueueWorker] 邮件队列任务出错: {e}")

        # 等待1分钟
        time.sleep(60)

def start_background_workers():
    """启动后台任务"""
    # 启动天气解锁任务
    weather_thread = threading.Thread(target=weather_unlock_worker, daemon=True)
    weather_thread.start()
    app.logger.info("[BackgroundWorkers] 天气解锁任务已启动")

    # 启动邮件队列任务
    email_thread = threading.Thread(target=email_queue_worker, daemon=True)
    email_thread.start()
    app.logger.info("[BackgroundWorkers] 邮件队列任务已启动")

if __name__ == '__main__':
    # 启动后台任务
    try:
        start_background_workers()
    except Exception as e:
        app.logger.error(f"启动后台任务失败: {e}")

    app.run(host='0.0.0.0', port=5024, debug=False)
