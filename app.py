from curses import flash
import threading
from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
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
import pyotp
import secrets
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import json
import qrcode
from PIL import Image

def load_sensitive_words_from_csv(file_path):
    """
    从 all.csv 文件中加载标记为敏感词 (_sensitivewords=1) 的词到集合中
    :param file_path: all.csv 文件路径
    """
    global SENSITIVE_WORDS_SET
    try:
        # Use 'utf-8-sig' to automatically handle the BOM character
        with open(file_path, 'r', encoding='utf-8-sig') as csvfile:
            reader = csv.DictReader(csvfile)
            # With utf-8-sig, the column names should now be clean without BOM
            words_from_csv = {
                row['keyword'].strip() # Now this should work correctly
                for row in reader
                if row.get('_sensitivewords') == '1' and row.get('keyword', '').strip()
            }
            
        SENSITIVE_WORDS_SET = words_from_csv
        print(f"成功从 all.csv 加载 {len(SENSITIVE_WORDS_SET)} 个标记为敏感的唯一词语。")
        
    except FileNotFoundError:
        print(f"错误：未找到敏感词 CSV 文件 {file_path}")
        SENSITIVE_WORDS_SET = set()
    except KeyError as e:
        print(f"错误：CSV 文件 {file_path} 中缺少必要的列: {e}")
        SENSITIVE_WORDS_SET = set()

def generate_totp_secret():
    """生成一个新的 TOTP 密钥"""
    return pyotp.random_base32()

def derive_key_from_password(password: str, salt: bytes) -> bytes:
    """从用户密码派生加密/解密密钥"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

def encrypt_secret(secret: str, password: str) -> dict:
    """使用用户密码加密 TOTP 密钥"""
    salt = os.urandom(16)  # 生成随机盐
    key = derive_key_from_password(password, salt)
    fernet = Fernet(key)
    encrypted_secret = fernet.encrypt(secret.encode())
    # 返回加密后的密钥和盐，以便解密
    return {"encrypted_secret": base64.b64encode(encrypted_secret).decode(), "salt": base64.b64encode(salt).decode()}

def decrypt_secret(encrypted_data: dict, password: str) -> str:
    """使用用户密码解密 TOTP 密钥"""
    try:
        salt = base64.b64decode(encrypted_data["salt"])
        encrypted_secret_bytes = base64.b64decode(encrypted_data["encrypted_secret"])
        key = derive_key_from_password(password, salt)
        fernet = Fernet(key)
        decrypted_secret = fernet.decrypt(encrypted_secret_bytes)
        return decrypted_secret.decode()
    except Exception as e:
        print(f"解密失败: {e}")
        raise ValueError("密码错误或加密数据损坏")

def save_encrypted_secret(encrypted_data: dict, filepath: str):
    """将加密的密钥数据保存到文件"""
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(encrypted_data, f)

def load_encrypted_secret(filepath: str) -> dict:
    """从文件加载加密的密钥数据"""
    with open(filepath, 'r', encoding='utf-8') as f:
        return json.load(f)

def initialize_totp_secret():
    """初始化 TOTP 密钥 - 支持静默自动解密"""
    secret_file_path = os.path.join(os.path.dirname(__file__), 'totp_secret.json')
    qr_file_path = os.path.join(os.path.dirname(__file__), 'totp_setup_qr.png')
    
    # 从配置中获取解密密码
    decrypt_password = app.config.get('totp_decrypt_password')
    if not decrypt_password:
        print("\n[ERROR] config.yaml 中缺少 'totp_decrypt_password'，无法自动解密 TOTP 密钥！")
        return None

    # 情况1: 存在加密文件 → 尝试自动解密
    if os.path.exists(secret_file_path):
        try:
            encrypted_data = load_encrypted_secret(secret_file_path)
            totp_secret = decrypt_secret(encrypted_data, decrypt_password)
            print(f"\n[SUCCESS] 自动解密 TOTP 密钥成功！(来自 {secret_file_path})")
            return totp_secret
        except Exception as e:
            print(f"\n[ERROR] 自动解密失败: {e}")
            print("[INFO] 将生成新的 TOTP 密钥...")

    # 情况2: 文件不存在 或 解密失败 → 自动生成新密钥并加密保存
    print("\n[INFO] 正在生成新的 TOTP 密钥（静默模式）...")
    new_secret = generate_totp_secret()
    
    # 生成二维码（可选，后台运行时可能不需要）
    try:
        issuer_name = "RainMail_Admin"
        account_name = "admin"
        totp_uri = pyotp.totp.TOTP(new_secret).provisioning_uri(account_name, issuer_name=issuer_name)
        qr_img = qrcode.make(totp_uri)
        qr_img.save(qr_file_path)
        print(f"[SUCCESS] TOTP 二维码已保存至: {qr_file_path}")
    except Exception as e:
        print(f"[WARNING] 生成二维码失败: {e}")

    # 用配置中的密码加密并保存
    encrypted_data = encrypt_secret(new_secret, decrypt_password)
    save_encrypted_secret(encrypted_data, secret_file_path)
    print(f"[SUCCESS] 新 TOTP 密钥已加密保存至 '{secret_file_path}'")
    
    return new_secret

def is_sensitive(message):
    """检查消息是否包含敏感词，并返回命中的第一个敏感词"""
    # 遍历敏感词集合，检查消息是否包含任何一个词
    for word in SENSITIVE_WORDS_SET:
        # 使用 'in' 操作符进行子串匹配
        if word in message:
            return word # 返回命中的敏感词
    return None # 如果没有命中任何词，返回 None

# 配置日志
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

# --- 新增：加载配置文件 ---
config_path = os.path.join(os.path.dirname(__file__), 'config.yaml')
if os.path.exists(config_path):
    with open(config_path, 'r', encoding='utf-8') as f:
        config = yaml.safe_load(f)
        app.config.update(config)
else:
    print("警告: config.yaml 文件未找到！")
app.secret_key = 'rainmail_secret_key_2024'
TURNSTILE_SECRET_KEY = app.config.get('TURNSTILE_SECRET_KEY')
TURNSTILE_SITE_KEY = app.config.get('TURNSTILE_SITE_KEY')
ASK_TIMES = app.config.get('TIMES', 40) # 请求频率
LOCATION_ID = app.config.get('LOCATION_ID', 101280101)  # 广东广州的和风天气位置ID
SENSITIVE_WORDS_SET = set()

API_HOSTS = [
    app.config.get('HEFENG_HOST1'),
    app.config.get('HEFENG_HOST2'),
]
API_KEYS = [
    app.config.get('HEFENG_KEY1'),
    app.config.get('HEFENG_KEY2'),
]

API_PAIRS = [(host, key) for host, key in zip(API_HOSTS, API_KEYS) if host and key]

if not API_PAIRS:
    print("[ERROR] 没有找到有效的 HEFENG_HOST 和 HEFENG_KEY 配置对，天气功能将不可用。")
    # 可以设置一个标志，或者让 get_weather_status 返回默认值
    API_PAIRS_AVAILABLE = False
else:
    API_PAIRS_AVAILABLE = True

# 用于追踪当前 API Pair 索引的全局变量
_current_api_pair_index = 0
# 创建一个锁，确保多线程环境下索引的安全更新
_api_pair_lock = threading.Lock()

# 数据库配置
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///rainmail.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# 定义消息模型
class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now)
    location = db.Column(db.String(50), default='广州')

    def to_dict(self):
        return {
            'id': self.id,
            'content': self.content,
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            'location': self.location
        }

# 初始化数据库
with app.app_context():
    db.create_all()

sensitive_words_csv_file = os.path.join(os.path.dirname(__file__), 'resources', 'all.csv')
load_sensitive_words_from_csv(sensitive_words_csv_file)

# 全局变量存储 TOTP 密钥
ADMIN_TOTP_SECRET = initialize_totp_secret()
if ADMIN_TOTP_SECRET:
    print("\n[INFO] TOTP 双重认证已配置。管理员登录需要验证码。")
else:
    print("\n[ERROR] TOTP 双重认证配置失败，可能影响管理员登录。")
    ADMIN_TOTP_SECRET = None # 确保变量被定义

# 全局状态变量
current_weather_state = 'sunny'  # 默认晴天状态
last_weather_check = 0
weather_cache_time = ASK_TIMES  # 缓存
force_rain_until = None  # 强制降雨结束时间
last_weather_data = {}  # 存储最后一次天气数据

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

def validate_turnstile(turnstile_response, user_ip):
    """
    验证 Cloudflare Turnstile Token
    """
    payload = {
        'secret': TURNSTILE_SECRET_KEY,
        'response': turnstile_response,
        'remoteip': user_ip
    }
    response = requests.post('https://challenges.cloudflare.com/turnstile/v0/siteverify', data=payload)
    result = response.json()
    return result.get('success', False)

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

def get_weather_status():
    """获取广州天气状态和详细数据"""
    global current_weather_state, last_weather_check, last_weather_data, force_rain_until, _current_api_pair_index # 声明使用全局变量

    current_time = time.time()

    # 检查强制降雨状态
    if force_rain_until and datetime.now() < force_rain_until:
        current_weather_state = 'rainy'
        return current_weather_state

    # 检查缓存是否过期
    if current_time - last_weather_check < weather_cache_time:
        return current_weather_state

    # 注意：这里只是在准备调用 API 前切换，即使上一个没失败
    if API_PAIRS_AVAILABLE: # 确保有 Pair 可用再切换
        with _api_pair_lock: # 获取锁以安全地修改共享变量
            _current_api_pair_index = (_current_api_pair_index + 1) % len(API_PAIRS)
        print(f"[INFO] 主动切换到下一个 API Pair (当前索引: {_current_api_pair_index})") # 可选的提示信息

    # 检查是否有可用的 API 对
    if not API_PAIRS_AVAILABLE:
        print("[WARN] 无可用的 API 配置对，保持上次天气状态。")
        return current_weather_state # 返回上次的状态

    # 尝试使用列表中的每一个 Host-Key 对
    num_pairs = len(API_PAIRS)
    attempt_count = 0
    
    # 这里 current_pair_index 会是上面主动切换后的值
    while attempt_count < num_pairs:
        # 在循环内获取当前 Pair，确保每次迭代都获取最新的索引
        # (这里其实用上面切换后的 _current_api_pair_index 也可以，但为了健壮性，再取一次)
        current_pair_index = _current_api_pair_index
        hefeng_host, api_key = API_PAIRS[current_pair_index]
        
        try:
            # 构建正确的 API URL，使用当前对的 host 和 key
            url = f"https://{hefeng_host}/v7/weather/now"
            params = {
                'location': LOCATION_ID, # 使用全局变量 LOCATION_ID
                'key': api_key
            }
            
            response = requests.get(url, params=params, timeout=10)
            
            # --- 重要: 检查响应状态码 ---
            if response.status_code == 429: # Too Many Requests
                print(f"[WARN] API Pair {current_pair_index} ({hefeng_host[:20]}.../{api_key[:5]}...) 触发速率限制 (429)，切换到下一个。")
                # 在处理速率限制错误后，安全地切换到下一个 Pair
                with _api_pair_lock: # 获取锁
                    _current_api_pair_index = (_current_api_pair_index + 1) % num_pairs
                attempt_count += 1
                continue # 继续尝试下一个 Pair
            
            if response.status_code != 200:
                print(f"[WARN] API Pair {current_pair_index} ({hefeng_host[:20]}.../{api_key[:5]}...) 请求失败，状态码: {response.status_code}")
                # 即使是其他错误，也切换到下一个 Pair，以增加鲁棒性
                with _api_pair_lock: # 获取锁
                    _current_api_pair_index = (_current_api_pair_index + 1) % num_pairs
                attempt_count += 1
                continue # 继续尝试下一个 Pair

            data = response.json()
            
            # --- 重要: 检查响应体中的错误码 ---
            if data.get('code') == '401': # Unauthorized, 可能是 Key 无效或 Host-Key 不匹配
                 print(f"[ERROR] API Pair {current_pair_index} ({hefeng_host[:20]}.../{api_key[:5]}...) 无效 (401 Unauthorized)，或 Host-Key 不匹配。")
                 # Key 无效或 Host-Key 不匹配，也切换到下一个
                 with _api_pair_lock: # 获取锁
                     _current_api_pair_index = (_current_api_pair_index + 1) % num_pairs
                 attempt_count += 1
                 continue # 继续尝试下一个 Pair
            elif data.get('code') != '200': # 其他和风 API 错误
                 print(f"[WARN] API Pair {current_pair_index} ({hefeng_host[:20]}.../{api_key[:5]}...) 返回错误: {data.get('code', 'Unknown Code')}, Message: {data.get('message', 'No message')}")
                 # 尝试下一个 Pair
                 with _api_pair_lock: # 获取锁
                     _current_api_pair_index = (_current_api_pair_index + 1) % num_pairs
                 attempt_count += 1
                 continue # 继续尝试下一个 Pair

            # --- 成功获取数据 ---
            now_data = data['now']
            weather_text = now_data.get('text', '')
            icon_code = now_data.get('icon', '')

            # 判断是否为雨天：检查文本或图标
            is_rainy = ('雨' in weather_text) or (icon_code.startswith('3'))
            current_weather_state = 'rainy' if is_rainy else 'sunny'
            last_weather_check = current_time
            last_weather_data = now_data # 更新最后的数据

            print(f"广州天气更新 (来自 Pair {current_pair_index}): {weather_text} (图标: {icon_code}), 状态: {current_weather_state}")
            
            return current_weather_state # 返回状态

        except requests.exceptions.Timeout:
            print(f"[WARN] API Pair {current_pair_index} ({hefeng_host[:20]}.../{api_key[:5]}...) 请求超时，切换到下一个。")
            with _api_pair_lock: # 获取锁
                _current_api_pair_index = (_current_api_pair_index + 1) % num_pairs
            attempt_count += 1
            continue # 继续尝试下一个 Pair
        except requests.exceptions.RequestException as e:
            print(f"[ERROR] API Pair {current_pair_index} ({hefeng_host[:20]}.../{api_key[:5]}...) 请求异常: {str(e)}，切换到下一个。")
            with _api_pair_lock: # 获取锁
                _current_api_pair_index = (_current_api_pair_index + 1) % num_pairs
            attempt_count += 1
            continue # 继续尝试下一个 Pair
        except ValueError: # JSON decode error
            print(f"[ERROR] API Pair {current_pair_index} ({hefeng_host[:20]}.../{api_key[:5]}...) 返回非 JSON 格式，切换到下一个。")
            with _api_pair_lock: # 获取锁
                _current_api_pair_index = (_current_api_pair_index + 1) % num_pairs
            attempt_count += 1
            continue # 继续尝试下一个 Pair
        except KeyError as e: # 如果 data['now'] 不存在
            print(f"[ERROR] API Pair {current_pair_index} ({hefeng_host[:20]}.../{api_key[:5]}...) 响应格式错误，缺少字段: {e}，切换到下一个。")
            with _api_pair_lock: # 获取锁
                _current_api_pair_index = (_current_api_pair_index + 1) % num_pairs
            attempt_count += 1
            continue # 继续尝试下一个 Pair

    # 如果所有 Pairs 都尝试过了，都失败了
    print("[CRITICAL] 所有 API Pairs 均尝试失败，无法获取天气状态，保持上次状态。")
    # 保持上一次的有效状态
    return current_weather_state

def get_dashboard_data():
    """获取仪表盘数据"""
    weather_status = get_weather_status()
    
    # 获取降雨概率
    precip_prob = last_weather_data.get('precip', '0') if last_weather_data else '0'
    
    # 获取CPU温度
    cpu_temp = get_cpu_temperature()
    
    # 获取消息数量
    message_count = Message.query.count()
    
    return {
        'weather_status': weather_status,
        'precip_prob': precip_prob,
        'cpu_temp': round(cpu_temp, 1),
        'message_count': message_count
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
    dashboard_data = get_dashboard_data()
    site_key = app.config.get('TURNSTILE_SITE_KEY', '')
    return render_template('index.html', **dashboard_data, turnstile_site_key=site_key)
    # return render_template('index.html', **dashboard_data)

@app.route('/api/messages', methods=['GET', 'POST'])
def handle_messages():
    """消息API接口"""
    weather_status = get_weather_status()
    
    if request.method == 'POST':
        # 提交新消息
        try:
            content = request.json.get('content', '').strip()
            if not content:
                return jsonify({'error': '内容不能为空'}), 400
            
            turnstile_token = request.json.get('cf_token') # 注意这里的字段名要与前端一致
            user_ip = request.headers.get('CF-Connecting-IP', request.remote_addr)
            
            if not turnstile_token:
                return jsonify({"error": "请完成人机验证"}), 400
                
            if not validate_turnstile(turnstile_token, user_ip):
                return jsonify({"error": "人机验证失败，请刷新网页"}), 400

            # --- 修改: 调用 is_sensitive 函数并获取命中的词 ---
            hit_word = is_sensitive(content) # 接收命中的词
            if hit_word: # 如果命中，hit_word 不为 None
                app.logger.warning(f"API 敏感词拦截: 内容: {content[:50]}..., 触发规则: [{hit_word}]") # 记录日志，显示命中的词
                # 返回模糊错误信息，避免暴露具体规则
                return jsonify({"error": "内容包含不合适的词汇，已被系统拦截。", "blocked": True}), 400

            # 过滤XSS
            content = sanitize_input(content)
            
            # 创建新消息
            message = Message(content=content)
            db.session.add(message)
            db.session.commit()
            
            # 生成分享卡片信息
            message_count = Message.query.count()
            share_data = {
                'message_id': message.id,
                'total_messages': message_count,
                'created_at': message.created_at.strftime('%Y-%m-%d %H:%M:%S'),
                'weather_status': weather_status
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
        # 获取消息列表
        if weather_status == 'sunny':
            return jsonify({'error': '晴天模式下无法查看消息'}), 403
        
        messages = Message.query.order_by(Message.created_at.desc()).all()
        return jsonify({
            'messages': [msg.to_dict() for msg in messages],
            'weather_status': weather_status
        })

@app.route('/api/weather')
def weather_api():
    """天气状态API"""
    dashboard_data = get_dashboard_data()
    return jsonify(dashboard_data)

@app.route('/api/health')
def health_check():
    """健康检查接口"""
    return jsonify({'status': 'healthy', 'timestamp': datetime.now().isoformat()})

# 管理员路由
@app.route('/admin', methods=['GET', 'POST'])
def admin_login():
    """管理员登录"""
    if request.method == 'POST':
        # --- 新增：管理员登录人机验证 ---
        turnstile_token = request.form.get('cf-turnstile-response')
        user_ip = request.headers.get('CF-Connecting-IP', request.remote_addr) # 获取真实 IP
        username = request.form.get('username')
        password = request.form.get('password')
        totp_code = request.form.get('totp_code') # 获取前端提交的 TOTP 码

        if not turnstile_token:
            # --- 修改：不再返回 JSON，而是渲染模板 ---
            site_key = app.config.get('TURNSTILE_SITE_KEY', '')
            return render_template('admin_login.html', error='请完成人机验证', turnstile_site_key=site_key)

        if not validate_turnstile(turnstile_token, user_ip):
            site_key = app.config.get('TURNSTILE_SITE_KEY', '')
            return render_template('admin_login.html', error='人机验证失败，请刷新网页', turnstile_site_key=site_key)
        # --- 结束新增 ---

        # 验证 TOTP (如果密钥存在)
        totp_valid = True # 默认为真，以防 TOTP 未正确初始化
        if ADMIN_TOTP_SECRET:
             if not totp_code:
                 flash('请输入双重认证验证码')
                 return render_template('admin_login.html')
             totp = pyotp.TOTP(ADMIN_TOTP_SECRET)
             totp_valid = totp.verify(totp_code, valid_window=1) # 允许前后偏移1个时间窗口

        # --- 修正：统一从 config 获取管理员凭据 ---
        admin_username_from_config = app.config.get('admin_username')
        admin_password_from_config = app.config.get('admin_password')

        # 验证用户名、密码和 TOTP
        if (username == admin_username_from_config and
            password == admin_password_from_config and
            totp_valid):
            session['admin_logged_in'] = True
            return redirect(url_for('admin_dashboard'))
        else:
            # 提供更模糊的错误信息以增强安全性
            flash('登录凭据无效或双重认证失败')
            site_key = app.config.get('TURNSTILE_SITE_KEY', '')
            return render_template('admin_login.html', error='用户名或密码错误', turnstile_site_key=site_key)

    site_key = app.config.get('TURNSTILE_SITE_KEY', '')
    return render_template('admin_login.html', turnstile_site_key=site_key)

@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    """管理员仪表盘"""
    messages = Message.query.order_by(Message.created_at.desc()).all()
    dashboard_data = get_dashboard_data()
    
    return render_template('admin_dashboard.html', 
                         messages=messages,
                         **dashboard_data)

@app.route('/admin/force_rain', methods=['POST'])
@admin_required
def admin_force_rain():
    """强制降雨"""
    global force_rain_until, current_weather_state
    
    duration = config.get('force_rain_duration', 40)
    force_rain_until = datetime.now() + timedelta(minutes=duration)
    current_weather_state = 'rainy'
    
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

@app.route('/api/weather/meta')
def weather_meta():
    """返回天气元信息：上次更新时间、地点、天气文本、倒计时等"""
    from datetime import datetime
    global last_weather_check, last_weather_data, current_weather_state
    
    now = time.time()
    elapsed = now - last_weather_check
    remaining = max(0, weather_cache_time - elapsed)
    
    # 从 last_weather_data 获取天气描述，兜底处理
    weather_text = last_weather_data.get('text', '未知') if last_weather_data else '未知'
    location_name = app.config.get('LOCATION_NAME')  # 从配置读取
    
    return jsonify({
        'location': location_name,
        'weather_text': weather_text,
        'last_update': datetime.fromtimestamp(last_weather_check).strftime('%Y-%m-%d %H:%M:%S') if last_weather_check else None,
        'next_refresh_in_seconds': int(remaining),
        'current_state': current_weather_state  # 'rainy' or 'sunny'
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5024, debug=False)