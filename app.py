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
import random
import string

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
ASK_TIMES = app.config.get('TIMES', 3600) # 请求频率, 统一为1小时 (3600秒)
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

    def to_dict(self):
        return {
            'id': self.id,
            'content': self.content,
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            'location': self.location,
            'unique_identifier': self.unique_identifier
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

# 初始化数据库
with app.app_context():
    db.create_all()

# sensitive_words_csv_file = os.path.join(os.path.dirname(__file__), 'resources', 'all.csv')
# load_sensitive_words_from_csv(sensitive_words_csv_file)

# 全局变量存储 TOTP 密钥
ADMIN_TOTP_SECRET = initialize_totp_secret()
if ADMIN_TOTP_SECRET:
    print("\n[INFO] TOTP 双重认证已配置。管理员登录需要验证码。")
else:
    print("\n[ERROR] TOTP 双重认证配置失败，可能影响管理员登录。")
    ADMIN_TOTP_SECRET = None # 确保变量被定义

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
    site_key = app.config.get('TURNSTILE_SITE_KEY', '')
    return render_template('index.html', **dashboard_data, turnstile_site_key=site_key)

@app.route('/api/messages', methods=['GET', 'POST'])
def handle_messages():
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

            if ai_moderation_check(content):
              app.logger.warning(f"AI 语义拦截: {content}")
              return jsonify({"error": "内容未通过系统安全审查", "blocked": True}), 400

            # 过滤XSS
            content = sanitize_input(content)

            # 创建新消息
            message = Message(content=content)
            message.unique_identifier = generate_unique_id()
            db.session.add(message)
            db.session.commit()

            # 生成分享卡片信息
            message_count = Message.query.count()
            share_data = {
                'message_id': message.id,
                'total_messages': message_count,
                'created_at': message.created_at.strftime('%Y-%m-%d %H:%M:%S'),
                'weather_status': 'sunny', # 提交时不关心当前天气，返回固定值或从请求上下文获取
                'unique_identifier': message.unique_identifier # 将 ID 包含在 share_data 中
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

        messages = Message.query.order_by(Message.created_at.desc()).all()
        return jsonify({
            'messages': [msg.to_dict() for msg in messages],
            'weather_status': weather_status, # 可选：返回该城市的天气状态
            'city': city # 可选：告知前端是哪个城市的天气
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

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5024, debug=False)