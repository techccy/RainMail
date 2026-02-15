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

# 配置日志
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
# --- 新增：加载配置文件 ---
config_path = os.path.join(os.path.dirname(__file__), 'config.yaml')
if os.path.exists(config_path):
    with open(config_path, 'r', encoding='utf-8') as f:
        config = yaml.safe_load(f)
        app.config.update(config)
else:
    print("警告: config.yaml 文件未找到！")
app.secret_key = 'rainmail_secret_key_2024'
# TURNSTILE_SECRET_KEY = config.get('TURNSTILE_SECRET_KEY')
TURNSTILE_SECRET_KEY = app.config.get('TURNSTILE_SECRET_KEY')
TURNSTILE_SITE_KEY = app.config.get('TURNSTILE_SITE_KEY')

# 读取配置文件
# with open('config.yaml', 'r') as f:
#     config = yaml.safe_load(f)

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

# 全局状态变量
current_weather_state = 'sunny'  # 默认晴天状态
last_weather_check = 0
weather_cache_time = 120  # 2分钟缓存
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
    global current_weather_state, last_weather_check, last_weather_data
    
    current_time = time.time()
    
    # 检查强制降雨状态
    if force_rain_until and datetime.now() < force_rain_until:
        current_weather_state = 'rainy'
        return current_weather_state
    
    # 检查缓存是否过期
    if current_time - last_weather_check < weather_cache_time:
        return current_weather_state
    
    try:
        # 和风天气API调用
        url = f"https://devapi.qweather.com/v7/weather/now?location=101240310&key={config['API_KEY']}"
        response = requests.get(url, timeout=10)
        data = response.json()
        
        if data['code'] == '200':
            icon_code = data['now']['icon']
            # 检查天气图标代码是否以3开头（雨/雪/阵雨）
            if icon_code.startswith('3'):
                current_weather_state = 'rainy'
            else:
                current_weather_state = 'sunny'
            
            last_weather_check = current_time
            last_weather_data = data['now']
            logger.info(f"Weather status updated: {current_weather_state}, icon: {icon_code}")
            
        else:
            logger.warning(f"Weather API error: {data['code']} - {data.get('message', 'Unknown error')}")
            
    except Exception as e:
        logger.error(f"Weather API request failed: {str(e)}")
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


            # --- 新增：敏感词过滤 ---
            # 你可以将 SENSITIVE_WORDS 放到 config.yaml 中，更灵活
            SENSITIVE_WORDS = ['习近平', '共产党', '色情', '赌博', '发票']
            for word in SENSITIVE_WORDS:
                if word in content:
                    app.logger.warning(f"API 敏感词拦截: [{word}] 内容: {content[:50]}...")
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

        if not turnstile_token:
            # --- 修改：不再返回 JSON，而是渲染模板 ---
            site_key = app.config.get('TURNSTILE_SITE_KEY', '')
            return render_template('admin_login.html', error='请完成人机验证', turnstile_site_key=site_key)
            # return jsonify({"error": "请完成人机验证"}), 400
            # site_key = app.config.get('TURNSTILE_SITE_KEY', '')
            # return render_template('admin_login.html', error='请完成人机验证。', turnstile_site_key=site_key)
            # return redirect(url_for('admin_login'))

        if not validate_turnstile(turnstile_token, user_ip):
            site_key = app.config.get('TURNSTILE_SITE_KEY', '')
            return render_template('admin_login.html', error='人机验证失败，请刷新网页', turnstile_site_key=site_key)
            # return jsonify({"error": "人机验证失败，请刷新网页"}), 400
            # site_key = app.config.get('TURNSTILE_SITE_KEY', '')
            # return render_template('admin_login.html', error='人机验证失败，请刷新页面重试。', turnstile_site_key=site_key)
            # return redirect(url_for('admin_login'))
        # --- 结束新增 ---
        username = request.form.get('username')
        password = request.form.get('password')
        
        # 验证管理员凭据
        if (username == config.get('admin_username') and 
            password == config.get('admin_password')):
            session['admin_logged_in'] = True
            return redirect(url_for('admin_dashboard'))
        else:
            site_key = app.config.get('TURNSTILE_SITE_KEY', '')
            return render_template('admin_login.html', error='用户名或密码错误', turnstile_site_key=site_key)
            # return render_template('admin_login.html', error='用户名或密码错误')
        
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
    
    duration = config.get('force_rain_duration', 60)
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

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5024, debug=False)
