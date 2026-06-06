import os
from dotenv import load_dotenv

def load_config_from_env():
    """
    从环境变量加载所有配置，优先从环境变量读取
    如果 .env 文件存在则加载，否则直接使用已注入的环境变量

    如果必要的环境变量缺失，抛出异常
    """
    # 1. 尝试加载 .env 文件（如果存在）
    env_path = os.path.join(os.path.dirname(__file__), '.env')
    if os.path.exists(env_path):
        load_dotenv(env_path)

    config = {}

    # 2. 必需配置（如果缺失则报错）
    REQUIRED_ENV_VARS = ['SECRET_KEY']
    missing = []
    for var in REQUIRED_ENV_VARS:
        value = os.environ.get(var)
        if not value:
            missing.append(var)
    if missing:
        raise ValueError(f"缺少必需的环境变量: {', '.join(missing)}")

    # 3. 环境变量映射表（环境变量名 -> 配置键）
    ENV_MAPPINGS = {
        # Flask
        'SECRET_KEY': 'SECRET_KEY',

        # 邮件配置
        'MAIL_SERVER': 'MAIL_SERVER',
        'MAIL_PORT': 'MAIL_PORT',
        'MAIL_USE_TLS': 'MAIL_USE_TLS',
        'MAIL_USE_SSL': 'MAIL_USE_SSL',
        'MAIL_USERNAME': 'MAIL_USERNAME',
        'MAIL_PASSWORD': 'MAIL_PASSWORD',
        'MAIL_DEFAULT_SENDER': 'MAIL_DEFAULT_SENDER',
        'MAIL_ENABLED': 'MAIL_ENABLED',

        # 人机验证
        'CAPTCHA_PROVIDER': 'CAPTCHA_PROVIDER',
        'TURNSTILE_SITE_KEY': 'TURNSTILE_SITE_KEY',
        'TURNSTILE_SECRET_KEY': 'TURNSTILE_SECRET_KEY',
        'RECAPTCHA_V3_SITE_KEY': 'RECAPTCHA_V3_SITE_KEY',
        'RECAPTCHA_V3_SECRET_KEY': 'RECAPTCHA_V3_SECRET_KEY',
        'RECAPTCHA_V3_THRESHOLD': 'RECAPTCHA_V3_THRESHOLD',
        'ALTCHA_HMAC_KEY': 'ALTCHA_HMAC_KEY',
        'ALTCHA_DIFFICULTY': 'ALTCHA_DIFFICULTY',
        'VERIFY_DURATION_MINUTES': 'VERIFY_DURATION_MINUTES',

        # 和风天气
        'HEFENG_HOST1': 'HEFENG_HOST1',
        'HEFENG_HOST2': 'HEFENG_HOST2',
        'HEFENG_HOST3': 'HEFENG_HOST3',
        'HEFENG_HOST4': 'HEFENG_HOST4',
        'HEFENG_KEY1': 'HEFENG_KEY1',
        'HEFENG_KEY2': 'HEFENG_KEY2',
        'HEFENG_KEY3': 'HEFENG_KEY3',
        'HEFENG_KEY4': 'HEFENG_KEY4',

        # 位置配置
        'LOCATION_ID': 'LOCATION_ID',
        'LOCATION_NAME': 'LOCATION_NAME',

        # 管理员配置
        'ADMIN_USERNAME': 'admin_username',
        'ADMIN_PASSWORD': 'admin_password',

        # AI 内容审核
        'AI_MODERATION_API_KEY': 'AI_MODERATION.API_KEY',
        'AI_MODERATION_BASE_URL': 'AI_MODERATION.BASE_URL',
        'AI_MODERATION_MODEL': 'AI_MODERATION.MODEL',
        'AI_MODERATION_SYSTEM_PROMPT': 'AI_MODERATION.SYSTEM_PROMPT',

        # 微信配置
        'WECHAT_ENABLED': 'WECHAT_ENABLED',
        'WECHAT_APP_ID': 'WECHAT_APP_ID',
        'WECHAT_APP_SECRET': 'WECHAT_APP_SECRET',
        'WECHAT_TOKEN': 'WECHAT_TOKEN',
        'WECHAT_ENCODING_AES_KEY': 'WECHAT_ENCODING_AES_KEY',
        'WECHAT_TEMPLATE_ID': 'WECHAT_TEMPLATE_ID',

        # 微信公众号消息模板
        'WECHAT_SUBSCRIBE_REPLY': 'WECHAT_SUBSCRIBE_REPLY',
        'WECHAT_BIND_INSTRUCTION': 'WECHAT_BIND_INSTRUCTION',
        'WECHAT_DEFAULT_REPLY': 'WECHAT_DEFAULT_REPLY',

        # 邮件模板
        'EMAIL_VERIFY_SUBJECT': 'EMAIL_VERIFY_SUBJECT',
        'EMAIL_NEW_LETTER_SUBJECT': 'EMAIL_NEW_LETTER_SUBJECT',
        'EMAIL_UNLOCKED_SUBJECT': 'EMAIL_UNLOCKED_SUBJECT',
        'EMAIL_TEST_SUBJECT': 'EMAIL_TEST_SUBJECT',
        'EMAIL_TEST_BODY': 'EMAIL_TEST_BODY',

        # 应用通知模板
        'NOTIFICATION_LETTER_UNLOCKED_TITLE': 'NOTIFICATION_LETTER_UNLOCKED_TITLE',
        'NOTIFICATION_LETTER_UNLOCKED_CONTENT': 'NOTIFICATION_LETTER_UNLOCKED_CONTENT',

        # 应用配置
        'APP_NAME': 'APP_NAME',
        'APP_NAME_CN': 'APP_NAME_CN',
        'APP_URL': 'APP_URL',

        # 其他配置
        'TIMES': 'times',
        'FORCE_RAIN_DURATION': 'force_rain_duration',
        'PRIVATE_DELIVERY_REQUIRE_LOGIN': 'PRIVATE_DELIVERY_REQUIRE_LOGIN',
        'IPINFO_TOKEN': 'IPINFO_TOKEN',
        'SESSION_COOKIE_SECURE': 'SESSION_COOKIE_SECURE',
        'CSP_POLICY': 'CSP_POLICY',
    }

    # 4. 从环境变量加载配置
    for env_key, config_key in ENV_MAPPINGS.items():
        env_value = os.environ.get(env_key)
        if env_value is not None:
            # 处理嵌套键（如 AI_MODERATION.API_KEY）
            if '.' in config_key:
                parts = config_key.split('.')
                obj = config
                for part in parts[:-1]:
                    if part not in obj:
                        obj[part] = {}
                    obj = obj[part]
                obj[parts[-1]] = convert_env_value(env_value)
            else:
                config[config_key] = convert_env_value(env_value)

    return config


def convert_env_value(value):
    """智能转换环境变量值的类型"""
    if not isinstance(value, str):
        return value

    # 布尔值
    if value.lower() in ('true', 'yes', '1'):
        return True
    if value.lower() in ('false', 'no', '0'):
        return False
    # 数字
    try:
        if '.' in value:
            return float(value)
        return int(value)
    except ValueError:
        pass
    # 字符串
    return value


# 不可编辑的配置（因为来自环境变量）
READ_ONLY_CONFIG_KEYS = {
    'SECRET_KEY', 'admin_password',
    'HEFENG_KEY1', 'HEFENG_KEY2', 'HEFENG_KEY3', 'HEFENG_KEY4',
    'TURNSTILE_SECRET_KEY', 'RECAPTCHA_V3_SECRET_KEY',
    'ALTCHA_HMAC_KEY', 'MAIL_PASSWORD',
    'AI_MODERATION.API.KEY', 'WECHAT_APP_SECRET',
    'WECHAT_ENCODING_AES_KEY', 'IPINFO_TOKEN'
}
