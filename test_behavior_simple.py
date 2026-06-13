#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""用户行为跟踪器简单测试（不依赖数据库）"""

import time
import hmac
import hashlib
import base64
import secrets
from datetime import datetime

class UserBehaviorTracker:
    """用户行为轨迹分析 - 防止自动化脚本攻击"""
    
    def __init__(self, secret_key):
        self.SECRET_KEY = secret_key.encode()
        self.MIN_PAGE_TIME = 8  # 最小页面停留时间（秒）
        self.MIN_INPUT_FOCUS = 1  # 最少聚焦次数
        self.MIN_INPUT_CHARS = 1  # 最少输入字符数
        self.TOKEN_EXPIRY = 600  # Token有效期（秒）
    
    def generate_form_token(self):
        """生成加密的 Form_Token"""
        timestamp = str(int(time.time()))
        random_str = secrets.token_hex(16)
        
        # 拼接数据：timestamp + random_str
        data = f"{timestamp}:{random_str}"
        
        # 使用 HMAC-SHA256 加密
        signature = hmac.new(
            self.SECRET_KEY,
            data.encode(),
            hashlib.sha256
        ).hexdigest()
        
        # Base64 编码
        token = base64.b64encode(f"{data}:{signature}".encode()).decode()
        
        return {
            'form_token': token,
            'generated_at': int(timestamp),
            'expires_at': int(timestamp) + self.TOKEN_EXPIRY
        }
    
    def verify_form_token(self, form_token):
        """验证 Form_Token 是否有效"""
        try:
            decoded = base64.b64decode(form_token.encode()).decode()
            parts = decoded.split(':')
            
            if len(parts) != 3:
                return False, "Token格式错误"
            
            timestamp, random_str, signature = parts
            
            # 重新计算签名
            data = f"{timestamp}:{random_str}"
            expected_signature = hmac.new(
                self.SECRET_KEY,
                data.encode(),
                hashlib.sha256
            ).hexdigest()
            
            # 验证签名
            if not hmac.compare_digest(signature, expected_signature):
                return False, "Token签名无效"
            
            # 验证时间戳（防止重放攻击）
            token_time = int(timestamp)
            current_time = int(time.time())
            
            if current_time - token_time > self.TOKEN_EXPIRY:
                return False, "Token已过期"
            
            if token_time > current_time:
                return False, "Token时间无效"
            
            return True, int(timestamp)
            
        except Exception as e:
            print(f"[ERROR] Form token验证错误: {str(e)}")
            return False, "Token验证失败"
    
    def validate_user_behavior(self, form_token, page_stay_time, input_focus_count, input_char_count):
        """验证用户行为"""
        # 验证 Form_Token
        is_valid, result = self.verify_form_token(form_token)
        if not is_valid:
            return False, result
        
        token_time = result
        current_time = int(time.time())
        max_stay_time = current_time - token_time
        
        # 验证页面停留时间
        if page_stay_time < self.MIN_PAGE_TIME:
            return False, f"页面停留时间不足{self.MIN_PAGE_TIME}秒"
        
        # 验证停留时间不超过最大值（防止脚本长时间等待）
        if page_stay_time > max_stay_time + 60:  # 允许60秒误差
            return False, "页面停留时间异常"
        
        # 验证输入框聚焦次数
        if input_focus_count < self.MIN_INPUT_FOCUS:
            return False, "未检测到输入框交互"
        
        # 验证输入字符数
        if input_char_count < self.MIN_INPUT_CHARS:
            return False, "未检测到输入内容"
        
        return True, "验证通过"

def main():
    print("=" * 70)
    print("用户行为跟踪器测试")
    print("=" * 70)
    
    secret_key = 'test_secret_key_12345'
    tracker = UserBehaviorTracker(secret_key)
    
    # 测试 1: 生成 Token
    print("\n[Test 1] 生成 Form_Token")
    token_data = tracker.generate_form_token()
    print(f"✓ Token 生成成功")
    print(f"  - Token: {token_data['form_token'][:50]}...")
    print(f"  - 生成时间: {datetime.fromtimestamp(token_data['generated_at'])}")
    print(f"  - 过期时间: {datetime.fromtimestamp(token_data['expires_at'])}")
    
    # 测试 2: 验证有效 Token
    print("\n[Test 2] 验证有效 Token")
    is_valid, result = tracker.verify_form_token(token_data['form_token'])
    if is_valid:
        print(f"✓ Token 验证通过")
        print(f"  - 解析时间: {datetime.fromtimestamp(result)}")
    else:
        print(f"✗ Token 验证失败: {result}")
    
    # 测试 3: 验证无效 Token
    print("\n[Test 3] 验证无效 Token")
    is_valid, result = tracker.verify_form_token("invalid_token_data")
    if not is_valid:
        print(f"✓ 无效 Token 被正确拒绝: {result}")
    else:
        print(f"✗ 应该拒绝无效 Token")
    
    # 测试 4: 用户行为验证成功
    print("\n[Test 4] 用户行为验证成功")
    is_valid, message = tracker.validate_user_behavior(
        token_data['form_token'],
        page_stay_time=10,
        input_focus_count=2,
        input_char_count=50
    )
    if is_valid:
        print(f"✓ 用户行为验证通过: {message}")
    else:
        print(f"✗ 用户行为验证失败: {message}")
    
    # 测试 5: 页面停留时间不足
    print("\n[Test 5] 页面停留时间不足测试")
    is_valid, message = tracker.validate_user_behavior(
        token_data['form_token'],
        page_stay_time=5,  # 小于8秒
        input_focus_count=1,
        input_char_count=10
    )
    if not is_valid and "页面停留时间不足" in message:
        print(f"✓ 停留时间不足被正确拦截: {message}")
    else:
        print(f"✗ 应该拦截停留时间不足")
    
    # 测试 6: 无输入框聚焦
    print("\n[Test 6] 无输入框聚焦测试")
    is_valid, message = tracker.validate_user_behavior(
        token_data['form_token'],
        page_stay_time=10,
        input_focus_count=0,  # 没有聚焦
        input_char_count=10
    )
    if not is_valid and "未检测到输入框交互" in message:
        print(f"✓ 无输入框交互被正确拦截: {message}")
    else:
        print(f"✗ 应该拦截无输入框交互")
    
    # 测试 7: 无输入内容
    print("\n[Test 7] 无输入内容测试")
    is_valid, message = tracker.validate_user_behavior(
        token_data['form_token'],
        page_stay_time=10,
        input_focus_count=1,
        input_char_count=0  # 没有输入字符
    )
    if not is_valid and "未检测到输入内容" in message:
        print(f"✓ 无输入内容被正确拦截: {message}")
    else:
        print(f"✗ 应该拦截无输入内容")
    
    # 测试 8: Token 过期测试
    print("\n[Test 8] Token 过期测试")
    expired_tracker = UserBehaviorTracker(secret_key)
    expired_tracker.TOKEN_EXPIRY = 1
    expired_token = expired_tracker.generate_form_token()
    
    print(f"  等待2秒使 token 过期...")
    time.sleep(2)
    
    is_valid, message = expired_tracker.verify_form_token(expired_token['form_token'])
    if not is_valid and "过期" in message:
        print(f"✓ 过期 Token 被正确拒绝: {message}")
    else:
        print(f"✗ 应该拒绝过期 Token")
    
    print("\n" + "=" * 70)
    print("所有测试完成！")
    print("=" * 70)

if __name__ == '__main__':
    main()

