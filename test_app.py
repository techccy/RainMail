#!/usr/bin/env python3
"""
雨天信箱测试脚本
用于验证核心功能是否符合验收标准
"""

import requests
import time
import json
import sys

BASE_URL = "http://localhost:5000"

def test_weather_sync():
    """测试天气同步功能"""
    print("测试天气同步功能...")
    
    # 测试天气API
    try:
        response = requests.get(f"{BASE_URL}/api/weather", timeout=5)
        data = response.json()
        print(f"当前天气状态: {data['weather_status']}")
        return True
    except Exception as e:
        print(f"天气API测试失败: {e}")
        return False

def test_data_isolation():
    """测试数据隔离功能"""
    print("测试数据隔离功能...")
    
    # 模拟晴天状态下的读取请求
    try:
        response = requests.get(f"{BASE_URL}/api/messages", timeout=5)
        if response.status_code == 403:
            print("✓ 晴天模式下正确拒绝读取请求")
            return True
        else:
            print(f"✗ 期望403错误码，得到: {response.status_code}")
            return False
    except Exception as e:
        print(f"数据隔离测试失败: {e}")
        return False

def test_message_submission():
    """测试消息提交功能"""
    print("测试消息提交功能...")
    
    test_message = "这是一个测试消息 - " + time.strftime("%Y-%m-%d %H:%M:%S")
    
    try:
        response = requests.post(
            f"{BASE_URL}/api/messages",
            json={"content": test_message},
            headers={"Content-Type": "application/json"},
            timeout=5
        )
        
        if response.status_code == 200:
            data = response.json()
            print(f"✓ 消息提交成功: {data['message']}")
            print(f"  消息ID: {data['share_data']['message_id']}")
            return True
        else:
            print(f"✗ 消息提交失败: {response.status_code}")
            return False
    except Exception as e:
        print(f"消息提交测试失败: {e}")
        return False

def test_xss_protection():
    """测试XSS防护功能"""
    print("测试XSS防护功能...")
    
    xss_test = "<script>alert('xss')</script>测试内容"
    
    try:
        response = requests.post(
            f"{BASE_URL}/api/messages",
            json={"content": xss_test},
            headers={"Content-Type": "application/json"},
            timeout=5
        )
        
        if response.status_code == 200:
            print("✓ XSS测试消息提交成功")
            # 这里可以进一步验证数据库中的内容是否被过滤
            return True
        else:
            print(f"✗ XSS测试失败: {response.status_code}")
            return False
    except Exception as e:
        print(f"XSS测试失败: {e}")
        return False

def test_health_check():
    """测试健康检查接口"""
    print("测试健康检查接口...")
    
    try:
        response = requests.get(f"{BASE_URL}/api/health", timeout=5)
        if response.status_code == 200:
            data = response.json()
            print(f"✓ 健康检查正常: {data['status']}")
            return True
        else:
            print(f"✗ 健康检查失败: {response.status_code}")
            return False
    except Exception as e:
        print(f"健康检查测试失败: {e}")
        return False

def main():
    """主测试函数"""
    print("=" * 50)
    print("雨天信箱功能测试")
    print("=" * 50)
    
    tests = [
        test_health_check,
        test_weather_sync,
        test_message_submission,
        test_xss_protection,
        test_data_isolation
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        if test():
            passed += 1
        print()
    
    print("=" * 50)
    print(f"测试结果: {passed}/{total} 通过")
    
    if passed == total:
        print("✓ 所有测试通过！")
        return 0
    else:
        print("✗ 部分测试失败")
        return 1

if __name__ == "__main__":
    # 等待应用启动
    print("等待应用启动...")
    time.sleep(2)
    sys.exit(main())