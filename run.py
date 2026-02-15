#!/usr/bin/env python3
"""
雨天信箱启动脚本
使用：python run.py
"""

import os
import sys
from app import app

def check_dependencies():
    """检查依赖是否安装"""
    try:
        import flask
        import flask_sqlalchemy
        import requests
        import yaml
        print("✓ 所有依赖已安装")
        return True
    except ImportError as e:
        print(f"✗ 缺少依赖: {e}")
        print("请运行: pip install -r requirements.txt")
        return False

def create_database():
    """创建数据库"""
    try:
        with app.app_context():
            from app import db
            db.create_all()
            print("✓ 数据库初始化完成")
            return True
    except Exception as e:
        print(f"✗ 数据库初始化失败: {e}")
        return False

def main():
    """主函数"""
    print("=" * 50)
    print("雨天信箱启动程序")
    print("=" * 50)
    
    # 检查依赖
    if not check_dependencies():
        return 1
    
    # 创建数据库
    if not create_database():
        return 1
    
    print("✓ 启动Flask应用...")
    print("访问地址: http://localhost:5024")
    print("按 Ctrl+C 停止服务")
    print("=" * 50)
    
    # 启动应用
    app.run(host='0.0.0.0', port=5024, debug=True)
    
    return 0

if __name__ == "__main__":
    sys.exit(main())