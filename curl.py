# curl.py
import time
import sys
import os
import signal
import atexit

while True:
    os.system("curl -s -L http://localhost:5024")
    time.sleep(60)  # 每3000秒请求一次