from ast import While
import os
import time

while True:
    os.system("curl http://localhost:5024") 
    time.sleep(3)  # 每隔3秒执行一次