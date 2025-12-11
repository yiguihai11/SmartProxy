import subprocess
import time
import sys

# 启动 smartproxy
proc = subprocess.Popen(['./smartproxy'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

try:
    # 等待启动
    time.sleep(2)
    
    # 使用 curl 发起一个简单的请求
    import subprocess as sp
    curl_proc = sp.run(['curl', '-x', 'http://127.0.0.1:1080', '-s', '-o', '/dev/null', '-w', '%{http_code}', 'http://httpbin.org/get'], 
                      capture_output=True, text=True, timeout=5)
    print(f'Curl exit code: {curl_proc.returncode}')
    
    # 等待一下让日志输出
    time.sleep(1)
    
finally:
    # 停止 smartproxy
    proc.terminate()
    output, _ = proc.communicate(timeout=2)
    
    # 查找相关日志
    for line in output.split('\n'):
        if 'DEBUG: clientConn' in line or 'IPv4 splice enabled' in line or 'Connections should support IPv4' in line:
            print(line)
