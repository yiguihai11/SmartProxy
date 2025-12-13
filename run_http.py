import http.server
import socketserver
import os

# 核心配置（按需改）
PORT = 8000  # 端口（8000不占用系统端口，无需管理员权限）
WEB_ROOT = "./"  # 网页根目录（默认脚本所在文件夹，即index.html存放的文件夹）

# 切换到网页根目录
os.chdir(WEB_ROOT)

# 创建HTTP服务器
Handler = http.server.SimpleHTTPRequestHandler
with socketserver.TCPServer(("", PORT), Handler) as httpd:
    print(f"HTTP服务已启动，访问地址：http://localhost:{PORT}")
    print("停止服务请按：Ctrl + C")
    httpd.serve_forever()
