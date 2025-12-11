import socket
import ssl
import time

def test_proxy(host, port):
    print(f"\n测试 {host}:{port}...")
    
    try:
        # SOCKS5 握手
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect(('127.0.0.1', 1080))
        
        # 发送认证
        sock.send(b'\x05\x01\x00')
        response = sock.recv(2)
        if response != b'\x05\x00':
            print(f"认证失败: {response.hex()}")
            return
        
        # 发送连接请求
        req = b'\x05\x01\x00\x03' + b'\x01' + socket.inet_aton(host) + port.to_bytes(2, 'big')
        sock.send(req)
        response = sock.recv(10)
        if response[0] != 0x05 or response[1] != 0x00:
            print(f"连接失败: {response.hex()}")
            return
        
        # SSL 握手（如果需要）
        if port == 443:
            context = ssl.create_default_context()
            sock = context.wrap_socket(sock, server_hostname=host)
        
        # 发送简单的 HTTP GET
        request = f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
        sock.send(request.encode())
        
        # 接收响应
        response = b''
        while True:
            try:
                data = sock.recv(4096)
                if not data:
                    break
                response += data
                # 如果收到完整响应头
                if b'\r\n\r\n' in response:
                    # 读取到第一个空行
                    headers, _, body = response.partition(b'\r\n\r\n')
                    if body:
                        print(f"✅ 收到响应: {len(response)} 字节")
                        print(f"   状态: {response.decode('utf-8', errors='ignore').split('\\n')[0]}")
                        return True
                    # 如果没有 body，继续读取
            except socket.timeout:
                break
        
        if response:
            print(f"✅ 收到部分响应: {len(response)} 字节")
            print(f"   状态: {response.decode('utf-8', errors='ignore').split('\\n')[0]}")
            return True
        else:
            print("❌ 未收到任何响应")
            return False
            
    except Exception as e:
        print(f"❌ 错误: {e}")
        return False
    finally:
        try:
            sock.close()
        except:
            pass

# 测试不同站点
print("=== 简单代理测试 ===")
test_proxy("8.8.8.8", 80)
test_proxy("8.8.8.8", 443)
