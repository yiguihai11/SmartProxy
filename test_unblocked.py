import socket
import ssl
import time

def test_proxy(host, port, description=""):
    print(f"\n测试 {host}:{port} {description}...")

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
            return False

        # 发送连接请求 - 使用 IP 地址而不是域名
        if ':' in host:  # IPv6
            req = b'\x05\x01\x00\x04' + socket.inet_pton(socket.AF_INET6, host) + port.to_bytes(2, 'big')
        else:  # IPv4
            req = b'\x05\x01\x00\x01' + socket.inet_aton(host) + port.to_bytes(2, 'big')

        sock.send(req)
        response = sock.recv(10 if ':' not in host else 22)
        if response[0] != 0x05 or response[1] != 0x00:
            print(f"连接失败: {response.hex()}")
            return False

        # SSL 握手（如果需要）
        if port == 443:
            context = ssl.create_default_context()
            sock = context.wrap_socket(sock, server_hostname=host)

        # 发送简单的 HTTP GET
        request = f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
        sock.send(request.encode())

        # 接收响应
        response = b''
        start_time = time.time()
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
                        elapsed = time.time() - start_time
                        print(f"✅ 收到完整响应: {len(response)} 字节 (用时: {elapsed:.2f}s)")
                        print(f"   状态: {response.decode('utf-8', errors='ignore').split('\\n')[0]}")
                        return True
                    # 如果没有 body，继续读取
            except socket.timeout:
                break

        if response:
            elapsed = time.time() - start_time
            print(f"✅ 收到部分响应: {len(response)} 字节 (用时: {elapsed:.2f}s)")
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

# 测试未知的非屏蔽 IP
print("=== 测试未知的非屏蔽 IP 地址 ===")
print("使用 8.8.8.8 (Google DNS) 和 1.1.1.1 (Cloudflare DNS)")

# 测试 Google DNS
test_proxy("8.8.8.8", 53, "Google DNS - TCP")

# 测试 Cloudflare DNS
test_proxy("1.1.1.1", 53, "Cloudflare DNS - TCP")

# 测试一个公开的 HTTP 服务
test_proxy("93.184.216.34", 80, "example.com IP - HTTP")

print("\n=== 测试完成 ===")