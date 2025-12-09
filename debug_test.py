#!/usr/bin/env python3
import socket
import struct

def test_raw_socks5(target_domain, target_ip, port, proxy_host="127.0.0.1", proxy_port=1080):
    """测试原始SOCKS5连接，不发送任何HTTP请求"""
    try:
        # 创建SOCKS5连接
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        print(f"正在连接到代理 {proxy_host}:{proxy_port}...")
        sock.connect((proxy_host, proxy_port))

        # SOCKS5握手
        print("发送SOCKS5握手...")
        auth_request = b"\x05\x01\x00"  # 版本5，1种认证方法，无认证
        sock.send(auth_request)
        auth_response = sock.recv(2)
        print(f"认证响应: {auth_response.hex()}")
        if len(auth_response) != 2 or auth_response[0] != 0x05 or auth_response[1] != 0x00:
            return f"SOCKS5握手失败：响应异常 {auth_response.hex()}"

        # SOCKS5连接请求
        print(f"发送连接请求到 {target_domain}({target_ip}):{port}...")
        connect_request = b"\x05\x01\x00\x03"  # 版本5，连接命令，保留0，域名类型
        connect_request += bytes([len(target_ip)]) + target_ip.encode()
        connect_request += struct.pack(">H", port)
        sock.send(connect_request)

        connect_response = sock.recv(10)
        print(f"连接响应: {connect_response.hex()}")
        if len(connect_response) < 10 or connect_response[0] != 0x05 or connect_response[1] != 0x00:
            return f"SOCKS5连接失败：响应异常 {connect_response.hex()}"

        print("SOCKS5连接成功！")

        # 不发送任何HTTP请求，只是等待看是否有数据
        print("等待接收数据（不发送HTTP请求）...")
        sock.settimeout(2)
        try:
            data = sock.recv(4096)
            if data:
                print(f"意外收到 {len(data)} 字节数据: {data[:100].hex()}")
                print(f"前50字节转字符串: {data[:50]}")
            else:
                print("没有收到数据（正常）")
        except socket.timeout:
            print("超时，没有收到数据（正常）")
        except Exception as e:
            print(f"接收数据时出错: {e}")

        return "测试完成"

    except Exception as e:
        return f"测试失败：{str(e)}"
    finally:
        if 'sock' in locals():
            sock.close()

if __name__ == "__main__":
    # 测试一个国外IP（会走代理）
    print("=== 测试国外IP（走代理）===")
    result = test_raw_socks5("cp.cloudflare.com", "104.16.133.229", 80)
    print(f"结果: {result}")

    print("\n=== 测试国外IP 443端口（走代理）===")
    result = test_raw_socks5("cp.cloudflare.com", "104.16.133.229", 443)
    print(f"结果: {result}")