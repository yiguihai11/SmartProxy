#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
import struct
import time
import select

def test_raw_udp():
    """测试UDP直连，不通过SOCKS5"""

    print("=== 测试UDP直连 ===")

    # 创建UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(10)

    # DNS查询包
    dns_query = b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
    dns_query += b'\x03www\x05baidu\x03com\x00\x00\x01\x00\x01'

    try:
        # 发送到DNS服务器
        target = ('119.29.29.29', 53)
        print(f"\n发送DNS查询到 {target}")
        start = time.time()
        sock.sendto(dns_query, target)

        # 接收响应
        print("等待响应...")
        ready = select.select([sock], [], [], 10)
        if ready[0]:
            response, addr = sock.recvfrom(1024)
            end = time.time()

            print(f"\n✅ 收到响应!")
            print(f"  来源: {addr}")
            print(f"  大小: {len(response)} bytes")
            print(f"  耗时: {(end-start)*1000:.2f} ms")

            # 解析响应头
            if len(response) >= 12:
                header = struct.unpack('!HHHHHH', response[:12])
                print(f"  DNS ID: 0x{header[0]:04x}")
                print(f"  Flags: 0x{header[1]:04x}")
                print(f"  答案数: {header[3]}")

                if header[0] == 0x1234:  # 检查ID是否匹配
                    print("  ✅ DNS ID匹配!")
        else:
            print("❌ 超时，未收到响应")

    except Exception as e:
        print(f"错误: {e}")
        import traceback
        traceback.print_exc()

    finally:
        sock.close()


def test_tcp_dns():
    """测试通过TCP进行DNS查询"""

    print("\n\n=== 测试TCP DNS查询 ===")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)

    try:
        # 连接到Google DNS over TCP
        print("\n连接到Google DNS (TCP)...")
        sock.connect(('8.8.8.8', 53))
        print("✅ 连接成功")

        # 构造TCP DNS查询
        # 前2字节是长度
        dns_query = b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
        dns_query += b'\x03www\x05google\x03com\x00\x00\x01\x00\x01'

        # 添加长度前缀
        tcp_query = struct.pack('!H', len(dns_query)) + dns_query

        print(f"\n发送DNS查询 ({len(tcp_query)} bytes)")
        start = time.time()
        sock.send(tcp_query)

        # 接收响应
        # 先读2字节长度
        length_data = sock.recv(2)
        if len(length_data) == 2:
            response_length = struct.unpack('!H', length_data)[0]
            print(f"响应长度: {response_length} bytes")

            # 读取响应内容
            response = b''
            while len(response) < response_length:
                chunk = sock.recv(response_length - len(response))
                if not chunk:
                    break
                response += chunk

            end = time.time()

            if len(response) == response_length:
                print(f"\n✅ 收到完整响应!")
                print(f"  耗时: {(end-start)*1000:.2f} ms")

                # 解析响应头
                if len(response) >= 12:
                    header = struct.unpack('!HHHHHH', response[:12])
                    print(f"  DNS ID: 0x{header[0]:04x}")
                    print(f"  Flags: 0x{header[1]:04x}")
                    print(f"  答案数: {header[3]}")

                    if header[0] == 0x1234:
                        print("  ✅ DNS ID匹配!")

                        # 尝试解析IP地址
                        if header[3] > 0:
                            # 简单查找IP地址
                            for i in range(12, len(response)-4):
                                if response[i:i+4] == b'\xc0\x0c':  # 压缩指针
                                    i += 2
                                    if i+4 <= len(response):
                                        ip = socket.inet_ntoa(response[i:i+4])
                                        print(f"  IP地址: {ip}")
                                        break
            else:
                print(f"❌ 响应不完整: {len(response)}/{response_length} bytes")
        else:
            print("❌ 无法读取响应长度")

    except Exception as e:
        print(f"错误: {e}")
        import traceback
        traceback.print_exc()

    finally:
        sock.close()


if __name__ == '__main__':
    test_raw_udp()
    test_tcp_dns()