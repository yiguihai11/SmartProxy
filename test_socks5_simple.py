#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socks
import socket
import time

def test_socks5_dns():
    """使用PySocks测试通过SOCKS5代理进行DNS查询"""

    # 创建SOCKS5代理socket
    print("创建SOCKS5代理连接...")

    # 直接使用PySocks创建socket
    proxy_sock = socks.socksocket(socket.AF_INET, socket.SOCK_DGRAM)
    proxy_sock.set_proxy(socks.SOCKS5, "127.0.0.1", 1080)
    proxy_sock.settimeout(10)

    # DNS查询包 (查询www.baidu.com)
    dns_query = b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
    dns_query += b'\x03www\x05baidu\x03com\x00\x00\x01\x00\x01'

    try:
        # 直接发送DNS查询
        print("\n发送DNS查询到119.29.29.29:53...")
        start_time = time.time()
        proxy_sock.sendto(dns_query, ('119.29.29.29', 53))
        print("查询已发送")

        # 接收响应
        print("\n等待响应...")
        response, addr = proxy_sock.recvfrom(1024)
        end_time = time.time()

        print(f"\n收到响应!")
        print(f"响应来源: {addr}")
        print(f"响应大小: {len(response)} bytes")
        print(f"响应时间: {(end_time - start_time)*1000:.2f} ms")

        # 解析响应
        if len(response) >= 12:
            import struct
            header = struct.unpack('!HHHHHH', response[:12])
            print(f"\nDNS响应头:")
            print(f"  ID: {header[0]}")
            print(f"  Flags: {header[1]:#04x}")
            print(f"  问题数: {header[2]}")
            print(f"  答案数: {header[3]}")

            if header[3] > 0:
                print("  ✅ DNS查询成功!")

                # 尝试解析答案部分
                offset = 12
                # 跳过查询部分
                for _ in range(header[2]):
                    while offset < len(response) and response[offset] != 0:
                        length = response[offset]
                        if length == 0:
                            offset += 1
                            break
                        offset += 1 + length
                    if offset < len(response):
                        offset += 1
                    if offset + 4 <= len(response):
                        offset += 4  # 跳过类型和类

                # 解析答案记录
                for i in range(header[3]):
                    if offset >= len(response):
                        break

                    # 解析名称（可能被压缩）
                    name = ""
                    while offset < len(response):
                        length = response[offset]
                        if length == 0:
                            offset += 1
                            break
                        elif (length & 0xC0) == 0xC0:
                            # 压缩指针
                            offset += 2
                            name += "."
                            break
                        else:
                            offset += 1
                            if offset + length <= len(response):
                                name_part = response[offset:offset+length].decode('ascii', errors='ignore')
                                name += name_part + "."
                                offset += length

                    # 解析类型、类、TTL、数据长度
                    if offset + 10 <= len(response):
                        rr_type, rr_class, ttl, rdlength = struct.unpack('!HHIH', response[offset:offset+10])
                        offset += 10

                        if offset + rdlength <= len(response):
                            rdata = response[offset:offset+rdlength]
                            offset += rdlength

                            print(f"\n  答案 {i+1}:")
                            print(f"    名称: {name}")
                            print(f"    类型: {rr_type}")
                            print(f"    TTL: {ttl}")

                            if rr_type == 1 and len(rdata) == 4:  # A记录
                                ip = socket.inet_ntoa(rdata)
                                print(f"    IP地址: {ip}")
                            else:
                                print(f"    数据: {rdata.hex()}")
        else:
            print("  ❌ 响应太短")

    except Exception as e:
        print(f"\n错误: {e}")
        import traceback
        traceback.print_exc()

    finally:
        proxy_sock.close()

if __name__ == '__main__':
    test_socks5_dns()