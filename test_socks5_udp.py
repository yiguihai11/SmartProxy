#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
import socks
import struct
import time

def test_socks5_udp():
    """测试SOCKS5 UDP代理"""
    print("测试SOCKS5 UDP代理...")

    # 1. 首先建立TCP连接到SOCKS5服务器
    print("\n1. 连接到SOCKS5服务器...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)

    try:
        sock.connect(('127.0.0.1', 1080))
        print("   TCP连接成功")
    except Exception as e:
        print(f"   连接失败: {e}")
        return

    # 2. SOCKS5握手
    print("\n2. SOCKS5认证...")
    # 发送认证方法选择
    sock.send(b'\x05\x01\x00')  # VER=5, NMETHODS=1, METHOD=0(无认证)

    # 接收服务器响应
    response = sock.recv(2)
    if len(response) != 2 or response[0] != 5 or response[1] != 0:
        print(f"   认证失败: {response}")
        return
    print("   认证成功")

    # 3. 发送UDP ASSOCIATE请求
    print("\n3. 请求UDP ASSOCIATE...")
    # VER=5, CMD=3(UDP ASSOCIATE), RSV=0, ATYP=1(IPv4), DST.ADDR=0.0.0.0, DST.PORT=0
    udp_request = b'\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00'
    sock.send(udp_request)

    # 接收响应
    response = sock.recv(1024)  # 接收足够的数据
    if len(response) < 10 or response[0] != 5:
        print(f"   UDP ASSOCIATE失败: {response}")
        return

    print(f"   响应数据长度: {len(response)} bytes")
    print(f"   响应数据: {response[:20].hex()}")

    # 解析UDP转发地址
    if response[1] == 0:  # 成功
        if response[3] == 1:  # IPv4
            udp_ip = socket.inet_ntoa(response[4:8])
            udp_port = struct.unpack('!H', response[8:10])[0]
        elif response[3] == 3:  # 域名
            domain_len = response[4]
            domain = response[5:5+domain_len].decode('ascii')
            udp_port = struct.unpack('!H', response[5+domain_len:7+domain_len])[0]
            udp_ip = socket.gethostbyname(domain)
        elif response[3] == 4:  # IPv6
            # IPv6地址是16字节
            ipv6_bytes = response[4:20]
            udp_ip = socket.inet_ntop(socket.AF_INET6, ipv6_bytes)
            udp_port = struct.unpack('!H', response[20:22])[0]
            # 转换为IPv4地址（如果可能）
            try:
                # 尝试转换为IPv4映射的IPv6地址
                if udp_ip.startswith('::ffff:'):
                    udp_ip = udp_ip[7:]
            except:
                pass
        else:
            print(f"   不支持的地址类型: {response[3]}")
            return

        print(f"   UDP转发地址: {udp_ip}:{udp_port}")

        # 如果返回的端口是0，使用SOCKS5服务器的端口
        if udp_port == 0:
            # 根据RFC 1928，应该使用TCP连接的端口进行UDP通信
            udp_ip = '127.0.0.1'
            # 从smartproxy日志看，UDP绑定在一个随机端口，我们需要从TCP连接获取
            # 但更好的方法是使用标准SOCKS5库
            print("   端口为0，使用127.0.0.1")
    else:
        print(f"   UDP ASSOCIATE失败，错误码: {response[1]}")
        return

    # 4. 创建UDP socket连接到转发地址
    print("\n4. 创建UDP连接...")
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sock.settimeout(5)

    # 5. 构造DNS查询包
    print("\n5. 发送DNS查询...")
    # 简单的DNS查询包 (查询www.baidu.com)
    dns_query = b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
    dns_query += b'\x03www\x05baidu\x03com\x00\x00\x01\x00\x01'

    # 6. 发送DNS查询到SOCKS5 UDP端口
    # SOCKS5 UDP数据包格式: RSV(2) + FRAG(1) + ATYP(1) + DST.ADDR + DST.PORT + DATA
    target_ip = socket.inet_aton('119.29.29.29')  # DNS服务器IP
    target_port = struct.pack('!H', 53)  # DNS端口

    udp_packet = b'\x00\x00\x00\x01' + target_ip + target_port + dns_query

    print(f"   发送到 {udp_ip}:{udp_port}")
    udp_sock.sendto(udp_packet, (udp_ip, udp_port))
    print("   DNS查询已发送")

    # 7. 接收响应
    try:
        print("\n6. 等待DNS响应...")
        response, from_addr = udp_sock.recvfrom(1024)
        print(f"   收到响应，来自: {from_addr}")
        print(f"   响应大小: {len(response)} bytes")

        # 解析SOCKS5 UDP响应
        if len(response) >= 10:
            # 跳过SOCKS5头部(10字节)
            dns_response = response[10:]
            print(f"   DNS响应大小: {len(dns_response)} bytes")

            # 解析DNS响应头
            if len(dns_response) >= 12:
                header = struct.unpack('!HHHHHH', dns_response[:12])
                response_id = header[0]
                flags = header[1]
                answer_count = header[3]
                print(f"   响应ID: {response_id}, 标志: {flags:#04x}, 答案数: {answer_count}")

                if answer_count > 0:
                    print("   DNS查询成功！")
        else:
            print("   响应太短")

    except socket.timeout:
        print("   接收超时")
    except Exception as e:
        print(f"   错误: {e}")

    # 8. 清理
    udp_sock.close()
    sock.close()
    print("\n测试完成")

if __name__ == '__main__':
    test_socks5_udp()