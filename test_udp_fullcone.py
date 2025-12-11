#!/usr/bin/env python3
"""
测试UDP Full Cone NAT功能的脚本
"""
import socket
import time
import threading
import struct

def test_udp_fullcone():
    # SOCKS5代理服务器地址
    proxy_host = "127.0.0.1"
    proxy_port = 1080

    # 测试目标服务器（使用公共NTP服务器）
    target_host = "pool.ntp.org"
    target_port = 123

    print(f"测试UDP Full Cone NAT通过SOCKS5代理 {proxy_host}:{proxy_port}")
    print(f"目标服务器: {target_host}:{target_port}")
    print("-" * 60)

    # 1. 连接到SOCKS5代理
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((proxy_host, proxy_port))

    # 2. SOCKS5握手
    # 发送认证方法选择
    sock.send(b"\x05\x01\x00")  # VER=5, NMETHODS=1, METHOD=0x00(无认证)

    # 接收服务器响应
    response = sock.recv(2)
    if response != b"\x05\x00":
        print("认证协商失败")
        return

    print("✓ SOCKS5认证成功")

    # 3. 发送UDP ASSOCIATE请求
    # 构建请求: VER=5, CMD=3(UDP ASSOCIATE), RSV=0, ATYP=1(IPv4), DST.ADDR=0.0.0.0, DST.PORT=0
    udp_associate_req = b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00"
    sock.send(udp_associate_req)

    # 接收响应
    response = sock.recv(10)
    if len(response) < 10 or response[0] != 0x05 or response[1] != 0x00:
        print("UDP ASSOCIATE失败")
        print(f"响应: {response.hex()}")
        return

    # 解析UDP端点地址
    if response[3] == 0x01:  # IPv4
        udp_ip = socket.inet_ntoa(response[4:8])
        udp_port = struct.unpack("!H", response[8:10])[0]
    else:
        print("不支持的地址类型")
        return

    print(f"✓ UDP ASSOCIATE成功: {udp_ip}:{udp_port}")

    # 4. 创建UDP socket连接到代理的UDP端口
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sock.connect((udp_ip, udp_port))

    # 5. 构建SOCKS5 UDP数据包
    # 格式: RSV(2) + FRAG(1) + ATYP(1) + DST.ADDR + DST.PORT(2) + DATA
    target_ip = socket.gethostbyname(target_host)

    # 构建UDP数据包（NTP请求）
    ntp_packet = b'\x1b' + b'\x00' * 47  # 简单的NTP请求

    # SOCKS5 UDP封装
    udp_packet = b'\x00\x00\x00'  # RSV + FRAG
    udp_packet += b'\x01'  # ATYP=IPv4
    udp_packet += socket.inet_aton(target_ip)  # 目标IP
    udp_packet += struct.pack("!H", target_port)  # 目标端口
    udp_packet += ntp_packet  # 数据

    # 6. 发送UDP数据包
    print(f"\n发送UDP数据包到 {target_host}:{target_port}")
    udp_sock.send(udp_packet)
    print(f"✓ 发送了 {len(udp_packet)} 字节")

    # 7. 接收响应
    print("\n等待UDP响应...")
    udp_sock.settimeout(5.0)

    try:
        response_data, addr = udp_sock.recvfrom(1024)
        print(f"✓ 收到 {len(response_data)} 字节的响应")

        # 解析SOCKS5 UDP响应包
        if len(response_data) >= 10:
            # 跳过RSV(2) + FRAG(1) + ATYP(1)
            atyp = response_data[3]
            offset = 4

            # 根据地址类型解析源地址
            if atyp == 0x01:  # IPv4
                src_ip = socket.inet_ntoa(response_data[4:8])
                src_port = struct.unpack("!H", response_data[8:10])[0]
                offset = 10
            elif atyp == 0x03:  # 域名
                domain_len = response_data[4]
                src_ip = response_data[5:5+domain_len].decode('ascii')
                src_port = struct.unpack("!H", response_data[5+domain_len:5+domain_len+2])[0]
                offset = 5 + domain_len + 2
            else:
                src_ip = "未知"
                src_port = 0

            print(f"  源地址: {src_ip}:{src_port}")
            print(f"  数据长度: {len(response_data) - offset} 字节")

            # 验证是否是NTP响应
            ntp_response = response_data[offset:]
            if len(ntp_response) >= 48:
                print("  ✓ 看起来是有效的NTP响应")
            else:
                print("  ⚠ 数据长度不足，可能不是完整的NTP响应")

    except socket.timeout:
        print("✗ 等待响应超时")
    except Exception as e:
        print(f"✗ 接收错误: {e}")
    finally:
        sock.close()
        udp_sock.close()

    print("\n" + "-" * 60)
    print("测试完成！")

if __name__ == "__main__":
    test_udp_fullcone()