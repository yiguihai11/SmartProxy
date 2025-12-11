#!/usr/bin/env python3
"""
测试SOCKS5代理的IPv6支持
"""
import socket
import struct
import time
import sys

def test_ipv6_support():
    """测试IPv6支持"""
    proxy_host = "::1"  # IPv6本地地址
    proxy_port = 1080

    print("测试SOCKS5代理的IPv6支持")
    print("=" * 60)

    # 检查系统是否支持IPv6
    try:
        # 创建IPv6 socket测试
        test_sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        test_sock.bind(("::1", 0))
        test_port = test_sock.getsockname()[1]
        test_sock.close()
        print(f"✓ 系统支持IPv6 (测试端口: {test_port})")
    except Exception as e:
        print(f"✗ 系统不支持IPv6: {e}")
        return False

    # 测试SOCKS5代理的IPv6支持
    try:
        # 1. 连接到SOCKS5代理（IPv6）
        print(f"\n连接到SOCKS5代理: [{proxy_host}]:{proxy_port}")
        sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        sock.settimeout(5.0)
        sock.connect((proxy_host, proxy_port))
        print("✓ IPv6 TCP连接成功")

        # 2. SOCKS5握手
        sock.send(b"\x05\x01\x00")  # 无认证
        response = sock.recv(2)
        if response != b"\x05\x00":
            print("✗ SOCKS5认证失败")
            return False
        print("✓ SOCKS5认证成功")

        # 3. 测试TCP IPv6连接
        # 连接到IPv6 NTP服务器
        ipv6_server = "2001:4860:4860::8888"  # Google DNS IPv6
        req = build_connect_request_ipv6(ipv6_server, 123)
        sock.send(req)

        # 读取响应
        resp = sock.recv(30)
        if len(resp) >= 10 and resp[0] == 0x05 and resp[1] == 0x00:
            print("✓ IPv6 TCP连接成功")
        else:
            print("✗ IPv6 TCP连接失败")
            return False

        # 4. 测试UDP ASSOCIATE
        udp_req = build_udp_associate_request_ipv6()
        sock.send(udp_req)

        # 读取UDP ASSOCIATE响应
        udp_resp = sock.recv(22)  # IPv6响应应该更长
        if len(udp_resp) >= 22 and udp_resp[0] == 0x05 and udp_resp[1] == 0x00:
            if udp_resp[3] == 0x04:  # IPv6
                udp_ip = parse_ipv6_address(udp_resp[4:20])
                udp_port = struct.unpack("!H", udp_resp[20:22])[0]
                print(f"✓ UDP ASSOCIATE成功: [{udp_ip}]:{udp_port}")

                # 5. 测试IPv6 UDP通信
                return test_ipv6_udp(sock, udp_ip, udp_port, ipv6_server, 123)
            else:
                print("✗ UDP ASSOCIATE返回非IPv6地址")
                return False
        else:
            print("✗ UDP ASSOCIATE失败")
            return False

    except Exception as e:
        print(f"✗ IPv6测试失败: {e}")
        return False

def build_connect_request_ipv6(ipv6, port):
    """构建IPv6连接请求"""
    req = bytearray()
    req.append(0x05)  # VER
    req.append(0x01)  # CMD CONNECT
    req.append(0x00)  # RSV
    req.append(0x04)  # ATYP IPv6

    # IPv6地址 (16字节)
    addr = socket.inet_pton(socket.AF_INET6, ipv6)
    req.extend(addr)

    # 端口
    req.extend(struct.pack("!H", port))

    return bytes(req)

def build_udp_associate_request_ipv6():
    """构建IPv6 UDP ASSOCIATE请求"""
    req = bytearray()
    req.append(0x05)  # VER
    req.append(0x03)  # CMD UDP ASSOCIATE
    req.append(0x00)  # RSV
    req.append(0x04)  # ATYP IPv6

    # IPv6地址 ::1
    req.extend([0x00] * 16)

    # 端口 0
    req.extend([0x00, 0x00])

    return bytes(req)

def parse_ipv6_address(data):
    """解析IPv6地址"""
    if len(data) != 16:
        return "::"
    return socket.inet_ntop(socket.AF_INET6, data)

def test_ipv6_udp(tcp_sock, udp_ip, udp_port, target_ip, target_port):
    """测试IPv6 UDP通信"""
    try:
        # 创建UDP socket
        udp_sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)

        # 连接到代理的UDP端口
        udp_sock.connect((udp_ip, udp_port))
        print(f"✓ UDP socket连接成功")

        # 构建IPv6 NTP请求
        ntp_packet = b'\x1b' + b'\x00' * 47

        # 构建SOCKS5 UDP数据包
        udp_packet = bytearray()
        udp_packet.extend([0x00, 0x00, 0x00])  # RSV + FRAG
        udp_packet.append(0x04)  # ATYP IPv6

        # IPv6目标地址
        target_addr = socket.inet_pton(socket.AF_INET6, target_ip)
        udp_packet.extend(target_addr)

        # 目标端口
        udp_packet.extend(struct.pack("!H", target_port))

        # NTP数据
        udp_packet.extend(ntp_packet)

        # 发送UDP数据
        print(f"\n发送IPv6 UDP数据包到 [{target_ip}]:{target_port}")
        udp_sock.send(udp_packet)
        print(f"✓ 发送了 {len(udp_packet)} 字节")

        # 接收响应
        udp_sock.settimeout(5.0)
        try:
            response, addr = udp_sock.recvfrom(1024)
            print(f"✓ 收到 {len(response)} 字节的IPv6 UDP响应")

            # 解析响应
            if len(response) >= 22:  # IPv6响应最小长度
                if response[3] == 0x04:  # IPv6
                    src_ip = parse_ipv6_address(response[4:20])
                    src_port = struct.unpack("!H", response[20:22])[0]
                    print(f"  响应来源: [{src_ip}]:{src_port}")

                    ntp_data = response[22:]
                    if len(ntp_data) >= 48:
                        print("  ✓ 看起来是有效的NTP响应")
                        return True
                    else:
                        print("  ⚠ NTP响应不完整")
                else:
                    print("  ⚠ 响应不是IPv6格式")
            else:
                print("  ⚠ 响应长度不足")

        except socket.timeout:
            print("✗ 等待IPv6 UDP响应超时")
            return False

    except Exception as e:
        print(f"✗ IPv6 UDP测试失败: {e}")
        return False

    return False

def main():
    print("SOCKS5 IPv6支持测试工具")
    print("=" * 60)

    # 使用命令行参数指定代理地址
    proxy_host = "::1"
    proxy_port = 1080

    if len(sys.argv) > 1:
        proxy_host = sys.argv[1]
    if len(sys.argv) > 2:
        proxy_port = int(sys.argv[2])

    print(f"测试代理: [{proxy_host}]:{proxy_port}")
    print()

    success = test_ipv6_support()

    print("\n" + "=" * 60)
    print("测试结果:")
    print(f"  IPv6支持: {'✓ 成功' if success else '✗ 失败'}")

    if not success:
        print("\n建议:")
        print("  1. 确保系统启用了IPv6")
        print("  2. 检查SOCKS5代理是否监听IPv6地址")
        print("  3. 确认网络支持IPv6连接")

if __name__ == "__main__":
    main()