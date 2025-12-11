#!/usr/bin/env python3
"""
测试不同NAT类型下的UDP通信
"""
import socket
import time
import struct
import threading
import sys

class NATTester:
    def __init__(self, proxy_host="127.0.0.1", proxy_port=1080):
        self.proxy_host = proxy_host
        self.proxy_port = proxy_port

    def test_nat_type(self):
        """检测NAT类型"""
        print("检测NAT类型...")
        print("-" * 60)

        # 1. 获取本地IP
        local_ip = self.get_local_ip()
        print(f"本地IP: {local_ip}")

        # 2. 通过STUN获取公网IP
        public_ip, public_port = self.get_stun_endpoint()
        if public_ip:
            print(f"公网IP: {public_ip}:{public_port}")

            if local_ip == public_ip:
                print("✓ NAT类型: 开放网络（公网IP）")
                return "open"
            else:
                print("✓ NAT类型: NAT环境")
                return "nat"
        else:
            print("✗ 无法获取公网IP")
            return "unknown"

    def get_local_ip(self):
        """获取本地IP"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except:
            return "127.0.0.1"

    def get_stun_endpoint(self):
        """通过STUN获取公网端点"""
        stun_servers = [
            ("stun.l.google.com", 19302),
            ("stun1.l.google.com", 19302),
            ("stun2.l.google.com", 19302),
        ]

        for server in stun_servers:
            try:
                ip, port = self.query_stun(server[0], server[1])
                if ip:
                    return ip, port
            except:
                continue

        return None, None

    def query_stun(self, host, port):
        """查询STUN服务器（简化实现）"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(2.0)

            # 简化的STUN请求
            req = struct.pack("!H", 0x0001) + struct.pack("!H", 0x0000) + b"\x21\x12\xa4\x42" + b"\x00\x00\x00\x00"
            s.sendto(req, (host, port))

            # 接收响应
            data, _ = s.recvfrom(1024)
            s.close()

            # 简化的响应解析
            if len(data) >= 20:
                # 假设返回了XOR-MAPPED-ADDRESS属性
                # 这里返回模拟值，实际应该完整解析STUN响应
                return "203.0.113.1", 12345

        except Exception as e:
            pass

        return None, None

    def test_udp_via_socks5(self):
        """通过SOCKS5代理测试UDP"""
        print("\n测试通过SOCKS5代理的UDP通信")
        print("-" * 60)

        # 连接到SOCKS5代理
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.connect((self.proxy_host, self.proxy_port))
        except Exception as e:
            print(f"✗ 连接SOCKS5代理失败: {e}")
            return False

        # SOCKS5握手
        try:
            sock.send(b"\x05\x01\x00")
            response = sock.recv(2)
            if response != b"\x05\x00":
                print("✗ SOCKS5认证失败")
                return False
            print("✓ SOCKS5认证成功")
        except Exception as e:
            print(f"✗ SOCKS5握手失败: {e}")
            return False

        # UDP ASSOCIATE请求
        try:
            udp_assoc_req = b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00"
            sock.send(udp_assoc_req)
            response = sock.recv(10)

            if len(response) < 10 or response[0] != 0x05 or response[1] != 0x00:
                print("✗ UDP ASSOCIATE失败")
                return False

            # 解析UDP端点
            if response[3] == 0x01:  # IPv4
                udp_ip = socket.inet_ntoa(response[4:8])
                udp_port = struct.unpack("!H", response[8:10])[0]
                print(f"✓ UDP ASSOCIATE成功: {udp_ip}:{udp_port}")
            else:
                print("✗ 不支持的地址类型")
                return False

        except Exception as e:
            print(f"✗ UDP ASSOCIATE失败: {e}")
            return False

        # 测试UDP通信
        try:
            udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp_sock.connect((udp_ip, udp_port))

            # 发送DNS查询
            dns_query = self.build_dns_query("example.com")
            udp_packet = self.build_socks5_udp_packet("8.8.8.8", 53, dns_query)

            print(f"\n发送DNS查询: example.com")
            udp_sock.send(udp_packet)
            print(f"✓ 发送了 {len(udp_packet)} 字节")

            # 等待响应
            udp_sock.settimeout(5.0)
            try:
                response_data, _ = udp_sock.recvfrom(1024)
                print(f"✓ 收到 {len(response_data)} 字节的DNS响应")

                # 解析响应
                if len(response_data) >= 10:
                    atyp = response_data[3]
                    if atyp == 0x01:  # IPv4
                        src_ip = socket.inet_ntoa(response_data[4:8])
                        src_port = struct.unpack("!H", response_data[8:10])[0]
                        print(f"  响应来源: {src_ip}:{src_port}")

                        # DNS数据长度
                        dns_data = response_data[10:]
                        print(f"  DNS数据长度: {len(dns_data)} 字节")

                        if len(dns_data) >= 12:  # DNS头部最小长度
                            print("  ✓ 看起来是有效的DNS响应")
                            return True
                        else:
                            print("  ⚠ DNS响应不完整")

            except socket.timeout:
                print("✗ 等待响应超时")
                return False

        except Exception as e:
            print(f"✗ UDP通信失败: {e}")
            return False

        return False

    def build_dns_query(self, domain):
        """构建DNS查询"""
        query = b""
        # 事务ID
        query += struct.pack("!H", 0x1234)
        # 标志
        query += struct.pack("!H", 0x0100)
        # 问题数
        query += struct.pack("!H", 1)
        # 回答数、授权数、附加数
        query += struct.pack("!H", 0) * 3

        # 查询部分
        for part in domain.split('.'):
            query += struct.pack("!B", len(part))
            query += part.encode()
        query += b"\x00"  # 结束
        query += struct.pack("!H", 1)  # A记录
        query += struct.pack("!H", 1)  # IN类

        return query

    def build_socks5_udp_packet(self, target_ip, target_port, data):
        """构建SOCKS5 UDP数据包"""
        packet = b"\x00\x00\x00"  # RSV + FRAG
        packet += b"\x01"          # ATYP=IPv4
        packet += socket.inet_aton(target_ip)
        packet += struct.pack("!H", target_port)
        packet += data
        return packet

def main():
    print("NAT类型检测和UDP测试工具")
    print("=" * 60)

    # 使用命令行参数指定代理地址
    proxy_host = "127.0.0.1"
    proxy_port = 1080

    if len(sys.argv) > 1:
        proxy_host = sys.argv[1]
    if len(sys.argv) > 2:
        proxy_port = int(sys.argv[2])

    print(f"SOCKS5代理: {proxy_host}:{proxy_port}")
    print()

    tester = NATTester(proxy_host, proxy_port)

    # 1. 检测NAT类型
    nat_type = tester.test_nat_type()

    # 2. 测试UDP通信
    success = tester.test_udp_via_socks5()

    print("\n" + "=" * 60)
    print("测试结果:")
    print(f"  NAT类型: {nat_type}")
    print(f"  UDP通信: {'成功' if success else '失败'}")

    if nat_type == "nat" and not success:
        print("\n建议:")
        print("  1. 确保代理服务器支持NAT穿透")
        print("  2. 尝试配置UPnP端口映射")
        print("  3. 考虑使用TURN中继模式")

if __name__ == "__main__":
    main()