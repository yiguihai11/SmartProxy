#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
import socks
import struct
import time
import threading
import sys

class SOCKS5UDPTester:
    """SOCKS5 UDP 代理测试器"""

    def __init__(self, socks5_host='127.0.0.1', socks5_port=1080):
        self.socks5_host = socks5_host
        self.socks5_port = socks5_port
        self.tcp_sock = None
        self.udp_sock = None
        self.udp_relay_addr = None

    def connect(self):
        """连接到SOCKS5服务器并建立UDP ASSOCIATE"""
        try:
            # 1. 建立TCP连接
            print("\n1. 建立TCP连接到SOCKS5服务器...")
            self.tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.tcp_sock.settimeout(10)
            self.tcp_sock.connect((self.socks5_host, self.socks5_port))
            print(f"   ✓ TCP连接成功: {self.socks5_host}:{self.socks5_port}")

            # 2. SOCKS5握手
            print("\n2. SOCKS5认证...")
            self.tcp_sock.send(b'\x05\x01\x00')  # VER=5, NMETHODS=1, METHOD=0
            response = self.tcp_sock.recv(2)
            if response != b'\x05\x00':
                print(f"   ✗ 认证失败: {response}")
                return False
            print("   ✓ 认证成功")

            # 3. 发送UDP ASSOCIATE请求
            print("\n3. 请求UDP ASSOCIATE...")
            udp_request = b'\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00'
            self.tcp_sock.send(udp_request)

            # 4. 接收响应
            response = self.tcp_sock.recv(1024)
            if len(response) < 10 or response[0] != 5 or response[1] != 0:
                print(f"   ✗ UDP ASSOCIATE失败: {response}")
                return False

            # 解析UDP转发地址
            if response[3] == 1:  # IPv4
                udp_ip = socket.inet_ntoa(response[4:8])
                udp_port = struct.unpack('!H', response[8:10])[0]
            elif response[3] == 4:  # IPv6
                ipv6_bytes = response[4:20]
                udp_ip = socket.inet_ntop(socket.AF_INET6, ipv6_bytes)
                udp_port = struct.unpack('!H', response[20:22])[0]
                # 如果是 ::1，转换为 127.0.0.1
                if udp_ip == '::1':
                    udp_ip = '127.0.0.1'
            else:
                print(f"   ✗ 不支持的地址类型: {response[3]}")
                return False

            self.udp_relay_addr = (udp_ip, udp_port)
            print(f"   ✓ UDP转发地址: {udp_ip}:{udp_port}")

            # 5. 创建UDP socket
            print("\n4. 创建UDP socket...")
            self.udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.udp_sock.settimeout(10)
            print(f"   ✓ UDP socket创建成功")

            return True

        except Exception as e:
            print(f"   ✗ 连接失败: {e}")
            return False

    def build_dns_query(self, domain, query_id=0x1234):
        """构建DNS查询包"""
        query = struct.pack('!HHHHHH', query_id, 0x0100, 1, 0, 0, 0)

        # 添加查询域名
        for part in domain.split('.'):
            if part:
                query += bytes([len(part)]) + part.encode('ascii')
        query += b'\x00'

        # 添加查询类型和类（A记录，IN类）
        query += struct.pack('!HH', 1, 1)

        return query

    def parse_dns_response(self, data):
        """解析DNS响应"""
        if len(data) < 12:
            return None, "响应太短"

        # 解析头部
        header = struct.unpack('!HHHHHH', data[:12])
        query_id, flags, qdcount, ancount, nscount, arcount = header

        result = {
            'id': query_id,
            'flags': flags,
            'qdcount': qdcount,
            'ancount': ancount,
            'answers': []
        }

        # 检查响应码
        rcode = flags & 0x000F
        if rcode != 0:
            return None, f"DNS错误: {rcode}"

        # 简化处理：直接查找A记录
        offset = 12

        # 跳过查询部分
        for _ in range(qdcount):
            while offset < len(data) and data[offset] != 0:
                length = data[offset]
                if length == 0:
                    break
                offset += 1 + length
            if offset < len(data):
                offset += 1  # 跳过结束标记
            offset += 4  # 跳过类型和类

        # 解析答案
        for i in range(ancount):
            if offset >= len(data):
                break

            # 跳过名称（可能有压缩）
            while offset < len(data):
                if data[offset] == 0:
                    offset += 1
                    break
                elif data[offset] & 0xC0 == 0xC0:
                    offset += 2
                    break
                else:
                    length = data[offset]
                    offset += 1 + length

            # 解析类型、类、TTL、数据长度
            if offset + 10 > len(data):
                break

            rr_type, rr_class, ttl, rdlength = struct.unpack('!HHIH', data[offset:offset+10])
            offset += 10

            if offset + rdlength > len(data):
                break

            rdata = data[offset:offset+rdlength]
            offset += rdlength

            answer = {
                'type': rr_type,
                'class': rr_class,
                'ttl': ttl,
                'data': rdata
            }

            # 如果是A记录，解析IP
            if rr_type == 1 and len(rdata) == 4:
                answer['ip'] = socket.inet_ntoa(rdata)

            result['answers'].append(answer)

        return result, None

    def test_dns_query(self, domain, dns_server, use_proxy=True):
        """测试DNS查询"""
        print(f"\n{'='*60}")
        print(f"测试DNS查询: {domain} -> {dns_server}")
        print(f"{'='*60}")

        try:
            # 构建DNS查询
            dns_query = self.build_dns_query(domain)

            # 构建SOCKS5 UDP包
            # RSV(2) + FRAG(1) + ATYP(1) + DST.ADDR + DST.PORT + DATA
            target_ip = socket.inet_aton(dns_server)
            target_port = struct.pack('!H', 53)

            if use_proxy:
                # 通过SOCKS5代理发送
                udp_packet = b'\x00\x00\x00\x01' + target_ip + target_port + dns_query

                print(f"发送查询 (通过SOCKS5): {len(udp_packet)} bytes")
                start_time = time.time()

                self.udp_sock.sendto(udp_packet, self.udp_relay_addr)

                print(f"查询已发送到 {self.udp_relay_addr}")
            else:
                # 直接发送（不使用代理）
                print(f"发送查询 (直连): {len(dns_query)} bytes")
                start_time = time.time()

                self.udp_sock.sendto(dns_query, (dns_server, 53))

            # 接收响应
            print("\n等待响应...")
            try:
                response, addr = self.udp_sock.recvfrom(1024)
                end_time = time.time()

                print(f"\n✓ 收到响应!")
                print(f"  来源: {addr}")
                print(f"  大小: {len(response)} bytes")
                print(f"  耗时: {(end_time-start_time)*1000:.2f} ms")

                if use_proxy:
                    # 解析SOCKS5 UDP响应
                    if len(response) >= 10:
                        # 跳过SOCKS5头部
                        rsv = response[0:2]
                        frag = response[2]
                        atyp = response[3]

                        # 跳过源地址
                        if atyp == 1:  # IPv4
                            offset = 10
                        elif atyp == 4:  # IPv6
                            offset = 22
                        else:
                            offset = 10

                        dns_response = response[offset:]
                    else:
                        dns_response = response
                else:
                    dns_response = response

                # 解析DNS响应
                result, error = self.parse_dns_response(dns_response)

                if error:
                    print(f"  ✗ DNS解析错误: {error}")
                else:
                    print(f"  DNS ID: 0x{result['id']:04x}")
                    print(f"  标志: 0x{result['flags']:04x}")
                    print(f"  答案数: {result['ancount']}")

                    if result['id'] == 0x1234:
                        print("  ✓ DNS ID匹配!")

                    if result['answers']:
                        print("\n  答案记录:")
                        for i, ans in enumerate(result['answers'], 1):
                            print(f"    {i}. 类型: {ans['type']}, TTL: {ans['ttl']}")
                            if 'ip' in ans:
                                print(f"       IP: {ans['ip']}")

                    return True

            except socket.timeout:
                print(f"  ✗ 超时，未收到响应")
                return False

        except Exception as e:
            print(f"  ✗ 错误: {e}")
            import traceback
            traceback.print_exc()
            return False

    def test_multiple_queries(self):
        """测试多个连续查询"""
        print("\n\n" + "="*80)
        print("测试连续DNS查询")
        print("="*80)

        test_cases = [
            ('www.baidu.com', '119.29.29.29'),
            ('www.google.com', '8.8.8.8'),
            ('github.com', '1.1.1.1'),
        ]

        success_count = 0
        total_count = len(test_cases)

        for domain, dns in test_cases:
            if self.test_dns_query(domain, dns):
                success_count += 1
            time.sleep(0.5)  # 间隔

        print(f"\n\n测试结果: {success_count}/{total_count} 成功")
        return success_count == total_count

    def disconnect(self):
        """断开连接"""
        if self.tcp_sock:
            self.tcp_sock.close()
        if self.udp_sock:
            self.udp_sock.close()

    def test_direct_vs_proxy(self):
        """对比直连和代理的响应"""
        print("\n\n" + "="*80)
        print("对比测试: 直连 vs SOCKS5代理")
        print("="*80)

        domain = 'www.baidu.com'
        dns_server = '119.29.29.29'

        # 创建第二个UDP socket用于直连测试
        direct_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        direct_udp.settimeout(10)

        try:
            # 1. 直连测试
            print("\n1. 直连测试")
            print("-"*40)
            dns_query = self.build_dns_query(domain, 0x5678)

            start = time.time()
            direct_udp.sendto(dns_query, (dns_server, 53))
            response, _ = direct_udp.recvfrom(1024)
            end = time.time()

            result, error = self.parse_dns_response(response)
            if error:
                print(f"直连失败: {error}")
            else:
                print(f"直连成功: {len(response)} bytes, 耗时 {(end-start)*1000:.2f} ms")
                if result['answers']:
                    for ans in result['answers']:
                        if 'ip' in ans:
                            print(f"  IP: {ans['ip']}")

            # 2. SOCKS5代理测试
            print("\n2. SOCKS5代理测试")
            print("-"*40)
            if self.test_dns_query(domain, dns_server, use_proxy=True):
                print("代理测试成功")

        finally:
            direct_udp.close()

    def run_all_tests(self):
        """运行所有测试"""
        print("SOCKS5 UDP 代理综合测试")
        print("="*80)
        print(f"SOCKS5服务器: {self.socks5_host}:{self.socks5_port}")

        # 连接到SOCKS5
        if not self.connect():
            print("\n✗ 无法连接到SOCKS5服务器")
            return False

        try:
            # 1. 基本DNS查询测试
            print("\n\n[测试 1] 基本DNS查询测试")
            self.test_dns_query('www.baidu.com', '119.29.29.29')

            # 2. 直连vs代理对比测试
            print("\n\n[测试 2] 直连vs代理对比")
            self.test_direct_vs_proxy()

            # 3. 多查询测试
            print("\n\n[测试 3] 多查询并发测试")
            success = self.test_multiple_queries()

            print("\n\n" + "="*80)
            if success:
                print("✅ 所有测试通过! UDP代理工作正常")
            else:
                print("❌ 部分测试失败，UDP代理可能有问题")
            print("="*80)

            return success

        finally:
            self.disconnect()


def main():
    """主函数"""
    if len(sys.argv) > 1:
        host = sys.argv[1]
        port = int(sys.argv[2]) if len(sys.argv) > 2 else 1080
    else:
        host = '127.0.0.1'
        port = 1080

    print(f"使用 SOCKS5 代理: {host}:{port}")

    tester = SOCKS5UDPTester(host, port)
    tester.run_all_tests()


if __name__ == '__main__':
    main()