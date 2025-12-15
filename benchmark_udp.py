#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
import socks
import struct
import time
import statistics
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

class UDPBenchmark:
    """UDP代理性能测试器"""

    def __init__(self, socks5_host='127.0.0.1', socks5_port=1080):
        self.socks5_host = socks5_host
        self.socks5_port = socks5_port

    def setup_socks5_connection(self):
        """建立SOCKS5连接"""
        try:
            # TCP连接
            tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            tcp_sock.settimeout(10)
            tcp_sock.connect((self.socks5_host, self.socks5_port))

            # SOCKS5握手
            tcp_sock.send(b'\x05\x01\x00')
            response = tcp_sock.recv(2)
            if response != b'\x05\x00':
                return None, None

            # UDP ASSOCIATE
            udp_request = b'\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00'
            tcp_sock.send(udp_request)
            response = tcp_sock.recv(1024)

            if len(response) < 10 or response[0] != 5 or response[1] != 0:
                return None, None

            # 解析UDP地址
            if response[3] == 1:  # IPv4
                udp_ip = socket.inet_ntoa(response[4:8])
                udp_port = struct.unpack('!H', response[8:10])[0]
            elif response[3] == 4:  # IPv6
                ipv6_bytes = response[4:20]
                udp_ip = socket.inet_ntop(socket.AF_INET6, ipv6_bytes)
                udp_port = struct.unpack('!H', response[20:22])[0]
                if udp_ip == '::1':
                    udp_ip = '127.0.0.1'
            else:
                return None, None

            # 创建UDP socket
            udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp_sock.settimeout(10)

            return tcp_sock, (udp_sock, (udp_ip, udp_port))

        except Exception as e:
            print(f"SOCKS5连接失败: {e}")
            return None, None

    def build_dns_query(self, domain, query_id):
        """构建DNS查询"""
        query = struct.pack('!HHHHHH', query_id, 0x0100, 1, 0, 0, 0)
        for part in domain.split('.'):
            if part:
                query += bytes([len(part)]) + part.encode('ascii')
        query += b'\x00'
        query += struct.pack('!HH', 1, 1)
        return query

    def test_single_query(self, use_socks5=True, domain='www.baidu.com', dns='119.29.29.29'):
        """测试单次查询"""
        try:
            if use_socks5:
                tcp_sock, udp_info = self.setup_socks5_connection()
                if not tcp_sock:
                    return None, "SOCKS5连接失败"

                udp_sock, udp_addr = udp_info
                dns_query = self.build_dns_query(domain, 0x1234)

                # 构建SOCKS5 UDP包
                target_ip = socket.inet_aton(dns)
                target_port = struct.pack('!H', 53)
                udp_packet = b'\x00\x00\x00\x01' + target_ip + target_port + dns_query

                start = time.time()
                udp_sock.sendto(udp_packet, udp_addr)

                response, _ = udp_sock.recvfrom(1024)
                end = time.time()

                tcp_sock.close()
                udp_sock.close()

                return (end - start) * 1000, None  # 返回毫秒

            else:
                # 直连测试
                udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                udp_sock.settimeout(10)

                dns_query = self.build_dns_query(domain, 0x5678)

                start = time.time()
                udp_sock.sendto(dns_query, (dns, 53))

                response, _ = udp_sock.recvfrom(1024)
                end = time.time()

                udp_sock.close()

                return (end - start) * 1000, None

        except Exception as e:
            return None, str(e)

    def benchmark_concurrent(self, num_threads=10, queries_per_thread=10, use_socks5=True):
        """并发测试"""
        print(f"\n并发测试: {num_threads} 线程, 每线程 {queries_per_thread} 查询")
        print("-" * 50)

        results = []
        errors = []

        def worker():
            thread_results = []
            for i in range(queries_per_thread):
                domain = f"www{i % 5}.baidu.com"  # 轮换域名
                dns = ['119.29.29.29', '223.5.5.5', '114.114.114.114'][i % 3]  # 轮换DNS

                result, error = self.test_single_query(use_socks5, domain, dns)
                if result:
                    thread_results.append(result)
                else:
                    errors.append(error)

            return thread_results

        # 使用线程池
        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = [executor.submit(worker) for _ in range(num_threads)]

            for future in as_completed(futures):
                results.extend(future.result())

        # 统计结果
        if results:
            avg_time = statistics.mean(results)
            min_time = min(results)
            max_time = max(results)
            median_time = statistics.median(results)

            print(f"成功查询: {len(results)}")
            print(f"失败查询: {len(errors)}")
            print(f"平均响应时间: {avg_time:.2f} ms")
            print(f"最快响应时间: {min_time:.2f} ms")
            print(f"最慢响应时间: {max_time:.2f} ms")
            print(f"中位数响应时间: {median_time:.2f} ms")

            # 计算QPS
            total_time = sum(results)
            if total_time > 0:
                qps = len(results) * 1000 / total_time
                print(f"QPS (每秒查询数): {qps:.2f}")

            return avg_time, len(results), len(errors)
        else:
            print("所有查询都失败了!")
            for err in errors[:5]:
                print(f"  错误: {err}")
            return None, 0, len(errors)

    def benchmark_sequential(self, num_queries=50, use_socks5=True):
        """顺序测试"""
        print(f"\n顺序测试: {num_queries} 个查询")
        print("-" * 50)

        results = []
        for i in range(num_queries):
            domain = f"test{i % 10}.example.com"
            dns = ['8.8.8.8', '1.1.1.1'][i % 2]

            result, error = self.test_single_query(use_socks5, domain, dns)
            if result:
                results.append(result)
                print(f"查询 {i+1}: {result:.2f} ms")
            else:
                print(f"查询 {i+1}: 失败 - {error}")

        if results:
            avg = statistics.mean(results)
            print(f"\n平均响应时间: {avg:.2f} ms")
            return avg
        return None

    def run_full_benchmark(self):
        """运行完整基准测试"""
        print("UDP代理性能基准测试")
        print("=" * 50)
        print(f"SOCKS5服务器: {self.socks5_host}:{self.socks5_port}")

        # 直连基准
        print("\n[直连基准测试]")
        print("-" * 50)
        direct_avg = self.benchmark_sequential(20, use_socks5=False)
        direct_concurrent, success1, fail1 = self.benchmark_concurrent(5, 10, use_socks5=False)

        # SOCKS5代理测试
        print("\n\n[SOCKS5代理测试]")
        print("-" * 50)
        proxy_avg = self.benchmark_sequential(20, use_socks5=True)
        proxy_concurrent, success2, fail2 = self.benchmark_concurrent(5, 10, use_socks5=True)

        # 对比报告
        print("\n\n" + "=" * 50)
        print("性能对比报告")
        print("=" * 50)

        if direct_avg and proxy_avg:
            overhead = proxy_avg - direct_avg
            overhead_percent = (overhead / direct_avg) * 100
            print(f"平均响应时间:")
            print(f"  直连: {direct_avg:.2f} ms")
            print(f"  SOCKS5: {proxy_avg:.2f} ms")
            print(f"  开销: {overhead:.2f} ms ({overhead_percent:.1f}%)")

        print(f"\n并发测试成功率:")
        print(f"  直连: {success1}/{success1+fail1} ({success1/(success1+fail1)*100:.1f}%)")
        print(f"  SOCKS5: {success2}/{success2+fail2} ({success2/(success2+fail2)*100:.1f}%)")

        # 评估
        if proxy_avg and direct_avg:
            if overhead_percent < 100:
                print("\n✅ 性能良好: 开销小于100ms")
            elif overhead_percent < 200:
                print("\n⚠️  性能一般: 开销在100-200ms之间")
            else:
                print("\n❌ 性能较差: 开销超过200ms")


def main():
    """主函数"""
    import sys

    if len(sys.argv) > 1:
        host = sys.argv[1]
        port = int(sys.argv[2]) if len(sys.argv) > 2 else 1080
    else:
        host = '127.0.0.1'
        port = 1080

    benchmark = UDPBenchmark(host, port)
    benchmark.run_full_benchmark()


if __name__ == '__main__':
    main()