#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
import struct
import time
import sys
import socks

class DNSQuery:
    """DNS查询类"""

    def __init__(self):
        self.query_id = 0

    def build_query(self, domain, qtype='A'):
        """构造DNS查询包"""
        # DNS头部结构 (12字节)
        # ID (2字节) | Flags (2字节) | QDCOUNT (2字节) | ANCOUNT (2字节) | NSCOUNT (2字节) | ARCOUNT (2字节)
        header = struct.pack('!HHHHHH',
            self._get_id(),  # ID
            0x0100,         # Flags: 标准查询, 递归期望
            1,              # QDCOUNT: 问题数
            0,              # ANCOUNT: 答案数
            0,              # NSCOUNT: 权威记录数
            0               # ARCOUNT: 附加记录数
        )

        # 查询部分
        query = self._encode_domain(domain)

        # 查询类型和类别
        if qtype == 'A':
            qtype_code = 1    # A记录
        elif qtype == 'AAAA':
            qtype_code = 28   # AAAA记录
        elif qtype == 'MX':
            qtype_code = 15   # MX记录
        elif qtype == 'TXT':
            qtype_code = 16   # TXT记录
        else:
            qtype_code = 1    # 默认A记录

        query += struct.pack('!HH', qtype_code, 1)  # 类别: 1 (IN)

        return header + query

    def _get_id(self):
        """获取查询ID"""
        self.query_id += 1
        return self.query_id & 0xFFFF

    def _encode_domain(self, domain):
        """编码域名为DNS格式"""
        encoded = b''
        for part in domain.split('.'):
            if part:
                encoded += bytes([len(part)]) + part.encode('ascii')
        encoded += b'\x00'  # 结束标记
        return encoded

    def parse_response(self, response):
        """解析DNS响应"""
        if len(response) < 12:
            return None

        # 解析头部
        header = struct.unpack('!HHHHHH', response[:12])
        query_id, flags, qdcount, ancount, nscount, arcount = header

        # 检查响应码
        rcode = flags & 0x000F
        if rcode != 0:
            return {
                'error': True,
                'rcode': rcode,
                'error_msg': self._get_error_message(rcode)
            }

        # 解析答案
        answers = []
        offset = 12

        # 跳过查询部分
        for _ in range(qdcount):
            offset = self._skip_name(response, offset)
            offset += 4  # 跳过类型和类别

        # 解析答案记录
        for _ in range(ancount):
            name, offset = self._parse_name(response, offset)
            if offset + 10 > len(response):
                break

            rr_type, rr_class, ttl, rdlength = struct.unpack('!HHIH', response[offset:offset+10])
            offset += 10

            if offset + rdlength > len(response):
                break

            rdata = response[offset:offset+rdlength]
            offset += rdlength

            answer = {
                'name': name,
                'type': rr_type,
                'class': rr_class,
                'ttl': ttl,
                'data': self._parse_rdata(rr_type, rdata)
            }
            answers.append(answer)

        return {
            'query_id': query_id,
            'answers': answers,
            'error': False
        }

    def _skip_name(self, data, offset):
        """跳过域名（不解析）"""
        while offset < len(data):
            length = data[offset]
            if length == 0:
                return offset + 1
            elif (length & 0xC0) == 0xC0:  # 压缩指针
                return offset + 2
            else:
                offset += length + 1
        return offset

    def _parse_name(self, data, offset):
        """解析域名"""
        original_offset = offset
        name_parts = []
        jumped = False

        while offset < len(data):
            length = data[offset]

            if length == 0:
                if not jumped:
                    offset += 1
                break
            elif (length & 0xC0) == 0xC0:  # 压缩指针
                if not jumped:
                    offset += 2
                pointer = ((length & 0x3F) << 8) | data[offset + 1]
                offset = pointer
                jumped = True
            else:
                offset += 1
                if offset + length > len(data):
                    break
                part = data[offset:offset+length].decode('ascii', errors='ignore')
                name_parts.append(part)
                offset += length

        return '.'.join(name_parts), (offset if not jumped else original_offset + 2)

    def _parse_rdata(self, rr_type, rdata):
        """解析资源数据"""
        if rr_type == 1:  # A记录
            if len(rdata) == 4:
                return socket.inet_ntoa(rdata)
        elif rr_type == 28:  # AAAA记录
            if len(rdata) == 16:
                return socket.inet_ntop(socket.AF_INET6, rdata)
        elif rr_type == 5:  # CNAME记录
            # 简化处理，返回字节数据
            return rdata.hex()
        elif rr_type == 16:  # TXT记录
            try:
                if rdata and len(rdata) >= 1:
                    txt_len = rdata[0]
                    if txt_len <= len(rdata) - 1:
                        return rdata[1:1+txt_len].decode('utf-8', errors='ignore')
            except:
                pass
        return rdata.hex()

    def _get_error_message(self, rcode):
        """获取错误消息"""
        error_messages = {
            0: "No error",
            1: "Format error - The name server was unable to interpret the query",
            2: "Server failure - The name server was unable to process this query",
            3: "Name Error - The domain name does not exist",
            4: "Not Implemented - The name server does not support the requested kind of query",
            5: "Refused - The name server refuses to perform the specified operation"
        }
        return error_messages.get(rcode, f"Unknown error code: {rcode}")


def dns_query(domain, dns_server, timeout=5, qtype='A', use_socks5=False, socks5_host='127.0.0.1', socks5_port=1080):
    """执行DNS查询"""
    query = DNSQuery()
    query_packet = query.build_query(domain, qtype)

    # 创建UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)

    # 如果使用SOCKS5代理
    if use_socks5:
        sock = socks.socksocket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.set_proxy(socks.SOCKS5, socks5_host, socks5_port)

    try:
        # 发送查询
        start_time = time.time()
        sock.sendto(query_packet, (dns_server, 53))

        # 接收响应
        response, addr = sock.recvfrom(1024)
        end_time = time.time()

        # 解析响应
        result = query.parse_response(response)
        if result:
            result['server'] = dns_server
            result['domain'] = domain
            result['query_time'] = (end_time - start_time) * 1000  # 毫秒
            result['response_size'] = len(response)
            result['from_addr'] = addr[0]
            result['via_socks5'] = use_socks5

        return result

    except socket.timeout:
        return {
            'error': True,
            'error_msg': f"Timeout after {timeout} seconds",
            'server': dns_server,
            'domain': domain,
            'via_socks5': use_socks5
        }
    except Exception as e:
        return {
            'error': True,
            'error_msg': str(e),
            'server': dns_server,
            'domain': domain,
            'via_socks5': use_socks5
        }
    finally:
        sock.close()


def main():
    """主函数"""
    if len(sys.argv) < 2:
        print("用法: python dns_query.py <domain> [type] [--socks5]")
        print("示例: python dns_query.py www.baidu.com")
        print("      python dns_query.py www.baidu.com AAAA")
        print("      python dns_query.py www.google.com A --socks5")
        print("\n支持的记录类型: A, AAAA, MX, TXT")
        print("--socks5: 通过SOCKS5代理(127.0.0.1:1080)发送查询")
        sys.exit(1)

    domain = sys.argv[1]
    qtype = sys.argv[2] if len(sys.argv) > 2 and not sys.argv[2].startswith('--') else 'A'
    use_socks5 = '--socks5' in sys.argv

    # DNS服务器列表
    dns_servers = [
        ('119.29.29.29', 'DNSPod (中国)'),
        ('8.8.8.8', 'Google DNS')
    ]

    print(f"查询域名: {domain} (类型: {qtype})")
    if use_socks5:
        print("使用SOCKS5代理: 127.0.0.1:1080")
    print("-" * 80)

    for server_ip, server_name in dns_servers:
        print(f"\n查询服务器: {server_name} ({server_ip})")
        print("-" * 40)

        result = dns_query(domain, server_ip, qtype=qtype, use_socks5=use_socks5)

        if result.get('error'):
            print(f"错误: {result['error_msg']}")
        else:
            print(f"查询ID: {result['query_id']}")
            print(f"查询时间: {result['query_time']:.2f} ms")
            print(f"响应大小: {result['response_size']} bytes")
            print(f"响应来源: {result['from_addr']}")
            if result.get('via_socks5'):
                print("(通过SOCKS5代理)")

            if result['answers']:
                print("\n答案记录:")
                for i, ans in enumerate(result['answers'], 1):
                    print(f"  {i}. 名称: {ans['name']}")
                    print(f"     类型: {ans['type']}")
                    print(f"     TTL: {ans['ttl']} 秒")
                    print(f"     数据: {ans['data']}")
            else:
                print("未找到答案记录")

    print("\n" + "=" * 80)


if __name__ == '__main__':
    main()