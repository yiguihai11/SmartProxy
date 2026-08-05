#!/usr/bin/env python3
"""
通过 SOCKS5 代理（127.0.0.1:1080）使用 UDP 查询 DNS（测试防污染）
依赖：pip install pysocks dnspython
"""

import sys
import socket

try:
    import socks
    import dns.message
except ImportError as e:
    print("请安装依赖：pip install pysocks dnspython")
    sys.exit(1)

# 配置（请根据需要修改）
PROXY_HOST = "127.0.0.1"
PROXY_PORT = 1080
DNS_SERVER = "114.114.114.114"   # 国内 DNS（可换成 1.1.1.1 测试国外）
DNS_PORT = 53
QUERY_DOMAIN = "v2ex.com"
QUERY_TYPE = "A"   # 或 AAAA

def main():
    print(f"通过 SOCKS5 代理 {PROXY_HOST}:{PROXY_PORT} 使用 UDP 查询 {QUERY_DOMAIN} ({QUERY_TYPE})")
    print(f"DNS 服务器: {DNS_SERVER}:{DNS_PORT} (UDP)\n")

    # 创建 UDP socket 并设置 SOCKS5 代理
    s = socks.socksocket(socket.AF_INET, socket.SOCK_DGRAM)
    s.set_proxy(socks.SOCKS5, PROXY_HOST, PROXY_PORT)
    s.settimeout(10)  # 响应超时

    # 对于 UDP，connect 并不建立真正的连接，而是设定默认目标地址
    s.connect((DNS_SERVER, DNS_PORT))

    # 构造 DNS 查询报文
    q = dns.message.make_query(QUERY_DOMAIN, QUERY_TYPE)
    wire = q.to_wire()

    # 发送查询
    s.send(wire)

    # 接收响应
    try:
        wire_response = s.recv(4096)
    except socket.timeout:
        print("请求超时，可能代理或 DNS 服务器无响应")
        sys.exit(1)

    # 解析响应
    response = dns.message.from_wire(wire_response)
    if response.answer:
        for answer in response.answer:
            print(f"=== {answer.name} ({answer.rdtype}) ===")
            for item in answer.items:
                print(item)
    else:
        print("未获得任何回答")

if __name__ == "__main__":
    main()