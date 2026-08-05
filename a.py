#!/usr/bin/env python3
"""
通过 SOCKS5 代理（127.0.0.1:1080）使用 UDP 查询NTP时间
新增并发多线程测试，默认并发5条请求
依赖：pip install pysocks
"""

import sys
import socket
import struct
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import socks
except ImportError as e:
    print("请安装依赖：pip install pysocks -i https://pypi.tuna.tsinghua.edu.cn/simple")
    sys.exit(1)

# 配置（请根据需要修改）
PROXY_HOST = "127.0.0.1"
PROXY_PORT = 1081
NTP_SERVER = "time.google.com"
NTP_PORT = 123
TIMEOUT = 10
THREAD_COUNT = 5  # 并发查询数量

def build_ntp_packet() -> bytes:
    """构造标准NTP v4 48字节请求包"""
    # LI=0, Version=4, Mode=3(客户端) → 0x1b
    header = struct.pack("!B", 0x1b)
    # 填充剩余47个0字节
    return header + b"\x00" * 47

def parse_ntp_timestamp(raw_data: bytes) -> float:
    """解析NTP返回包，转为Unix时间戳"""
    if len(raw_data) < 48:
        raise Exception("NTP返回数据包长度不足")
    # 提取传输时间戳（32~39字节）
    sec, frac = struct.unpack("!II", raw_data[32:40])
    # NTP基准1900-01-01，Unix基准1970-01-01，差值2208988800秒
    unix_ts = sec - 2208988800 + frac / (2 ** 32)
    return unix_ts

def single_ntp_query(task_id: int):
    """单线程NTP查询任务，每个线程独立创建Socket避免并发冲突"""
    print(f"[任务{task_id}] 发起NTP UDP请求至 {NTP_SERVER}:{NTP_PORT}")
    s = None
    try:
        # 每个任务独立创建SOCKS5 UDP socket
        s = socks.socksocket(socket.AF_INET, socket.SOCK_DGRAM)
        s.set_proxy(socks.SOCKS5, PROXY_HOST, PROXY_PORT, rdns=True)
        s.settimeout(TIMEOUT)

        s.connect((NTP_SERVER, NTP_PORT))
        ntp_req = build_ntp_packet()
        s.send(ntp_req)

        wire_response = s.recv(1024)
        unix_ts = parse_ntp_timestamp(wire_response)
        local_ts = time.time()
        time_offset = unix_ts - local_ts

        print(f"\n[任务{task_id}] === 查询成功 ===")
        print(f"NTP标准时间戳: {unix_ts:.6f}")
        print(f"本地系统时间戳: {local_ts:.6f}")
        print(f"时间偏移(服务器-本地): {time_offset:.3f} 秒")
        print(f"可读标准时间: {time.ctime(unix_ts)}\n")

    except socket.timeout:
        print(f"\n[任务{task_id}] ❌ 请求超时！")
        print("  1. SOCKS5代理未开启UDP Relay转发")
        print("  2. NTP服务器网络不通\n")
    except Exception as err:
        print(f"\n[任务{task_id}] ❌ 查询异常：{str(err)}\n")
    finally:
        if s is not None:
            s.close()

def main():
    print(f"通过 SOCKS5 代理 {PROXY_HOST}:{PROXY_PORT} UDP并发{THREAD_COUNT}线程查询NTP")
    print(f"NTP 服务器: {NTP_SERVER}:{NTP_PORT}\n")

    # 线程池并发执行
    with ThreadPoolExecutor(max_workers=THREAD_COUNT) as executor:
        futures = [executor.submit(single_ntp_query, task_id=i+1) for i in range(THREAD_COUNT)]
        # 等待所有任务完成
        for future in as_completed(futures):
            future.result()

    print("全部并发NTP查询任务执行完毕")

if __name__ == "__main__":
    main()
