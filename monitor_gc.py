#!/usr/bin/env python3
"""
监控GC变化
"""
import requests
import time

BASE_URL = "http://localhost:8080"

def monitor_gc():
    print("监控SmartProxy GC变化...")
    print("按 Ctrl+C 停止监控")
    print("=" * 50)

    last_gc_count = 0

    try:
        while True:
            response = requests.get(f"{BASE_URL}/api/memory/stats", timeout=5)
            if response.status_code == 200:
                data = response.json()
                if data.get('success'):
                    stats = data.get('data', {})
                    gc_count = stats.get('num_gc', 0)
                    alloc_mb = stats.get('alloc', 0) / 1024 / 1024

                    if gc_count != last_gc_count:
                        print(f"[{time.strftime('%H:%M:%S')}] GC运行次数: {gc_count} (+{gc_count - last_gc_count}) | 内存: {alloc_mb:.2f}MB")
                        last_gc_count = gc_count
                    else:
                        print(f"[{time.strftime('%H:%M:%S')}] GC次数: {gc_count} | 内存: {alloc_mb:.2f}MB", end='\r')

            time.sleep(5)  # 每5秒检查一次

    except KeyboardInterrupt:
        print("\n监控停止")
    except Exception as e:
        print(f"错误: {e}")

if __name__ == "__main__":
    monitor_gc()