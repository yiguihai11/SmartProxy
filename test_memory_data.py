#!/usr/bin/env python3
"""
测试内存监控API返回的实际数据
"""
import requests
import json

BASE_URL = "http://localhost:8080"

def test_memory_data():
    print("测试内存监控API返回的实际数据")
    print("=" * 50)

    # 测试基本内存统计
    url = BASE_URL + "/api/memory/stats"
    print(f"\n请求: {url}")

    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            data = response.json()
            if data.get('success'):
                print("✓ 成功获取数据")
                print("返回的数据:")
                print(json.dumps(data, indent=2))

                # 检查是否有实际数据
                stats = data.get('data', {})
                if stats.get('alloc', 0) > 0:
                    print("\n✓ 检测到实际内存数据!")
                    print(f"  已分配内存: {stats.get('alloc', 0)} bytes")
                    print(f"  GC次数: {stats.get('num_gc', 0)}")
                    print(f"  活跃连接: {stats.get('active_connections', 0)}")
                else:
                    print("\n⚠️  数据似乎为空或默认值")
                    print("可能原因:")
                    print("1. SmartProxy刚启动，还未收集数据")
                    print("2. 内存监控器未正确初始化")
                    print("3. 当前没有活跃连接")
            else:
                print(f"✗ API返回失败: {data.get('error')}")
        else:
            print(f"✗ HTTP错误: {response.status_code}")
    except Exception as e:
        print(f"✗ 错误: {str(e)}")

if __name__ == "__main__":
    test_memory_data()