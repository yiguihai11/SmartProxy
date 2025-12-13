#!/usr/bin/env python3
"""
测试内存监控API的Python脚本
"""
import requests
import json
import time

BASE_URL = "http://localhost:8080"

def test_api():
    print("SmartProxy 内存监控 API 测试")
    print("=" * 50)

    # 测试各个API端点
    endpoints = [
        ("/api/memory/stats", "基本内存统计"),
        ("/api/memory/usage", "内存使用报告"),
        ("/api/memory/efficiency", "内存效率分析"),
        ("/api/memory/pools", "对象池统计"),
        ("/api/memory/history?limit=5", "内存历史记录(最近5条)")
    ]

    for endpoint, description in endpoints:
        url = BASE_URL + endpoint
        print(f"\n测试: {description}")
        print(f"URL: {url}")

        try:
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                data = response.json()
                if data.get('success'):
                    print(f"✓ 成功")
                    if 'data' in data:
                        print(f"  数据字段: {list(data['data'].keys()) if isinstance(data['data'], dict) else type(data['data']).__name__}")
                else:
                    print(f"✗ 失败: {data.get('error', '未知错误')}")
            else:
                print(f"✗ HTTP错误: {response.status_code}")
        except requests.exceptions.ConnectionError:
            print(f"✗ 连接失败 - 请确保SmartProxy正在运行在 {BASE_URL}")
        except Exception as e:
            print(f"✗ 错误: {str(e)}")

    print("\n" + "=" * 50)
    print("测试完成！")
    print("\n提示:")
    print("1. 如果看到连接失败，请先启动SmartProxy: ./smartproxy")
    print("2. 然后访问 http://localhost:8080/memory.html 查看内存监控界面")
    print("3. 或访问 http://localhost:8080/ 查看主管理界面")

if __name__ == "__main__":
    test_api()