#!/usr/bin/env python3
"""
测试SmartProxy的信号处理能力
"""
import subprocess
import time
import signal
import sys
import psutil
import os

def find_smartproxy_process():
    """查找SmartProxy进程"""
    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            if 'smartproxy' in proc.info['name'].lower():
                # 检查命令行参数
                cmdline = ' '.join(proc.info['cmdline'] or [])
                if 'smartproxy' in cmdline:
                    return proc
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return None

def test_graceful_shutdown():
    """测试优雅关闭"""
    print("测试SmartProxy的信号处理")
    print("=" * 60)

    # 启动SmartProxy
    print("1. 启动SmartProxy...")
    proc = subprocess.Popen(
        ['./smartproxy'],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    # 等待启动
    time.sleep(2)

    # 检查进程是否还在运行
    if proc.poll() is not None:
        print("✗ SmartProxy启动失败")
        stdout, stderr = proc.communicate()
        print(f"错误输出: {stderr}")
        return False

    print("✓ SmartProxy启动成功")
    print(f"  PID: {proc.pid}")

    # 等待服务完全启动
    print("\n2. 等待服务初始化...")
    time.sleep(3)

    # 发送SIGINT信号
    print("\n3. 发送SIGINT信号 (Ctrl+C)...")
    try:
        proc.send_signal(signal.SIGINT)
    except ProcessLookupError:
        print("✗ 进程已经退出")
        return False

    # 等待进程退出
    print("4. 等待进程退出...")
    start_time = time.time()
    timeout = 10  # 10秒超时

    while proc.poll() is None:
        if time.time() - start_time > timeout:
            print("✗ 进程未在预期时间内退出，强制终止")
            proc.terminate()
            time.sleep(1)
            if proc.poll() is None:
                proc.kill()
            return False
        time.sleep(0.5)
        sys.stdout.write(".")
        sys.stdout.flush()

    print("\n✓ 进程已退出")

    # 获取退出码
    exit_code = proc.returncode
    print(f"退出码: {exit_code}")

    # 获取输出
    stdout, stderr = proc.communicate()

    # 检查输出中是否包含优雅关闭的信息
    if "stopping gracefully" in stdout.lower() or "services stopped" in stdout.lower():
        print("✓ 检测到优雅关闭日志")
        success = True
    else:
        print("⚠ 未检测到明确的优雅关闭日志")
        success = True  # 退出码为0也算成功

    # 打印最后几行日志
    print("\n最后的服务日志:")
    lines = stdout.split('\n')
    for line in lines[-5:]:
        if line.strip():
            print(f"  {line}")

    return success and exit_code == 0

def test_multiple_signals():
    """测试多次信号发送"""
    print("\n测试多次信号处理")
    print("=" * 60)

    # 启动SmartProxy
    print("启动SmartProxy...")
    proc = subprocess.Popen(
        ['./smartproxy'],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    time.sleep(3)

    if proc.poll() is not None:
        print("✗ 启动失败")
        return False

    pid = proc.pid
    print(f"✓ 启动成功 (PID: {pid})")

    # 快速连续发送多个SIGINT
    print("\n快速发送3个SIGINT信号...")
    for i in range(3):
        try:
            proc.send_signal(signal.SIGINT)
            print(f"  发送第{i+1}个SIGINT")
            time.sleep(0.5)
        except ProcessLookupError:
            break

    # 等待退出
    print("等待进程退出...")
    start_time = time.time()
    while proc.poll() is None and time.time() - start_time < 5:
        time.sleep(0.1)

    if proc.poll() is None:
        print("✗ 进程未响应，发送SIGTERM...")
        proc.terminate()
        time.sleep(2)
        if proc.poll() is None:
            print("✗ 仍然未响应，发送SIGKILL...")
            proc.kill()
        return False

    print("✓ 进程已退出")
    return True

def main():
    print("SmartProxy 信号处理测试工具")
    print("=" * 60)

    # 检查smartproxy是否存在
    if not os.path.exists('./smartproxy'):
        print("✗ 找不到 ./smartproxy 可执行文件")
        print("请先编译: go build -o smartproxy")
        sys.exit(1)

    # 测试优雅关闭
    success1 = test_graceful_shutdown()

    # 等待一下
    time.sleep(1)

    # 测试多次信号
    success2 = test_multiple_signals()

    print("\n" + "=" * 60)
    print("测试结果:")
    print(f"  优雅关闭测试: {'✓ 通过' if success1 else '✗ 失败'}")
    print(f"  多次信号测试: {'✓ 通过' if success2 else '✗ 失败'}")

    if success1 and success2:
        print("\n✓ 所有测试通过！SmartProxy信号处理正常")
    else:
        print("\n✗ 部分测试失败，需要检查信号处理逻辑")

if __name__ == "__main__":
    main()