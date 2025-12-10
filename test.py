# 完整依赖模块导入（无需额外安装，Python标准库）
import socket
import struct
import ssl
import ipaddress
import subprocess
import time
import os
import signal
import argparse

# ---------------------- 全局配置（可根据实际环境调整） ----------------------
# SmartProxy进程全局变量：供终止函数访问
smartproxy_process = None
# 核心配置项（根据实际路径/端口修改）
SMARTPROXY_EXE_REL_PATH = "./smartproxy"  # SmartProxy程序相对脚本的路径
SMARTPROXY_CONF_REL_PATH = "conf/config.json"  # SmartProxy配置文件相对路径
DEFAULT_SOCKS5_PORT = 1080                      # 默认SOCKS5监听端口（从config.json获取）
TEST_DOMAIN_DNS = "music.163.com"               # DNS测试目标域名
TCP_TEST_CONFIGS = [                             # TCP测试配置（可增删目标）
    {
        "target_domain": "cp.cloudflare.com",
        "target_ip": "104.16.133.229",
        "ports": [80, 443],
        "timeout": 3
    },
    {
        "target_domain": "wifi.vivo.com.cn",
        "target_ip": "112.90.223.30",
        "ports": [80, 443],
        "timeout": 3
    },
    {
        "target_domain": "t66y.com",
        "target_ip": "205.185.121.64",
        "ports": [80, 443],
        "timeout": 4
    }
]

# ---------------------- 核心：SmartProxy三步终止函数（2→15→9，脚本自主调用） ----------------------
def auto_terminate_smartproxy():
    """
    脚本自主终止SmartProxy进程，按优先级发送信号：
    1. SIGINT(2)：模拟Ctrl+C，让SmartProxy尝试优雅中断
    2. SIGTERM(15)：标准优雅终止信号（第一步失败后重试）
    3. SIGKILL(9)：强制终止兜底（前两步均失败）
    """
    global smartproxy_process
    # SmartProxy不存在或已退出，直接返回
    if not smartproxy_process or smartproxy_process.poll() is not None:
        return

    pid = smartproxy_process.pid
    print(f"\n=== 开始自动终止SmartProxy进程（PID：{pid}），信号顺序：2→15→9 ===")

    # 第一步：发送SIGINT（信号2）
    print(f"1. 发送 SIGINT(2) → SmartProxy（模拟Ctrl+C中断）...")
    os.kill(pid, signal.SIGINT)
    time.sleep(1)  # 等待1秒，给SmartProxy执行清理（如关闭连接、释放内存）
    if smartproxy_process.poll() is not None:
        print(f"✅ 成功：SmartProxy被 SIGINT(2) 终止（退出码：{smartproxy_process.returncode}）")
        return

    # 第二步：发送SIGTERM（信号15）（第一步失败后重试）
    print(f"2. SIGINT(2) 失败，发送 SIGTERM(15) → SmartProxy（优雅终止）...")
    os.kill(pid, signal.SIGTERM)
    time.sleep(1)
    if smartproxy_process.poll() is not None:
        print(f"✅ 成功：SmartProxy被 SIGTERM(15) 终止（退出码：{smartproxy_process.returncode}）")
        return

    # 第三步：发送SIGKILL（信号9）（兜底强制终止，不可抗拒）
    print(f"3. SIGTERM(15) 失败，发送 SIGKILL(9) → SmartProxy（强制终止）...")
    os.kill(pid, signal.SIGKILL)
    time.sleep(0.5)
    if smartproxy_process.poll() is not None:
        print(f"✅ 成功：SmartProxy被 SIGKILL(9) 强制终止（退出码：{smartproxy_process.returncode}）")
    else:
        print(f"❌ 异常：SIGKILL(9) 仍未终止，需手动执行 `kill -9 {pid}`")

# ---------------------- SmartProxy配置读取函数 ----------------------
def get_socks5_config(config_file_path):
    """读取SmartProxy配置文件，获取SOCKS5监听端口"""
    try:
        import json
        with open(config_file_path, 'r', encoding='utf-8') as f:
            config = json.load(f)

        # 获取SOCKS5端口
        socks5_port = config.get('listener', {}).get('socks5_port', DEFAULT_SOCKS5_PORT)
        print(f"✅ 读取配置成功：SOCKS5监听端口 = {socks5_port}")
        return socks5_port

    except FileNotFoundError:
        print(f"⚠️  配置文件不存在：{config_file_path}，使用默认端口 {DEFAULT_SOCKS5_PORT}")
        return DEFAULT_SOCKS5_PORT
    except json.JSONDecodeError:
        print(f"⚠️  配置文件格式错误，使用默认端口 {DEFAULT_SOCKS5_PORT}")
        return DEFAULT_SOCKS5_PORT
    except Exception as e:
        print(f"⚠️  读取配置文件失败：{str(e)}，使用默认端口 {DEFAULT_SOCKS5_PORT}")
        return DEFAULT_SOCKS5_PORT



def test_tcp_through_socks5(target_domain, target_ip, port, proxy_host, proxy_port, timeout):
    """通过SOCKS5代理进行TCP连接测试"""
    try:
        # 创建SOCKS5连接
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        # 连接到SOCKS5代理
        sock.connect((proxy_host, proxy_port))

        # SOCKS5握手
        auth_request = b"\x05\x01\x00"
        sock.send(auth_request)
        auth_response = sock.recv(2)
        if len(auth_response) != 2 or auth_response[0] != 0x05 or auth_response[1] != 0x00:
            return f"SOCKS5握手失败：响应异常 {auth_response.hex()}"

        # SOCKS5连接请求
        connect_request = b"\x05\x01\x00\x03"
        connect_request += bytes([len(target_ip)]) + target_ip.encode()
        connect_request += struct.pack(">H", port)
        sock.send(connect_request)

        connect_response = sock.recv(10)
        if len(connect_response) < 10 or connect_response[0] != 0x05 or connect_response[1] != 0x00:
            return f"SOCKS5连接失败：响应异常 {connect_response.hex()}"

        # 443端口启用SSL
        if port == 443:
            context = ssl.create_default_context()
            sock = context.wrap_socket(sock, server_hostname=target_domain)

        # 发送HTTP请求
        if target_domain == "t66y.com":
            path = "/"
        else:
            path = "/generate_204"
        http_request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {target_domain}\r\n"
            f"User-Agent: MAUI WAP Browser/1.0\r\n"
            f"Connection: close\r\n\r\n"
        ).encode("utf-8")
        sock.sendall(http_request)

        # 接收响应
        response_data = sock.recv(1024)
        if not response_data:
            return "代理TCP失败：连接成功但无响应数据"

        response = response_data.decode("utf-8", errors="ignore")
        status_line = response.splitlines()[0].strip()
        if not status_line:
            return "代理TCP失败：响应无状态行，格式异常"

        status_parts = status_line.split()
        if len(status_parts) < 2:
            return f"代理TCP失败：状态行无效（内容：{status_line}）"

        status_code = status_parts[1]
        if status_code in ("200", "204"):
            return f"代理TCP成功：HTTP状态码{status_code}（连接+请求正常）"
        else:
            return f"代理TCP失败：HTTP状态码{status_code}（非预期响应）"

    except Exception as e:
        return f"代理TCP测试失败：{str(e)}"
    finally:
        if 'sock' in locals():
            sock.close()

# ---------------------- DNS测试核心函数 ----------------------
def build_dns_query(domain):
    """构建DNS查询包（A记录，递归查询）"""
    tid = 0x1234  # 事务ID（随机即可）
    flags = 0x0100  # 递归查询标记（RD=1）
    # 头部：事务ID(2B) + 标志(2B) + 问题数(2B) + 回答数(2B) + 权威数(2B) + 附加数(2B)
    header = struct.pack(">HHHHHH", tid, flags, 1, 0, 0, 0)
    # 问题部分：域名（按点分割，每个段前加长度字节）+ 终止符(0x00)
    qname = b""
    for part in domain.split("."):
        qname += struct.pack("B", len(part)) + part.encode("utf-8")
    qname += b"\x00"
    # 查询类型（A记录=0x0001）+ 查询类（IN=0x0001）
    question = qname + struct.pack(">HH", 0x0001, 0x0001)
    return header + question

def _test_single_dns(dns_ip, dns_port, query, iface, timeout):
    """测试单个DNS服务器的响应能力"""
    try:
        # 自动适配IPv4/IPv6
        ip = ipaddress.ip_address(dns_ip)
        family = socket.AF_INET6 if ip.version == 6 else socket.AF_INET
        # 创建UDP套接字（DNS默认用UDP）
        sock = socket.socket(family, socket.SOCK_DGRAM)
        # 绑定指定网卡（需root权限）
        if iface:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, iface.encode())
        sock.settimeout(timeout)

        # 发送DNS查询
        sent_bytes = sock.sendto(query, (dns_ip, dns_port))
        if sent_bytes != len(query):
            return f"发送失败：预期{len(query)}字节，实际发送{sent_bytes}字节"
        
        # 接收响应
        response, addr = sock.recvfrom(1024)  # DNS响应通常不超过1024字节
        return f"成功：收到{len(response)}字节响应，前32位Hex：{response.hex()[:32]}..."

    except socket.timeout:
        return f"超时：{timeout}秒内未收到响应"
    except PermissionError:
        return f"权限不足：绑定网卡{iface}需用sudo运行脚本"
    except Exception as e:
        return f"测试失败：{str(e)}（如IP无效、端口不可达）"
    finally:
        # 确保套接字关闭（避免资源泄漏）
        if 'sock' in locals():
            sock.close()



def test_dns_servers_via_smartproxy(dns_host="127.0.0.1", dns_port=1053, timeout=3):
    """通过SmartProxy DNS服务测试不同的DNS解析策略"""
    print(f"\n=== SmartProxy DNS服务测试（目标域名：{TEST_DOMAIN_DNS}，SmartProxy DNS：{dns_host}:{dns_port}）===")
    print(f"注意：SmartProxy会自动选择最优DNS服务器和路由策略")
    print(f"包含：DNS污染检测、中国/外国DNS服务器选择、代理查询等完整功能")

    # 构建DNS查询包
    query = build_dns_query(TEST_DOMAIN_DNS)

    try:
        # 创建UDP套接字连接SmartProxy的DNS服务
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)

        # 发送DNS查询到SmartProxy的DNS服务
        print(f"\n通过SmartProxy DNS服务智能查询 {TEST_DOMAIN_DNS}...")
        sent_bytes = sock.sendto(query, (dns_host, dns_port))
        if sent_bytes != len(query):
            print(f"  ❌ 发送失败：预期{len(query)}字节，实际发送{sent_bytes}字节")
            return

        # 接收DNS响应
        response, addr = sock.recvfrom(1024)
        print(f"  ✅ SmartProxy智能DNS服务成功：收到{len(response)}字节响应")

        # 解析响应中的IP地址
        if len(response) >= 12:
            print(f"  📝 DNS响应详情：{response.hex()[:64]}...")

            # 简单解析A记录
            ips = []
            # 跳过DNS头部(12字节)
            answer_count = int.from_bytes(response[6:8], 'big')
            if answer_count > 0:
                offset = 12
                # 跳过查询部分
                while offset < len(response) and response[offset] != 0:
                    offset += 1
                offset += 5  # 跳过结尾和QTYPE/QCLASS

                # 解析回答部分
                for _ in range(min(answer_count, 5)):  # 最多解析5个记录
                    if offset + 12 > len(response):
                        break
                    if response[offset] == 0 and response[offset+1] == 1 and response[offset+2] == 0 and response[offset+3] == 1:
                        # A记录
                        ip_bytes = response[offset+12:offset+16]
                        if len(ip_bytes) == 4:
                            ip = ".".join(str(b) for b in ip_bytes)
                            ips.append(ip)
                    offset += 16

                if ips:
                    print(f"  🌐 解析到IP地址：{', '.join(ips)}")
                    # 检查IP归属
                    for ip in ips:
                        if any(ip.startswith(prefix) for prefix in ['112.', '39.', '119.', '223.', '183.', '202.', '58.', '61.', '125.', '180.']):
                            print(f"    🇨🇳 {ip} 可能是中国IP")
                        else:
                            print(f"    🌍 {ip} 可能是外国IP")

    except socket.timeout:
        print(f"  ❌ SmartProxy DNS服务超时：{timeout}秒内未收到响应")
    except Exception as e:
        print(f"  ❌ SmartProxy DNS服务测试失败：{str(e)}")
    finally:
        if 'sock' in locals():
            sock.close()


# ---------------------- TCP（含HTTPS）测试核心函数 ----------------------
def _test_single_tcp(target_domain, target_ip, port, iface, timeout):
    """测试单个TCP端口的连接+请求能力（443端口自动走SSL）"""
    try:
        # 自动适配IPv4/IPv6
        ip = ipaddress.ip_address(target_ip)
        family = socket.AF_INET6 if ip.version == 6 else socket.AF_INET
        # 创建TCP套接字
        sock = socket.socket(family, socket.SOCK_STREAM)
        # 绑定指定网卡（需root权限）
        if iface:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, iface.encode())
        sock.settimeout(timeout)

        # 连接目标IP:端口
        sock.connect((target_ip, port))
        # 443端口自动启用SSL/TLS（模拟HTTPS请求）
        if port == 443:
            context = ssl.create_default_context()  # 使用系统默认SSL配置
            sock = context.wrap_socket(sock, server_hostname=target_domain)  # 验证域名

        # 发送简单HTTP请求（用/generate_204端点，无返回体，适合测试）
        http_request = (
            f"GET /generate_204 HTTP/1.1\r\n"
            f"Host: {target_domain}\r\n"
            f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36\r\n"
            f"Accept: */*\r\n"
            f"Connection: close\r\n\r\n"
        ).encode("utf-8")
        sock.sendall(http_request)

        # 接收响应并解析状态码
        response_data = sock.recv(1024)
        if not response_data:
            return "失败：连接成功但无响应数据"
        
        # 解析HTTP状态码（忽略编码错误，兼容非UTF-8响应）
        response = response_data.decode("utf-8", errors="ignore")
        status_line = response.splitlines()[0].strip()  # 第一行是状态行（如HTTP/1.1 204 No Content）
        if not status_line:
            return "失败：响应无状态行，格式异常"
        
        status_parts = status_line.split()
        if len(status_parts) < 2:
            return f"失败：状态行无效（内容：{status_line}）"
        
        status_code = status_parts[1]
        if status_code in ("200", "204"):
            return f"成功：HTTP状态码{status_code}（连接+请求正常）"
        else:
            return f"失败：HTTP状态码{status_code}（非预期响应）"

    except ConnectionRefusedError:
        return "失败：连接被拒绝（目标端口未开放）"
    except ConnectionResetError:
        return "失败：连接被重置（可能被防火墙/ACL拦截）"
    except socket.timeout:
        return f"超时：{timeout}秒内未完成连接/接收响应"
    except ssl.SSLError as e:
        return f"SSL错误：{str(e)}（如证书无效、协议不兼容）"
    except PermissionError:
        return f"权限不足：绑定网卡{iface}需用sudo运行脚本"
    except Exception as e:
        return f"测试失败：{str(e)}（如IP不可达、网络中断）"
    finally:
        # 确保套接字关闭（避免资源泄漏）
        if 'sock' in locals():
            sock.close()

def test_tcp_servers_via_socks5(proxy_host, proxy_port):
    """通过SOCKS5代理批量测试所有配置的TCP目标"""
    print(f"\n=== TCP（含HTTPS）代理测试开始（代理：{proxy_host}:{proxy_port}）===")
    for config in TCP_TEST_CONFIGS:
        target_domain = config["target_domain"]
        target_ip = config["target_ip"]
        ports = config["ports"]
        timeout = config["timeout"]

        print(f"\n测试目标：{target_domain}（{target_ip}）")
        for port in ports:
            print(f"\n  端口 {port} 通过代理...")
            result = test_tcp_through_socks5(target_domain, target_ip, port, proxy_host, proxy_port, timeout)
            print(f"    {'✅' if '成功' in result else '❌'} {result}")

# ---------------------- 主逻辑（启动SmartProxy→执行代理测试→终止SmartProxy） ----------------------
def run_test_workflow(socks5_port=DEFAULT_SOCKS5_PORT, start_smartproxy=True):
    global smartproxy_process
    # 获取脚本所在目录（确保SmartProxy程序路径正确，不受运行目录影响）
    script_dir = os.path.dirname(os.path.abspath(__file__))
    smartproxy_exe = os.path.join(script_dir, SMARTPROXY_EXE_REL_PATH)
    smartproxy_conf = os.path.join(script_dir, SMARTPROXY_CONF_REL_PATH)

    try:
        # 第一步：启动SmartProxy（仅当参数允许且程序存在）
        if start_smartproxy:
            # 检查SmartProxy程序是否存在
            if not os.path.exists(smartproxy_exe):
                raise FileNotFoundError(f"SmartProxy程序不存在：{smartproxy_exe}（请检查SMARTPROXY_EXE_REL_PATH配置）")
            # 启动SmartProxy进程（stdout/stderr重定向，便于后续查看输出）
            print(f"=== 启动 SmartProxy（配置：{smartproxy_conf}，监听端口：{socks5_port}）===")
            smartproxy_process = subprocess.Popen(
                args=[smartproxy_exe],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,  # 合并stderr到stdout，统一读取
                text=True,                 # 输出按字符串处理（而非字节）
                cwd=script_dir             # 以脚本目录为工作目录
            )
            # 等待2秒，确保SmartProxy进程启动完成（避免测试时服务未就绪）
            time.sleep(2)
            # 检查SmartProxy启动状态
            if smartproxy_process.poll() is not None:
                raise RuntimeError(f"SmartProxy启动失败（退出码：{smartproxy_process.returncode}），请检查配置文件")
            print(f"✅ SmartProxy启动成功（PID：{smartproxy_process.pid}，状态：存活）")

        # 第二步：通过SOCKS5代理执行网络测试（DNS + TCP）
        proxy_host = "127.0.0.1"  # 本地代理
        proxy_port = socks5_port

        print(f"\n=== 开始通过SmartProxy进行网络测试（{proxy_host}:{proxy_port}）===")
        test_dns_servers_via_smartproxy()  # 测试SmartProxy智能DNS服务(1053端口)
        test_tcp_servers_via_socks5(proxy_host, proxy_port)

        # 第三步：测试完成后，主动终止SmartProxy（核心逻辑）
        if start_smartproxy:
            auto_terminate_smartproxy()

    except Exception as e:
        # 测试/启动过程中出现异常，立即终止SmartProxy（避免残留）
        print(f"\n⚠️  工作流异常中断：{str(e)}")
        if start_smartproxy:
            print("立即终止SmartProxy进程...")
            auto_terminate_smartproxy()
        raise  # 保留异常抛出（便于用户排查问题，注释则不抛出）

    finally:
        # 双重兜底：确保SmartProxy完全退出（极端情况三步终止失败时补充）
        if start_smartproxy and smartproxy_process:
            if smartproxy_process.poll() is not None:
                print(f"\n=== 最终检查：SmartProxy已退出（退出码：{smartproxy_process.returncode}）===")
            else:
                print(f"\n=== 紧急兜底：SmartProxy仍存活，强制发送 SIGKILL(9) ===")
                os.kill(smartproxy_process.pid, signal.SIGKILL)
                print(f"✅ 兜底强制终止完成（PID：{smartproxy_process.pid}）")
        else:
            print(f"\n=== 未启动SmartProxy，无需终止 ===")

        # 读取并打印SmartProxy运行日志（若有）
        if start_smartproxy and smartproxy_process:
            smartproxy_log = smartproxy_process.stdout.read()
            if smartproxy_log:
                print(f"\n=== SmartProxy运行日志 ===")
                print(smartproxy_log)
            else:
                print(f"\n=== SmartProxy无额外运行日志 ===")

# ---------------------- 命令行参数解析+程序入口 ----------------------
if __name__ == "__main__":
    # 创建参数解析器（支持--no-start-smartproxy跳过SmartProxy启动）
    parser = argparse.ArgumentParser(
        description="SmartProxy网络测试脚本（自动启动SmartProxy+SOCKS5代理DNS/TCP测试，按2→15→9终止）",
        formatter_class=argparse.RawTextHelpFormatter  # 保留帮助信息换行
    )
    # 添加参数：--no-start-smartproxy（无需传值，添加则跳过SmartProxy启动）
    parser.add_argument(
        "--no-start-smartproxy",
        action="store_true",
        help="仅执行DNS和TCP测试，不启动SmartProxy\n"
             "（示例：python3 test.py --no-start-smartproxy）"
    )
    # 添加参数：--port（指定SOCKS5端口，默认从配置读取）
    parser.add_argument(
        "--port",
        type=int,
        help=f"指定SmartProxy的SOCKS5端口（默认从{SMARTPROXY_CONF_REL_PATH}读取）\n"
             "（示例：python3 test.py --port 1090）"
    )
    # 解析命令行参数
    args = parser.parse_args()

    # 获取SOCKS5端口
    if args.port:
        socks5_port = args.port
        print(f"使用命令行指定端口：{socks5_port}")
    else:
        # 从配置文件读取端口
        script_dir = os.path.dirname(os.path.abspath(__file__))
        config_file = os.path.join(script_dir, SMARTPROXY_CONF_REL_PATH)
        socks5_port = get_socks5_config(config_file)

    # 执行主工作流（根据参数控制是否启动SmartProxy）
    run_test_workflow(
        socks5_port=socks5_port,
        start_smartproxy=not args.no_start_smartproxy  # --no-start-smartproxy为True则不启动
    )
