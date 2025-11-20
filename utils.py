#!/usr/bin/env python3
"""
公共工具函数模块 - 统一管理重复的工具函数和常量
"""

import socket
import struct
import asyncio
import logging
import ipaddress
import os
import time
from typing import Optional, Tuple, Union, Dict, List, Any, Set

# 导入通用路由基数树
from route_trie import UniversalRouteTrie, RouteTrieStats, create_route_trie, load_routes_from_file

# ---------------------- 常量定义 ----------------------

# SOCKS5协议常量
SOCKS5_VERSION = 0x05
SOCKS5_AUTH_NONE = 0x00
SOCKS5_AUTH_GSSAPI = 0x01
SOCKS5_AUTH_USERPASS = 0x02
SOCKS5_AUTH_NO_ACCEPTABLE = 0xFF
SOCKS5_CMD_CONNECT = 0x01
SOCKS5_CMD_BIND = 0x02
SOCKS5_CMD_UDP_ASSOCIATE = 0x03
SOCKS5_ATYP_IPV4 = 0x01
SOCKS5_ATYP_DOMAIN = 0x03
SOCKS5_ATYP_IPV6 = 0x04
SOCKS5_REPLY_SUCCESS = 0x00
SOCKS5_REPLY_GENERAL_FAILURE = 0x01
SOCKS5_REPLY_CONNECTION_NOT_ALLOWED = 0x02
SOCKS5_REPLY_NETWORK_UNREACHABLE = 0x03
SOCKS5_REPLY_HOST_UNREACHABLE = 0x04
SOCKS5_REPLY_CONNECTION_REFUSED = 0x05
SOCKS5_REPLY_TTL_EXPIRED = 0x06
SOCKS5_REPLY_COMMAND_NOT_SUPPORTED = 0x07
SOCKS5_REPLY_ADDRESS_TYPE_NOT_SUPPORTED = 0x08

# TLS版本常量
TLS_VERSION_10 = 0x0301
TLS_VERSION_11 = 0x0302
TLS_VERSION_12 = 0x0303

# 默认端口常量
DEFAULT_HTTP_PORTS = {80, 8080, 8000, 8888}
DEFAULT_HTTPS_PORTS = {443, 8443}
SMART_DETECT_PORTS = DEFAULT_HTTP_PORTS | DEFAULT_HTTPS_PORTS

# ---------------------- IP地址处理工具 ----------------------

def parse_ipv4_address(data: bytes, offset: int = 0) -> str:
    """解析IPv4地址"""
    return socket.inet_ntoa(data[offset:offset+4])

def parse_ipv6_address(data: bytes, offset: int = 0) -> str:
    """解析IPv6地址"""
    ipv6_bytes = data[offset:offset+16]
    return socket.inet_ntop(socket.AF_INET6, ipv6_bytes)

def is_private_ip(ip: str) -> bool:
    """检查是否为私有IP地址"""
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private
    except ValueError:
        return False

def is_local_ip(ip: str) -> bool:
    """检查是否为本地IP地址"""
    return ip in ('127.0.0.1', '::1', '0.0.0.0')

# ---------------------- 域名解析工具 ----------------------

async def resolve_hostname(hostname: str, port: int = None, family: int = socket.AF_UNSPEC) -> List[Tuple]:
    """异步解析主机名"""
    try:
        loop = asyncio.get_event_loop()
        result = await loop.getaddrinfo(
            hostname, port,
            family=family,
            type=socket.SOCK_STREAM,
            flags=socket.AI_ADDRCONFIG
        )
        return result
    except (socket.gaierror, Exception) as e:
        logging.getLogger(__name__).error(f"❌ Failed to resolve {hostname}: {e}")
        return []

def resolve_hostname_sync(hostname: str, port: int = None, family: int = socket.AF_UNSPEC) -> List[Tuple]:
    """同步解析主机名"""
    try:
        return socket.getaddrinfo(hostname, port, family=family)
    except (socket.gaierror, Exception) as e:
        logging.getLogger(__name__).error(f"❌ Failed to resolve {hostname}: {e}")
        return []

# ---------------------- 数据处理工具 ----------------------

def pack_socks5_address(address: str, port: int) -> bytes:
    """打包SOCKS5地址格式"""
    try:
        # 尝试解析为IP地址
        ip_obj = ipaddress.ip_address(address)
        if ip_obj.version == 4:
            # IPv4
            return struct.pack('!B4sH', SOCKS5_ATYP_IPV4,
                             socket.inet_aton(address), port)
        else:
            # IPv6
            return struct.pack('!B16sH', SOCKS5_ATYP_IPV6,
                             socket.inet_pton(socket.AF_INET6, address), port)
    except ValueError:
        # 域名
        domain_bytes = address.encode('utf-8')
        return struct.pack(f'!B{len(domain_bytes)}sH',
                          SOCKS5_ATYP_DOMAIN, domain_bytes, port)

def unpack_socks5_address(data: bytes) -> Tuple[str, int]:
    """解包SOCKS5地址格式"""
    if not data:
        raise ValueError("Empty data")

    atyp = data[0]
    offset = 1

    if atyp == SOCKS5_ATYP_IPV4:
        if len(data) < offset + 6:
            raise ValueError("Invalid IPv4 address format")
        ip = parse_ipv4_address(data, offset)
        offset += 4
    elif atyp == SOCKS5_ATYP_DOMAIN:
        if len(data) < offset + 1:
            raise ValueError("Invalid domain address format")
        domain_len = data[offset]
        offset += 1
        if len(data) < offset + domain_len + 2:
            raise ValueError("Invalid domain address format")
        ip = data[offset:offset+domain_len].decode('utf-8')
        offset += domain_len
    elif atyp == SOCKS5_ATYP_IPV6:
        if len(data) < offset + 18:
            raise ValueError("Invalid IPv6 address format")
        ip = parse_ipv6_address(data, offset)
        offset += 16
    else:
        raise ValueError(f"Unknown address type: {atyp}")

    if len(data) < offset + 2:
        raise ValueError("Missing port information")

    port = struct.unpack('!H', data[offset:offset+2])[0]
    return ip, port

# ---------------------- 网络连接工具 ----------------------

async def create_connection_with_timeout(
    host: str,
    port: int,
    timeout: float = 10.0,
    source_address: Optional[Tuple[str, int]] = None
) -> Optional[socket.socket]:
    """创建带超时的TCP连接"""
    try:
        loop = asyncio.get_event_loop()
        sock = socket.socket(socket.AF_INET if ':' not in host else socket.AF_INET6)
        sock.settimeout(timeout)

        if source_address:
            sock.bind(source_address)

        await loop.sock_connect(sock, (host, port))
        return sock
    except Exception as e:
        logging.getLogger(__name__).error(f"❌ Failed to connect to {host}:{port}: {e}")
        if 'sock' in locals():
            sock.close()
        return None

# ---------------------- 错误处理装饰器 ----------------------

def log_errors(func):
    """错误处理装饰器，自动记录异常"""
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            logger = logging.getLogger(func.__module__)
            logger.error(f"❌ {func.__name__} failed: {e}")
            return None
    return wrapper

def log_async_errors(func):
    """异步错误处理装饰器"""
    async def wrapper(*args, **kwargs):
        try:
            return await func(*args, **kwargs)
        except Exception as e:
            logger = logging.getLogger(func.__module__)
            logger.error(f"❌ {func.__name__} failed: {e}")
            return None
    return wrapper

# ---------------------- 协议检测工具 ----------------------

def is_tls_handshake(data: bytes) -> bool:
    """检测是否为TLS握手包"""
    if len(data) < 3:
        return False
    return data[0] == 0x16  # TLS Handshake

def is_http_request(data: bytes) -> bool:
    """检测是否为HTTP请求"""
    if len(data) < 4:
        return False
    try:
        text_start = data[:4].decode('ascii').upper()
        return text_start.startswith(('GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ', 'OPTIONS '))
    except UnicodeDecodeError:
        return False

def get_port_protocol(port: int) -> str:
    """根据端口号判断可能的协议"""
    if port in DEFAULT_HTTP_PORTS:
        return 'HTTP'
    elif port in DEFAULT_HTTPS_PORTS:
        return 'HTTPS'
    else:
        return 'UNKNOWN'

# ---------------------- 缓冲区管理工具 ----------------------

class CircularBuffer:
    """循环缓冲区"""

    def __init__(self, size: int):
        self.size = size
        self.buffer = bytearray(size)
        self.start = 0
        self.end = 0
        self.count = 0

    def put(self, data: bytes) -> int:
        """添加数据到缓冲区"""
        data_len = len(data)
        available = self.size - self.count

        if data_len > available:
            # 覆盖旧数据
            overflow = data_len - available
            self.start = (self.start + overflow) % self.size
            self.count -= overflow

        for byte in data:
            self.buffer[self.end] = byte
            self.end = (self.end + 1) % self.size
            if self.count < self.size:
                self.count += 1

        return min(data_len, available)

    def get(self, size: int = None) -> bytes:
        """从缓冲区获取数据"""
        if self.count == 0:
            return b''

        if size is None or size > self.count:
            size = self.count

        result = bytearray()
        for _ in range(size):
            result.append(self.buffer[self.start])
            self.start = (self.start + 1) % self.size
            self.count -= 1

        return bytes(result)

    def peek(self, size: int = None) -> bytes:
        """查看数据但不移除"""
        if self.count == 0:
            return b''

        if size is None or size > self.count:
            size = self.count

        result = bytearray()
        pos = self.start
        for _ in range(size):
            result.append(self.buffer[pos])
            pos = (pos + 1) % self.size

        return bytes(result)

    def __len__(self) -> int:
        return self.count
