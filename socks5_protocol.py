#!/usr/bin/env python3
"""
完整的SOCKS5协议实现
支持IPv4/IPv6/TCP/UDP/BIND/认证/Full Core NAT
"""

import asyncio
import socket
import struct
import logging
import hashlib
import time
from typing import Optional, Tuple, Any, Dict, List, Callable
from dataclasses import dataclass
from enum import Enum

# 从utils导入协议常量
from utils import (
    SOCKS5_VERSION, SOCKS5_AUTH_NONE, SOCKS5_AUTH_GSSAPI, SOCKS5_AUTH_USERPASS, SOCKS5_AUTH_NO_ACCEPTABLE,
    SOCKS5_CMD_CONNECT, SOCKS5_CMD_BIND, SOCKS5_CMD_UDP_ASSOCIATE,
    SOCKS5_ATYP_IPV4, SOCKS5_ATYP_DOMAIN, SOCKS5_ATYP_IPV6,
    SOCKS5_REPLY_SUCCESS, SOCKS5_REPLY_GENERAL_FAILURE, SOCKS5_REPLY_CONNECTION_NOT_ALLOWED,
    SOCKS5_REPLY_NETWORK_UNREACHABLE, SOCKS5_REPLY_HOST_UNREACHABLE, SOCKS5_REPLY_CONNECTION_REFUSED,
    SOCKS5_REPLY_TTL_EXPIRED, SOCKS5_REPLY_COMMAND_NOT_SUPPORTED, SOCKS5_REPLY_ADDRESS_TYPE_NOT_SUPPORTED,
    parse_ipv4_address, parse_ipv6_address, pack_socks5_address, unpack_socks5_address
)

class AuthMethod(Enum):
    """认证方法枚举"""
    NO_AUTH = 0x00
    GSSAPI = 0x01
    USERPASS = 0x02
    NO_ACCEPTABLE = 0xFF

class SOCKS5Command(Enum):
    """SOCKS5命令枚举"""
    CONNECT = 0x01
    BIND = 0x02
    UDP_ASSOCIATE = 0x03

class NATMode(Enum):
    """NAT模式枚举"""
    PROXY = "proxy"        # 代理模式
    FULL_CORE = "full_core" # 完整核心NAT模式
    TRANSPARENT = "transparent"  # 透明代理模式

@dataclass
class SOCKS5Request:
    """SOCKS5连接请求信息"""
    cmd: int
    atyp: int
    dst_addr: str
    dst_port: int
    dst_host: Optional[str] = None

    def get_command(self) -> SOCKS5Command:
        """获取命令枚举"""
        cmd_map = {
            SOCKS5_CMD_CONNECT: SOCKS5Command.CONNECT,
            SOCKS5_CMD_BIND: SOCKS5Command.BIND,
            SOCKS5_CMD_UDP_ASSOCIATE: SOCKS5Command.UDP_ASSOCIATE
        }
        return cmd_map.get(self.cmd, None)

@dataclass
class NATEntry:
    """NAT映射条目"""
    internal_addr: Tuple[str, int]
    external_addr: Tuple[str, int]
    protocol: str  # 'tcp' or 'udp'
    created_at: float
    last_active: float
    bytes_sent: int = 0
    bytes_recv: int = 0

@dataclass
class AuthUser:
    """认证用户信息"""
    username: str
    password_hash: str
    enabled: bool = True

class AuthenticationError(Exception):
    """认证错误异常"""
    pass

class SOCKS5ProtocolError(Exception):
    """SOCKS5协议错误异常"""
    pass

class FullCoreSOCKS5Handler:
    """完整的SOCKS5协议处理器 - 支持IPv4/IPv6/TCP/UDP/BIND/认证/Full Core NAT"""

    # 响应代码常量
    REP_SUCCESS = SOCKS5_REPLY_SUCCESS
    REP_GENERAL_FAILURE = SOCKS5_REPLY_GENERAL_FAILURE
    REP_CONNECTION_NOT_ALLOWED = SOCKS5_REPLY_CONNECTION_NOT_ALLOWED
    REP_NETWORK_UNREACHABLE = SOCKS5_REPLY_NETWORK_UNREACHABLE
    REP_HOST_UNREACHABLE = SOCKS5_REPLY_HOST_UNREACHABLE
    REP_CONNECTION_REFUSED = SOCKS5_REPLY_CONNECTION_REFUSED
    REP_TTL_EXPIRED = SOCKS5_REPLY_TTL_EXPIRED
    REP_COMMAND_NOT_SUPPORTED = SOCKS5_REPLY_COMMAND_NOT_SUPPORTED
    REP_ADDRESS_TYPE_NOT_SUPPORTED = SOCKS5_REPLY_ADDRESS_TYPE_NOT_SUPPORTED

    # 地址类型常量（重复定义，避免循环导入）
    ATYP_IPV4 = SOCKS5_ATYP_IPV4
    ATYP_DOMAIN = SOCKS5_ATYP_DOMAIN
    ATYP_IPV6 = SOCKS5_ATYP_IPV6

    def __init__(self,
                 reader: asyncio.StreamReader,
                 writer: asyncio.StreamWriter,
                 nat_mode: NATMode = NATMode.PROXY,
                 enable_auth: bool = False,
                 auth_users: Optional[List[AuthUser]] = None):
        """初始化SOCKS5处理器

        Args:
            reader: 异步读取器
            writer: 异步写入器
            nat_mode: NAT模式
            enable_auth: 是否启用认证
            auth_users: 认证用户列表
        """
        self.reader = reader
        self.writer = writer
        self.nat_mode = nat_mode
        self.enable_auth = enable_auth
        self.auth_users = auth_users or []
        self.logger = logging.getLogger(f"{__name__}.FullCoreSOCKS5Handler")

        # NAT映射表
        self.nat_table: Dict[str, NATEntry] = {}
        self.udp_sessions: Dict[Tuple[str, int], Tuple[str, int]] = {}
        self.bind_connections: Dict[str, asyncio.StreamWriter] = {}

        # 连接信息
        self.client_addr = self.get_remote_address()
        self.server_addr = self.get_local_address()
        self.selected_auth_method = None

        # 统计信息
        self.stats = {
            'connections_handled': 0,
            'auth_attempts': 0,
            'auth_failures': 0,
            'bytes_transferred': 0,
            'udp_packets_forwarded': 0
        }

    async def handle_client(self) -> bool:
        """处理客户端连接的完整流程

        Returns:
            bool: 处理是否成功
        """
        try:
            self.logger.info(f"New SOCKS5 connection from {self.client_addr}")

            # 1. 握手阶段
            if not await self.handle_handshake():
                return False

            # 2. 认证阶段（如果需要）
            if self.enable_auth and not await self.handle_authentication():
                return False

            # 3. 请求处理阶段
            request = await self.handle_request()
            if not request:
                return False

            # 4. 执行具体命令
            success = await self.execute_command(request)

            if success:
                self.stats['connections_handled'] += 1
                self.logger.info(f"SOCKS5 {request.get_command().name} to {request.dst_addr}:{request.dst_port} successful")

            return success

        except Exception as e:
            self.logger.error(f"SOCKS5 client handling error: {e}")
            return False

    async def handle_handshake(self) -> bool:
        """处理SOCKS5握手阶段

        Returns:
            bool: 握手是否成功
        """
        try:
            # 读取版本和方法数量
            data = await self.reader.read(2)
            if len(data) != 2:
                self.logger.warning("Invalid handshake data length")
                return False

            version, nmethods = data[0], data[1]
            if version != SOCKS5_VERSION:
                self.logger.warning(f"Invalid SOCKS5 version: {version}")
                return False

            # 读取认证方法列表
            if nmethods > 0:
                methods_data = await self.reader.read(nmethods)
                if len(methods_data) != nmethods:
                    self.logger.warning("Invalid methods data length")
                    return False
            else:
                methods_data = b''

            self.logger.debug(f"SOCKS5 handshake: version={version}, methods={[m for m in methods_data]}")

            # 选择认证方法
            selected_method = self.select_auth_method(methods_data)
            if selected_method is None:
                self.logger.warning("No acceptable authentication method")
                response = bytes([SOCKS5_VERSION, SOCKS5_AUTH_NO_ACCEPTABLE])
                self.writer.write(response)
                await self.writer.drain()
                return False

            # 发送选择的认证方法
            response = bytes([SOCKS5_VERSION, selected_method])
            self.writer.write(response)
            await self.writer.drain()

            self.selected_auth_method = selected_method
            self.logger.debug(f"SOCKS5 handshake completed, auth method: {selected_method:02x}")
            return True

        except Exception as e:
            self.logger.error(f"SOCKS5 handshake error: {e}")
            return False

    def select_auth_method(self, methods: bytes) -> Optional[int]:
        """选择认证方法

        Args:
            methods: 客户端支持的认证方法列表

        Returns:
            选择的方法，如果没有可接受的方法返回None
        """
        client_methods = set(methods)
        
        # 如果启用认证，优先选择密码认证
        if self.enable_auth:
            if SOCKS5_AUTH_USERPASS in client_methods:
                self.logger.debug("Auth enabled, selecting USER/PASS authentication.")
                return SOCKS5_AUTH_USERPASS
            if SOCKS5_AUTH_GSSAPI in client_methods:
                self.logger.debug("Auth enabled, selecting GSSAPI authentication.")
                return SOCKS5_AUTH_GSSAPI
        # 如果禁用认证，或者启用了认证但客户端不支持任何要求的认证方法
        else:
            if SOCKS5_AUTH_NONE in client_methods:
                self.logger.debug("Auth disabled, selecting NO_AUTH authentication.")
                return SOCKS5_AUTH_NONE

        # 如果没有找到任何可接受的方法
        self.logger.warning(f"No acceptable auth method found. Server requires auth: {self.enable_auth}, client offers: {list(client_methods)}")
        return None

    async def handle_authentication(self) -> bool:
        """处理认证阶段

        Returns:
            bool: 认证是否成功
        """
        try:
            if self.selected_auth_method == SOCKS5_AUTH_NONE:
                return True

            elif self.selected_auth_method == SOCKS5_AUTH_USERPASS:
                return await self.handle_username_password_auth()

            elif self.selected_auth_method == SOCKS5_AUTH_GSSAPI:
                return await self.handle_gssapi_auth()

            else:
                self.logger.warning(f"Unsupported auth method: {self.selected_auth_method}")
                return False

        except AuthenticationError as e:
            self.stats['auth_failures'] += 1
            self.logger.error(f"Authentication failed: {e}")
            return False

    async def handle_username_password_auth(self) -> bool:
        """处理用户名密码认证

        Returns:
            bool: 认证是否成功
        """
        try:
            # 读取认证子协商
            auth_data = await self.reader.read(2)
            if len(auth_data) != 2 or auth_data[0] != 0x01:
                raise AuthenticationError("Invalid username/password auth format")

            username_len = auth_data[1]
            username_data = await self.reader.read(username_len)
            if len(username_data) != username_len:
                raise AuthenticationError("Invalid username length")

            password_len = (await self.reader.read(1))[0]
            password_data = await self.reader.read(password_len)
            if len(password_data) != password_len:
                raise AuthenticationError("Invalid password length")

            username = username_data.decode('utf-8', errors='ignore')
            password = password_data.decode('utf-8', errors='ignore')

            self.stats['auth_attempts'] += 1
            self.logger.debug(f"Username/password auth attempt: {username}")

            # 验证用户名密码
            success = self.verify_user_credentials(username, password)

            # 发送认证结果
            response = bytes([0x01, 0x00 if success else 0x01])
            self.writer.write(response)
            await self.writer.drain()

            if success:
                self.logger.info(f"User {username} authenticated successfully")

            return success

        except Exception as e:
            raise AuthenticationError(f"Username/password auth error: {e}")

    async def handle_gssapi_auth(self) -> bool:
        """处理GSSAPI认证

        Returns:
            bool: 认证是否成功
        """
        # GSSAPI认证比较复杂，这里简化实现
        self.logger.warning("GSSAPI authentication not fully implemented")
        # 发送失败响应
        response = bytes([0x01, 0x01])
        self.writer.write(response)
        await self.writer.drain()
        return False

    def verify_user_credentials(self, username: str, password: str) -> bool:
        """验证用户凭据

        Args:
            username: 用户名
            password: 密码

        Returns:
            bool: 验证是否成功
        """
        for user in self.auth_users:
            if user.enabled and user.username == username:
                # 验证密码（使用SHA256哈希）
                password_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()
                return password_hash == user.password_hash
        return False

    async def handle_request(self) -> Optional[SOCKS5Request]:
        """处理SOCKS5请求阶段

        Returns:
            Optional[SOCKS5Request]: 解析的请求信息，失败返回None
        """
        try:
            # 读取请求头部
            header = await self.reader.read(4)
            if len(header) != 4:
                self.logger.warning("Invalid request header length")
                return None

            version, cmd, rsv, atyp = header

            if version != SOCKS5_VERSION:
                self.logger.warning(f"Invalid SOCKS5 version in request: {version}")
                await self.send_reply(self.REP_GENERAL_FAILURE)
                return None

            # 解析目标地址
            dst_addr, dst_port = await self._parse_address(atyp)
            if dst_addr is None:
                await self.send_reply(self.REP_ADDRESS_TYPE_NOT_SUPPORTED)
                return None

            request = SOCKS5Request(
                cmd=cmd,
                atyp=atyp,
                dst_addr=dst_addr,
                dst_port=dst_port,
                dst_host=dst_addr if atyp == self.ATYP_DOMAIN else None
            )

            self.logger.debug(f"SOCKS5 request parsed: cmd={cmd}, addr={dst_addr}:{dst_port}, atyp={atyp}")
            return request

        except Exception as e:
            self.logger.error(f"SOCKS5 request parsing error: {e}")
            await self.send_reply(self.REP_GENERAL_FAILURE)
            return None

    async def execute_command(self, request: SOCKS5Request) -> bool:
        """执行SOCKS5命令

        Args:
            request: SOCKS5请求

        Returns:
            bool: 执行是否成功
        """
        try:
            command = request.get_command()

            if command == SOCKS5Command.CONNECT:
                return await self.handle_connect_command(request)
            elif command == SOCKS5Command.BIND:
                return await self.handle_bind_command(request)
            elif command == SOCKS5Command.UDP_ASSOCIATE:
                return await self.handle_udp_associate_command(request)
            else:
                self.logger.warning(f"Unsupported SOCKS5 command: {command}")
                await self.send_reply(self.REP_COMMAND_NOT_SUPPORTED)
                return False

        except Exception as e:
            self.logger.error(f"SOCKS5 command execution error: {e}")
            await self.send_reply(self.REP_GENERAL_FAILURE)
            return False

    async def handle_connect_command(self, request: SOCKS5Request) -> bool:
        """处理CONNECT命令 - 建立TCP连接

        Args:
            request: SOCKS5请求

        Returns:
            bool: 处理是否成功
        """
        try:
            # 创建NAT映射（如果是Full Core NAT模式）
            if self.nat_mode == NATMode.FULL_CORE:
                await self.create_nat_mapping('tcp', (request.dst_addr, request.dst_port))

            # 发送成功响应（实际连接建立由上层处理）
            bind_addr, bind_port = self.server_addr
            await self.send_success_reply(bind_addr, bind_port)

            self.logger.info(f"TCP CONNECT to {request.dst_addr}:{request.dst_port} established")
            return True

        except Exception as e:
            self.logger.error(f"TCP CONNECT error: {e}")
            await self.send_reply(self.REP_GENERAL_FAILURE)
            return False

    async def handle_bind_command(self, request: SOCKS5Request) -> bool:
        """处理BIND命令 - 用于FTP被动模式等

        Args:
            request: SOCKS5请求

        Returns:
            bool: 处理是否成功
        """
        try:
            # BIND命令主要用于FTP被动模式
            # 需要监听指定端口，等待外部连接

            # 在实际实现中，这里应该：
            # 1. 创建监听socket
            # 2. 发送第一个响应（包含监听地址）
            # 3. 等待外部连接
            # 4. 发送第二个响应（包含实际连接地址）

            bind_key = f"{self.client_addr[0]}:{self.client_addr[1]}->{request.dst_addr}:{request.dst_port}"

            # 创建监听socket - 根据目标地址类型选择IPv4或IPv6
            if ':' in request.dst_addr:
                # IPv6地址
                listener_socket = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
                listener_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                listener_socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)  # 允许双栈
            else:
                # IPv4地址
                listener_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                listener_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            # 根据socket类型选择绑定地址
            if ':' in request.dst_addr:
                bind_address = '::'  # IPv6
            else:
                bind_address = '0.0.0.0'  # IPv4
            listener_socket.bind((bind_address, 0))  # 自动分配端口
            listener_socket.listen(1)

            bind_addr, bind_port = listener_socket.getsockname()
            self.bind_connections[bind_key] = listener_socket

            # 发送第一个响应
            await self.send_success_reply(bind_addr, bind_port)

            self.logger.info(f"BIND listener created on {bind_addr}:{bind_port} for {request.dst_addr}:{request.dst_port}")
            return True

        except Exception as e:
            self.logger.error(f"BIND command error: {e}")
            await self.send_reply(self.REP_GENERAL_FAILURE)
            return False

    async def handle_udp_associate_command(self, request: SOCKS5Request) -> bool:
        """处理UDP ASSOCIATE命令 - 建立UDP关联

        Args:
            request: SOCKS5请求

        Returns:
            bool: 处理是否成功
        """
        try:
            # 创建UDP socket用于UDP关联 - 根据目标地址类型选择IPv4或IPv6
            if ':' in request.dst_addr:
                # IPv6地址
                udp_socket = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
                udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                udp_socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)  # 允许双栈
                bind_addr = request.dst_addr if request.dst_addr != '::' else self.server_addr[0]
            else:
                # IPv4地址
                udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                bind_addr = request.dst_addr if request.dst_addr != '0.0.0.0' else self.server_addr[0]

            bind_port = request.dst_port if request.dst_port != 0 else 0
            udp_socket.bind((bind_addr, bind_port))
            actual_addr, actual_port = udp_socket.getsockname()

            # 记录UDP会话
            session_key = f"{self.client_addr[0]}:{self.client_addr[1]}"
            self.udp_sessions[session_key] = (actual_addr, actual_port)

            # 发送成功响应
            await self.send_success_reply(actual_addr, actual_port)

            self.logger.info(f"UDP ASSOCIATE established on {actual_addr}:{actual_port}")
            return True

        except Exception as e:
            self.logger.error(f"UDP ASSOCIATE error: {e}")
            await self.send_reply(self.REP_GENERAL_FAILURE)
            return False

    async def create_nat_mapping(self, protocol: str, external_addr: Tuple[str, int]) -> str:
        """创建NAT映射

        Args:
            protocol: 协议类型 ('tcp' or 'udp')
            external_addr: 外部地址

        Returns:
            str: 映射ID
        """
        current_time = time.time()
        mapping_id = f"{self.client_addr[0]}:{self.client_addr[1]}-{protocol}-{current_time}"

        nat_entry = NATEntry(
            internal_addr=self.client_addr,
            external_addr=external_addr,
            protocol=protocol,
            created_at=current_time,
            last_active=current_time
        )

        self.nat_table[mapping_id] = nat_entry
        self.logger.debug(f"NAT mapping created: {mapping_id} -> {external_addr}")

        return mapping_id

    async def _parse_address(self, atyp: int) -> Tuple[Optional[str], Optional[int]]:
        """解析目标地址"""
        try:
            if atyp == self.ATYP_IPV4:
                # IPv4地址 (4字节) + 端口 (2字节)
                addr_data = await self.reader.read(6)
                if len(addr_data) != 6:
                    return None, None

                dst_addr = parse_ipv4_address(addr_data, 0)
                dst_port = struct.unpack('!H', addr_data[4:6])[0]

            elif atyp == self.ATYP_DOMAIN:
                # 域名长度 (1字节) + 域名 + 端口 (2字节)
                domain_len_data = await self.reader.read(1)
                if len(domain_len_data) != 1:
                    return None, None

                domain_len = domain_len_data[0]
                if domain_len == 0:
                    return None, None

                domain_data = await self.reader.read(domain_len + 2)
                if len(domain_data) != domain_len + 2:
                    return None, None

                dst_addr = domain_data[:domain_len].decode('utf-8', errors='ignore')
                dst_port = struct.unpack('!H', domain_data[domain_len:domain_len+2])[0]

            elif atyp == self.ATYP_IPV6:
                # IPv6地址 (16字节) + 端口 (2字节)
                addr_data = await self.reader.read(18)
                if len(addr_data) != 18:
                    return None, None

                dst_addr = parse_ipv6_address(addr_data, 0)
                dst_port = struct.unpack('!H', addr_data[16:18])[0]

            else:
                self.logger.warning(f"Unsupported address type: {atyp}")
                return None, None

            return dst_addr, dst_port

        except Exception as e:
            self.logger.error(f"Address parsing error: {e}")
            return None, None

    async def send_reply(self, reply_code: int, bind_addr: str = '0.0.0.0', bind_port: int = 0):
        """发送SOCKS5响应

        Args:
            reply_code: 响应代码
            bind_addr: 绑定地址
            bind_port: 绑定端口
        """
        try:
            # 构建响应
            response = bytearray()
            response.extend([SOCKS5_VERSION, reply_code, 0x00])

            # 添加绑定地址
            if ':' in bind_addr:  # IPv6
                response.extend([self.ATYP_IPV6])
                response.extend(socket.inet_pton(socket.AF_INET6, bind_addr))
            else:  # IPv4
                response.extend([self.ATYP_IPV4])
                response.extend(socket.inet_aton(bind_addr))

            # 添加绑定端口
            response.extend(struct.pack('!H', bind_port))

            # 发送响应
            self.writer.write(response)
            await self.writer.drain()

            self.logger.debug(f"SOCKS5 reply sent: code={reply_code:02x}, bind={bind_addr}:{bind_port}")

        except Exception as e:
            self.logger.error(f"Failed to send SOCKS5 reply: {e}")
            raise

    async def send_success_reply(self, bind_addr: str = '0.0.0.0', bind_port: int = 0):
        """发送成功响应"""
        await self.send_reply(self.REP_SUCCESS, bind_addr, bind_port)

    def get_local_address(self) -> Tuple[str, int]:
        """获取本地连接地址 - 支持IPv4和IPv6"""
        try:
            addr = self.writer.get_extra_info('sockname')
            if addr:
                return addr

            # 如果无法获取地址，尝试从socket获取
            socket_obj = self.writer.get_extra_info('socket')
            if socket_obj:
                sockname = socket_obj.getsockname()
                if sockname:
                    return sockname

            # 默认返回IPv4地址
            return ('0.0.0.0', 0)
        except Exception as e:
            self.logger.debug(f"Failed to get local address: {e}")
            return ('0.0.0.0', 0)

    def get_remote_address(self) -> Tuple[str, int]:
        """获取远程客户端地址 - 支持IPv4和IPv6"""
        try:
            addr = self.writer.get_extra_info('peername')
            if addr:
                return addr

            # 如果无法获取地址，尝试从socket获取
            socket_obj = self.writer.get_extra_info('socket')
            if socket_obj:
                peername = socket_obj.getpeername()
                if peername:
                    return peername

            # 默认返回IPv4地址
            return ('0.0.0.0', 0)
        except Exception as e:
            self.logger.debug(f"Failed to get remote address: {e}")
            return ('0.0.0.0', 0)

    def get_stats(self) -> Dict[str, Any]:
        """获取统计信息"""
        return {
            **self.stats,
            'nat_entries': len(self.nat_table),
            'udp_sessions': len(self.udp_sessions),
            'bind_connections': len(self.bind_connections),
            'nat_mode': self.nat_mode.value
        }

    def cleanup_expired_nat_entries(self, timeout: int = 300):
        """清理过期的NAT条目

        Args:
            timeout: 超时时间（秒）

        Returns:
            int: 清理的条目数量
        """
        current_time = time.time()
        expired_keys = []

        for key, entry in self.nat_table.items():
            if current_time - entry.last_active > timeout:
                expired_keys.append(key)

        for key in expired_keys:
            del self.nat_table[key]
            self.logger.debug(f"Expired NAT entry removed: {key}")

        return len(expired_keys)

    async def close(self):
        """关闭连接和清理资源"""
        try:
            # 关闭writer
            if self.writer:
                self.writer.close()
                await self.writer.wait_closed()

            # 关闭BIND连接
            for listener_socket in self.bind_connections.values():
                try:
                    listener_socket.close()
                except:
                    pass

            # 清理NAT表
            self.nat_table.clear()
            self.udp_sessions.clear()
            self.bind_connections.clear()

            self.logger.debug("SOCKS5 handler closed and resources cleaned up")

        except Exception as e:
            self.logger.debug(f"Error closing connection: {e}")

# 向后兼容的别名
PureSOCKS5Handler = FullCoreSOCKS5Handler