#!/usr/bin/env python3
"""
UDP中继协议处理器
处理SOCKS5 UDP ASSOCIATE数据包转发
"""

import asyncio
import socket
import struct
import logging
from typing import Optional, Tuple, Dict
from dataclasses import dataclass

# 导入公共工具函数
from utils import (
    parse_ipv4_address, unpack_socks5_address, pack_socks5_address,
    SOCKS5_ATYP_IPV4, SOCKS5_ATYP_DOMAIN, SOCKS5_ATYP_IPV6,
    resolve_hostname_sync
)

@dataclass
class UDPDatagram:
    """UDP数据包"""
    data: bytes
    src_addr: Tuple[str, int]
    dst_addr: Tuple[str, int]

class UDPRelayProtocol(asyncio.DatagramProtocol):
    """UDP中继协议"""

    def __init__(self, socks5_handler, use_proxy: bool = False):
        self.socks5_handler = socks5_handler
        self.use_proxy = use_proxy  # 是否使用代理模式
        self.logger = logging.getLogger(f"{__name__}.UDPRelayProtocol")

        # UDP连接映射: 客户端地址 -> 目标地址
        self.connections: Dict[Tuple[str, int], Tuple[str, int]] = {}

        # UDP socket池用于直连模式
        self.udp_sockets: Dict[Tuple[str, int], socket.socket] = {}

        # 目标服务器socket映射: 目标地址 -> socket
        self.target_sockets: Dict[Tuple[str, int], socket.socket] = {}

        self.transport = None

    def connection_made(self, transport):
        """UDP连接建立"""
        self.transport = transport
        self.logger.info("UDP relay protocol ready")

    def datagram_received(self, data: bytes, src_addr: Tuple[str, int]):
        """收到UDP数据包"""
        try:
            self.logger.debug(f"Received UDP datagram from {src_addr}: {len(data)} bytes")

            # 解析SOCKS5 UDP数据包格式
            if len(data) < 10:  # 最小SOCKS5 UDP包头长度
                self.logger.warning(f"UDP packet too short: {len(data)} bytes")
                return

            # 解析SOCKS5 UDP包头
            # RSV(2) + FRAG(1) + ATYP(1) + DST.ADDR + DST.PORT + DATA
            rsv = data[0:2]
            frag = data[2]
            atyp = data[3]

            if frag != 0:
                self.logger.warning(f"Fragmented UDP packets not supported: frag={frag}")
                return

            if atyp == 0x01:  # IPv4
                if len(data) < 10:
                    return
                dst_ip = parse_ipv4_address(data, 4)
                dst_port = struct.unpack('!H', data[8:10])[0]
                payload = data[10:]
            elif atyp == 0x03:  # 域名
                domain_len = data[4]
                if len(data) < 7 + domain_len:
                    return
                domain = data[5:5+domain_len].decode('utf-8', errors='ignore')
                dst_port = struct.unpack('!H', data[5+domain_len:7+domain_len])[0]
                # 解析域名到IP
                try:
                    ip_info = resolve_hostname_sync(domain)
                    if ip_info:
                        dst_ip = ip_info[0][4][0]
                    else:
                        dst_ip = domain
                except:
                    dst_ip = domain
                payload = data[7+domain_len:]
            else:
                self.logger.warning(f"Unsupported address type: {atyp}")
                return

            self.logger.info(f"UDP packet: {src_addr} -> {dst_ip}:{dst_port} ({len(payload)} bytes)")

            # UDP流量跳过SNI分析，避免性能影响
            # SNI分析只适用于TCP流量，UDP/QUIC的SNI处理开销较大且收益有限
            # if dst_port in [443, 8443]:  # HTTPS端口
            #     self._analyze_udp_for_sni(payload, dst_ip, dst_port)

            # 建立或更新连接映射
            self.connections[src_addr] = (dst_ip, dst_port)

            # 转发数据到目标
            self._forward_to_target(payload, dst_ip, dst_port, src_addr)

        except Exception as e:
            self.logger.error(f"Error processing UDP datagram: {e}")

    def _analyze_udp_for_sni(self, payload: bytes, dst_ip: str, dst_port: int):
        """分析UDP数据包中的SNI信息 - 已禁用，UDP跳过SNI分析以提高性能"""
        # SNI分析只适用于TCP流量
        # UDP/QUIC的SNI处理开销较大且收益有限
        # 如果将来需要QUIC SNI分析，建议在专门的QUIC解析器中实现
        pass

    def _forward_to_target(self, payload: bytes, dst_ip: str, dst_port: int, src_addr: Tuple[str, int]):
        """转发数据到目标服务器（支持直连和代理模式）"""
        try:
            if self.use_proxy:
                # 🌐 代理模式：通过SOCKS5代理转发
                self._forward_via_proxy(payload, dst_ip, dst_port, src_addr)
            else:
                # 🔓 直连模式：直接连接目标服务器
                self._forward_direct(payload, dst_ip, dst_port, src_addr)

        except Exception as e:
            mode = "PROXY" if self.use_proxy else "DIRECT"
            self.logger.error(f"Error forwarding via {mode} to {dst_ip}:{dst_port}: {e}")

    def _forward_direct(self, payload: bytes, dst_ip: str, dst_port: int, src_addr: Tuple[str, int]):
        """直连模式：直接转发数据到目标服务器"""
        target_key = (dst_ip, dst_port)

        # 检查是否已有到目标的socket
        if target_key not in self.target_sockets:
            # 创建新的UDP socket到目标
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(5.0)
            sock.connect((dst_ip, dst_port))
            self.target_sockets[target_key] = sock
            self.logger.info(f"🔓 Created direct UDP socket to {dst_ip}:{dst_port}")

        # 发送数据
        target_socket = self.target_sockets[target_key]
        target_socket.send(payload)

        # 启动数据接收任务
        asyncio.create_task(self._receive_from_target(target_key, src_addr))

    def _forward_via_proxy(self, payload: bytes, dst_ip: str, dst_port: int, src_addr: Tuple[str, int]):
        """代理模式：通过SOCKS5代理转发数据"""
        # 构建SOCKS5 UDP转发包
        # 格式: RSV(2) + FRAG(1) + ATYP(1) + DST.ADDR + DST.PORT + DATA

        udp_packet = bytearray()
        udp_packet.extend([0x00, 0x00])  # RSV
        udp_packet.extend([0x00])        # FRAG (0 = 无分片)
        udp_packet.extend([0x01])        # ATYP (1 = IPv4)

        try:
            # 目标IP地址
            dst_ip_bytes = socket.inet_aton(dst_ip)
        except socket.error:
            # 如果是域名，先解析到IP
            ip_info = resolve_hostname_sync(dst_ip)
            if ip_info:
                dst_ip_bytes = socket.inet_aton(ip_info[0][4][0])
            else:
                self.logger.error(f"Cannot resolve domain: {dst_ip}")
                return

        udp_packet.extend(dst_ip_bytes)
        udp_packet.extend(struct.pack('!H', dst_port))  # 目标端口
        udp_packet.extend(payload)  # 实际数据

        # 通过代理转发
        try:
            if hasattr(self.socks5_handler, 'udp_transport') and self.socks5_handler.udp_transport:
                # 通过已建立的UDP代理连接转发
                proxy_addr = ('127.0.0.1', self.socks5_handler.selected_proxy.port)
                self.socks5_handler.udp_transport.sendto(bytes(udp_packet), proxy_addr)
                self.logger.debug(f"🌐 Forwarded UDP packet via proxy to {dst_ip}:{dst_port}")
            else:
                self.logger.error("No UDP proxy connection available")
        except Exception as e:
            self.logger.error(f"Failed to forward via proxy: {e}")

    async def _receive_from_target(self, target_key: Tuple[str, int], client_addr: Tuple[str, int]):
        """从目标服务器接收数据"""
        try:
            target_socket = self.target_sockets[target_key]

            # 等待响应
            try:
                # 使用asyncio的线程池来执行阻塞的socket操作
                loop = asyncio.get_event_loop()
                data = await loop.run_in_executor(None, target_socket.recv, 4096)

                if data:
                    self.logger.debug(f"Received UDP response from {target_key}: {len(data)} bytes")

                    # 构建SOCKS5 UDP响应包
                    response = self._build_udp_response(data, target_key)

                    # 发送回客户端
                    if self.transport:
                        self.transport.sendto(response, client_addr)

            except socket.timeout:
                self.logger.debug(f"Timeout waiting for response from {target_key}")
            except Exception as e:
                self.logger.debug(f"Error receiving from {target_key}: {e}")

        except Exception as e:
            self.logger.error(f"UDP receive error: {e}")

    def _build_udp_response(self, data: bytes, target_key: Tuple[str, int]) -> bytes:
        """构建SOCKS5 UDP响应包"""
        try:
            dst_ip, dst_port = target_key

            # 构建响应包头
            response = bytearray()
            response.extend([0x00, 0x00])  # RSV
            response.extend([0x00])          # FRAG
            response.extend([0x01])          # ATYP = IPv4

            # 目标地址
            response.extend(socket.inet_aton(dst_ip))
            response.extend(struct.pack('!H', dst_port))

            # 数据部分
            response.extend(data)

            return bytes(response)

        except Exception as e:
            self.logger.error(f"Error building UDP response: {e}")
            return data  # 备用：直接返回原数据

    def error_received(self, exc):
        """UDP错误处理"""
        self.logger.error(f"UDP error: {exc}")

    def connection_lost(self, exc):
        """UDP连接丢失"""
        self.logger.info(f"UDP connection lost: {exc}")

    def cleanup(self):
        """清理资源"""
        try:
            # 关闭所有目标socket
            for sock in self.target_sockets.values():
                try:
                    sock.close()
                except:
                    pass

            self.target_sockets.clear()
            self.connections.clear()

            if self.transport:
                self.transport.close()

        except Exception as e:
            self.logger.error(f"Error during cleanup: {e}")