#!/usr/bin/env python3
"""
SNI感知的数据转发模块
支持在检测到SNI后进行代理节点切换
"""

import asyncio
import logging
import time
from typing import Optional, Tuple, Any

class SNIAwareRelay:
    """SNI感知的数据转发器"""

    def __init__(self, socks5_handler, target_ip: str, target_port: int):
        self.socks5_handler = socks5_handler
        self.target_ip = target_ip
        self.target_port = target_port
        self.logger = logging.getLogger(f"{__name__}.SNIAwareRelay")

        self.initial_proxy = None
        self.current_proxy = None
        self.relayed_data = False  # 是否已经转发了数据
        self.sni_checked = False  # 是否已经进行了SNI检测

    async def connect_with_sni_detection(self) -> bool:
        """
        建立连接并进行SNI检测

        Returns:
            bool: 连接是否成功
        """
        try:
            # 1. 选择初始代理节点
            traffic_info = self.socks5_handler.traffic_info
            self.initial_proxy = self.socks5_handler.config.proxy_selector.select_proxy(traffic_info)
            self.current_proxy = self.initial_proxy

            if not self.initial_proxy:
                self.logger.error("No proxy node available for connection")
                return False

            self.logger.info(f"🎯 Initial proxy selected: {self.initial_proxy.identifier}")

            # 2. 建立到初始代理的连接
            success = await self._connect_to_proxy(self.initial_proxy)
            if not success:
                return False

            # 3. 发送SOCKS5连接请求到目标
            success = await self._send_socks5_connect()
            if not success:
                return False

            return True

        except Exception as e:
            self.logger.error(f"Error in SNI-aware connection: {e}")
            return False

    async def _connect_to_proxy(self, proxy_node: Any) -> bool:
        """连接到代理服务器"""
        try:
            from utils import SOCKS5_VERSION, SOCKS5_AUTH_NONE

            reader, writer = await asyncio.open_connection(
                proxy_node.ip,
                proxy_node.port
            )

            # SOCKS5握手
            writer.write(bytes([SOCKS5_VERSION, 1, SOCKS5_AUTH_NONE]))
            await writer.drain()

            response = await reader.read(2)
            if len(response) != 2 or response[0] != SOCKS5_VERSION or response[1] != SOCKS5_AUTH_NONE:
                self.logger.error(f"Proxy authentication failed: {proxy_node.identifier}")
                writer.close()
                await writer.wait_closed()
                return False

            self.upstream_reader = reader
            self.upstream_writer = writer

            self.logger.info(f"Connected to proxy {proxy_node.identifier}")
            return True

        except Exception as e:
            self.logger.error(f"Proxy connection error: {e}")
            return False

    async def _send_socks5_connect(self) -> bool:
        """发送SOCKS5 CONNECT请求"""
        try:
            from utils import (
                SOCKS5_VERSION, SOCKS5_CMD_CONNECT, SOCKS5_ATYP_IPV4, SOCKS5_ATYP_IPV6,
                SOCKS5_REPLY_SUCCESS
            )
            import socket
            import struct

            # 构建SOCKS5连接请求
            if ':' in self.target_ip:  # IPv6
                atyp = SOCKS5_ATYP_IPV6
                addr_bytes = socket.inet_pton(socket.AF_INET6, self.target_ip)
            else:  # IPv4
                atyp = SOCKS5_ATYP_IPV4
                addr_bytes = socket.inet_aton(self.target_ip)

            connect_req = bytes([SOCKS5_VERSION, SOCKS5_CMD_CONNECT, 0x00, atyp]) + \
                         addr_bytes + struct.pack('!H', self.target_port)

            self.upstream_writer.write(connect_req)
            await self.upstream_writer.drain()

            # 读取连接响应
            response = await self.upstream_reader.read(10)
            if len(response) < 4 or response[0] != SOCKS5_VERSION or response[1] != SOCKS5_REPLY_SUCCESS:
                self.logger.error(f"Proxy connection failed: {self.current_proxy.identifier}")
                return False

            return True

        except Exception as e:
            self.logger.error(f"SOCKS5 CONNECT error: {e}")
            return False

    async def relay_data_with_sni_check(self, client_data: bytes) -> bool:
        """
        转发客户端数据并进行SNI检测

        Args:
            client_data: 客户端发送的数据

        Returns:
            bool: 转发是否成功
        """
        try:
            # SNI检测（只对第一个数据包进行一次）
            if not self.sni_checked and not self.relayed_data:
                await self._perform_sni_detection(client_data)
                self.sni_checked = True

            # 转发数据到当前代理
            if self.upstream_writer:
                self.upstream_writer.write(client_data)
                await self.upstream_writer.drain()
                self.relayed_data = True
                return True

            return False

        except Exception as e:
            self.logger.error(f"Data relay error: {e}")
            return False

    async def _perform_sni_detection(self, data: bytes):
        """执行SNI检测和代理切换"""
        try:
            # 使用proxy_selector进行SNI检测和重新绑定
            new_proxy = self.socks5_handler.config.proxy_selector.check_sni_and_rebind(
                self.current_proxy, data, self.target_port
            )

            if new_proxy and new_proxy != self.current_proxy:
                self.logger.info(f"🔄 Switching proxy due to SNI detection: {self.current_proxy.identifier} -> {new_proxy.identifier}")

                # 关闭当前连接
                if hasattr(self, 'upstream_writer') and self.upstream_writer:
                    self.upstream_writer.close()
                    await self.upstream_writer.wait_closed()

                # 连接到新代理
                success = await self._connect_to_proxy(new_proxy)
                if success:
                    success = await self._send_socks5_connect()
                    if success:
                        self.current_proxy = new_proxy
                        self.logger.info(f"✅ Successfully switched to proxy: {new_proxy.identifier}")

                        # 通知SOCKS5处理器更新代理信息
                        self.socks5_handler.selected_proxy = new_proxy
                    else:
                        self.logger.error(f"Failed to send CONNECT through new proxy: {new_proxy.identifier}")
                else:
                    self.logger.error(f"Failed to connect to new proxy: {new_proxy.identifier}")

        except Exception as e:
            self.logger.error(f"SNI detection error: {e}")

    async def start_relay_loop(self):
        """启动数据转发循环"""
        try:
            tasks = [
                asyncio.create_task(self._relay_client_to_server()),
                asyncio.create_task(self._relay_server_to_client())
            ]

            await asyncio.gather(*tasks, return_exceptions=True)

        except Exception as e:
            self.logger.error(f"Relay loop error: {e}")

    async def _relay_client_to_server(self):
        """转发客户端到服务器的数据"""
        try:
            while True:
                data = await self.socks5_handler.socks5_handler.reader.read(8192)
                if not data:
                    break

                # 转发数据并进行SNI检测
                success = await self.relay_data_with_sni_check(data)
                if not success:
                    break

        except Exception as e:
            self.logger.error(f"Client to server relay error: {e}")

    async def _relay_server_to_client(self):
        """转发服务器到客户端的数据"""
        try:
            while True:
                if hasattr(self, 'upstream_reader') and self.upstream_reader:
                    data = await self.upstream_reader.read(8192)
                    if not data:
                        break

                    self.socks5_handler.socks5_handler.writer.write(data)
                    await self.socks5_handler.socks5_handler.writer.drain()
                else:
                    await asyncio.sleep(0.1)

        except Exception as e:
            self.logger.error(f"Server to client relay error: {e}")

    async def cleanup(self):
        """清理资源"""
        try:
            if hasattr(self, 'upstream_writer') and self.upstream_writer:
                self.upstream_writer.close()
                await self.upstream_writer.wait_closed()
        except Exception as e:
            self.logger.error(f"Cleanup error: {e}")