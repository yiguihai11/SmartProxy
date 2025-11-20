#!/usr/bin/env python3
"""
智能代理启动器 - 整合业务逻辑
调用纯净的SOCKS5协议处理器，实现智能路由功能
"""

import asyncio
import socket
import struct
import json
import logging
import ssl
import re
import ipaddress
import time
import threading
import sys
import signal
import os
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from urllib.parse import urlparse

# 导入完整的SOCKS5协议处理器
from socks5_protocol import (
    FullCoreSOCKS5Handler, PureSOCKS5Handler, SOCKS5Request,
    AuthUser, NATMode, AuthenticationError, SOCKS5ProtocolError
)

# 导入UDP中继处理器
from udp_relay import UDPRelayProtocol

# 导入SNI感知转发器
from sni_aware_relay import SNIAwareRelay
from sni_extractor import extract_sni

# 导入DNS模块
from dns_module import SmartDNSServer

# 导入Web服务器模块
from web_server import WebServer

# 导入配置管理器
from config import Config
from blacklist import BlacklistEntry
from utils import (
    is_private_ip, is_local_ip,
    SOCKS5_VERSION, SOCKS5_AUTH_NONE, SOCKS5_CMD_CONNECT, SOCKS5_CMD_UDP_ASSOCIATE,
    SOCKS5_ATYP_IPV4, SOCKS5_ATYP_DOMAIN, SOCKS5_ATYP_IPV6,
    SOCKS5_REPLY_SUCCESS
)

# ---------------------- 路由决策常量 ----------------------
class RouteDecision:
    DIRECT = "DIRECT"  # 直连
    PROXY = "PROXY"    # 走代理
    BLOCK = "BLOCK"    # 拒绝连接

@dataclass
class RouteResult:
    """路由决策结果"""
    decision: str  # DIRECT, PROXY, BLOCK
    proxy_node: Optional[Any] = None  # 选择的代理节点

    @property
    def is_direct(self) -> bool:
        return self.decision == RouteDecision.DIRECT

    @property
    def is_proxy(self) -> bool:
        return self.decision == RouteDecision.PROXY

    @property
    def is_block(self) -> bool:
        return self.decision == RouteDecision.BLOCK

# ---------------------- 数据类 ----------------------
@dataclass
class TrafficInfo:
    """流量信息"""
    target_ip: str
    target_port: int
    protocol: str = 'tcp'  # 'tcp' or 'udp'
    hostname: Optional[str] = None

# ---------------------- 智能路由器 ----------------------
class SmartRouter:
    """智能路由器"""

    def __init__(self, config: Config):
        self.config = config
        self.logger = logging.getLogger(f"{__name__}.SmartRouter")
        self.proxy_nodes = config.proxy_nodes

    def _match_pattern(self, pattern: str, value: str) -> bool:
        """简单的模式匹配，支持通配符"""
        if '*' in pattern:
            regex_pattern = pattern.replace('.', r'\.').replace('*', '.*')
            return re.fullmatch(regex_pattern, value) is not None
        else:
            return pattern == value

    def _check_acl_rules(self, traffic_info: "TrafficInfo") -> Optional[str]:
        """
        检查所有ACL规则，返回路由决策 ('DIRECT', 'PROXY', 'BLOCK')。
        """
        for rule in self.config.config_data.get('acl_rules', []):
            pattern = rule.get('pattern', '')
            action = rule.get('action', 'allow')

            # 根据action确定决策
            if action == 'allow':
                decision = RouteDecision.DIRECT
            elif action == 'deny':
                decision = RouteDecision.PROXY
            elif action == 'block':
                decision = RouteDecision.BLOCK
            else:
                continue  # 未知action，跳过

            # 1. 检查模式是否为端口
            if pattern.isdigit():
                if traffic_info.target_port == int(pattern):
                    self.logger.debug(f"ACL port rule matched: {pattern} -> {decision}")
                    return decision
                continue

            # 2. 检查模式是否为IP地址或CIDR
            try:
                target_ip_obj = ipaddress.ip_address(traffic_info.target_ip)
                pattern_net = ipaddress.ip_network(pattern, strict=False)
                if target_ip_obj in pattern_net:
                    self.logger.debug(f"ACL IP/CIDR rule matched: {pattern} -> {decision}")
                    return decision
                continue
            except ValueError:
                # 如果不是有效的IP/CIDR，则假定为域名模式
                pass

            # 3. 假定模式为域名 (仅TCP流量检查域名，UDP跳过)
            if traffic_info.protocol == 'tcp' and traffic_info.hostname and self._match_pattern(pattern, traffic_info.hostname):
                self.logger.debug(f"ACL hostname rule matched: {pattern} -> {decision}")
                return decision

        return None  # 没有ACL规则匹配

    def _check_udp_acl_rules(self, traffic_info: "TrafficInfo") -> Optional[str]:
        """
        检查UDP流量的ACL规则，只检查IP、CIDR、端口规则，不检查域名规则
        返回路由决策 ('DIRECT', 'PROXY', 'BLOCK')。
        """
        for rule in self.config.config_data.get('acl_rules', []):
            pattern = rule.get('pattern', '')
            action = rule.get('action', 'allow')

            # 根据action确定决策
            if action == 'allow':
                decision = RouteDecision.DIRECT
            elif action == 'deny':
                decision = RouteDecision.PROXY
            elif action == 'block':
                decision = RouteDecision.BLOCK
            else:
                continue  # 未知action，跳过

            # 1. 检查模式是否为端口
            if pattern.isdigit():
                if traffic_info.target_port == int(pattern):
                    self.logger.info(f"🔍 UDP ACL port rule matched: {pattern} -> {decision}")
                    return decision
                continue

            # 2. 检查模式是否为IP地址或CIDR
            try:
                target_ip_obj = ipaddress.ip_address(traffic_info.target_ip)
                pattern_net = ipaddress.ip_network(pattern, strict=False)
                if target_ip_obj in pattern_net:
                    self.logger.info(f"🔍 UDP ACL IP/CIDR rule matched: {pattern} -> {decision}")
                    return decision
                continue
            except ValueError:
                # 如果不是有效的IP/CIDR，则跳过（UDP不检查域名规则）
                continue

        return None  # 没有UDP ACL规则匹配

    def _check_proxy_bind_rules(self, traffic_info: "TrafficInfo") -> Optional["ProxyNode"]:
        """
        检查代理绑定规则，返回绑定的代理节点

        Args:
            traffic_info: 流量信息

        Returns:
            ProxyNode or None: 绑定的代理节点，没有匹配则返回None
        """
        proxy_bind_rules = self.config.config_data.get('proxy_bind_rules', [])

        # 优先级：域名绑定 > 端口绑定
        # 1. 首先检查域名模式规则 (优先级最高)
        if traffic_info.hostname:
            for rule in proxy_bind_rules:
                pattern = rule.get('pattern', '')
                target_identifier = rule.get('target', '')

                if not target_identifier:
                    continue

                # 跳过端口和端口列表规则，只检查域名模式
                if pattern.isdigit() or (pattern.startswith('[') and pattern.endswith(']')):
                    continue

                # 检查域名模式
                if self._match_pattern(pattern, traffic_info.hostname):
                    self.logger.info(f"🔗 Proxy bind hostname rule matched: {pattern} -> {target_identifier}")
                    return self._find_proxy_node(target_identifier)

        # 2. 然后检查端口规则
        for rule in proxy_bind_rules:
            pattern = rule.get('pattern', '')
            target_identifier = rule.get('target', '')

            if not target_identifier:
                continue

            # 检查端口规则
            if pattern.isdigit():
                if traffic_info.target_port == int(pattern):
                    self.logger.info(f"🔗 Proxy bind port rule matched: {pattern} -> {target_identifier}")
                    return self._find_proxy_node(target_identifier)
                continue

            # 检查端口列表规则 [8080,8443]
            if pattern.startswith('[') and pattern.endswith(']'):
                try:
                    import ast
                    port_list = ast.literal_eval(pattern)
                    if isinstance(port_list, list) and traffic_info.target_port in port_list:
                        self.logger.info(f"🔗 Proxy bind port list rule matched: {pattern} -> {target_identifier}")
                        return self._find_proxy_node(target_identifier)
                except:
                    pass
                continue

        return None  # 没有匹配的绑定规则

    def _find_proxy_node(self, identifier: str) -> Optional["ProxyNode"]:
        """
        根据identifier查找代理节点

        Args:
            identifier: 代理节点标识符

        Returns:
            ProxyNode or None: 找到的代理节点，未找到则返回None
        """
        for node in self.proxy_nodes:
            if hasattr(node, 'identifier') and node.identifier == identifier:
                if hasattr(node, 'enabled') and node.enabled:
                    return node
                else:
                    self.logger.warning(f"🔗 Proxy node {identifier} found but disabled")
                    return None

        self.logger.error(f"🔗 Proxy node {identifier} not found in proxy_nodes")
        return None

    def route_traffic(self, traffic_info: "TrafficInfo") -> RouteResult:
        """
        基于流量信息进行路由决策。

        Args:
            traffic_info: 流量信息

        Returns:
            RouteResult: 路由决策结果
        """
        try:
            self.logger.info(f"Routing decision - IP: {traffic_info.target_ip}:{traffic_info.target_port}, Hostname: {traffic_info.hostname}, Protocol: {traffic_info.protocol}")

            # 移除路由决策时的proxy_bind_rules检查
            # 改为在建立连接后通过SNI检测进行延迟绑定

            # UDP流量参与ACL规则的IP/CIDR/端口判断，但不参与黑名单判断
            if traffic_info.protocol == 'udp':
                # 1. 检查UDP的ACL规则 (IP/CIDR/端口)
                acl_decision = self._check_udp_acl_rules(traffic_info)
                if acl_decision:
                    self.logger.info(f"🔍 UDP ACL-based routing: {acl_decision} for {traffic_info.target_ip}:{traffic_info.target_port}")
                    if acl_decision == RouteDecision.DIRECT:
                        return RouteResult(RouteDecision.DIRECT)
                    elif acl_decision == RouteDecision.BLOCK:
                        return RouteResult(RouteDecision.BLOCK)
                    else:  # PROXY
                        proxy = self.config.proxy_selector.select_proxy(traffic_info)
                        return RouteResult(RouteDecision.PROXY, proxy)

                # 2. 如果没有ACL规则匹配，则基于chnroutes判断
                if self._should_direct_connect_by_chn_route(traffic_info):
                    self.logger.info(f"🔓 UDP China route: {traffic_info.target_ip} -> DIRECT")
                    return RouteResult(RouteDecision.DIRECT)  # 中国IP直连
                else:
                    self.logger.info(f"🌐 UDP Foreign route: {traffic_info.target_ip} -> PROXY")
                    proxy = self.config.proxy_selector.select_proxy(traffic_info)
                    return RouteResult(RouteDecision.PROXY, proxy)  # 外国IP走代理

            # TCP流量的完整智能路由判断
            # 1. 检查黑名单 (高优先级)
            blacklist_entry = self.config.blacklist.is_blacklisted(traffic_info.target_ip)
            if blacklist_entry:
                self.logger.warning(f"🚨 Target {traffic_info.target_ip} is blacklisted, forcing PROXY.")
                proxy = self.config.proxy_selector.select_proxy(traffic_info)
                return RouteResult(RouteDecision.PROXY, proxy)

            # 2. 检查ACL规则
            acl_decision = self._check_acl_rules(traffic_info)
            if acl_decision:
                self.logger.info(f"ACL-based routing: {acl_decision} for {traffic_info.hostname or traffic_info.target_ip}")
                if acl_decision == RouteDecision.DIRECT:
                    return RouteResult(RouteDecision.DIRECT)
                elif acl_decision == RouteDecision.BLOCK:
                    return RouteResult(RouteDecision.BLOCK)
                else:  # PROXY
                    proxy = self.config.proxy_selector.select_proxy(traffic_info)
                    return RouteResult(RouteDecision.PROXY, proxy)

            # 3. 如果没有ACL规则匹配，则回退到基于中国路由的智能分流
            if self._should_direct_connect_by_chn_route(traffic_info):
                self.logger.info(f"Smart routing (CHN): {traffic_info.hostname or traffic_info.target_ip} -> DIRECT")
                return RouteResult(RouteDecision.DIRECT)
            else:
                self.logger.info(f"Smart routing (Foreign): {traffic_info.hostname or traffic_info.target_ip} -> PROXY")
                proxy = self.config.proxy_selector.select_proxy(traffic_info)
                return RouteResult(RouteDecision.PROXY, proxy)

        except Exception as e:
            self.logger.error(f"Routing decision error: {e}", exc_info=True)
            return RouteResult(RouteDecision.DIRECT)  # 出现异常时默认直连

    def _should_direct_connect_by_chn_route(self, traffic_info: "TrafficInfo") -> bool:
        """根据中国路由表判断是否应该直连"""
        # 私有/本地地址总是直连
        if is_private_ip(traffic_info.target_ip) or is_local_ip(traffic_info.target_ip):
            return True

        # 对于TCP流量，优先检查域名
        if traffic_info.protocol == 'tcp' and traffic_info.hostname and hasattr(self.config.china_route_manager, 'is_china_domain'):
             if self.config.china_route_manager.is_china_domain(traffic_info.hostname):
                return True

        # 对于UDP和TCP流量，都基于IP判断chnroutes
        is_china = self.config.china_route_manager.is_china_ip(traffic_info.target_ip)
        if traffic_info.protocol == 'udp':
            self.logger.debug(f"UDP China route check: {traffic_info.target_ip} -> {'China' if is_china else 'Foreign'}")
        return is_china

# ---------------------- 智能SOCKS5处理器 ----------------------
class SmartSOCKS5Handler:
    """智能SOCKS5处理器 - 使用完整的SOCKS5协议处理器"""

    def __init__(self, config: Config, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        # 创建完整的SOCKS5协议处理器
        self.socks5_handler = FullCoreSOCKS5Handler(
            reader=reader,
            writer=writer,
            nat_mode=config.socks5_config.nat_mode,
            enable_auth=config.socks5_config.enable_auth,
            auth_users=config.auth_users
        )
        self.config = config

        # 业务逻辑相关
        self.logger = logging.getLogger(f"{__name__}.SmartSOCKS5Handler")
        self.smart_router = SmartRouter(config)
        self.blacklist = config.blacklist

        # 连接信息
        self.target_ip = None
        self.target_port = None
        self.traffic_info = None
        self.selected_proxy = None

        # 客户端连接信息
        self.client_ip = None
        self.client_port = None

    async def handle(self):
        """处理SOCKS5连接"""
        try:
            # 获取客户端地址
            client_addr = self.socks5_handler.get_remote_address()
            self.client_ip = client_addr[0] if client_addr else 'unknown'
            self.client_port = client_addr[1] if len(client_addr) > 1 else 0
            self.logger.info(f"New SOCKS5 connection from {client_addr}")

            # 使用完整的SOCKS5协议处理器处理连接
            success = await self.socks5_handler.handle_client()
            if not success:
                return

            # 获取解析后的请求
            # 注意：FullCoreSOCKS5Handler已经处理了握手和认证
            # 这里需要重新解析请求以获取业务逻辑需要的信息
            request = await self.socks5_handler.handle_request()
            if not request:
                return

            self.target_ip = request.dst_addr
            self.target_port = request.dst_port

            # 创建流量信息
            self.traffic_info = TrafficInfo(
                target_ip=self.target_ip,
                target_port=self.target_port,
                protocol='tcp'
            )

            # 业务逻辑处理（CONNECT和UDP_ASSOCIATE已经在协议层处理）
            # 这里只需要添加智能路由逻辑
            if request.cmd == SOCKS5_CMD_CONNECT:
                await self._apply_smart_routing(request)
            elif request.cmd == SOCKS5_CMD_UDP_ASSOCIATE:
                await self._handle_udp_smart_routing(request)
            # BIND命令不需要额外的业务逻辑处理

        except Exception as e:
            self.logger.error(f"SOCKS5 handler error: {e}")

    async def _apply_smart_routing(self, request: SOCKS5Request):
        """应用智能路由逻辑"""
        try:
            # 智能路由决策
            route_result = self.smart_router.route_traffic(self.traffic_info)

            # 处理路由决策结果
            if route_result.is_block:
                self.logger.warning(f"🚫 Connection blocked by ACL rules: {self.target_ip}:{self.target_port}")
                await self.socks5_handler.send_reply(self.socks5_handler.REP_CONNECTION_NOT_ALLOWED)
                return

            # 设置代理节点（如果有）
            self.selected_proxy = route_result.proxy_node

            if route_result.is_proxy:
                self.logger.info(f"🌐 Via proxy {route_result.proxy_node.identifier} to {self.target_ip}:{self.target_port}")
            else:  # DIRECT
                self.logger.info(f"🔓 Direct connection to {self.target_ip}:{self.target_port}")

        except Exception as e:
            self.logger.error(f"Smart routing error: {e}")

    async def _handle_udp_smart_routing(self, request: SOCKS5Request):
        """处理UDP智能路由 - UDP流量已改为默认使用代理，此方法已弃用"""
        # UDP流量现在默认使用代理，不再需要智能路由判断
        self.logger.debug("UDP smart routing is disabled - UDP traffic defaults to proxy mode")
        pass

    PROBING_PORTS = {80, 8080, 443, 8443}

    async def _handle_probing_connect(self):
        """
        处理探测性连接，实现“直连尝试、失败/策略回退到代理”的逻辑。
        仅用于特定端口 (PROBING_PORTS).
        """
        self.logger.info(f"⚡️ Starting probing connect for {self.target_ip}:{self.target_port}")
        upstream_reader, upstream_writer = None, None
        client_hello_data = None
        use_proxy = False
        reason = ""

        # 1. 尝试TCP直连
        try:
            self.logger.debug("Probing: Attempting direct TCP connection...")
            upstream_reader, upstream_writer = await asyncio.wait_for(
                asyncio.open_connection(self.target_ip, self.target_port),
                timeout=self.config.smart_proxy.timeout_ms / 1000
            )
            self.logger.info("Probing: Direct TCP connection successful.")
        except Exception as e:
            self.logger.warning(f"Probing: Direct TCP connection failed: {e}. Falling back to proxy.")
            use_proxy = True
            reason = f"Direct connection failed: {e}"

        # 2. 如果直连成功，尝试读取Client Hello并解析SNI
        if not use_proxy and upstream_reader:
            try:
                # 从客户端读取第一个数据包
                client_hello_data = await self.socks5_handler.reader.read(4096)
                if not client_hello_data:
                    self.logger.warning("Probing: Client disconnected before sending data.")
                    if upstream_writer:
                        upstream_writer.close()
                        await upstream_writer.wait_closed()
                    return

                # 解析SNI
                sni = extract_sni(client_hello_data)
                if sni:
                    self.logger.info(f"Probing: SNI '{sni}' extracted.")
                    # 更新流量信息以进行更精确的路由
                    self.traffic_info.hostname = sni
                    # 检查SNI是否命中强制代理规则 (ACL deny 或 proxy_bind)
                    acl_decision = self.smart_router._check_acl_rules(self.traffic_info)
                    bind_node = self.smart_router._check_proxy_bind_rules(self.traffic_info)

                    if bind_node:
                        use_proxy = True
                        self.selected_proxy = bind_node
                        reason = f"SNI '{sni}' matched proxy bind rule"
                    elif acl_decision == RouteDecision.PROXY:
                        use_proxy = True
                        reason = f"SNI '{sni}' matched ACL deny rule"
                else:
                    self.logger.info("Probing: No SNI found in initial packet (could be HTTP or other non-TLS protocol).")
            except Exception as e:
                self.logger.error(f"Probing: Error reading/parsing Client Hello: {e}. Defaulting to initial route decision.")

        # 3. 如果经过SNI判断后仍未决定使用代理，则使用初始路由判断作为最后依据
        if not use_proxy:
            initial_route = self.smart_router.route_traffic(self.traffic_info)
            if initial_route.is_proxy:
                use_proxy = True
                reason = "Initial IP-based routing decision was PROXY"
                self.selected_proxy = initial_route.proxy_node # 使用初始选择的代理
            elif initial_route.is_block:
                self.logger.warning(f"🚫 Connection blocked by initial ACL rules: {self.target_ip}:{self.target_port}")
                await self.socks5_handler.send_reply(self.socks5_handler.REP_CONNECTION_NOT_ALLOWED)
                if upstream_writer:
                    upstream_writer.close()
                    await upstream_writer.wait_closed()
                return

        # 4. 执行最终决策
        if use_proxy:
            self.logger.info(f"🌐 Final decision: PROXY. Reason: {reason}")
            # 如果直连曾成功，现在需要关掉它
            if upstream_writer:
                upstream_writer.close()
                await upstream_writer.wait_closed()

            # 选择一个代理（如果SNI绑定规则没有指定）
            if not self.selected_proxy:
                 self.selected_proxy = self.config.proxy_selector.select_proxy(self.traffic_info)

            # 通过代理连接
            success = await self._connect_to_proxy()
            if success:
                # 将截获的client hello数据（如果有）发送到代理隧道
                if client_hello_data:
                    self.upstream_writer.write(client_hello_data)
                    await self.upstream_writer.drain()
                await self.socks5_handler.send_success_reply()
                await self._relay_data_via_proxy()
            else:
                await self.socks5_handler.send_reply(self.socks5_handler.REP_HOST_UNREACHABLE)
        else:
            self.logger.info("🔓 Final decision: DIRECT.")
            # 使用已建立的直连
            if upstream_writer and client_hello_data:
                upstream_writer.write(client_hello_data)
                await upstream_writer.drain()

            await self.socks5_handler.send_success_reply()
            await self._relay_data_direct(upstream_reader, upstream_writer)

    async def _handle_connect_request(self, request: SOCKS5Request):
        """处理CONNECT请求"""
        try:
            # 检查是否为探测端口
            if self.target_port in self.PROBING_PORTS:
                await self._handle_probing_connect()
            else:
                # 对于非探测端口，使用旧的、简单的路由逻辑
                self.logger.info(f"Non-probing port {self.target_port}, using standard routing.")
                route_result = self.smart_router.route_traffic(self.traffic_info)

                if route_result.is_block:
                    self.logger.warning(f"🚫 Connection blocked by ACL rules: {self.target_ip}:{self.target_port}")
                    await self.socks5_handler.send_reply(self.socks5_handler.REP_CONNECTION_NOT_ALLOWED)
                    return

                self.selected_proxy = route_result.proxy_node
                if route_result.is_direct:
                    await self._handle_direct_connect()
                else: # PROXY
                    await self._handle_sni_aware_proxy_connect() # 维持旧的SNI感知逻辑

        except Exception as e:
            self.logger.error(f"CONNECT request error: {e}", exc_info=True)
            await self.socks5_handler.send_reply(self.socks5_handler.REP_GENERAL_FAILURE)


    async def _handle_sni_aware_proxy_connect(self):
        """处理SNI感知的代理连接"""
        try:
            self.logger.info(f"🌐 SNI-aware proxy connect to {self.target_ip}:{self.target_port}")

            # 创建SNI感知转发器
            sni_relay = SNIAwareRelay(self, self.target_ip, self.target_port)

            # 建立连接并进行SNI检测
            success = await sni_relay.connect_with_sni_detection()
            if success:
                await self.socks5_handler.send_success_reply()
                # 启动数据转发循环（包含SNI检测）
                await sni_relay.start_relay_loop()
            else:
                await self.socks5_handler.send_reply(self.socks5_handler.REP_HOST_UNREACHABLE)

            # 清理资源
            await sni_relay.cleanup()

        except Exception as e:
            self.logger.error(f"SNI-aware proxy connect error: {e}")
            await self.socks5_handler.send_reply(self.socks5_handler.REP_HOST_UNREACHABLE)

    async def _handle_direct_connect(self):
        """处理直连"""
        try:
            self.logger.info(f"🔓 Direct connect to {self.target_ip}:{self.target_port}")

            # 建立直连
            upstream_reader, upstream_writer = await asyncio.open_connection(
                self.target_ip, self.target_port
            )

            await self.socks5_handler.send_success_reply()

            # 开始数据转发
            await self._relay_data_direct(upstream_reader, upstream_writer)

        except Exception as e:
            self.logger.error(f"Direct connect error: {e}")
            await self.socks5_handler.send_reply(self.socks5_handler.REP_HOST_UNREACHABLE)

    async def _handle_proxy_connect(self):
        """处理代理连接"""
        try:
            self.logger.info(f"🌐 Proxy connect to {self.target_ip}:{self.target_port} via {self.selected_proxy.identifier}")

            # 连接到代理
            success = await self._connect_to_proxy()
            if success:
                await self.socks5_handler.send_success_reply()
                await self._relay_data_via_proxy()
            else:
                await self.socks5_handler.send_reply(self.socks5_handler.REP_HOST_UNREACHABLE)

        except Exception as e:
            self.logger.error(f"Proxy connect error: {e}")
            await self.socks5_handler.send_reply(self.socks5_handler.REP_HOST_UNREACHABLE)

    async def _handle_udp_associate_request(self, request: SOCKS5Request):
        """处理UDP ASSOCIATE请求"""
        try:
            self.logger.info(f"🔄 UDP ASSOCIATE request for {self.target_ip}:{self.target_port}")

            # 创建UDP流量信息进行路由决策
            udp_traffic_info = TrafficInfo(
                target_ip=self.target_ip,
                target_port=self.target_port,
                protocol='udp'
            )

            # UDP流量基于ACL和chnroutes进行智能分流
            route_result = self.smart_router.route_traffic(udp_traffic_info)

            # 处理路由决策结果
            if route_result.is_block:
                self.logger.warning(f"🚫 UDP association blocked by ACL rules: {self.target_ip}:{self.target_port}")
                await self.socks5_handler.send_reply(self.socks5_handler.REP_CONNECTION_NOT_ALLOWED)
                return

            # 设置代理节点（如果有）
            self.selected_proxy = route_result.proxy_node
            use_proxy = route_result.is_proxy

            if route_result.is_proxy:
                self.logger.info(f"🌐 UDP will use proxy: {route_result.proxy_node.identifier} -> {self.target_ip}:{self.target_port}")
            else:  # DIRECT
                self.logger.info(f"🔓 UDP direct connection -> {self.target_ip}:{self.target_port}")

            # 创建UDP服务器 - 根据路由决定是否使用代理
            bind_address = ('0.0.0.0', 0)  # 绑定到任意可用端口
            transport, protocol = await asyncio.get_event_loop().create_datagram_endpoint(
                lambda: UDPRelayProtocol(self, use_proxy=use_proxy),  # 根据路由决定
                local_addr=bind_address
            )

            # 获取实际绑定的地址
            actual_bind_addr = transport.get_extra_info('sockname')

            # 发送成功响应
            await self.socks5_handler.send_success_reply(
                bind_addr=actual_bind_addr[0],
                bind_port=actual_bind_addr[1]
            )

            self.logger.info(f"UDP ASSOCIATE established, listening on {actual_bind_addr}")

            # 保持TCP连接活跃
            try:
                while True:
                    data = await self.socks5_handler.reader.read(1)
                    if not data:
                        break
            except Exception:
                pass
            finally:
                transport.close()
                protocol.cleanup()

        except Exception as e:
            self.logger.error(f"UDP ASSOCIATE error: {e}")
            await self.socks5_handler.send_reply(self.socks5_handler.REP_GENERAL_FAILURE)

    async def _connect_to_proxy(self) -> bool:
        """连接到代理服务器"""
        try:
            reader, writer = await asyncio.open_connection(
                self.selected_proxy.ip,
                self.selected_proxy.port
            )

            # SOCKS5握手
            writer.write(bytes([SOCKS5_VERSION, 1, SOCKS5_AUTH_NONE]))
            await writer.drain()

            response = await reader.read(2)
            if len(response) != 2 or response[0] != SOCKS5_VERSION or response[1] != SOCKS5_AUTH_NONE:
                self.logger.error(f"Proxy authentication failed: {self.selected_proxy.identifier}")
                writer.close()
                await writer.wait_closed()
                return False

            # 发送连接请求
            if ':' in self.target_ip:  # IPv6
                atyp = SOCKS5_ATYP_IPV6
                addr_bytes = socket.inet_pton(socket.AF_INET6, self.target_ip)
            else:  # IPv4
                atyp = SOCKS5_ATYP_IPV4
                addr_bytes = socket.inet_aton(self.target_ip)

            connect_req = bytes([SOCKS5_VERSION, SOCKS5_CMD_CONNECT, 0x00, atyp]) + \
                         addr_bytes + struct.pack('!H', self.target_port)

            writer.write(connect_req)
            await writer.drain()

            # 读取连接响应
            response = await reader.read(10)
            if len(response) < 4 or response[0] != SOCKS5_VERSION or response[1] != SOCKS5_REPLY_SUCCESS:
                self.logger.error(f"Proxy connection failed: {self.selected_proxy.identifier}")
                writer.close()
                await writer.wait_closed()
                return False

            self.upstream_reader = reader
            self.upstream_writer = writer

            self.logger.info(f"Connected to proxy {self.selected_proxy.identifier}")
            return True

        except Exception as e:
            self.logger.error(f"Proxy connection error: {e}")
            return False

    async def _relay_data_direct(self, upstream_reader, upstream_writer):
        """直连模式数据转发"""
        try:
            tasks = [
                asyncio.create_task(self.socks5_handler.reader.read(8192)),
                asyncio.create_task(upstream_reader.read(8192))
            ]

            while True:
                done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)

                for task in done:
                    try:
                        data = await task
                        if not data:
                            return

                        # 判断数据来源并转发
                        if task == tasks[0]:  # 客户端数据
                            upstream_writer.write(data)
                            await upstream_writer.drain()
                        else:  # 服务器数据
                            self.socks5_handler.writer.write(data)
                            await self.socks5_handler.writer.drain()
                    except Exception as e:
                        self.logger.error(f"Data relay error: {e}")
                        return

                # 重新创建任务
                tasks = [
                    asyncio.create_task(self.socks5_handler.reader.read(8192)),
                    asyncio.create_task(upstream_reader.read(8192))
                ]

        except Exception as e:
            self.logger.error(f"Direct data relay error: {e}")

    async def _relay_data_via_proxy(self):
        """代理模式数据转发"""
        try:
            tasks = [
                asyncio.create_task(self.socks5_handler.reader.read(8192)),
                asyncio.create_task(self.upstream_reader.read(8192))
            ]

            while True:
                done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)

                for task in done:
                    try:
                        data = await task
                        if not data:
                            return

                        # 判断数据来源并转发
                        if task == tasks[0]:  # 客户端数据
                            self.upstream_writer.write(data)
                            await self.upstream_writer.drain()
                        else:  # 代理服务器数据
                            self.socks5_handler.writer.write(data)
                            await self.socks5_handler.writer.drain()
                    except Exception as e:
                        self.logger.error(f"Proxy data relay error: {e}")
                        return

                # 重新创建任务
                tasks = [
                    asyncio.create_task(self.socks5_handler.reader.read(8192)),
                    asyncio.create_task(self.upstream_reader.read(8192))
                ]

        except Exception as e:
            self.logger.error(f"Proxy data relay error: {e}")

# ---------------------- SOCKS5服务器 ----------------------
class SmartSOCKS5Server:
    """智能SOCKS5服务器"""

    def __init__(self, config: Config):
        self.config = config
        self.server = None
        self.running = False
        self.logger = logging.getLogger(__name__)

        # 连接数管理
        self.active_connections = 0
        self.connection_lock = asyncio.Lock()
        self.max_connections = config.socks5_config.max_connections if config.socks5_config.max_connections > 0 else None

        # NAT清理任务
        self.nat_cleanup_task = None
        self.nat_cleanup_interval = config.socks5_config.cleanup_interval if config.socks5_config.cleanup_interval > 0 else None

        # 活动处理器列表（用于NAT清理）
        self.active_handlers = set()
        self.handlers_lock = asyncio.Lock()

    async def start(self):
        """启动SOCKS5服务器"""
        try:
            # 根据配置选择监听地址
            if self.config.listener.ipv6_enabled:
                # IPv6监听 - 双栈支持
                host = '::'  # 监听所有IPv6和IPv4地址（如果系统支持双栈）
                self.logger.info("IPv6 enabled, listening on :::")
            else:
                # IPv4监听
                host = '0.0.0.0'
                self.logger.info("IPv4 only, listening on 0.0.0.0")

            self.server = await asyncio.start_server(
                self._handle_client,
                host,
                self.config.listener.socks5_port,
                reuse_address=True
            )

            self.running = True
            self.logger.info(f"Smart SOCKS5 server started on {host}:{self.config.listener.socks5_port}")
            self.logger.info("TCP traffic inspection enabled for ports: 80, 8080, 443, 8443")

            # 启动NAT清理任务
            if self.nat_cleanup_interval:
                self.nat_cleanup_task = asyncio.create_task(self._nat_cleanup_loop())
                self.logger.info(f"NAT清理任务已启动，间隔: {self.nat_cleanup_interval}秒")

            async with self.server:
                await self.server.serve_forever()

        except Exception as e:
            self.logger.error(f"Failed to start server: {e}")
            raise

    async def stop(self):
        """停止SOCKS5服务器"""
        self.running = False

        # 停止NAT清理任务
        if self.nat_cleanup_task:
            self.nat_cleanup_task.cancel()
            try:
                await self.nat_cleanup_task
            except asyncio.CancelledError:
                pass
            self.logger.info("NAT清理任务已停止")

        if self.server:
            self.server.close()
            await self.server.wait_closed()
            self.logger.info("Smart SOCKS5 server stopped")

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """处理客户端连接"""
        # 连接数检查
        async with self.connection_lock:
            if self.max_connections is not None and self.active_connections >= self.max_connections:
                self.logger.warning(f"连接数达到上限 {self.max_connections}，拒绝新连接")
                try:
                    writer.close()
                    await writer.wait_closed()
                except:
                    pass
                return

            self.active_connections += 1
            self.logger.debug(f"新连接建立，当前连接数: {self.active_connections}/{self.max_connections or '∞'}")

        handler = SmartSOCKS5Handler(self.config, reader, writer)

        # 注册处理器到服务器
        async with self.handlers_lock:
            self.active_handlers.add(handler)
            self.logger.debug(f"注册处理器，当前活动处理器数: {len(self.active_handlers)}")

        try:
            await handler.handle()
        except Exception as e:
            self.logger.error(f"Client handler error: {e}")
        finally:
            # 减少连接计数
            async with self.connection_lock:
                self.active_connections -= 1
                self.logger.debug(f"连接关闭，当前连接数: {self.active_connections}/{self.max_connections or '∞'}")

            # 注销处理器
            async with self.handlers_lock:
                self.active_handlers.discard(handler)
                self.logger.debug(f"注销处理器，当前活动处理器数: {len(self.active_handlers)}")

            try:
                writer.close()
                await writer.wait_closed()
            except:
                pass

    async def _nat_cleanup_loop(self):
        """NAT清理循环任务"""
        self.logger.info(f"NAT清理循环启动，间隔: {self.nat_cleanup_interval}秒")

        while self.running:
            try:
                await asyncio.sleep(self.nat_cleanup_interval)

                if not self.running:
                    break

                # 执行NAT清理
                await self._perform_nat_cleanup()

            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"NAT清理循环错误: {e}")

        self.logger.info("NAT清理循环已停止")

    async def _perform_nat_cleanup(self):
        """执行NAT清理"""
        try:
            async with self.handlers_lock:
                if not self.active_handlers:
                    return

                self.logger.debug(f"开始NAT清理，检查 {len(self.active_handlers)} 个活动处理器")

                total_cleaned = 0
                for handler in list(self.active_handlers):  # 复制列表避免并发修改
                    try:
                        # 调用处理器的NAT清理方法
                        if hasattr(handler, 'socks5_handler') and hasattr(handler.socks5_handler, 'cleanup_expired_nat_entries'):
                            # 使用配置的超时时间
                            timeout = self.config.connection_settings.tcp_timeout_seconds
                            cleaned = handler.socks5_handler.cleanup_expired_nat_entries(timeout)
                            if cleaned > 0:
                                self.logger.debug(f"处理器 {id(handler)} 清理了 {cleaned} 个过期NAT条目")
                                total_cleaned += cleaned
                    except Exception as e:
                        self.logger.error(f"处理器 {id(handler)} NAT清理失败: {e}")

                if total_cleaned > 0:
                    self.logger.info(f"NAT清理完成，共清理 {total_cleaned} 个过期条目")
                else:
                    self.logger.debug("NAT清理完成，没有过期条目")

        except Exception as e:
            self.logger.error(f"NAT清理执行失败: {e}")

# ---------------------- 代理服务管理器 ----------------------
class ProxyManager:
    """代理服务管理器"""

    def __init__(self):
        self.config = None
        self.server = None
        self.dns_server = None
        self.web_server = None
        self.running = False
        self._stop_requested = False  # 停止请求标志
        self.health_check_task = None  # 健康检查任务

    async def _run_periodic_health_checks(self):
        """运行周期性的健康检查"""
        while self.running:
            try:
                await asyncio.sleep(60)  # 每60秒检查一次
                if self.config and self.config.proxy_selector:
                    self.logger.debug("Running periodic proxy health check...")
                    self.config.proxy_selector.health_check()
            except asyncio.CancelledError:
                self.logger.info("Health check task cancelled.")
                break
            except Exception as e:
                self.logger.error(f"Error in periodic health check: {e}")

    async def start(self):
        """启动代理服务"""
        try:
            print("正在加载配置...")
            self.config = Config()
            self.logger = logging.getLogger(__name__) # 初始化logger

            # 获取监听端口
            socks5_port = self.config.listener.socks5_port
            dns_port = self.config.listener.dns_port

            # 启动DNS服务器
            if dns_port > 0:
                print("正在启动智能DNS服务器...")
                self.dns_server = SmartDNSServer(
                    self.config.config_data,
                    self.config.china_route_manager
                )
            else:
                print("⚠️ DNS服务器已禁用")

            # 启动Web管理界面
            web_config = self.config.config_data.get('web_interface', {})
            if web_config.get('enabled', True):
                print("正在启动Web管理界面...")
                self.web_server = WebServer(self.config)
                self.web_server.start()
                web_port = web_config.get('port', 8080)
                print(f"🌐 Web管理界面: http://0.0.0.0:{web_port}")
            else:
                print("⚠️ Web管理界面已禁用")

            print("正在启动SOCKS5代理服务器...")
            self.server = SmartSOCKS5Server(self.config)

            # 设置信号处理
            signal.signal(signal.SIGINT, self._signal_handler)
            signal.signal(signal.SIGTERM, self._signal_handler)

            # 显示启动信息
            print("✅ 配置加载完成")
            print("✅ 中国路由表加载完成")
            print(f"🚀 启动智能代理服务器...")
            print(f"📡 SOCKS5监听端口: {socks5_port}")
            if dns_port > 0:
                print(f"🌐 DNS监听端口: {dns_port}")
            print(f"🔐 客户端认证: {'启用' if self.config.socks5_config.enable_auth else '禁用'}")
            print(f"🌐 NAT模式: {self.config.socks5_config.nat_mode.value}")

            enabled_nodes = [n for n in self.config.proxy_nodes if n.enabled]
            print(f"⚡ 启用代理节点: {len(enabled_nodes)} 个")
            for node in enabled_nodes[:3]:  # 只显示前3个
                auth_info = f"({node.username})" if node.username else ""
                print(f"   - {node.identifier}: {node.ip}:{node.port} {auth_info}")
            if len(enabled_nodes) > 3:
                print(f"   - 还有 {len(enabled_nodes)-3} 个节点...")

            # 显示DNS配置
            dns_config = self.config.config_data.get('dns', {})
            # DNS配置可能在groups中或直接在dns下
            if 'groups' in dns_config:
                cn_servers = dns_config.get('groups', {}).get('cn', [])
                foreign_servers = dns_config.get('groups', {}).get('foreign', [])
            else:
                cn_servers = dns_config.get('cn', [])
                foreign_servers = dns_config.get('foreign', [])
            print(f"🌍 DNS配置: 国内组{len(cn_servers)}个, 国外组{len(foreign_servers)}个")

            print(f"📝 日志文件: smartproxy.log")
            print("\n按 Ctrl+C 停止服务\n")

            self.running = True
            # 启动后台健康检查任务
            self.health_check_task = asyncio.create_task(self._run_periodic_health_checks())

            # 启动服务器
            tasks = []
            tasks.append(asyncio.create_task(self.server.start()))

            if self.dns_server:
                tasks.append(asyncio.create_task(self.dns_server.start()))

            # 等待任务直到收到停止信号
            while not self._stop_requested:
                try:
                    await asyncio.sleep(0.1)  # 短暂休眠，让协程切换
                except asyncio.CancelledError:
                    break

        except Exception as e:
            error_msg = str(e)
            if "address already in use" in error_msg or "errno 98" in error_msg:
                print(f"❌ 端口 {port} 被占用，正在自动清理...")

                # 自动清理占用端口的进程
                killed = await self._kill_processes_using_port(port)

                if killed:
                    print(f"🔄 端口已清理，正在重新启动...")
                    # 等待2秒让端口释放
                    await asyncio.sleep(2)

                    # 重新尝试启动
                    try:
                        print(f"🚀 重新启动智能代理服务器...")
                        self.running = True
                        if not self.health_check_task or self.health_check_task.done():
                             self.health_check_task = asyncio.create_task(self._run_periodic_health_checks())
                        await self.server.start()
                        print(f"✅ 服务器启动成功！")
                    except Exception as retry_e:
                        print(f"❌ 重试启动失败: {retry_e}")
                        sys.exit(1)
                else:
                    print(f"❌ 无法清理端口 {port}，请手动检查")
                    sys.exit(1)
            else:
                print(f"❌ 启动失败: {e}")
                sys.exit(1)

        # 如果收到停止请求，进行清理
        if self._stop_requested:
            await self._immediate_stop()

    async def stop(self):
        """停止代理服务"""
        if self.running:
            print("\n正在停止代理服务...")
            self.running = False

            # 取消健康检查任务
            if self.health_check_task:
                self.health_check_task.cancel()
                await asyncio.sleep(0.1) # 给任务一点时间来处理取消

            # 停止Web管理界面
            if self.web_server:
                self.web_server.stop()
                print("Web管理界面已停止")

            # 停止DNS服务器
            if self.dns_server:
                await self.dns_server.stop()
                print("智能DNS服务器已停止")

            # 停止SOCKS5服务器
            if self.server:
                await self.server.stop()
                print("SOCKS5代理服务器已停止")

            print("所有服务已停止")

    async def _kill_processes_using_port(self, port: int) -> bool:
        """强制终止所有可能占用端口的进程"""
        try:
            import subprocess
            killed = False

            print(f"🔍 查找占用端口 {port} 的进程...")

            # 方法1: 查找所有start_proxy相关进程
            print("🔪 查找start_proxy进程...")
            cmd1 = "ps aux | grep 'start_proxy' | grep -v grep"
            result1 = subprocess.run(cmd1, shell=True, capture_output=True, text=True)

            if result1.stdout.strip():
                lines = result1.stdout.strip().split('\n')
                for line in lines:
                    parts = line.split()
                    if len(parts) >= 2:
                        pid = parts[1]
                        try:
                            subprocess.run(f"kill -9 {pid}", shell=True)
                            print(f"   ✅ 终止进程 {pid}: {line}")
                            killed = True
                        except Exception as e:
                            print(f"   ❌ 终止进程 {pid} 失败: {e}")

            # 方法2: 查找Python进程（更彻底）
            print("🔪 查找Python进程...")
            cmd2 = "ps aux | grep 'python' | grep -v grep"
            result2 = subprocess.run(cmd2, shell=True, capture_output=True, text=True)

            if result2.stdout.strip():
                lines = result2.stdout.strip().split('\n')
                for line in lines:
                    if 'python' in line and ('start_proxy' in line or 'smartproxy' in line):
                        parts = line.split()
                        if len(parts) >= 2:
                            pid = parts[1]
                            try:
                                subprocess.run(f"kill -9 {pid}", shell=True)
                                print(f"   ✅ 终止Python进程 {pid}: {line}")
                                killed = True
                            except Exception as e:
                                print(f"   ❌ 终止Python进程 {pid} 失败: {e}")

            # 方法3: 使用pkill强制清理
            print("🔪 使用pkill强制清理...")
            try:
                subprocess.run("pkill -9 -f 'start_proxy'", shell=True)
                subprocess.run("pkill -9 -f 'python.*smartproxy'", shell=True)
                subprocess.run("pkill -9 -f 'python.*1080'", shell=True)
                subprocess.run("pkill -9 -f 'python.*1085'", shell=True)
                print("   ✅ 执行pkill强制清理")
                killed = True
            except Exception as e:
                print(f"   ⚠️ pkill执行: {e}")

            if killed:
                # 等待进程完全退出
                print(f"⏳ 等待端口释放...")
                await asyncio.sleep(3)

                # 再次检查是否有进程仍在运行
                final_check = subprocess.run(cmd1, shell=True, capture_output=True, text=True)
                if final_check.stdout.strip():
                    print(f"⚠️ 仍有进程运行，再次强制清理...")
                    subprocess.run("pkill -9 -f 'python'", shell=True)
                    await asyncio.sleep(2)

                print(f"✅ 进程清理完成")
            else:
                print(f"ℹ️ 未找到需要清理的进程")

            return killed

        except Exception as e:
            print(f"❌ 进程清理失败: {e}")
            return False

    async def _check_and_kill_port_users(self, port: int) -> bool:
        """检查并终止占用指定端口的Python进程"""
        try:
            import subprocess
            killed = False

            # 查找所有start_proxy.py进程
            cmd = f"ps aux | grep 'python.*start_proxy' | grep -v grep"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

            if result.stdout.strip():
                lines = result.stdout.strip().split('\n')
                for line in lines:
                    if 'start_proxy' in line:
                        # 提取进程ID
                        parts = line.split()
                        if len(parts) >= 2:
                            pid = parts[1]
                            try:
                                subprocess.run(f"kill -9 {pid}", shell=True)
                                print(f"🔪 终止start_proxy进程 {pid}")
                                killed = True
                            except Exception as e:
                                print(f"⚠️  终止进程{pid}失败: {e}")

            # 查找可能占用端口的其他Python进程（更彻底的清理）
            cmd2 = f"ps aux | grep 'python' | grep -v grep"
            result2 = subprocess.run(cmd2, shell=True, capture_output=True, text=True)

            if result2.stdout.strip():
                lines = result2.stdout.strip().split('\n')
                for line in lines:
                    if 'python' in line and 'start_proxy' in line:
                        parts = line.split()
                        if len(parts) >= 2:
                            pid = parts[1]
                            try:
                                subprocess.run(f"kill -9 {pid}", shell=True)
                                print(f"🔪 终止Python进程 {pid}")
                                killed = True
                            except Exception as e:
                                print(f"⚠️  终止进程{pid}失败: {e}")

            if killed:
                # 等待进程完全退出
                await asyncio.sleep(2)
                print(f"✅ 已清理占用端口 {port} 的进程")
            else:
                print(f"ℹ️  端口 {port} 当前没有被占用")

            return killed

        except Exception as e:
            print(f"⚠️  端口检查失败: {e}")
            return False

    def _signal_handler(self, signum, frame):
        """信号处理器"""
        print(f"\n收到信号 {signum}, 正在停止服务...")
        if self.running:
            self.running = False
            # 设置停止标志
            self._stop_requested = True

    async def _immediate_stop(self):
        """立即停止所有服务"""
        print("正在立即停止所有服务...")

        # 取消健康检查任务
        if self.health_check_task:
            self.health_check_task.cancel()

        # 停止Web服务器
        if self.web_server:
            self.web_server.stop()

        # 停止DNS服务器
        if self.dns_server:
            await self.dns_server.stop()

        # 停止SOCKS5服务器
        if self.server:
            await self.server.stop()

        print("所有服务已停止")

# ---------------------- 主程序 ----------------------
async def main():
    """主函数"""
    # 检查是否在正确的目录
    if not os.path.exists("conf/config.json"):
        print("错误: 找不到配置文件 conf/config.json")
        print("请在项目根目录运行此脚本")
        sys.exit(1)

    manager = ProxyManager()
    try:
        await manager.start()
    except KeyboardInterrupt:
        print("\n用户中断，正在停止服务...")
        await manager.stop()
    except Exception as e:
        print(f"服务错误: {e}")
        await manager.stop()
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())