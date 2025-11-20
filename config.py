#!/usr/bin/env python3
"""
配置管理器模块
"""

import json
import logging
import hashlib
from dataclasses import dataclass, field
from typing import List, Optional

# 导入协议和业务逻辑类
from socks5_protocol import AuthUser, NATMode
from china_routes import ChinaRouteManager
from proxy_selector import ProxySelector
from timeout_manager import ConnectionTimeoutManager
from blacklist import SmartBlacklist

# ---------------------- 配置数据类 ----------------------

@dataclass
class ConnectionSettings:
    """连接设置"""
    tcp_timeout_seconds: int = 60
    udp_timeout_seconds: int = 300

@dataclass
class ProxyNode:
    """代理节点"""
    identifier: str
    protocol: str
    ip: str
    port: int
    weight: int = 1
    enabled: bool = True
    username: Optional[str] = None
    password: Optional[str] = None
    auth_method: str = "none"  # none, userpass

@dataclass
class ListenerConfig:
    """监听器配置"""
    socks5_port: int = 1080
    dns_port: int = 1053
    ipv6_enabled: bool = False

@dataclass
class SOCKS5Config:
    """SOCKS5协议配置"""
    nat_mode: str = "proxy"  # proxy, full_core, transparent
    enable_auth: bool = False
    auth_users: List[dict] = field(default_factory=list)
    max_connections: int = 1000
    cleanup_interval: int = 300  # NAT清理间隔（秒）

@dataclass
class Config:
    """主配置类，加载并管理所有配置和服务"""
    def __init__(self, config_file='conf/config.json'):
        self.config_data = self._load_config(config_file)
        self.listener = ListenerConfig(**self.config_data.get('listener', {}))
        self.connection_settings = ConnectionSettings(**self.config_data.get('connection_settings', {}))

        # 加载SOCKS5配置
        socks5_config_data = self.config_data.get('socks5', {})
        self.socks5_config = SOCKS5Config(**socks5_config_data)

        # 转换NAT模式
        nat_mode_map = {
            "proxy": NATMode.PROXY,
            "full_core": NATMode.FULL_CORE,
            "transparent": NATMode.TRANSPARENT
        }
        self.socks5_config.nat_mode = nat_mode_map.get(
            self.socks5_config.nat_mode,
            NATMode.PROXY
        )

        # 加载认证用户
        self.auth_users = []
        for user_data in self.socks5_config.auth_users:
            password_hash = user_data.get('password_hash')
            if not password_hash and 'password' in user_data:
                # 如果提供的是明文密码，生成哈希
                password_hash = hashlib.sha256(user_data['password'].encode('utf-8')).hexdigest()

            self.auth_users.append(AuthUser(
                username=user_data['username'],
                password_hash=password_hash,
                enabled=user_data.get('enabled', True)
            ))

        # 加载代理节点
        self.proxy_nodes = []
        for node_config in self.config_data.get('proxy_nodes', []):
            self.proxy_nodes.append(ProxyNode(**node_config))

        # 初始化中国路由管理器
        self.chnroutes = self.config_data.get('chnroutes', {})
        self.china_route_manager = ChinaRouteManager(self.chnroutes)

        # 初始化智能代理选择器
        self.proxy_selector = ProxySelector(self.proxy_nodes, self)

        # 初始化连接超时管理器
        self.timeout_manager = ConnectionTimeoutManager(self)

        # 初始化黑名单管理器
        blacklist_expiry = self.config_data.get('smart_proxy', {}).get('blacklist_expiry_minutes', 360)
        self.blacklist = SmartBlacklist(blacklist_expiry)

    def _load_config(self, config_file):
        """加载配置文件"""
        try:
            with open(config_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            logging.error(f"Failed to load config {config_file}: {e}")
            return {}
