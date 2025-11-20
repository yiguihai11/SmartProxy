#!/usr/bin/env python3
"""
连接超时管理器模块
"""

import logging
import time
from typing import Dict, List, Any

class ConnectionTimeoutManager:
    """智能连接超时管理器 - 根据连接类型和状态动态调整超时策略"""

    def __init__(self, config: Any):
        self.config = config
        self.logger = logging.getLogger(f"{__name__}.ConnectionTimeoutManager")

        # 连接状态跟踪
        self.active_connections = {}  # 活跃连接状态
        self.connection_stats = {     # 连接统计信息
            'tcp_connections': 0,
            'udp_sessions': 0,
            'total_timeouts': 0,
            'avg_connection_duration': 0.0
        }

        # 动态超时策略
        self.adaptive_timeouts = {
            'tcp_short': 30,      # 短连接TCP超时 (如HTTP请求)
            'tcp_long': 300,      # 长连接TCP超时 (如WebSocket)
            'tcp_idle': 60,       # 空闲TCP超时 (默认配置)
            'udp_active': 60,     # 活跃UDP会话超时
            'udp_idle': 180       # 空闲UDP会话超时
        }

        # 连接类型检测模式
        self.connection_patterns = {
            'http_ports': [80, 443, 8080, 8443],
            'streaming_ports': [1935, 8000, 9000],
            'gaming_ports': range(10000, 20000),
            'bittorrent_ports': [6881, 6882, 6883, 6884, 6885, 6886, 6887, 6888, 6889]
        }

    def get_tcp_timeout(self, connection_info: Dict[str, Any]) -> int:
        """
        根据连接信息动态确定TCP超时时间

        Args:
            connection_info: 包含目标端口、协议类型、连接状态等信息

        Returns:
            优化的超时时间（秒）
        """
        target_port = connection_info.get('target_port', 0)
        bytes_transferred = connection_info.get('bytes_transferred', 0)
        connection_age = connection_info.get('connection_age', 0)
        is_idle = connection_info.get('is_idle', False)

        # 检测连接类型
        if target_port in self.connection_patterns['http_ports']:
            # HTTP/HTTPS连接 - 通常较短但有keep-alive
            if bytes_transferred > 1024 * 1024:  # 大文件传输
                return min(self.adaptive_timeouts['tcp_long'], connection_age + 120)
            elif is_idle:
                return self.adaptive_timeouts['tcp_short']
            else:
                return self.adaptive_timeouts['tcp_idle']

        elif target_port in self.connection_patterns['streaming_ports']:
            # 流媒体连接 - 需要更长的超时
            return self.adaptive_timeouts['tcp_long']

        elif target_port in self.connection_patterns['gaming_ports']:
            # 游戏连接 - 需要低延迟但稳定的连接
            return max(self.adaptive_timeouts['tcp_idle'], 120)

        elif target_port in self.connection_patterns['bittorrent_ports']:
            # P2P连接 - 长时间保持
            return self.adaptive_timeouts['tcp_long']

        else:
            # 默认策略 - 根据连接历史动态调整
            if connection_age > 300 and bytes_transferred > 10 * 1024 * 1024:
                # 长期活跃的大流量连接
                return self.adaptive_timeouts['tcp_long']
            elif is_idle:
                return self.adaptive_timeouts['tcp_idle']
            else:
                return self.config.connection_settings.get('tcp_timeout_seconds', 60)

    def get_udp_timeout(self, session_info: Dict[str, Any]) -> int:
        """
        根据UDP会话信息确定超时时间

        Args:
            session_info: 包含端口、协议类型、活动状态等信息

        Returns:
            优化的超时时间（秒）
        """
        target_port = session_info.get('target_port', 0)
        packet_count = session_info.get('packet_count', 0)
        last_activity = session_info.get('last_activity', 0)
        time_since_activity = time.time() - last_activity

        # DNS查询 - 短超时
        if target_port == 53:
            return 30

        # DHCP - 中等超时
        elif target_port in [67, 68]:
            return 120

        # 游戏或实时应用 - 根据活动频率调整
        elif packet_count > 100:  # 高频会话
            if time_since_activity < 10:  # 仍在活跃
                return self.adaptive_timeouts['udp_active']
            else:  # 短暂空闲
                return self.adaptive_timeouts['udp_idle']

        # 默认UDP会话超时
        return self.config.connection_settings.get('udp_timeout_seconds', 300)

    def should_force_close_udp(self, session_info: Dict[str, Any]) -> bool:
        """
        判断是否应该强制关闭UDP会话

        Args:
            session_info: UDP会话信息

        Returns:
            是否强制关闭
        """
        # 检查会话异常情况
        error_count = session_info.get('error_count', 0)
        last_activity = session_info.get('last_activity', 0)
        time_since_activity = time.time() - last_activity
        timeout = self.get_udp_timeout(session_info)

        # 异常情况立即关闭
        if error_count > 5:
            return True

        # 长时间无活动且无数据传输
        if time_since_activity > timeout * 1.5:
            return True

        return False

    def register_connection(self, conn_id: str, conn_type: str, info: Dict[str, Any]):
        "注册新连接进行跟踪"
        self.active_connections[conn_id] = {
            'type': conn_type,
            'created_at': time.time(),
            'last_activity': time.time(),
            'info': info
        }

        if conn_type == 'tcp':
            self.connection_stats['tcp_connections'] += 1
        elif conn_type == 'udp':
            self.connection_stats['udp_sessions'] += 1

    def update_connection_activity(self, conn_id: str, bytes_count: int = 0):
        "更新连接活动状态"
        if conn_id in self.active_connections:
            self.active_connections[conn_id]['last_activity'] = time.time()
            self.active_connections[conn_id]['info']['bytes_transferred'] = \
                self.active_connections[conn_id]['info'].get('bytes_transferred', 0) + bytes_count

    def cleanup_expired_connections(self) -> List[str]:
        "清理过期连接，返回被清理的连接ID列表"
        current_time = time.time()
        expired_connections = []

        for conn_id, conn_data in list(self.active_connections.items()):
            conn_type = conn_data['type']
            last_activity = conn_data['last_activity']

            if conn_type == 'tcp':
                timeout = self.get_tcp_timeout(conn_data['info'])
            elif conn_type == 'udp':
                timeout = self.get_udp_timeout(conn_data['info'])
            else:
                continue

            if current_time - last_activity > timeout:
                expired_connections.append(conn_id)
                del self.active_connections[conn_id]

                # 更新统计
                if conn_type == 'tcp':
                    self.connection_stats['tcp_connections'] -= 1
                elif conn_type == 'udp':
                    self.connection_stats['udp_sessions'] -= 1
                self.connection_stats['total_timeouts'] += 1

        return expired_connections

    def get_connection_stats(self) -> Dict[str, Any]:
        "获取连接统计信息"
        return {
            **self.connection_stats,
            'active_connections': len(self.active_connections),
            'memory_usage_estimate': len(self.active_connections) * 256  # 估算内存使用
        }
