#!/usr/bin/env python3
"""
智能代理选择器模块
"""

import logging
import time
import random
import re
from typing import List, Any, Optional, Dict

# 导入SNI提取器
from sni_extractor import SNIExtractor

class ProxySelector:
    """智能代理选择器 - 统一管理代理节点选择逻辑"""

    def __init__(self, proxy_nodes: List[Any], config: Any = None):
        self.logger = logging.getLogger(f"{__name__}.ProxySelector")
        self.proxy_nodes = proxy_nodes
        self.config = config
        self.current_index = 0
        self.node_health = {}  # 节点健康状态
        self.node_stats = {}   # 节点统计信息

        # SNI提取器
        self.sni_extractor = SNIExtractor()

        # 初始化节点状态
        for i, node in enumerate(self.proxy_nodes):
            node_id = getattr(node, 'identifier', f'proxy_{i}')
            self.node_health[node_id] = {
                'alive': True,
                'last_check': 0,
                'fail_count': 0,
                'response_time': 0.0
            }
            self.node_stats[node_id] = {
                'total_requests': 0,
                'successful_requests': 0,
                'failed_requests': 0,
                'last_used': 0
            }

        # 创建代理节点映射，便于快速查找
        self.proxy_node_map = {}
        for node in self.proxy_nodes:
            node_id = getattr(node, 'identifier', None)
            if node_id:
                self.proxy_node_map[node_id] = node

    def select_proxy(self, traffic_info: Any = None) -> Optional[Any]:
        """
        智能选择代理节点

        Args:
            traffic_info: 流量信息，可用于高级选择逻辑

        Returns:
            选中的代理节点，如果没有可用节点则返回None
        """
        if not self.proxy_nodes:
            self.logger.warning("⚠️ No proxy nodes configured")
            return None

        # 1. 过滤健康的节点
        healthy_nodes = []
        for i, node in enumerate(self.proxy_nodes):
            node_id = getattr(node, 'identifier', f'proxy_{i}')
            health = self.node_health.get(node_id, {})

            if health.get('alive', True) and health.get('fail_count', 0) < 3:
                healthy_nodes.append((i, node, node_id))

        if not healthy_nodes:
            self.logger.warning("⚠️ No healthy proxy nodes available, falling back to first node")
            return self.proxy_nodes[0]

        # 2. 使用加权随机算法选择节点
        selected_index, selected_node, selected_id = self._weighted_random_selection(healthy_nodes)

        # 3. 更新统计信息
        self.node_stats[selected_id]['total_requests'] += 1
        self.node_stats[selected_id]['last_used'] = time.time()
        self.current_index = selected_index

        self.logger.debug(f"🎯 Selected proxy node: {selected_id}")
        return selected_node

    def _weighted_random_selection(self, healthy_nodes: List[tuple]) -> tuple:
        """
        加权随机选择算法

        Args:
            healthy_nodes: [(index, node, node_id), ...] 健康节点列表

        Returns:
            (index, node, node_id) 选中的节点信息
        """
        # 计算权重（基于响应时间和成功率）
        weights = []
        total_weight = 0

        for index, node, node_id in healthy_nodes:
            health = self.node_health[node_id]
            stats = self.node_stats[node_id]

            # 基础权重
            base_weight = 1.0

            # 响应时间权重（响应时间越短权重越高）
            response_time = health.get('response_time', 0.1)
            time_weight = max(0.1, 1.0 / (1.0 + response_time))

            # 成功率权重
            total_requests = max(1, stats.get('total_requests', 1))
            success_rate = (total_requests - stats.get('failed_requests', 0)) / total_requests
            success_weight = max(0.1, success_rate)

            # 综合权重
            weight = base_weight * time_weight * success_weight
            weights.append(weight)
            total_weight += weight

        # 加权随机选择
        if total_weight > 0:
            rand_val = random.random() * total_weight
            cumulative_weight = 0

            for i, weight in enumerate(weights):
                cumulative_weight += weight
                if rand_val <= cumulative_weight:
                    return healthy_nodes[i]

        # 如果计算出错，返回第一个健康节点
        return healthy_nodes[0]

    def report_success(self, node: Any, response_time: float = 0.0):
        """
        报告代理节点成功使用

        Args:
            node: 代理节点
            response_time: 响应时间（毫秒）
        """
        node_id = getattr(node, 'identifier', 'unknown')
        if node_id in self.node_health:
            self.node_health[node_id]['alive'] = True
            self.node_health[node_id]['last_check'] = time.time()
            self.node_health[node_id]['response_time'] = response_time
            self.node_health[node_id]['fail_count'] = 0

        if node_id in self.node_stats:
            self.node_stats[node_id]['successful_requests'] += 1

    def report_failure(self, node: Any, error: str = ""):
        """
        报告代理节点使用失败

        Args:
            node: 代理节点
            error: 错误信息
        """
        node_id = getattr(node, 'identifier', 'unknown')
        self.logger.warning(f"❌ Proxy node {node_id} failed: {error}")

        if node_id in self.node_health:
            self.node_health[node_id]['alive'] = False
            self.node_health[node_id]['last_check'] = time.time()
            self.node_health[node_id]['fail_count'] += 1

        if node_id in self.node_stats:
            self.node_stats[node_id]['failed_requests'] += 1

    def get_proxy_stats(self) -> Dict[str, Any]:
        """获取代理节点统计信息"""
        return {
            'total_nodes': len(self.proxy_nodes),
            'healthy_nodes': sum(1 for h in self.node_health.values() if h.get('alive', True)),
            'node_health': self.node_health.copy(),
            'node_stats': self.node_stats.copy()
        }

    def health_check(self):
        """健康检查 - 重置连续失败次数过多的节点"""
        current_time = time.time()

        for node_id, health in self.node_health.items():
            # 获取健康检查间隔配置
            health_check_interval = 300  # 默认5分钟
            if self.config and hasattr(self.config, 'config_data'):
                health_check_interval = self.config.config_data.get('node_health_check', {}).get('interval_seconds', 300)

            # 如果节点失败次数过多且距离上次检查超过配置间隔，尝试恢复
            if (health.get('fail_count', 0) >= 3 and
                current_time - health.get('last_check', 0) > health_check_interval):
                health['alive'] = True
                health['fail_count'] = 2  # 给一个观察机会
                self.logger.info(f"🔄 Attempting to recover proxy node: {node_id}")

    def check_sni_and_rebind(self, initial_proxy: Any, data: bytes, target_port: int) -> Optional[Any]:
        """
        检查SNI并根据proxy_bind_rules重新绑定代理

        Args:
            initial_proxy: 初始选择的代理节点
            data: 客户端发送的数据
            target_port: 目标端口

        Returns:
            ProxyNode or None: 如果需要重新绑定则返回新的代理节点，否则返回None
        """
        try:
            # 1. 检查是否为TLS流量（基于常见TLS端口）
            tls_ports = [443, 8443, 993, 995, 465, 636, 989, 990, 992, 5061]
            if target_port not in tls_ports:
                return None

            # 2. 提取SNI信息
            sni = self.sni_extractor.parse_sni(data)
            if not sni:
                self.logger.debug(f"No SNI found in data for port {target_port}")
                return None

            self.logger.info(f"🔍 Detected SNI: {sni}")

            # 3. 检查proxy_bind_rules
            if not self.config:
                return None

            proxy_bind_rules = self.config.config_data.get('proxy_bind_rules', [])
            if not proxy_bind_rules:
                return None

            # 4. 查找匹配的绑定规则
            for rule in proxy_bind_rules:
                pattern = rule.get('pattern', '')
                target_identifier = rule.get('target', '')

                if not target_identifier:
                    continue

                # 跳过端口规则，只检查域名模式
                if pattern.isdigit() or (pattern.startswith('[') and pattern.endswith(']')):
                    continue

                # 检查域名模式匹配
                if self._match_hostname_pattern(pattern, sni):
                    self.logger.info(f"🔗 SNI-based proxy binding: {sni} matches {pattern} -> {target_identifier}")

                    # 查找目标代理节点
                    target_proxy = self.proxy_node_map.get(target_identifier)
                    if target_proxy:
                        # 检查是否与当前代理不同
                        initial_proxy_id = getattr(initial_proxy, 'identifier', '')
                        if initial_proxy_id != target_identifier:
                            self.logger.info(f"🔄 Rebinding from {initial_proxy_id} to {target_identifier} based on SNI")
                            return target_proxy
                        else:
                            self.logger.debug(f"🔗 Already using correct proxy: {target_identifier}")
                    else:
                        self.logger.warning(f"🔗 Target proxy {target_identifier} not found or disabled")

                    break

            return None

        except Exception as e:
            self.logger.error(f"Error in SNI-based rebinding: {e}")
            return None

    def _match_hostname_pattern(self, pattern: str, hostname: str) -> bool:
        """
        匹配主机名模式

        Args:
            pattern: 模式 (如 *.google.com)
            hostname: 主机名

        Returns:
            bool: 是否匹配
        """
        try:
            if '*' in pattern:
                # 通配符匹配
                regex_pattern = pattern.replace('.', r'\.').replace('*', '.*')
                return re.fullmatch(regex_pattern, hostname) is not None
            else:
                # 精确匹配
                return pattern == hostname
        except Exception:
            return False
