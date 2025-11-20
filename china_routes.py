#!/usr/bin/env python3
"""
中国路由管理器模块
使用通用路由基数树进行高性能IP路由查询
"""

import logging
from typing import Optional, Dict

# 导入通用路由基数树
from route_trie import UniversalRouteTrie, RouteTrieStats

class ChinaRouteManager:
    """高性能中国路由管理器 - 使用通用基数树支持IPv4和IPv6"""

    def __init__(self, config: Optional[Dict] = None):
        self.logger = logging.getLogger(f"{__name__}.ChinaRouteManager")
        self.enabled = False
        self.routes_file = "conf/chnroutes.txt"
        self.route_trie = UniversalRouteTrie()
        self._load_time = 0.0
        self._lookup_count = 0
        self._stats: RouteTrieStats = RouteTrieStats()

        if config:
            self.enabled = config.get('enable', False)
            self.routes_file = config.get('path', 'conf/chnroutes.txt')

        if self.enabled:
            self._load_routes()

    def _load_routes(self):
        """从文件加载中国路由规则到基数树"""
        try:
            stats = self.route_trie.insert_networks_from_file(self.routes_file)
            self._stats = stats
            self._load_time = stats.load_time

        except Exception as e:
            self.logger.error(f"❌ Failed to load China routes: {e}")
            self.enabled = False

    def is_china_ip(self, ip: str) -> bool:
        """判断IP是否为中国IP"""
        if not self.enabled:
            return False

        self._lookup_count += 1
        return self.route_trie.lookup(ip)

    def get_stats(self) -> Dict[str, any]:
        """获取统计信息"""
        if self._stats and self._stats.load_time > 0:
            return {
                'enabled': self.enabled,
                'routes_file': self.routes_file,
                'load_time': self._load_time,
                'lookup_count': self._lookup_count,
                'ipv4_networks': self._stats.ipv4_networks,
                'ipv6_networks': self._stats.ipv6_networks,
                'total_networks': self._stats.total_networks,
                'trie_nodes': self._stats.total_trie_nodes,
                'exact_ips': self._stats.total_exact_ips,
                'ipv4_trie_nodes': self._stats.ipv4_trie_nodes,
                'ipv6_trie_nodes': self._stats.ipv6_trie_nodes,
                'ipv4_exact_ips': self._stats.ipv4_exact_ips,
                'ipv6_exact_ips': self._stats.ipv6_exact_ips
            }
        else:
            return {
                'enabled': self.enabled,
                'routes_file': self.routes_file,
                'load_time': self._load_time,
                'lookup_count': self._lookup_count,
                'ipv4_networks': 0,
                'ipv6_networks': 0,
                'total_networks': 0,
                'trie_nodes': 0,
                'exact_ips': 0,
                'ipv4_trie_nodes': 0,
                'ipv6_trie_nodes': 0,
                'ipv4_exact_ips': 0,
                'ipv6_exact_ips': 0
            }

# 测试代码
if __name__ == "__main__":
    # 设置日志
    logging.basicConfig(level=logging.INFO)

    # 测试配置
    test_config = {
        'enable': True,
        'path': 'conf/chnroutes.txt'
    }

    # 创建中国路由管理器
    manager = ChinaRouteManager(test_config)

    # 测试IP查询
    test_ips = [
        "8.8.8.8",      # 美国Google DNS
        "114.114.114.114", # 中国114 DNS
        "1.1.1.1",      # Cloudflare DNS
        "223.5.5.5",    # 中国阿里DNS
        "2001:db8::1",  # IPv6测试
    ]

    print("IP查询测试:")
    for ip in test_ips:
        result = manager.is_china_ip(ip)
        print(f"  {ip}: {'中国' if result else '外国'}")

    # 显示统计信息
    stats = manager.get_stats()
    print(f"统计信息: {stats}")