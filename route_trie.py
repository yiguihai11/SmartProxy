#!/usr/bin/env python3
"""
通用路由基数树模块
支持IPv4和IPv6的高性能网络路由查找
"""

import asyncio
import ipaddress
import logging
from typing import Dict, Optional, Set
from dataclasses import dataclass, field

class IPv4TrieNode:
    """IPv4基数树节点"""
    __slots__ = ('children', 'is_network_end', 'network_info')

    def __init__(self):
        # 子节点：0-15每个十六进制位对应一个孩子
        self.children: Dict[int, 'IPv4TrieNode'] = {}
        self.is_network_end = False
        self.network_info: Optional[str] = None  # 存储网络信息

class IPv6TrieNode:
    """IPv6基数树节点"""
    __slots__ = ('children', 'is_network_end', 'network_info')

    def __init__(self):
        # 子节点：0-15每个十六进制位对应一个孩子
        self.children: Dict[int, 'IPv6TrieNode'] = {}
        self.is_network_end = False
        self.network_info: Optional[str] = None  # 存储网络信息

class IPv4RouteTrie:
    """高性能IPv4路由基数树"""

    def __init__(self):
        self.root = IPv4TrieNode()
        self.exact_ips: Set[int] = set()  # 精确IP匹配的哈希集合
        self.logger = logging.getLogger(f"{__name__}.IPv4RouteTrie")

    def insert_network(self, network_str: str):
        """插入一个IPv4网络段"""
        try:
            if '/' in network_str:
                # CIDR网络
                network = ipaddress.IPv4Network(network_str, strict=False)
                prefix_len = network.prefixlen

                # 将网络地址转换为32位整数
                network_int = int(network.network_address)

                # 只存储网络部分，忽略主机位
                if prefix_len <= 32:
                    self._insert_prefix(network_int, prefix_len, network_str)
            else:
                # 单个IP
                ip_int = int(ipaddress.IPv4Address(network_str))
                self.exact_ips.add(ip_int)

        except Exception as e:
            self.logger.warning(f"⚠️ Failed to insert IPv4 network {network_str}: {e}")

    def _insert_prefix(self, ip_int: int, prefix_len: int, network_info: str):
        """插入IPv4网络前缀到基数树"""
        node = self.root

        # 逐位插入，共prefix_len位
        for i in range(prefix_len):
            current_bit = (ip_int >> (31 - i)) & 1

            if current_bit not in node.children:
                node.children[current_bit] = IPv4TrieNode()

            node = node.children[current_bit]

        # 标记网络结束
        node.is_network_end = True
        node.network_info = network_info

    def lookup(self, ip_str: str) -> bool:
        """查找IPv4地址是否在路由表中"""
        try:
            ip_int = int(ipaddress.IPv4Address(ip_str))

            # 首先检查精确IP匹配
            if ip_int in self.exact_ips:
                return True

            # 在基数树中查找最长匹配
            return self._recursive_lookup(self.root, ip_int, 0)

        except Exception:
            return False

    def _recursive_lookup(self, node, ip_int: int, depth: int) -> bool:
        """递归查找IP是否匹配任何网络段"""
        # 如果当前节点标记为网络结束，检查IP是否在对应网络范围内
        if node.is_network_end and node.network_info:
            if '/' in node.network_info:
                network = ipaddress.IPv4Network(node.network_info, strict=False)
                ip = ipaddress.IPv4Address(ip_int)
                if ip in network:
                    return True

        # 如果已经遍历完所有32位，停止递归
        if depth >= 32:
            return False

        # 获取当前位对应的子节点
        current_bit = (ip_int >> (31 - depth)) & 1
        child_key = current_bit

        if child_key in node.children:
            return self._recursive_lookup(node.children[child_key], ip_int, depth + 1)

        return False

    def get_stats(self) -> Dict[str, int]:
        """获取统计信息"""
        def count_nodes(node):
            count = 1
            for child in node.children.values():
                count += count_nodes(child)
            return count

        return {
            'trie_nodes_count': count_nodes(self.root) - 1,
            'exact_ips_count': len(self.exact_ips)
        }

class IPv6RouteTrie:
    """高性能IPv6路由基数树"""

    def __init__(self):
        self.root = IPv6TrieNode()
        self.exact_ips: Set[int] = set()  # 精确IP匹配的哈希集合
        self.logger = logging.getLogger(f"{__name__}.IPv6RouteTrie")

    def insert_network(self, network_str: str):
        """插入一个IPv6网络段"""
        try:
            if '/' in network_str:
                # CIDR网络
                network = ipaddress.IPv6Network(network_str, strict=False)
                prefix_len = network.prefixlen

                # 将网络地址转换为128位整数
                network_int = int(network.network_address)

                # 只存储网络部分，忽略主机位
                if prefix_len <= 128:
                    self._insert_prefix(network_int, prefix_len, network_str)
            else:
                # 单个IP
                ip_int = int(ipaddress.IPv6Address(network_str))
                self.exact_ips.add(ip_int)

        except Exception as e:
            self.logger.warning(f"⚠️ Failed to insert IPv6 network {network_str}: {e}")

    def _insert_prefix(self, ip_int: int, prefix_len: int, network_info: str):
        """插入IPv6网络前缀到基数树"""
        node = self.root

        # 每4位为一个十六进制位，共32个
        for i in range(0, prefix_len, 4):
            if i + 4 <= prefix_len:
                # 提取当前4位
                nibble = (ip_int >> (128 - i - 4)) & 0xF

                if nibble not in node.children:
                    node.children[nibble] = IPv6TrieNode()

                node = node.children[nibble]

                # 如果这是最后一个完整的前缀，标记结束
                if i + 4 == prefix_len:
                    node.is_network_end = True
                    node.network_info = network_info
            else:
                # 不完整的4位，处理剩余位
                remaining_bits = prefix_len - i
                # 先提取当前的nibble
                nibble = (ip_int >> (128 - i - 4)) & 0xF
                # 扩展到完整的4位
                for mask in range(0, (1 << (4 - remaining_bits))):
                    extended_nibble = (nibble << (4 - remaining_bits)) | mask
                    if extended_nibble not in node.children:
                        node.children[extended_nibble] = IPv6TrieNode()
                    node.children[extended_nibble].is_network_end = True
                    node.children[extended_nibble].network_info = network_info
                break

    def lookup(self, ip_str: str) -> bool:
        """查找IPv6地址是否在路由表中"""
        try:
            ip_int = int(ipaddress.IPv6Address(ip_str))

            # 首先检查精确IP匹配
            if ip_int in self.exact_ips:
                return True

            # 然后在基数树中查找最长匹配
            node = self.root

            # 每4位为一个十六进制位，共32个
            for i in range(0, 128, 4):
                nibble = (ip_int >> (128 - i - 4)) & 0xF

                if nibble not in node.children:
                    break

                node = node.children[nibble]
                if node.is_network_end:
                    return True

            return False

        except Exception:
            return False

    def get_stats(self) -> Dict[str, int]:
        """获取统计信息"""
        def count_nodes(node):
            count = 1
            for child in node.children.values():
                count += count_nodes(child)
            return count

        return {
            'trie_nodes_count': count_nodes(self.root) - 1,
            'exact_ips_count': len(self.exact_ips)
        }

@dataclass
class RouteTrieStats:
    """路由基数树统计信息"""
    ipv4_networks: int = 0
    ipv6_networks: int = 0
    total_networks: int = 0
    ipv4_trie_nodes: int = 0
    ipv6_trie_nodes: int = 0
    total_trie_nodes: int = 0
    ipv4_exact_ips: int = 0
    ipv6_exact_ips: int = 0
    total_exact_ips: int = 0
    load_time: float = 0.0

class UniversalRouteTrie:
    """支持IPv4和IPv6的通用路由基数树"""

    def __init__(self):
        self.ipv4_trie = IPv4RouteTrie()
        self.ipv6_trie = IPv6RouteTrie()
        self.logger = logging.getLogger(f"{__name__}.UniversalRouteTrie")
        self._stats = RouteTrieStats()
        self._load_start_time = 0.0

    def begin_load(self):
        """开始加载过程，记录开始时间"""
        import time
        self._load_start_time = time.time()
        self._stats = RouteTrieStats()  # 重置统计

    def insert_network(self, network_str: str):
        """插入网络段，自动识别IPv4或IPv6"""
        try:
            if ':' in network_str:
                # IPv6地址
                self.ipv6_trie.insert_network(network_str)
                self._stats.ipv6_networks += 1
                self._stats.total_networks += 1
                self.logger.debug(f"Inserted IPv6 network: {network_str}")
            else:
                # IPv4地址
                self.ipv4_trie.insert_network(network_str)
                self._stats.ipv4_networks += 1
                self._stats.total_networks += 1
                self.logger.debug(f"Inserted IPv4 network: {network_str}")

        except Exception as e:
            self.logger.warning(f"⚠️ Failed to insert network {network_str}: {e}")

    def finish_load(self) -> RouteTrieStats:
        """完成加载过程，返回统计信息"""
        import time
        if self._load_start_time > 0:
            self._stats.load_time = time.time() - self._load_start_time

        # 获取详细的统计信息
        ipv4_stats = self.ipv4_trie.get_stats()
        ipv6_stats = self.ipv6_trie.get_stats()

        self._stats.ipv4_trie_nodes = ipv4_stats['trie_nodes_count']
        self._stats.ipv4_exact_ips = ipv4_stats['exact_ips_count']
        self._stats.ipv6_trie_nodes = ipv6_stats['trie_nodes_count']
        self._stats.ipv6_exact_ips = ipv6_stats['exact_ips_count']
        self._stats.total_trie_nodes = ipv4_stats['trie_nodes_count'] + ipv6_stats['trie_nodes_count']
        self._stats.total_exact_ips = ipv4_stats['exact_ips_count'] + ipv6_stats['exact_ips_count']

        return self._stats

    def lookup(self, ip_str: str) -> bool:
        """查找IP是否在路由表中，自动识别IPv4或IPv6"""
        try:
            if ':' in ip_str:
                # IPv6地址
                return self.ipv6_trie.lookup(ip_str)
            else:
                # IPv4地址
                return self.ipv4_trie.lookup(ip_str)
        except Exception:
            return False

    def get_stats(self) -> RouteTrieStats:
        """获取统计信息"""
        return self._stats

    def clear(self):
        """清空所有路由"""
        self.ipv4_trie = IPv4RouteTrie()
        self.ipv6_trie = IPv6RouteTrie()
        self._stats = RouteTrieStats()
        self._load_start_time = 0.0

    def insert_networks_from_file(self, file_path: str) -> RouteTrieStats:
        """从文件批量加载网络路由"""
        import os

        try:
            if not os.path.exists(file_path):
                self.logger.error(f"❌ Routes file not found: {file_path}")
                raise FileNotFoundError(f"Routes file not found: {file_path}")

            self.begin_load()
            routes_count = 0

            with open(file_path, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()

                    # 跳过注释和空行
                    if not line or line.startswith('#'):
                        continue

                    self.insert_network(line)
                    routes_count += 1

            stats = self.finish_load()
            self.logger.info(
                f"✅ Loaded {routes_count} routes from {file_path} in {stats.load_time:.3f}s "
                f"(IPv4: {stats.ipv4_networks}, IPv6: {stats.ipv6_networks}, "
                f"Trie: {stats.total_trie_nodes} nodes, {stats.total_exact_ips} exact IPs)"
            )

            return stats

        except Exception as e:
            self.logger.error(f"❌ Failed to load routes from {file_path}: {e}")
            raise

# 便捷函数
def create_route_trie() -> UniversalRouteTrie:
    """创建新的通用路由基数树"""
    return UniversalRouteTrie()

def load_routes_from_file(file_path: str) -> UniversalRouteTrie:
    """从文件创建并加载路由基数树"""
    trie = create_route_trie()
    trie.insert_networks_from_file(file_path)
    return trie

# 测试代码
if __name__ == "__main__":
    # 设置日志
    logging.basicConfig(level=logging.INFO)

    # 创建路由基数树
    trie = create_route_trie()

    # 插入测试网络
    trie.insert_network('192.168.1.0/24')
    trie.insert_network('2001:db8::/32')
    trie.insert_network('1.2.3.4')
    trie.insert_network('::1')

    # 测试查找
    print("IPv4测试:")
    print(f"  192.168.1.1: {trie.lookup('192.168.1.1')}")
    print(f"  10.0.0.1: {trie.lookup('10.0.0.1')}")
    print(f"  1.2.3.4: {trie.lookup('1.2.3.4')}")

    print("IPv6测试:")
    print(f"  2001:db8::1: {trie.lookup('2001:db8::1')}")
    print(f"  ::1: {trie.lookup('::1')}")

    # 显示统计信息
    stats = trie.get_stats()
    print(f"统计信息: {stats}")