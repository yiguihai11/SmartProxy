#!/usr/bin/env python3
"""
智能DNS模块
实现基于chnroutes的DNS分流查询
"""

import asyncio
import socket
import struct
import logging
import time
import random
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from collections import defaultdict
import threading

# 导入中国路由管理器
from china_routes import ChinaRouteManager

class DNSProxyProtocol:
    """DNS代理协议处理器"""

    def __init__(self):
        self.response = None
        self.event = asyncio.Event()
        self.logger = logging.getLogger(f"{__name__}.DNSProxyProtocol")

    def datagram_received(self, data: bytes, addr):
        """接收UDP数据包"""
        if not self.event.is_set():
            self.response = data
            self.event.set()

    def error_received(self, exc):
        """错误处理"""
        self.logger.error(f"DNS proxy error: {exc}")
        self.event.set()

    async def get_response(self):
        """获取响应"""
        await self.event.wait()
        return self.response

@dataclass
class DNSRecord:
    """DNS记录"""
    ips: List[str]  # IP地址列表
    ttl: int        # 生存时间
    timestamp: float  # 缓存时间戳

@dataclass
class DNSServer:
    """DNS服务器信息"""
    host: str
    port: int
    proxy: Optional[Any] = None  # 使用的代理节点

class SmartDNSResolver:
    """智能DNS解析器"""

    def __init__(self, config: Dict, china_route_manager: ChinaRouteManager):
        self.logger = logging.getLogger(f"{__name__}.SmartDNSResolver")
        self.config = config
        self.china_route_manager = china_route_manager

        # DNS服务器配置 - 支持两种配置结构
        if 'groups' in config:
            # 如果有groups包装，则从groups中获取
            groups_config = config.get('groups', {})
            cn_list = groups_config.get('cn', [])
            foreign_list = groups_config.get('foreign', [])
        else:
            # 否则直接从config根层获取
            cn_list = config.get('cn', [])
            foreign_list = config.get('foreign', [])

        self.cn_servers = self._parse_dns_servers(cn_list)
        self.foreign_servers = self._parse_dns_servers(foreign_list)

        # 缓存配置
        cache_config = config.get('cache', {})
        self.max_cache_size = cache_config.get('max_size', 2000)
        self.default_ttl = cache_config.get('default_ttl', 300)
        self.cleanup_interval = cache_config.get('cleanup_interval', 60)

        # DNS缓存
        self.cache: Dict[str, DNSRecord] = {}
        self.cache_lock = threading.RLock()

        # DNS劫持规则
        self.hijack_rules = self._parse_hijack_rules(config.get('hijack_rules', []))

        # 统计信息
        self.stats = {
            'total_queries': 0,
            'cache_hits': 0,
            'cn_queries': 0,
            'foreign_queries': 0,
            'mixed_results': 0,
            'hijacked_queries': 0,
            'errors': 0
        }

        # 启动缓存清理任务
        self._cleanup_task = None

    def _parse_dns_servers(self, server_list: List[str]) -> List[DNSServer]:
        """解析DNS服务器配置"""
        servers = []
        for server in server_list:
            try:
                if ':' in server:
                    host, port = server.rsplit(':', 1)
                    servers.append(DNSServer(host.strip(), int(port.strip())))
            except Exception as e:
                self.logger.error(f"Invalid DNS server format: {server} - {e}")
        return servers

    def _parse_hijack_rules(self, rules_config: List[Dict]) -> List[Dict]:
        """解析DNS劫持规则"""
        rules = []
        for rule_config in rules_config:
            try:
                pattern = rule_config.get('pattern', '').strip()
                target = rule_config.get('target', '').strip()
                description = rule_config.get('description', '')

                if not pattern or not target:
                    self.logger.warning(f"Invalid DNS hijack rule: pattern='{pattern}', target='{target}'")
                    continue

                # 验证target是否为有效IP
                import socket
                try:
                    socket.inet_aton(target)
                except socket.error:
                    self.logger.warning(f"Invalid target IP in DNS hijack rule: {target}")
                    continue

                rule = {
                    'pattern': pattern,
                    'target': target,
                    'description': description,
                    'is_wildcard': '*' in pattern
                }

                rules.append(rule)
                self.logger.info(f"Loaded DNS hijack rule: {pattern} -> {target} ({description})")

            except Exception as e:
                self.logger.error(f"Failed to parse DNS hijack rule: {rule_config} - {e}")

        return rules

    def _match_hijack_rule(self, domain: str) -> Optional[str]:
        """匹配DNS劫持规则，返回目标IP或None"""
        for rule in self.hijack_rules:
            pattern = rule['pattern']

            if rule['is_wildcard']:
                # 通配符匹配
                if pattern.startswith('*.'):
                    # 去掉 *. 前缀进行后缀匹配
                    suffix = pattern[2:]
                    if domain == suffix or domain.endswith('.' + suffix):
                        self.logger.debug(f"DNS hijack matched: {domain} -> {rule['target']} (wildcard)")
                        return rule['target']
                else:
                    # 其他通配符情况暂时不支持
                    pass
            else:
                # 精确匹配
                if domain == pattern:
                    self.logger.debug(f"DNS hijack matched: {domain} -> {rule['target']} (exact)")
                    return rule['target']

        return None

    async def start(self):
        """启动DNS解析器"""
        self.logger.info("SmartDNS resolver starting...")
        self.logger.info(f"CN servers: {[f'{s.host}:{s.port}' for s in self.cn_servers]}")
        self.logger.info(f"Foreign servers: {[f'{s.host}:{s.port}' for s in self.foreign_servers]}")
        self.logger.info(f"DNS hijack rules loaded: {len(self.hijack_rules)}")

        # 启动缓存清理任务
        if self.cleanup_interval > 0:
            self._cleanup_task = asyncio.create_task(self._cleanup_cache_task())

    async def stop(self):
        """停止DNS解析器"""
        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass

    async def resolve(self, domain: str, query_type: str = 'A') -> List[str]:
        """
        智能DNS解析

        Args:
            domain: 要解析的域名
            query_type: 查询类型 (A, AAAA等)

        Returns:
            List[str]: IP地址列表
        """
        self.stats['total_queries'] += 1
        cache_key = f"{domain}:{query_type}"

        # 0. 检查DNS劫持规则（优先级最高）
        hijacked_target = self._match_hijack_rule(domain)
        if hijacked_target:
            self.stats['hijacked_queries'] += 1
            self.logger.info(f"DNS hijacked: {domain} -> {hijacked_target}")

            # 为劫持的域名创建缓存条目（使用较短的TTL）
            self._cache_result(cache_key, [hijacked_target], 60)  # 1分钟TTL
            return [hijacked_target]

        # 1. 检查缓存
        with self.cache_lock:
            if cache_key in self.cache:
                record = self.cache[cache_key]
                # 检查TTL是否过期
                if time.time() - record.timestamp < record.ttl:
                    self.stats['cache_hits'] += 1
                    self.logger.debug(f"Cache hit for {domain}: {record.ips}")
                    return record.ips.copy()
                else:
                    # 缓存过期，删除
                    del self.cache[cache_key]

        # 2. 默认使用国内组查询
        result_ips = await self._query_with_group(domain, query_type, 'cn')
        if not result_ips:
            self.logger.warning(f"CN group query failed for {domain}")
            return []

        # 3. 分析结果，判断是否需要使用国外组结果
        cn_has_china_ip = any(self.china_route_manager.is_china_ip(ip) for ip in result_ips)
        cn_has_foreign_ip = any(not self.china_route_manager.is_china_ip(ip) for ip in result_ips)

        # 如果国内组返回的结果包含国外IP（被污染），使用国外组的查询结果
        if cn_has_foreign_ip:
            self.logger.info(f"CN group returned foreign IPs (polluted) for {domain}, using foreign group results")
            foreign_ips = await self._query_with_group(domain, query_type, 'foreign')
            if foreign_ips:
                self.logger.info(f"Using foreign group results for {domain}: {foreign_ips}")
                self.stats['mixed_results'] += 1

                # 缓存国外组的结果（更可靠）
                self._cache_result(cache_key, foreign_ips, self.default_ttl)
                return foreign_ips
            else:
                self.logger.warning(f"Foreign group query failed for {domain}, falling back to CN results")

        # 4. 缓存并返回国内组结果（纯净的情况下）
        self._cache_result(cache_key, result_ips, self.default_ttl)
        return result_ips

    async def _query_with_group(self, domain: str, query_type: str, group: str) -> List[str]:
        """使用指定组进行DNS查询"""
        if group == 'cn':
            servers = self.cn_servers
            self.stats['cn_queries'] += 1
            query_method = self._query_direct  # 国内查询直连
        else:
            servers = self.foreign_servers
            self.stats['foreign_queries'] += 1
            query_method = self._query_via_proxy  # 国外查询走代理

        # 随机选择一个服务器
        server = random.choice(servers)

        try:
            return await query_method(domain, query_type, server)
        except Exception as e:
            self.logger.error(f"DNS query error with {group} group {server.host}:{server.port}: {e}")
            self.stats['errors'] += 1

            # 尝试其他服务器
            for other_server in servers:
                if other_server != server:
                    try:
                        return await query_method(domain, query_type, other_server)
                    except Exception as e2:
                        self.logger.error(f"DNS query error with alternative server {other_server.host}:{other_server.port}: {e2}")

            return []

    async def _query_direct(self, domain: str, query_type: str, server: DNSServer) -> List[str]:
        """直连DNS查询"""
        try:
            # 创建UDP socket
            loop = asyncio.get_event_loop()

            # 构建DNS查询包
            query_data = self._build_dns_query(domain, query_type)

            # 发送查询
            transport, protocol = await loop.create_datagram_endpoint(
                lambda: DNSQueryProtocol(),
                local_addr=('0.0.0.0', 0)
            )

            try:
                transport.sendto(query_data, (server.host, server.port))

                # 等待响应
                response = await asyncio.wait_for(
                    protocol.get_response(),
                    timeout=5.0
                )

                return self._parse_dns_response(response)

            finally:
                transport.close()

        except Exception as e:
            self.logger.error(f"Direct DNS query error: {e}")
            raise

    async def _query_via_proxy(self, domain: str, query_type: str, server: DNSServer) -> List[str]:
        """通过代理进行DNS查询"""
        try:
            self.logger.info(f"Foreign DNS query via proxy: {domain}")

            # 如果已经指定了代理节点，使用该代理
            if server.proxy:
                return await self._query_via_specific_proxy(domain, query_type, server, server.proxy)

            # 否则，需要选择一个可用的代理节点
            # 这里需要从ProxySelector获取代理节点
            # 简化实现：先尝试配置中的代理节点

            # 获取代理选择器
            from config import Config
            config = Config()
            if hasattr(config, 'proxy_selector') and config.proxy_selector:
                # 创建流量信息用于代理选择
                traffic_info = type('TrafficInfo', (), {
                    'target_ip': server.host,
                    'target_port': server.port,
                    'protocol': 'udp',
                    'hostname': domain
                })()

                # 选择代理节点
                proxy_node = config.proxy_selector.select_proxy(traffic_info)
                if proxy_node:
                    return await self._query_via_specific_proxy(domain, query_type, server, proxy_node)
                else:
                    self.logger.warning("No available proxy for DNS query, falling back to direct")
                    return await self._query_direct(domain, query_type, server)
            else:
                self.logger.warning("No proxy selector available, using direct DNS query")
                return await self._query_direct(domain, query_type, server)

        except Exception as e:
            self.logger.error(f"Proxy DNS query error: {e}")
            raise

    async def _query_via_specific_proxy(self, domain: str, query_type: str, server: DNSServer, proxy_node) -> List[str]:
        """通过指定的代理节点进行DNS查询"""
        try:
            self.logger.info(f"Querying {domain} via proxy {proxy_node.identifier} -> {server.host}:{server.port}")

            # 构建DNS查询包
            query_data = self._build_dns_query(domain, query_type)

            # 通过SOCKS5代理发送UDP数据包
            # 这里需要实现UDP over SOCKS5的代理通信
            # 简化实现：使用SOCKS5 UDP ASSOCIATE
            loop = asyncio.get_event_loop()

            # 1. 连接到代理服务器
            reader, writer = await asyncio.open_connection(
                proxy_node.ip,
                proxy_node.port
            )

            try:
                # 2. SOCKS5握手
                from utils import SOCKS5_VERSION, SOCKS5_AUTH_NONE
                writer.write(bytes([SOCKS5_VERSION, 1, SOCKS5_AUTH_NONE]))
                await writer.drain()

                response = await reader.read(2)
                if len(response) != 2 or response[0] != SOCKS5_VERSION or response[1] != SOCKS5_AUTH_NONE:
                    self.logger.error(f"Proxy authentication failed: {proxy_node.identifier}")
                    return []

                # 3. 发送UDP ASSOCIATE请求
                # 构建SOCKS5 UDP ASSOCIATE请求
                udp_associate = self._build_udp_associate_request('0.0.0.0', 0)

                writer.write(udp_associate)
                await writer.drain()

                # 读取响应
                response = await reader.read(10)
                if len(response) < 4 or response[0] != SOCKS5_VERSION or response[1] != 0x00:
                    self.logger.error(f"UDP associate failed: {proxy_node.identifier}")
                    return []

                # 解析UDP代理地址
                if response[3] == 0x01:  # IPv4
                    udp_proxy_ip = socket.inet_ntop(socket.AF_INET, response[4:8])
                    udp_proxy_port = struct.unpack('!H', response[8:10])[0]
                else:
                    self.logger.error("Unsupported address type in UDP associate response")
                    return []

                self.logger.info(f"UDP proxy established: {udp_proxy_ip}:{udp_proxy_port}")

                # 4. 通过UDP代理发送DNS查询
                dns_response = await self._send_dns_via_udp_proxy(
                    query_data, server, udp_proxy_ip, udp_proxy_port
                )

                if dns_response:
                    return self._parse_dns_response(dns_response)

            finally:
                writer.close()
                await writer.wait_closed()

        except Exception as e:
            self.logger.error(f"SOCKS5 proxy DNS query error: {e}")
            raise

    def _build_udp_associate_request(self, bind_address: str, bind_port: int) -> bytes:
        """构建SOCKS5 UDP ASSOCIATE请求"""
        from utils import SOCKS5_VERSION, SOCKS5_CMD_UDP_ASSOCIATE, SOCKS5_ATYP_IPV4

        request = bytearray()
        request.extend([SOCKS5_VERSION, SOCKS5_CMD_UDP_ASSOCIATE, 0x00, SOCKS5_ATYP_IPV4])

        # 绑定地址
        request.extend(socket.inet_aton(bind_address))
        request.extend(struct.pack('!H', bind_port))

        return bytes(request)

    async def _send_dns_via_udp_proxy(self, query_data: bytes, dns_server: DNSServer,
                                     udp_proxy_ip: str, udp_proxy_port: int) -> bytes:
        """通过UDP代理发送DNS查询"""
        loop = asyncio.get_event_loop()

        # 创建UDP socket连接到代理
        transport, protocol = await loop.create_datagram_endpoint(
            lambda: DNSProxyProtocol(),
            local_addr=('0.0.0.0', 0)
        )

        try:
            # 构建SOCKS5 UDP数据包
            # SOCKS5 UDP包格式: RSV(2) + FRAG(1) + ATYP(1) + DST.ADDR + DST.PORT + DATA
            socks5_packet = self._build_socks5_udp_packet(dns_server.host, dns_server.port, query_data)

            # 发送查询到UDP代理
            transport.sendto(socks5_packet, (udp_proxy_ip, udp_proxy_port))

            # 等待响应
            response = await asyncio.wait_for(
                protocol.get_response(),
                timeout=5.0
            )

            # 从SOCKS5 UDP包中提取DNS响应数据
            return self._extract_dns_from_socks5_response(response)

        finally:
            transport.close()

    def _build_socks5_udp_packet(self, target_host: str, target_port: int, data: bytes) -> bytes:
        """构建SOCKS5 UDP数据包"""
        # SOCKS5 UDP包格式: RSV(2) + FRAG(1) + ATYP(1) + DST.ADDR + DST.PORT + DATA
        packet = bytearray()

        # RSV (Reserved) - 2 bytes, should be 0x0000
        packet.extend([0x00, 0x00])

        # FRAG - 1 byte, 0x00 for standalone
        packet.append(0x00)

        # ATYP (Address Type) - 1 byte
        if ':' in target_host:  # IPv6
            packet.append(0x04)  # ATYP_IPV6
            addr_bytes = socket.inet_pton(socket.AF_INET6, target_host)
        else:  # IPv4 or hostname
            try:
                socket.inet_pton(socket.AF_INET, target_host)
                packet.append(0x01)  # ATYP_IPV4
                addr_bytes = socket.inet_pton(socket.AF_INET, target_host)
            except socket.error:
                # Hostname
                packet.append(0x03)  # ATYP_DOMAINNAME
                encoded_host = target_host.encode('utf-8')
                packet.append(len(encoded_host))
                addr_bytes = encoded_host

        # DST.ADDR
        packet.extend(addr_bytes)

        # DST.PORT - 2 bytes
        packet.extend(struct.pack('!H', target_port))

        # DATA
        packet.extend(data)

        return bytes(packet)

    def _extract_dns_from_socks5_response(self, socks5_response: bytes) -> bytes:
        """从SOCKS5 UDP包中提取DNS响应数据"""
        try:
            if len(socks5_response) < 10:  # Minimum SOCKS5 UDP header size
                return b''

            # SOCKS5 UDP包格式: RSV(2) + FRAG(1) + ATYP(1) + DST.ADDR + DST.PORT + DATA
            pos = 0

            # Skip RSV (2 bytes)
            pos += 2

            # Skip FRAG (1 byte)
            pos += 1

            # Skip ATYP (1 byte)
            atyp = socks5_response[pos]
            pos += 1

            # Skip DST.ADDR based on address type
            if atyp == 0x01:  # IPv4
                pos += 4  # 4 bytes
            elif atyp == 0x03:  # Domain name
                if pos >= len(socks5_response):
                    return b''
                addr_len = socks5_response[pos]
                pos += 1 + addr_len
            elif atyp == 0x04:  # IPv6
                pos += 16  # 16 bytes
            else:
                return b''

            # Skip DST.PORT (2 bytes)
            pos += 2

            # The remaining is the actual DNS response data
            if pos >= len(socks5_response):
                return b''

            return socks5_response[pos:]

        except Exception as e:
            self.logger.error(f"Failed to extract DNS from SOCKS5 response: {e}")
            return b''

    def _build_dns_query(self, domain: str, query_type: str = 'A') -> bytes:
        """构建DNS查询包"""
        # DNS查询类型映射
        query_types = {
            'A': 1,
            'AAAA': 28,
            'CNAME': 5,
            'MX': 15,
            'TXT': 16
        }

        qtype = query_types.get(query_type, 1)  # 默认为A记录

        # DNS header
        transaction_id = random.randint(0, 65535)
        flags = 0x0100  # 标准查询
        questions = 1
        answer_rrs = 0
        authority_rrs = 0
        additional_rrs = 0

        header = struct.pack('!HHHHHH',
                           transaction_id, flags, questions,
                           answer_rrs, authority_rrs, additional_rrs)

        # Query section
        qname = self._encode_domain_name(domain)
        qclass = 1  # IN (Internet)

        query = struct.pack('!HH', qtype, qclass)

        return header + qname + query

    def _encode_domain_name(self, domain: str) -> bytes:
        """编码域名"""
        encoded = b''
        for part in domain.split('.'):
            if part:
                encoded += bytes([len(part)]) + part.encode('utf-8')
        encoded += b'\x00'  # 结束标记
        return encoded

    def _parse_dns_response(self, response: bytes) -> List[str]:
        """解析DNS响应"""
        try:
            if len(response) < 12:
                return []

            # 跳过DNS header
            pos = 12

            # 跳过查询部分
            pos = self._skip_query_section(response, pos)

            # 解析答案部分
            ips = []
            answer_count = struct.unpack('!H', response[6:8])[0]

            for _ in range(answer_count):
                if pos >= len(response):
                    break

                # 跳过名称
                pos = self._skip_name(response, pos)

                if pos + 10 > len(response):
                    break

                # 跳过类型、类、TTL
                pos += 8

                # 获取数据长度
                data_length = struct.unpack('!H', response[pos:pos+2])[0]
                pos += 2

                if pos + data_length > len(response):
                    break

                # 解析数据
                record_type = struct.unpack('!H', response[pos-10:pos-8])[0]

                if record_type == 1:  # A记录
                    if data_length == 4:
                        ip_bytes = response[pos:pos+4]
                        ip = socket.inet_ntop(socket.AF_INET, ip_bytes)
                        ips.append(ip)
                elif record_type == 28:  # AAAA记录
                    if data_length == 16:
                        ip_bytes = response[pos:pos+16]
                        ip = socket.inet_ntop(socket.AF_INET6, ip_bytes)
                        ips.append(ip)

                pos += data_length

            return ips

        except Exception as e:
            self.logger.error(f"DNS response parsing error: {e}")
            return []

    def _skip_query_section(self, data: bytes, pos: int) -> int:
        """跳过查询部分"""
        try:
            # 跳过查询名称
            pos = self._skip_name(data, pos)
            # 跳过类型和类 (4字节)
            return pos + 4
        except:
            return pos

    def _skip_name(self, data: bytes, pos: int) -> int:
        """跳过域名"""
        try:
            while pos < len(data):
                length = data[pos]
                pos += 1

                if length == 0:
                    break
                elif length & 0xC0:  # 压缩指针
                    pos += 1
                    break
                else:
                    pos += length

            return pos
        except:
            return pos

    def _cache_result(self, key: str, ips: List[str], ttl: int):
        """缓存DNS查询结果"""
        with self.cache_lock:
            # 检查缓存大小限制
            if len(self.cache) >= self.max_cache_size:
                # 删除最旧的记录
                oldest_key = min(self.cache.keys(),
                               key=lambda k: self.cache[k].timestamp)
                del self.cache[oldest_key]

            # 添加新记录
            self.cache[key] = DNSRecord(
                ips=ips.copy(),
                ttl=ttl,
                timestamp=time.time()
            )

    async def _cleanup_cache_task(self):
        """缓存清理任务"""
        while True:
            try:
                await asyncio.sleep(self.cleanup_interval)
                current_time = time.time()

                with self.cache_lock:
                    expired_keys = []
                    for key, record in self.cache.items():
                        if current_time - record.timestamp >= record.ttl:
                            expired_keys.append(key)

                    for key in expired_keys:
                        del self.cache[key]

                    if expired_keys:
                        self.logger.debug(f"Cleaned up {len(expired_keys)} expired DNS cache entries")

            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Cache cleanup error: {e}")

    def get_stats(self) -> Dict[str, Any]:
        """获取统计信息"""
        return {
            **self.stats,
            'cache_size': len(self.cache),
            'cn_servers_count': len(self.cn_servers),
            'foreign_servers_count': len(self.foreign_servers)
        }

class DNSQueryProtocol:
    """DNS查询协议处理器"""

    def __init__(self):
        self.response = None
        self.event = asyncio.Event()
        self.logger = logging.getLogger(f"{__name__}.DNSQueryProtocol")

    def connection_made(self, transport):
        """连接建立时调用"""
        self.transport = transport

    def datagram_received(self, data: bytes, addr):
        """接收UDP数据包"""
        if not self.event.is_set():
            self.response = data
            self.event.set()

    def error_received(self, exc):
        """错误处理"""
        self.logger.error(f"DNS query error: {exc}")
        self.event.set()

    def connection_lost(self, exc):
        """连接丢失时调用"""
        if exc:
            self.logger.error(f"DNS connection lost: {exc}")
        self.event.set()

    async def get_response(self):
        """获取响应"""
        await self.event.wait()
        return self.response

# DNS服务器类
class SmartDNSServer:
    """智能DNS服务器"""

    def __init__(self, config: Dict, china_route_manager: ChinaRouteManager):
        self.logger = logging.getLogger(f"{__name__}.SmartDNSServer")
        self.config = config
        self.port = config.get('listener', {}).get('dns_port', 1053)

        # 传递完整的配置，包括DNS劫持规则
        dns_config = config.get('dns', {})
        dns_config['hijack_rules'] = config.get('dns_hijack_rules', [])
        self.resolver = SmartDNSResolver(dns_config, china_route_manager)
        self.server = None

    async def start(self):
        """启动DNS服务器"""
        try:
            await self.resolver.start()

            self.server = await asyncio.start_server(
                self._handle_client,
                '0.0.0.0',
                self.port
            )

            self.logger.info(f"Smart DNS server started on port {self.port}")

            async with self.server:
                await self.server.serve_forever()

        except Exception as e:
            self.logger.error(f"Failed to start DNS server: {e}")
            raise

    async def stop(self):
        """停止DNS服务器"""
        await self.resolver.stop()
        if self.server:
            self.server.close()
            await self.server.wait_closed()
        self.logger.info("Smart DNS server stopped")

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """处理DNS客户端"""
        try:
            # 读取数据
            data = await reader.read(512)
            if not data:
                return

            # 解析查询
            domain, query_type = self._parse_dns_query(data)
            if not domain:
                return

            # 智能解析
            ips = await self.resolver.resolve(domain, query_type)

            # 构建响应
            response = self._build_dns_response(data, ips)

            # 发送响应
            writer.write(response)
            await writer.drain()

        except Exception as e:
            self.logger.error(f"DNS client handling error: {e}")
        finally:
            writer.close()
            await writer.wait_closed()

    def _parse_dns_query(self, data: bytes) -> Tuple[Optional[str], str]:
        """解析DNS查询"""
        try:
            if len(data) < 12:
                return None, 'A'

            # 跳过header
            pos = 12

            # 解析域名
            domain_parts = []
            while pos < len(data):
                length = data[pos]
                pos += 1

                if length == 0:
                    break

                if pos + length > len(data):
                    break

                part = data[pos:pos+length].decode('utf-8', errors='ignore')
                domain_parts.append(part)
                pos += length

            domain = '.'.join(domain_parts)

            # 获取查询类型
            if pos + 2 <= len(data):
                query_type = struct.unpack('!H', data[pos:pos+2])[0]
                query_type_map = {1: 'A', 28: 'AAAA', 5: 'CNAME'}
                query_type_str = query_type_map.get(query_type, 'A')
            else:
                query_type_str = 'A'

            return domain, query_type_str

        except Exception as e:
            self.logger.error(f"DNS query parsing error: {e}")
            return None, 'A'

    def _build_dns_response(self, query: bytes, ips: List[str]) -> bytes:
        """构建DNS响应"""
        try:
            # 复制查询头部并修改标志
            response = bytearray(query)
            response[2] |= 0x80  # 设置响应标志

            # 添加答案部分
            for ip in ips:
                # 这里简化处理，实际应该构建完整的DNS响应
                pass

            return bytes(response)

        except Exception as e:
            self.logger.error(f"DNS response building error: {e}")
            return query