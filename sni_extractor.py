#!/usr/bin/env python3
"""
SNI检测器 - 从TLS ClientHello中提取SNI信息
"""

import struct
import logging
from typing import Optional

# 导入公共工具函数
from utils import TLS_VERSION_10, TLS_VERSION_11, TLS_VERSION_12

class SNIExtractor:
    """SNI信息提取器"""

    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.SNIExtractor")

    def parse_sni(self, data: bytes) -> Optional[str]:
        """解析 TLS ClientHello 中的 SNI"""
        try:
            self.logger.debug(f"🔍 开始解析TLS包，长度: {len(data)} bytes")
            self.logger.debug(f"📦 TLS包前缀: {data[:20].hex() if len(data) >= 20 else data.hex()}")

            # 基本长度检查
            if len(data) < 43:  # TLS记录头(5) + 握手头(4) + 版本(2) + 随机数(32) = 43
                self.logger.debug(f"❌ TLS包太短: {len(data)} bytes")
                return None

            # 检查TLS记录类型
            if data[0] != 0x16:  # 0x16 = TLS Handshake
                self.logger.debug(f"❌ 非TLS握手包，类型: 0x{data[0]:02x}")
                return None

            # 检查TLS版本
            tls_version = struct.unpack('!H', data[1:3])[0]
            if tls_version not in (TLS_VERSION_10, TLS_VERSION_11, TLS_VERSION_12, 0x0304):  # TLS 1.0-1.3
                self.logger.debug(f"❌ 不支持的TLS版本: 0x{tls_version:04x}")
                return None

            # 解析记录层长度
            record_length = struct.unpack('!H', data[3:5])[0]
            self.logger.debug(f"📄 TLS记录长度: {record_length}")

            if 5 + record_length > len(data):
                self.logger.debug(f"❌ 记录长度超出数据范围: {5 + record_length} > {len(data)}")
                return None

            # 开始解析ClientHello
            pos = 5  # 跳过TLS记录头

            # 检查握手类型
            if data[pos] != 0x01:  # 0x01 = ClientHello
                self.logger.debug(f"❌ 非ClientHello，握手类型: 0x{data[pos]:02x}")
                return None

            pos += 1  # 跳过握手类型

            # 跳过握手消息长度（3字节）
            if pos + 3 > len(data):
                return None
            handshake_length = (data[pos] << 16) | (data[pos+1] << 8) | data[pos+2]
            pos += 3
            self.logger.debug(f"🤝 握手消息长度: {handshake_length}")

            # 跳过版本（2字节）
            if pos + 2 > len(data):
                return None
            client_version = struct.unpack('!H', data[pos:pos+2])[0]
            pos += 2
            self.logger.debug(f"🔢 客户端版本: 0x{client_version:04x}")

            # 跳过随机数（32字节）
            if pos + 32 > len(data):
                return None
            pos += 32

            # 跳过会话ID
            if pos >= len(data):
                return None
            session_id_length = data[pos]
            pos += 1
            if pos + session_id_length > len(data):
                return None
            pos += session_id_length
            self.logger.debug(f"🎯 会话ID长度: {session_id_length}")

            # 跳过密码套件
            if pos + 2 > len(data):
                return None
            cipher_suites_length = struct.unpack('!H', data[pos:pos+2])[0]
            pos += 2
            if pos + cipher_suites_length > len(data):
                return None
            pos += cipher_suites_length
            self.logger.debug(f"🔐 密码套件长度: {cipher_suites_length}")

            # 跳过压缩方法
            if pos >= len(data):
                return None
            compression_methods_length = data[pos]
            pos += 1
            if pos + compression_methods_length > len(data):
                return None
            pos += compression_methods_length
            self.logger.debug(f"🗜️ 压缩方法长度: {compression_methods_length}")

            # 检查扩展长度
            if pos + 2 > len(data):
                self.logger.debug(f"❌ 没有扩展数据")
                return None

            extensions_length = struct.unpack('!H', data[pos:pos+2])[0]
            pos += 2
            self.logger.debug(f"🔗 扩展长度: {extensions_length}")

            if pos + extensions_length > len(data):
                self.logger.debug(f"❌ 扩展数据超出范围")
                return None

            # 解析扩展
            end_pos = pos + extensions_length
            while pos + 4 <= end_pos:
                # 扩展类型（2字节）
                ext_type = struct.unpack('!H', data[pos:pos+2])[0]
                pos += 2

                # 扩展长度（2字节）
                ext_length = struct.unpack('!H', data[pos:pos+2])[0]
                pos += 2

                self.logger.debug(f"🔍 扩展类型: 0x{ext_type:04x}, 长度: {ext_length}")

                if ext_type == 0:  # SNI扩展
                    self.logger.debug("✅ 找到SNI扩展")
                    return self._parse_sni_extension_data(data[pos:pos+ext_length])
                elif ext_type == 3523 or ext_type == 65281:  # GREASE值，跳过
                    self.logger.debug(f"⚡ 跳过GREASE扩展: 0x{ext_type:04x}")
                else:
                    self.logger.debug(f"⏭️ 跳过其他扩展: 0x{ext_type:04x} ({self._get_extension_name(ext_type)})")

                # 跳过扩展数据
                pos += ext_length

            self.logger.debug("❌ 未找到SNI扩展")
            return None

        except Exception as e:
            self.logger.error(f"🚨 SNI解析异常: {e}")
            return None

    def _parse_sni_extension_data(self, sni_data: bytes) -> Optional[str]:
        """解析SNI扩展数据"""
        try:
            self.logger.debug(f"🎯 解析SNI扩展数据，长度: {len(sni_data)} bytes")

            if len(sni_data) < 5:
                self.logger.debug(f"❌ SNI扩展数据太短: {len(sni_data)} bytes")
                return None

            pos = 0

            # SNI列表长度（2字节）
            sni_list_length = struct.unpack('!H', sni_data[pos:pos+2])[0]
            pos += 2
            self.logger.debug(f"📋 SNI列表长度: {sni_list_length}")

            if sni_list_length != len(sni_data) - 2:
                self.logger.debug(f"❌ SNI列表长度不匹配: {sni_list_length} != {len(sni_data) - 2}")

            # SNI条目类型（1字节） - 应该是0（主机名）
            if pos >= len(sni_data):
                return None
            name_type = sni_data[pos]
            pos += 1
            self.logger.debug(f"🏷️ SNI类型: {name_type}")

            if name_type != 0:
                self.logger.debug(f"❌ 非主机名类型: {name_type}")
                return None

            # SNI长度（2字节）
            if pos + 2 > len(sni_data):
                return None
            name_length = struct.unpack('!H', sni_data[pos:pos+2])[0]
            pos += 2
            self.logger.debug(f"📝 SNI长度: {name_length}")

            # SNI数据
            if pos + name_length > len(sni_data):
                self.logger.debug(f"❌ SNI数据超出范围")
                return None

            hostname = sni_data[pos:pos+name_length].decode('utf-8', errors='ignore')
            self.logger.debug(f"🌐 提取到主机名: '{hostname}'")

            # 验证主机名
            if hostname and self._is_valid_hostname(hostname):
                self.logger.info(f"✅ SNI提取成功: {hostname}")
                return hostname
            else:
                self.logger.debug(f"❌ 无效的主机名: '{hostname}'")
                return None

        except Exception as e:
            self.logger.error(f"🚨 SNI扩展解析异常: {e}")
            return None

    def _get_extension_name(self, ext_type: int) -> str:
        """获取扩展名称"""
        extension_names = {
            0: "SNI",
            5: "Status Request",
            10: "Supported Groups",
            11: "EC Point Formats",
            13: "Signature Algorithms",
            16: "Application Layer Protocol Negotiation",
            18: "Signed Certificate Timestamp",
            21: "Padding",
            23: "Extended Master Secret",
            35: "Session Ticket",
            43: "Supported Versions",
            45: "PSK Key Exchange Modes",
            51: "Key Share",
            52: "Supported Early Data",
            13172: "NPN",
            65281: "Renegotiation Info"
        }
        return extension_names.get(ext_type, f"Unknown ({ext_type})")

  
    async def extract_sni_from_client_hello(self, client_data: bytes) -> Optional[str]:
        """
        从客户端TLS ClientHello包中提取SNI信息
        """
        return self.parse_sni(client_data)

    def _is_valid_hostname(self, hostname: str) -> bool:
        """验证主机名格式"""
        if not hostname or len(hostname) > 253:
            return False

        # 基本的主机名格式检查
        import re
        hostname_pattern = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$')
        return bool(hostname_pattern.match(hostname))


# 全局SNI提取器实例
sni_extractor = SNIExtractor()