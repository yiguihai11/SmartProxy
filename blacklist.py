#!/usr/bin/env python3
"""
智能黑名单管理器模块
"""
import time
import logging
import threading
from typing import Dict, Optional
from dataclasses import dataclass

@dataclass
class BlacklistEntry:
    """黑名单条目"""
    target_ip: str       # 目标IP地址
    target_port: int     # 目标端口
    added_time: float    # 加入黑名单的时间
    expire_time: float   # 过期时间
    reason: str          # 加入原因
    protocol: str = "unknown"  # 协议类型 (IPv4/IPv6)
    hostname: Optional[str] = None  # 合并的SNI/Host主机名

class SmartBlacklist:
    """智能黑名单管理器"""

    def __init__(self, expiry_minutes: int = 360):
        self.expiry_minutes = expiry_minutes
        self.blacklist: Dict[str, BlacklistEntry] = {}  # key: f"{target_ip}:{target_port}", value: BlacklistEntry
        self.logger = logging.getLogger(f"{__name__}.SmartBlacklist")

        # 启动清理线程
        self.cleanup_thread = threading.Thread(target=self._cleanup_expired_entries, daemon=True)
        self.cleanup_thread.start()

    def _detect_protocol(self, ip: str) -> str:
        """检测IP协议类型"""
        return "IPv6" if ":" in ip else "IPv4"

    def _generate_key(self, target_ip: str) -> str:
        """生成黑名单键 (仅基于IP)"""
        return target_ip

    def add_to_blacklist(self, target_ip: str, reason: str,
                        src_ip: str = "unknown", src_port: int = 0,
                        hostname: Optional[str] = None):
        """添加目标IP到黑名单"""
        try:
            current_time = time.time()
            expire_time = current_time + (self.expiry_minutes * 60)
            protocol = self._detect_protocol(target_ip)
            key = self._generate_key(target_ip) # 仅使用IP生成键

            # 如果已存在，更新主机名和过期时间
            if key in self.blacklist:
                entry = self.blacklist[key]
                entry.expire_time = expire_time  # 更新过期时间
                if hostname and not entry.hostname:
                    entry.hostname = hostname
                self.logger.warning(f"📋 Updated existing blacklist entry: {key} (Extended expiry to {self.expiry_minutes}min)")
                return

            # 创建新的黑名单条目 (port可以为0或用于日志记录)
            entry = BlacklistEntry(
                target_ip=target_ip,
                target_port=0, # 黑名单现在是IP级别的，端口设为0
                added_time=current_time,
                expire_time=expire_time,
                reason=reason,
                protocol=protocol,
                hostname=hostname
            )

            self.blacklist[key] = entry
            remaining_time = self.expiry_minutes
            host_info = f" ({hostname})" if hostname else ""
            self.logger.warning(f"⛔ Added to blacklist: {protocol} {target_ip}{host_info} (Reason: {reason}, Expires in {remaining_time}min)")

        except Exception as e:
            self.logger.error(f"❌ Failed to add to blacklist: {e}")

    def is_blacklisted(self, target_ip: str) -> Optional[BlacklistEntry]:
        """检查目标IP是否在黑名单中"""
        try:
            key = self._generate_key(target_ip) # 仅使用IP生成键

            if key in self.blacklist:
                entry = self.blacklist[key]
                current_time = time.time()

                # 检查是否过期
                if current_time > entry.expire_time:
                    del self.blacklist[key]
                    self.logger.debug(f"🗑️ Expired blacklist entry removed: {key}")
                    return None

                # 返回条目，包含剩余过期时间信息
                remaining_seconds = int(entry.expire_time - current_time)
                remaining_minutes = remaining_seconds // 60
                self.logger.debug(f"🔍 Found blacklist entry: {key} (expires in {remaining_minutes}min)")
                return entry

            return None

        except Exception as e:
            self.logger.error(f"❌ Failed to check blacklist: {e}")
            return None

    def _cleanup_expired_entries(self):
        """清理过期条目的后台任务"""
        while True:
            try:
                time.sleep(60)  # 每分钟检查一次
                current_time = time.time()
                expired_keys = []

                for key, entry in self.blacklist.items():
                    if current_time > entry.expire_time:
                        expired_keys.append(key)

                for key in expired_keys:
                    del self.blacklist[key]
                    self.logger.debug(f"🗑️ Cleaned up expired blacklist entry: {key}")

            except Exception as e:
                self.logger.error(f"Error cleaning up expired entries: {e}")
