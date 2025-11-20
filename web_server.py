#!/usr/bin/env python3
"""
Web管理界面服务器模块
基于asyncio和标准库实现现代美观的Web界面
"""

import asyncio
import json
import logging
import os
import urllib.parse
from pathlib import Path
from typing import Dict, Any, Optional
from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime
import threading
import socketserver
from socketserver import ThreadingMixIn

# 导入配置管理器
from config import Config

class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    """多线程HTTP服务器"""
    daemon_threads = True

class APIHandler(BaseHTTPRequestHandler):
    """API请求处理器"""

    def __init__(self, request, client_address, server):
        self.web_server = server.web_server_instance
        super().__init__(request, client_address, server)

    def do_GET(self):
        """处理GET请求"""
        path = self.path

        # API路由
        if path == '/api/config':
            response = self.web_server.get_config()
            self.send_json_response(response)
        elif path == '/api/status':
            response = self.web_server.get_status()
            self.send_json_response(response)
        elif path == '/api/stats':
            response = self.web_server.get_stats()
            self.send_json_response(response)
        elif path == '/api/file/chnroutes':
            response = self.web_server.get_chnroutes_file()
            self.send_json_response(response)
        elif path.startswith('/api/file/chnroutes/upload'):
            response = self.web_server.upload_chnroutes_file(self)
            self.send_json_response(response)
        elif path.startswith('/api/file/chnroutes/download'):
            response = self.web_server.download_chnroutes_file()
            if response:
                self.send_file_response(response)
            else:
                self.send_response(404)
                self.send_header('Content-type', 'text/plain')
                self.end_headers()
                self.wfile.write(b'File not found')
        else:
            # 尝试提供静态文件
            response = self.web_server.serve_static_file(path)
            if response is None:
                self.send_response(404)
                self.send_header('Content-type', 'text/plain')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                self.wfile.write(b'Not Found')
            else:
                # 静态文件响应
                try:
                    self.send_response(200)
                    self.send_header('Content-type', response['type'])
                    self.send_header('Access-Control-Allow-Origin', '*')
                    self.end_headers()

                    # 处理内容 - 检查是否已经是字节格式
                    if isinstance(response['content'], bytes):
                        self.wfile.write(response['content'])
                    else:
                        self.wfile.write(response['content'].encode('utf-8'))
                except (BrokenPipeError, ConnectionResetError, OSError) as e:
                    # 客户端提前断开连接是正常现象，忽略这些错误
                    pass

    def do_POST(self):
        """处理POST请求"""
        path = self.path
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)

        if path == '/api/config':
            try:
                # 解析JSON数据
                data = json.loads(post_data.decode('utf-8'))
                response = self.web_server.update_config(data)
                self.send_json_response(response)
            except json.JSONDecodeError:
                error_response = {'success': False, 'error': 'Invalid JSON data'}
                self.send_json_response(error_response)
        elif path == '/api/file/chnroutes/save':
            try:
                # 解析JSON数据
                data = json.loads(post_data.decode('utf-8'))
                response = self.web_server.save_chnroutes_file(data)
                self.send_json_response(response)
            except json.JSONDecodeError:
                error_response = {'success': False, 'error': 'Invalid JSON data'}
                self.send_json_response(error_response)
        else:
            self.send_response(404)
            self.send_header('Content-type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(b'{"success": false, "error": "Endpoint not found"}')

    def do_OPTIONS(self):
        """处理OPTIONS请求（CORS预检）"""
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()

    def send_json_response(self, response):
        """发送JSON响应"""
        try:
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
            self.send_header('Access-Control-Allow-Headers', 'Content-Type')
            self.end_headers()
            self.wfile.write(json.dumps(response).encode('utf-8'))
        except (BrokenPipeError, ConnectionResetError, OSError) as e:
            # 客户端提前断开连接是正常现象，忽略这些错误
            pass

    def send_file_response(self, file_data):
        """发送文件响应"""
        try:
            self.send_response(200)
            self.send_header('Content-type', 'application/octet-stream')
            self.send_header('Content-disposition', f'attachment; filename="{file_data["filename"]}"')
            self.send_header('Content-length', str(len(file_data['content'])))
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(file_data['content'])
        except (BrokenPipeError, ConnectionResetError, OSError) as e:
            # 客户端提前断开连接是正常现象，忽略这些错误
            pass

    def do_POST(self):
        """处理POST请求"""
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)

        path = self.path
        try:
            data = json.loads(post_data.decode('utf-8'))
        except:
            data = {}

        if path == '/api/config':
            response = self.web_server.update_config(data)
        elif path == '/api/reload':
            response = self.web_server.reload_config(data)
        else:
            response = {'success': False, 'error': 'Invalid endpoint'}

        self.send_json_response(response)

    def do_OPTIONS(self):
        """处理OPTIONS请求（CORS预检）"""
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()

    def log_message(self, format, *args):
        """重写日志方法，减少输出"""
        pass

class WebServer:
    """Web管理界面服务器"""

    def __init__(self, config: Config):
        self.config = config
        self.web_config = config.config_data.get('web_interface', {})
        self.port = self.web_config.get('port', 8080)
        self.enabled = self.web_config.get('enabled', True)

        self.logger = logging.getLogger(f"{__name__}.WebServer")
        self.server = None
        self.server_thread = None

        # 记录启动时间用于计算运行时间
        self.start_time = datetime.now()

        # 获取web根目录
        self.web_root = Path(__file__).parent / "web"

    def start(self):
        """启动Web服务器"""
        if not self.enabled:
            self.logger.info("Web interface disabled")
            return

        try:
            self.server = ThreadingHTTPServer(('0.0.0.0', self.port), APIHandler)
            self.server.web_server_instance = self # 将WebServer实例附加到服务器上

            # 在单独线程中运行服务器
            self.server_thread = threading.Thread(target=self.server.serve_forever, daemon=True)
            self.server_thread.start()

            self.logger.info(f"Web interface started on http://0.0.0.0:{self.port}")

        except Exception as e:
            self.logger.error(f"Failed to start web server: {e}")
            raise

    def stop(self):
        """停止Web服务器"""
        if self.server:
            self.server.shutdown()
            if self.server_thread:
                self.server_thread.join(timeout=5)
            self.logger.info("Web interface stopped")

    def get_config(self):
        """获取配置"""
        try:
            return {
                'success': True,
                'data': self.config.config_data
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }

    def update_config(self, data):
        """更新配置"""
        try:
            config_data = data.get('config')

            if not config_data:
                return {
                    'success': False,
                    'error': 'No config data provided'
                }

            # 实时更新内存中的配置
            self.config.config_data.update(config_data)

            # 保存配置到文件
            config_file = Path(__file__).parent / "conf" / "config.json"
            with open(config_file, 'w', encoding='utf-8') as f:
                json.dump(self.config.config_data, f, indent=2, ensure_ascii=False)

            return {
                'success': True,
                'message': 'Configuration updated and saved successfully'
            }

        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }

    def get_status(self):
        """获取服务器状态"""
        try:
            # 计算运行时间
            uptime_delta = datetime.now() - self.start_time
            hours, remainder = divmod(uptime_delta.total_seconds(), 3600)
            minutes, seconds = divmod(remainder, 60)
            uptime_str = f"{int(hours)}小时{int(minutes)}分钟{int(seconds)}秒"

            # 获取代理服务器状态
            status = {
                'server_running': True,  # 简化判断
                'uptime': uptime_str,
                'version': '1.0.0',
                'timestamp': datetime.now().isoformat()
            }

            # 获取连接统计（如果可用）
            try:
                # 这里可以添加获取实际连接数的逻辑
                status['active_connections'] = 0
                status['max_connections'] = 1000
            except:
                pass

            return {
                'success': True,
                'data': status
            }

        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }

    def get_stats(self):
        """获取统计信息"""
        try:
            # 计算运行时间
            uptime_delta = datetime.now() - self.start_time
            hours, remainder = divmod(uptime_delta.total_seconds(), 3600)
            minutes, seconds = divmod(remainder, 60)
            uptime_str = f"{int(hours)}小时{int(minutes)}分钟{int(seconds)}秒"

            stats = {
                'timestamp': datetime.now().isoformat(),
                'uptime': uptime_str
            }

            # 获取代理选择器统计
            try:
                if hasattr(self.config, 'proxy_selector') and self.config.proxy_selector:
                    proxy_stats = {}
                    stats['proxy'] = proxy_stats
            except:
                pass

            # 获取DNS统计
            try:
                if hasattr(self.config, 'dns_server') and self.config.dns_server:
                    dns_stats = self.config.dns_server.resolver.get_stats()
                    stats['dns'] = dns_stats
            except:
                pass

            return {
                'success': True,
                'data': stats
            }

        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }

    def reload_config(self, data):
        """重新加载配置"""
        try:
            # 这里可以实现配置重新加载逻辑
            return {
                'success': True,
                'message': 'Configuration reloaded successfully'
            }

        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }

    def serve_static_file(self, path):
        """提供静态文件服务，支持带查询参数的请求"""
        try:
            # 安全检查，防止路径遍历攻击
            if '..' in path or '\0' in path:
                return None

            # 默认返回index.html
            if path == '/' or path == '':
                path = '/index.html'

            # 分离查询参数
            from urllib.parse import urlparse, unquote
            parsed_path = urlparse(path)
            clean_path = unquote(parsed_path.path)  # 去掉URL编码和查询参数

            file_path = self.web_root / clean_path.lstrip('/')
            if file_path.exists() and file_path.is_file():
                # 根据文件扩展名设置Content-Type
                content_type = self.get_content_type(file_path.suffix)

                # 读取文件内容
                with open(file_path, 'rb') as f:
                    content = f.read()

                # 判断是否为二进制文件
                is_binary = self.is_binary_file(file_path.suffix)

                return {
                    'success': True,
                    'content': content,
                    'type': content_type,
                    'binary': is_binary
                }

            return None

        except Exception as e:
            self.logger.error(f"Error serving static file {path}: {e}")
            return None

    def is_binary_file(self, extension):
        """判断是否为二进制文件"""
        binary_extensions = {
            '.eot', '.woff', '.woff2', '.ttf', '.otf',  # 字体文件
            '.png', '.jpg', '.jpeg', '.gif', '.ico', '.webp',  # 图片文件
            '.pdf', '.zip', '.rar', '.7z', '.tar', '.gz'  # 压缩文件
        }
        return extension.lower() in binary_extensions

    def get_content_type(self, extension):
        """根据文件扩展名获取Content-Type"""
        content_types = {
            '.html': 'text/html',
            '.css': 'text/css',
            '.js': 'application/javascript',
            '.json': 'application/json',
            '.png': 'image/png',
            '.jpg': 'image/jpeg',
            '.gif': 'image/gif',
            '.ico': 'image/x-icon',
            '.svg': 'image/svg+xml',
            '.eot': 'application/vnd.ms-fontobject',
            '.woff': 'font/woff',
            '.woff2': 'font/woff2',
            '.ttf': 'font/ttf'
        }
        return content_types.get(extension.lower(), 'text/plain')

    def get_chnroutes_file(self):
        """获取中国路由规则文件"""
        try:
            config_file = Path(__file__).parent / "conf" / "chnroutes.txt"
            if config_file.exists():
                with open(config_file, 'r', encoding='utf-8') as f:
                    content = f.read()

                # 获取文件信息
                lines = content.count('\n') + (1 if content and not content.endswith('\n') else 0)
                size_bytes = config_file.stat().st_size
                size_str = self.format_file_size(size_bytes)

                return {
                    'success': True,
                    'content': content,
                    'lines': lines,
                    'size': size_str,
                    'size_bytes': size_bytes,
                    'path': str(config_file)
                }
            else:
                return {
                    'success': False,
                    'error': '中国路由规则文件不存在'
                }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }

    def save_chnroutes_file(self, data):
        """保存中国路由规则文件"""
        try:
            content = data.get('content', '')
            config_file = Path(__file__).parent / "conf" / "chnroutes.txt"

            # 备份原文件
            if config_file.exists():
                backup_file = config_file.with_suffix('.txt.bak')
                config_file.rename(backup_file)

            # 写入新内容
            with open(config_file, 'w', encoding='utf-8') as f:
                f.write(content)

            return {
                'success': True,
                'message': '中国路由规则文件保存成功'
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }

    def upload_chnroutes_file(self, request_handler):
        """上传中国路由规则文件"""
        try:
            content_type = request_handler.headers.get('Content-Type', '')
            if 'multipart/form-data' not in content_type:
                return {
                    'success': False,
                    'error': '请使用 multipart/form-data 格式上传文件'
                }

            # 解析multipart数据
            import cgi
            form = cgi.FieldStorage(
                fp=request_handler.rfile,
                headers=request_handler.headers,
                environ={'REQUEST_METHOD': 'POST'}
            )

            if 'file' not in form:
                return {
                    'success': False,
                    'error': '未找到文件字段'
                }

            file_item = form['file']
            if not file_item.filename:
                return {
                    'success': False,
                    'error': '未选择文件'
                }

            content = file_item.file.read()
            config_file = Path(__file__).parent / "conf" / "chnroutes.txt"

            # 备份原文件
            if config_file.exists():
                backup_file = config_file.with_suffix('.txt.bak')
                config_file.rename(backup_file)

            # 保存新文件
            with open(config_file, 'wb') as f:
                f.write(content)

            return {
                'success': True,
                'message': f'文件 {file_item.filename} 上传成功'
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }

    def download_chnroutes_file(self):
        """下载中国路由规则文件"""
        try:
            config_file = Path(__file__).parent / "conf" / "chnroutes.txt"
            if config_file.exists():
                with open(config_file, 'rb') as f:
                    content = f.read()

                return {
                    'filename': 'chnroutes.txt',
                    'content': content
                }
            else:
                return None
        except Exception as e:
            self.logger.error(f"Error downloading chnroutes file: {e}")
            return None

    def format_file_size(self, size_bytes):
        """格式化文件大小"""
        if size_bytes < 1024:
            return f"{size_bytes} B"
        elif size_bytes < 1024 * 1024:
            return f"{size_bytes / 1024:.1f} KB"
        elif size_bytes < 1024 * 1024 * 1024:
            return f"{size_bytes / (1024 * 1024):.1f} MB"
        else:
            return f"{size_bytes / (1024 * 1024 * 1024):.1f} GB"