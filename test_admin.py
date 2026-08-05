#!/usr/bin/env python3
"""admin API 测试脚本 — 通过 Unix socket 测试所有端点"""

import json
import sys
import socket
import http.client
import os

SOCKET_PATH = "/data/data/com.termux/files/home/tmp/smartproxy.sock"


class UnixSocketClient:
    """通过 Unix socket 发 HTTP 请求"""

    def __init__(self, sock_path):
        self.sock_path = sock_path

    def request(self, method, path, body=None):
        conn = http.client.HTTPConnection("localhost")
        conn.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        conn.sock.connect(self.sock_path)
        try:
            conn.request(method, path, body=body, headers={"Content-Type": "application/json"})
            resp = conn.getresponse()
            data = resp.read()
            return resp.status, data
        finally:
            conn.close()

    def get(self, path):
        return self.request("GET", path)

    def post(self, path, body=None):
        return self.request("POST", path, body)

    def delete(self, path):
        return self.request("DELETE", path)


def check(ok, msg):
    if ok:
        print(f"  ✅ {msg}")
    else:
        raise AssertionError(msg)


def get_first_alias(c):
    """从 /health 获取第一个代理的 alias"""
    _, data = c.get("/health")
    j = json.loads(data)
    proxies = j.get("proxies", [])
    if proxies:
        return proxies[0]["alias"]
    return None


def main():
    if not os.path.exists(SOCKET_PATH):
        print(f"❌ socket 不存在: {SOCKET_PATH}")
        print(f"   请确认程序已启动且路径正确")
        sys.exit(1)

    c = UnixSocketClient(SOCKET_PATH)
    passed = 0
    failed = 0

    def test(name, func):
        nonlocal passed, failed
        print(f"\n--- {name} ---")
        try:
            func()
            passed += 1
        except Exception as e:
            print(f"  ❌ 异常: {e}")
            failed += 1

    # ── 1. 基础状态 ──

    def test_stats():
        status, data = c.get("/stats")
        check(status == 200, f"HTTP {status}")
        j = json.loads(data)
        check("tcp" in j, "含 tcp 字段")
        check("udp" in j, "含 udp 字段")
        check("process" in j, "含 process 字段")
        p = j["process"]
        check(p.get("goroutines", 0) > 0, f"goroutines={p['goroutines']}")
        check(p.get("cpu_percent", -1) >= 0, f"cpu_percent={p['cpu_percent']:.1f}")
        check(p.get("uptime", "") != "", f"uptime={p['uptime']}")
        check(p.get("alloc_mb", "") != "", f"alloc_mb={p['alloc_mb']}")
        check(p.get("last_gc_pause", "") != "", f"last_gc_pause={p['last_gc_pause']}")

    test("GET /stats", test_stats)

    # ── 2. 路由表 ──

    def test_route():
        status, data = c.get("/route")
        check(status == 200, f"HTTP {status}")
        j = json.loads(data)
        check(j.get("loaded") is True, "loaded=true")
        check(j.get("v4", 0) > 0, f"v4={j['v4']}")
        check(j.get("v6", 0) > 0, f"v6={j['v6']}")
        check(j.get("entries", 0) > 0, f"entries={j['entries']}")

    test("GET /route", test_route)

    # ── 3. 上游健康 ──

    def test_health():
        status, data = c.get("/health")
        check(status == 200, f"HTTP {status}")
        j = json.loads(data)
        check("strategy" in j, f"strategy={j.get('strategy')}")
        check("proxies" in j, f"proxies count={len(j['proxies'])}")
        for p in j.get("proxies", []):
            check(p.get("alias", "") != "", f"alias={p['alias']}")
            h = p.get("health", {})
            check("available" in h, f"{p['alias']} available={h.get('available')}")
            check("state" in h, f"{p['alias']} state={h.get('state')}")

    test("GET /health", test_health)

    # ── 4. DNS 缓存 ──

    def test_cache():
        status, data = c.get("/cache")
        check(status == 200, f"HTTP {status}")
        j = json.loads(data)
        check("entries" in j, f"entries={j['entries']}")

    test("GET /cache", test_cache)

    # ── 5. 黑名单 ──

    def test_blacklist():
        status, data = c.get("/blacklist")
        check(status == 200, f"HTTP {status}")
        j = json.loads(data)
        check(isinstance(j, list), "返回列表")

    test("GET /blacklist", test_blacklist)

    # ── 6. 方法拒绝 ──

    def test_method_not_allowed():
        status, _ = c.post("/stats")
        check(status == 405, f"POST /stats → {status}")
        status, _ = c.post("/route")
        check(status == 405, f"POST /route → {status}")
        status, _ = c.delete("/route")
        check(status == 405, f"DELETE /route → {status}")
        status, _ = c.get("/cache/flush")
        check(status == 405, f"GET /cache/flush → {status}")

    test("方法拒绝 405", test_method_not_allowed)

    # ── 7. 写入端点 ──

    def test_cache_flush():
        status, data = c.post("/cache/flush")
        check(status == 200, f"POST /cache/flush → {status}")
        j = json.loads(data)
        check(j.get("status") == "ok", "status=ok")

    test("POST /cache/flush", test_cache_flush)

    def test_health_proxy_no_alias():
        status, _ = c.post("/health/proxy?action=disable")
        check(status == 400, f"no alias → {status}")

    test("POST /health/proxy 缺少参数", test_health_proxy_no_alias)

    def test_health_proxy_bad_action():
        status, _ = c.post("/health/proxy?alias=test-proxy&action=bad")
        check(status == 400, f"bad action → {status}")

    test("POST /health/proxy 错误 action", test_health_proxy_bad_action)

    def test_health_proxy_bad_alias():
        # 真实代理不存在时返回 404
        status, _ = c.post("/health/proxy?alias=nonexistent&action=disable")
        check(status == 404, f"bad alias → {status}")

    test("POST /health/proxy 未知 alias", test_health_proxy_bad_alias)

    def test_health_proxy_toggle():
        alias = get_first_alias(c)
        check(alias is not None, "获取到 alias")

        # 先禁用
        status, _ = c.post(f"/health/proxy?alias={alias}&action=disable")
        check(status == 200, f"disable {alias} → {status}")

        # 验证
        _, data = c.get("/health")
        j = json.loads(data)
        for p in j.get("proxies", []):
            if p["alias"] == alias:
                check(not p["health"]["available"], f"{alias} 已禁用")
                break

        # 启用
        status, _ = c.post(f"/health/proxy?alias={alias}&action=enable")
        check(status == 200, f"enable {alias} → {status}")

    test("POST /health/proxy 切换", test_health_proxy_toggle)

    def test_config_reload():
        status, data = c.post("/config/reload")
        j = json.loads(data)
        check(status == 200, f"POST /config/reload → {status}")
        check(j.get("status") == "ok", "status=ok")

    test("POST /config/reload", test_config_reload)

    # ── 8. 删除缓存条目 ──

    def test_cache_delete():
        # 没有 qname → 400
        status, _ = c.delete("/cache")
        check(status == 400, f"DELETE /cache no qname → {status}")

        # 正常删除
        status, _ = c.delete("/cache?qname=test.example.com&qtype=1")
        check(status == 204, f"DELETE /cache ok → {status}")

        # qtype 默认值
        status, _ = c.delete("/cache?qname=test.example.com")
        check(status == 204, f"DELETE /cache default qtype → {status}")

    test("DELETE /cache", test_cache_delete)

    # ── 9. 删除黑名单 ──

    def test_blacklist_delete():
        status, _ = c.delete("/blacklist")
        check(status == 400, f"DELETE /blacklist no host → {status}")

        status, _ = c.delete("/blacklist?host=10.0.0.1&type=ip")
        check(status == 204, f"DELETE /blacklist type=ip → {status}")

        status, _ = c.delete("/blacklist?host=evil.com&type=domain")
        check(status == 204, f"DELETE /blacklist type=domain → {status}")

        status, _ = c.delete("/blacklist?host=test.com")
        check(status == 204, f"DELETE /blacklist no type → {status}")

    test("DELETE /blacklist", test_blacklist_delete)

    # ── 10. 各端点返回 JSON ──

    def test_content_type():
        for path in ["/stats", "/route", "/health", "/cache", "/blacklist"]:
            _, data = c.get(path)
            ok = check(json.loads(data) is not None, f"{path} 是合法 JSON")

    test("返回合法 JSON", test_content_type)

    # ── 汇总 ──

    print(f"\n{'='*40}")
    print(f"通过: {passed}  |  失败: {failed}  |  总计: {passed+failed}")
    if failed == 0:
        print("🎉 全部通过")
    else:
        print(f"⚠️  有 {failed} 个测试失败")
        sys.exit(1)


if __name__ == "__main__":
    main()
