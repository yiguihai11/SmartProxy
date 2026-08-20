package engine

// TUN 隧道入口端到端回归测试。
//
// 与 SOCKS5 测试(direct_e2e_test.go / proxy_e2e_test.go)并列,补上 TUN 这条入口:
// 真实创建 /dev/net/tun 设备,测试进程用绑定 tun 的 socket 扮演「隧道内的客户端」,
// gVisor 栈终止连接后交给引擎 handler 转发——覆盖 Android VPN(fd 模式)和桌面 tun 的
// TCP/UDP 直连、代理、ACL 全链路。
//
// 前提:/dev/net/tun + CAP_NET_ADMIN(能建 tun 设备)。GitHub Actions 托管 runner
// 通常没有 /dev/net/tun,这些用例会自动 Skip;本机 Linux 上会真正执行。
//
// 客户端怎么进隧道:给 socket 打 SO_BINDTODEVICE(tun 设备名)——等价 `curl --interface tun0`,
// 内核把该 socket 的包强制走 tun 设备。源地址自动取 tun 子网地址(10.0.0.1),引擎装的
// selective route(from 10.0.0.1/24 → tun0)提供 tun 上的出路由。
//
// ⚠️ 目标地址为什么是 198.18.0.2 而不是 127.0.0.1(踩过的坑,不许再踩):
//
//  1. 拨 127.0.0.1 会被 gVisor 的「martian 包过滤」静默丢弃。sagernet gvisor fork
//     的 ipv4.go HandlePacket:在非回环 NIC 上,源或目的落在 127.0.0.0/8 的包直接 drop
//     (AllowExternalLoopbackTraffic 默认 false)。于是 SYN 进得了 tun fd,但永远到不了
//     TCP/UDP forwarder,客户端只能 i/o timeout。这就是「拨回环」的假象根源。
//  2. 解法:目标换成「非回环的本地别名」198.18.0.2(/32 加到 lo)。三个条件同时满足:
//       a) 非回环(198.18.0.0/15 是 RFC 2544 benchmark 段,不参与真实路由)→ gVisor martian 放过;
//       b) 本地地址 → 引擎 dial 198.18.0.2 走 pref-0 local 表,直接送到 echo 服务;
//       c) 客户端照样进隧道 → SO_BINDTODEVICE(tun0) 的 oif 约束会排除 dev-lo 的
//          local 路由,SYN 落进 selective route → 出 tun0。
//    127.0.0.1 同时是「本地」和「回环」,恰恰被条件 (a) 卡死;换成非回环别名后 (a)(b)(c)
//    全满足。
//
//  ⚠️ 第二层坑(内核 martian 源过滤,accept_local 门控):gVisor 回包的源地址 = 客户端
//  SYN 的目的地址 = 198.18.0.2,而 198.18.0.2 是本机 lo 上的本地别名。内核在 tun0 上
//  收到「源地址是本机另一个接口的本地地址」的包,会在路由阶段(prerouting 之后、
//  input/forward 之前)当伪造源静默丢弃——这正是本测试早期「SYN-ACK 能看到、连接却
//  永远建不起来」的根因。它由 net.ipv4.conf.<tun>.accept_local 门控,跟 rp_filter 无关。
//  生产环境踩不到:隧道服务器的地址永远是远端真实 IP,源地址不可能本机本地。测试里
//  startTUNEngine 给自建 tun 开 accept_local=1(结束恢复),放行这些回包。改这个文件时
//  别去掉——去掉就是「TCP 直连/代理全超时」的下一次踩坑。
//
//  一个「看似可行、实测不通」的替代方案(别走回头路):把 198.18.0.2 从 lo 上拿掉,只加
//  `ip route add 198.18.0.2/32 dev lo`,让引擎 dial 走 lo 到 0.0.0.0 listener。实测内核
//  ip_route_input 只在 LOCAL 表命中才做本地投递,main 表的 dev-lo 路由会转圈,0.0.0.0
//  listener 收不到包。要把地址做到「可达但不本地」只能靠 veth+netns(echo 挪进对端 ns)
//  或 NAT,复杂度不值。本地别名 + tun 接口 accept_local=1 是最小可行解。
//
//  ⚠️ 为什么 -race 下自动 Skip:sing-tun 的 GVisor.Start 里 newGVisorStack →
//  CreateNICWithOptions 先把 endpoint attach 上、dispatch 循环拉起,然后才逐个
//  SetTransportProtocolHandler 装 TCP/UDP/ICMP handler。gvisor 的
//  Stack.transportProtocolHandlers 是无锁 map,启动窗口期(哪怕只有一个 IPv6 DAD 包)
//  递送就会和「写 map」撞出 DATA RACE——竞态两侧全在 gvisor/sing-tun 依赖内,本仓库代码
//  只是调用方,无法修。所以 requireTUN 在 -race 下直接 Skip(用 Go 隐式的 race 构建标签
//  判定,见 race_enabled_test.go)。非 -race 的正常与 CI 回归仍全量跑这组用例。
//
// 早期版本是「测试进程手工往 tun fd 写裸 IP 包」,已被放弃:gVisor 栈的 dispatch 循环
// 也在读同一个 fd,双读者抢包导致 SYN 经常送不到栈里,测试随机超时。改成真实 socket 后
// 完全走内核,不再有抢读问题,也更贴近真实部署路径。
//
// TUN 路径与 SOCKS5 的关键差异:
//   - TUN UDP 走 internal/tun/handler.go 自己的转发,但已与 SOCKS5 对齐:转发同时累加
//     udp.* 面板计数器(直连=纯 payload、代理=带 SOCKS5 header 整帧),语义与
//     internal/udp 一致,见 TestEngineTUN_UDPCounters_Direct / _Proxy;
//   - TUN TCP 走 relay.TCPRelay(共享 relay.* 计数器),连接关闭才结算,
//     直连/代理用例都先关客户端连接再轮询计数;
//   - domain 规则:仅 smart_proxy 端口生效(非 smart / UDP 不做 SNI·Host 解析,性能取舍)。
//   - 完整差异清单见 docs/e2e-regression.md「TUN 与 SOCKS5 的 UDP 行为一致性」。

import (
	"bytes"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"smartproxy/internal/config"
)

// tunServerIP / tunServerNet 是 TUN 用例的「服务器地址」:一个加在 lo 上的非回环本地别名。
// 见文件头注释对 martian 过滤坑的说明。198.18.0.0/15 是 RFC 2544 benchmark 段,
// 真实部署一般不会占用,避免和 docker(172.16/12)、tun(10.0.0.1/24)撞网段。
const (
	tunServerIP  = "198.18.0.2"
	tunServerNet = "198.18.0.0/16"
)

// requireTUN 跳过没有 /dev/net/tun 或没权限建 tun 设备的环境(如 GitHub Actions);
// 以及 -race 下的运行(见文件头「为什么 -race 下跳过」)。
func requireTUN(t *testing.T) {
	t.Helper()
	if raceEnabled() {
		t.Skip("sing-tun gvisor 栈启动有上游数据竞态(见文件头),TUN e2e 仅在非 -race 下运行")
	}
	if _, err := os.Stat("/dev/net/tun"); err != nil {
		t.Skip("/dev/net/tun unavailable; skipping TUN e2e")
	}
	if err := exec.Command("ip", "tuntap", "add", "dev", "sp_probe0", "mode", "tun").Run(); err != nil {
		t.Skipf("cannot create tun device (need CAP_NET_ADMIN): %v", err)
	}
	_ = exec.Command("ip", "link", "del", "sp_probe0").Run()
}

// addLoAlias 把 <addr>/32 加到 lo,让该地址成为「本地非回环」地址——引擎 dial 它走 local 表,
// gVisor 的 martian 过滤(只拦 127.0.0.0/8)放过它。结束自动删除。
func addLoAlias(t *testing.T, addr string) {
	t.Helper()
	if err := exec.Command("ip", "addr", "replace", addr+"/32", "dev", "lo").Run(); err != nil {
		t.Fatalf("add lo alias %s/32: %v", addr, err)
	}
	t.Cleanup(func() { _ = exec.Command("ip", "addr", "del", addr+"/32", "dev", "lo").Run() })
}

// setAcceptLocal 把 net.ipv4.conf.<iface>.accept_local 设为 1。新建 tun 默认是 0,
// 直接写 1 即可;失败(tun 没建成/无权限)直接终止测试。
func setAcceptLocal(t *testing.T, iface string, val int) {
	t.Helper()
	key := "net.ipv4.conf." + iface + ".accept_local"
	if err := exec.Command("sysctl", "-w", key+"="+strconv.Itoa(val)).Run(); err != nil {
		t.Fatalf("set %s=%d: %v", key, val, err)
	}
}

// restoreAcceptLocal 尽力把 accept_local 恢复成默认 0。t.Cleanup 的 LIFO 顺序保证它
// 先于 link-del 执行,接口还在;即便接口已被删(如引擎启动中途失败),静默忽略即可——
// 接口删除本身就把它的 sysctl 带走了。
func restoreAcceptLocal(iface string) {
	_ = exec.Command("sysctl", "-w", "net.ipv4.conf."+iface+".accept_local=0").Run()
}

// startTUNEngine 起一个带真实 TUN 设备(10.0.0.1/24)的引擎,返回引擎和 tun 设备名。
// 引擎的 installSelectiveRoutes 会自动装 `from 10.0.0.1/24 → tun0` 的源路由,
// SO_BINDTODEVICE 的客户端 socket 正是靠它才有 tun 上的出路由。
func startTUNEngine(t *testing.T, spec engineSpec) (*Engine, string) {
	t.Helper()
	requireTUN(t)
	name := "sp" + strconv.Itoa(os.Getpid())
	_ = exec.Command("ip", "link", "del", name).Run() // 清理残留同名设备
	spec.tun = &config.TUNConfig{
		Enabled:      true,
		Name:         name,
		MTU:          1500,
		Inet4Address: []string{"10.0.0.1/24"},
	}
	eng := startEngine(t, spec)

	// 结束即删设备(先注册;Cleanup 按 LIFO 跑,所以后注册的恢复会先执行)。
	t.Cleanup(func() { _ = exec.Command("ip", "link", "del", name).Run() })

	// ⚠️ 内核 martian 源过滤:见文件头「第二层坑」。tun 接口收到「源=本机本地地址(lo 上
	// 的 198.18.0.2)」的 SYN-ACK 会被当伪造源丢弃,导致连接建不起来。给这个自建 tun 开
	// accept_local=1(读原值、结束后尽力恢复)。这行是 TUN 直连/代理用例成立的前提,别删。
	setAcceptLocal(t, name, 1)
	t.Cleanup(func() { restoreAcceptLocal(name) })
	return eng, name
}

// bindToTUN 返回 net.Dialer 的 Control:给 socket 打 SO_BINDTODEVICE,
// 等价 `curl --interface tun0`,强制该 socket 的包走 tun 设备(而非按目的地址路由)。
// 这是 TUN 测试客户端的进隧道方式。注意:因为 oif=tun0 会排除 dev-lo 的 local 路由,
// 发往本地别名 198.18.0.2 的包也会落进 tun fd 而非本地回环。
func bindToTUN(ifname string) func(network, address string, c syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error {
		var serr error
		if err := c.Control(func(fd uintptr) {
			serr = unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, ifname)
		}); err != nil {
			return err
		}
		return serr
	}
}

// tunDial 用绑定 tun 的 socket 拨号,测试进程扮演隧道内的客户端,目标恒为 tunServerIP。
// 源地址由内核按 tun 子网自动选(10.0.0.1),回包 dst=10.0.0.1 是本地地址能原路送回。
func tunDial(t *testing.T, ifname, network string, port int) net.Conn {
	t.Helper()
	addr := net.JoinHostPort(tunServerIP, strconv.Itoa(port))
	d := net.Dialer{Timeout: 10 * time.Second, Control: bindToTUN(ifname)}
	c, err := d.Dial(network, addr)
	if err != nil {
		t.Fatalf("tun client dial %s %s: %v", network, addr, err)
	}
	return c
}

// ── 用例 ───────────────────────────────────────────

// TestEngineTUN_DirectTCP:客户端经 tun 拨 198.18.0.2,ACL force-direct 规则 → 引擎直连 echo。
func TestEngineTUN_DirectTCP(t *testing.T) {
	requireTUN(t) // 必须先于 addLoAlias:无 CAP_NET_ADMIN 的环境(如 CI)在这里 Skip,
	// 而不是挂在 ip addr 的 Fatal 上(探测命令本身也要 CAP_NET_ADMIN,能建 tun 才继续)
	addLoAlias(t, tunServerIP)
	_, ifname := startTUNEngine(t, engineSpec{
		chnroute: tunServerNet + "\n",
		acl:      "proxy cidr " + tunServerNet + " direct\n",
	})
	echo := startTCPEchoOn(t, tunServerIP)
	echoPort := echo.Addr().(*net.TCPAddr).Port

	before := sampleCounters()
	c := tunDial(t, ifname, "tcp", echoPort)
	defer c.Close()
	c.SetDeadline(time.Now().Add(15 * time.Second))

	payload := []byte("hello tun direct tcp")
	if _, err := c.Write(payload); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf, payload) {
		t.Fatalf("TUN direct TCP echo mismatch: got %q want %q", buf, payload)
	}
	// relay.TCPRelay 连接关闭才结算,先关客户端再轮询
	c.Close()
	assertDirectTraffic(t, before, false)
}

// TestEngineTUN_DirectUDP:客户端经 tun 发 UDP 到 198.18.0.2,ACL force-direct → 引擎直连 echo。
func TestEngineTUN_DirectUDP(t *testing.T) {
	requireTUN(t) // 必须先于 addLoAlias:无 CAP_NET_ADMIN 的环境(如 CI)在这里 Skip,
	// 而不是挂在 ip addr 的 Fatal 上(探测命令本身也要 CAP_NET_ADMIN,能建 tun 才继续)
	addLoAlias(t, tunServerIP)
	_, ifname := startTUNEngine(t, engineSpec{
		chnroute: tunServerNet + "\n",
		acl:      "proxy cidr " + tunServerNet + " direct\n",
	})
	echo := startUDPEchoOn(t, tunServerIP)
	echoPort := echo.LocalAddr().(*net.UDPAddr).Port

	c := tunDial(t, ifname, "udp", echoPort)
	defer c.Close()
	c.SetDeadline(time.Now().Add(15 * time.Second))

	payload := []byte("hello tun direct udp")
	if _, err := c.Write(payload); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf, payload) {
		t.Fatalf("TUN direct UDP echo mismatch: got %q want %q", buf, payload)
	}
	// TUN UDP 走 internal/tun/handler.go 自己的转发,不经 internal/udp,udp.* 计数器不涨,
	// 只能靠回包内容断言(不能用 assertDirectTraffic)。
}

// TestEngineTUN_ProxyTCP:ACL 规则走上游 → 引擎 A 把 tun 流量交给 SOCKS5 引擎 B,B 直连 echo。
func TestEngineTUN_ProxyTCP(t *testing.T) {
	requireTUN(t) // 必须先于 addLoAlias:无 CAP_NET_ADMIN 的环境(如 CI)在这里 Skip,
	// 而不是挂在 ip addr 的 Fatal 上(探测命令本身也要 CAP_NET_ADMIN,能建 tun 才继续)
	addLoAlias(t, tunServerIP)
	// 上游 B:纯直连引擎,但 newTestEngine 只 force-direct 回环,这里必须显式覆盖 198.18.0.0/16,
	// 否则 B 对 198.18.0.2 落进空策略回退、无可用上游而报错。
	up := startEngine(t, engineSpec{
		chnroute: tunServerNet + "\n",
		acl:      "proxy cidr " + tunServerNet + " direct\n",
	})
	_, ifname := startTUNEngine(t, engineSpec{
		acl:      "proxy cidr " + tunServerNet + " up\n",
		upstream: []config.ProxyEntry{{Alias: "up", URL: "socks5://" + up.listener.Addr().String()}},
	})
	echo := startTCPEchoOn(t, tunServerIP)
	echoPort := echo.Addr().(*net.TCPAddr).Port

	beforeB := sampleCounters()
	c := tunDial(t, ifname, "tcp", echoPort)
	defer c.Close()
	c.SetDeadline(time.Now().Add(15 * time.Second))

	payload := []byte("hello tun proxy tcp")
	if _, err := c.Write(payload); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf, payload) {
		t.Fatalf("TUN proxy TCP echo mismatch: got %q want %q", buf, payload)
	}
	// 上游 B(直连引擎)收到了流量并直连 echo → B 的 relay.DirectBytesUp 增长
	c.Close()
	assertUpstreamDirect(t, beforeB, false)
}

// TestEngineTUN_ProxyUDP:ACL 规则走上游 → 引擎 A 把 tun UDP 交给 SOCKS5 引擎 B,B 直连 echo。
func TestEngineTUN_ProxyUDP(t *testing.T) {
	requireTUN(t) // 必须先于 addLoAlias:无 CAP_NET_ADMIN 的环境(如 CI)在这里 Skip,
	// 而不是挂在 ip addr 的 Fatal 上(探测命令本身也要 CAP_NET_ADMIN,能建 tun 才继续)
	addLoAlias(t, tunServerIP)
	up := startEngine(t, engineSpec{
		chnroute: tunServerNet + "\n",
		acl:      "proxy cidr " + tunServerNet + " direct\n",
	})
	_, ifname := startTUNEngine(t, engineSpec{
		acl:      "proxy cidr " + tunServerNet + " up\n",
		upstream: []config.ProxyEntry{{Alias: "up", URL: "socks5://" + up.listener.Addr().String()}},
	})
	echo := startUDPEchoOn(t, tunServerIP)
	echoPort := echo.LocalAddr().(*net.UDPAddr).Port

	beforeB := sampleCounters()
	c := tunDial(t, ifname, "udp", echoPort)
	defer c.Close()
	c.SetDeadline(time.Now().Add(20 * time.Second))

	payload := []byte("hello tun proxy udp")
	if _, err := c.Write(payload); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf, payload) {
		t.Fatalf("TUN proxy UDP echo mismatch: got %q want %q", buf, payload)
	}
	// B(SOCKS5 引擎)走 internal/udp 直连 echo → B 的 udp.DirectBytesUp 增长
	assertUpstreamDirect(t, beforeB, true)
}

// TestEngineTUN_BlockTCP:block ip 命中 → handler 直接关连接 → 客户端 Dial 必然失败。
// 非假阳性:直连用例(TestEngineTUN_DirectTCP)证明同一条链路报文能到 handler,
// 这里报文同样到达,只是被 block 规则关掉。
func TestEngineTUN_BlockTCP(t *testing.T) {
	requireTUN(t) // 必须先于 addLoAlias:无 CAP_NET_ADMIN 的环境(如 CI)在这里 Skip,
	// 而不是挂在 ip addr 的 Fatal 上(探测命令本身也要 CAP_NET_ADMIN,能建 tun 才继续)
	addLoAlias(t, tunServerIP)
	_, ifname := startTUNEngine(t, engineSpec{
		chnroute: tunServerNet + "\n",
		acl:      "block ip " + tunServerIP + "\n",
	})
	echo := startTCPEchoOn(t, tunServerIP)
	echoPort := echo.Addr().(*net.TCPAddr).Port

	// 直接 Dial,预期失败(RST 或超时都算 block 生效)
	c, err := (&net.Dialer{Timeout: 4 * time.Second, Control: bindToTUN(ifname)}).
		Dial("tcp", net.JoinHostPort(tunServerIP, strconv.Itoa(echoPort)))
	if err == nil {
		c.Close()
		t.Fatal("expected TUN block to reject the TCP dial, but it succeeded")
	}
}

// TestEngineTUN_BlockUDP:block ip 命中 → handler 关闭 UDP 连接、无回包 → 读超时断言。
func TestEngineTUN_BlockUDP(t *testing.T) {
	requireTUN(t) // 必须先于 addLoAlias:无 CAP_NET_ADMIN 的环境(如 CI)在这里 Skip,
	// 而不是挂在 ip addr 的 Fatal 上(探测命令本身也要 CAP_NET_ADMIN,能建 tun 才继续)
	addLoAlias(t, tunServerIP)
	_, ifname := startTUNEngine(t, engineSpec{
		chnroute: tunServerNet + "\n",
		acl:      "block ip " + tunServerIP + "\n",
	})
	echo := startUDPEchoOn(t, tunServerIP)
	echoPort := echo.LocalAddr().(*net.UDPAddr).Port

	c, err := (&net.Dialer{Timeout: 4 * time.Second, Control: bindToTUN(ifname)}).
		Dial("udp", net.JoinHostPort(tunServerIP, strconv.Itoa(echoPort)))
	if err != nil {
		t.Fatalf("tun client udp dial: %v", err)
	}
	defer c.Close()
	if _, err := c.Write([]byte("blocked")); err != nil {
		t.Fatal(err)
	}
	// block 命中 → 连接被 handler 关闭、无回包:短超时断言
	buf := make([]byte, 64)
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Read(buf); err == nil {
		t.Fatal("expected TUN block to drop the UDP packet, but got a reply")
	}
}

