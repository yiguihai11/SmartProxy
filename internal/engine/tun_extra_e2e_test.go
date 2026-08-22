package engine

// M7 额外 TUN(AddTunFd / RemoveTunFd)端到端回归测试。
//
// 覆盖免 root 热点共享的引擎侧:主 VPN TUN 之外再挂一条「测试网络 TUN」fd,
// 两条 TUN 的流量都进同一套 Router/RuleEng/UpstreamMgr/DNSHandler 分流/代理。
//
// 与 tun_e2e_test.go 相同的三条内核前提(见该文件头注释,不许再踩):
//  1. gVisor martian 回环过滤 → 目标用非回环本地别名 198.18.0.2,不拨 127.0.0.1;
//  2. 内核 martian 源过滤 → 额外 TUN 也要 accept_local=1(回包源=本机 lo 本地地址);
//  3. -race 下 sing-tun gvisor 启动窗口有上游数据竞态 → requireTUN 直接 Skip。
//
// 额外一条,fd 模式专属:fd 模式的 NativeTun.Start() 是 no-op(不装任何路由),
// 所以额外 TUN 必须先手动 `ip addr add` + `ip route add ... dev <name>`,否则
// SO_BINDTODEVICE 绑它时内核找不到 oif=额外 TUN 的路由,包根本进不了隧道。

import (
	"bytes"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// createTunFD 创建一条真实的 /dev/net/tun 设备并返回其 fd(裸 fd,给 AddTunFd 用)。
// 负责:建接口、ip addr 配地址、link up、accept_local=1;结束自动删接口。
// fd 所有权交给调用方(测试里随后 AddTunFd,由引擎负责关闭)。
func createTunFD(t *testing.T, name, addr string) int {
	t.Helper()
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("open /dev/net/tun: %v", err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) }) // 兜底:引擎没接管/没关的情况下不泄漏

	ifr, err := unix.NewIfreq(name)
	if err != nil {
		unix.Close(fd)
		t.Fatalf("NewIfreq %s: %v", name, err)
	}
	ifr.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI)
	if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr); err != nil {
		unix.Close(fd)
		t.Fatalf("TUNSETIFF %s: %v", name, err)
	}
	t.Cleanup(func() { _ = exec.Command("ip", "link", "del", name).Run() })

	if err := exec.Command("ip", "link", "set", name, "up").Run(); err != nil {
		t.Fatalf("ip link set %s up: %v", name, err)
	}
	if err := exec.Command("ip", "addr", "add", addr, "dev", name).Run(); err != nil {
		t.Fatalf("ip addr add %s dev %s: %v", addr, name, err)
	}
	// 与主 TUN 相同的内核 martian 源过滤坑:额外 TUN 收到的回包源是 lo 本地别名,
	// 不开 accept_local=1 会被静默丢弃,连接永远建不起来。
	setAcceptLocal(t, name, 1)
	t.Cleanup(func() { restoreAcceptLocal(name) })
	return fd
}

// extraTunName 返回一个与主 TUN(sp+pid)不冲突的唯一设备名。
func extraTunName(prefix string) string {
	return prefix + strconv.Itoa(os.Getpid())
}

// TestEngineTUN_AddRemoveLifecycle:AddTunFd 挂载 → RemoveTunFd 移除(幂等)→
// 再挂一条后靠 engine.Stop 清理,全程不 panic、map 状态正确。
func TestEngineTUN_AddRemoveLifecycle(t *testing.T) {
	requireTUN(t)
	eng := startEngine(t, engineSpec{}) // 无主 TUN,AddTunFd 是唯一 TUN

	name1 := extraTunName("spa")
	fd1 := createTunFD(t, name1, "10.0.2.1/24")
	if err := eng.AddTunFd(fd1, "10.0.2.1/24", "", 1500); err != nil {
		t.Fatalf("AddTunFd: %v", err)
	}
	eng.extraMu.Lock()
	if len(eng.extraTuns) != 1 {
		t.Fatalf("extraTuns after add = %d, want 1", len(eng.extraTuns))
	}
	eng.extraMu.Unlock()

	if err := eng.RemoveTunFd(fd1); err != nil {
		t.Fatalf("RemoveTunFd: %v", err)
	}
	eng.extraMu.Lock()
	if len(eng.extraTuns) != 0 {
		t.Fatalf("extraTuns after remove = %d, want 0", len(eng.extraTuns))
	}
	eng.extraMu.Unlock()
	if err := eng.RemoveTunFd(fd1); err != nil { // 幂等
		t.Fatalf("second RemoveTunFd: %v", err)
	}

	// 再挂一条,交给 t.Cleanup(eng.Stop) 清理,验证 Stop 兜底不 panic、不泄漏。
	_ = exec.Command("ip", "link", "del", name1).Run() // 释放名字,建新的
	name2 := extraTunName("spb")
	fd2 := createTunFD(t, name2, "10.0.3.1/24")
	if err := eng.AddTunFd(fd2, "10.0.3.1/24", "", 1500); err != nil {
		t.Fatalf("AddTunFd (2nd): %v", err)
	}
	// engine.Stop 由 startEngine 的 t.Cleanup 触发,这里只断言 map 非空即可
	eng.extraMu.Lock()
	got := len(eng.extraTuns)
	eng.extraMu.Unlock()
	if got != 1 {
		t.Fatalf("extraTuns before stop = %d, want 1", got)
	}
}

// TestEngineTUN_DualTUN_Traffic:主 TUN + 额外 fd TUN 同时拨 echo,两路都通、共享
// 同一套直连计数;RemoveTunFd 后额外 TUN 拨号失败(证明 teardown 生效)。
func TestEngineTUN_DualTUN_Traffic(t *testing.T) {
	requireTUN(t)
	addLoAlias(t, tunServerIP)
	eng, mainName := startTUNEngine(t, engineSpec{
		chnroute: tunServerNet + "\n",
		acl:      "proxy cidr " + tunServerNet + " direct\n",
	})

	// 额外 TUN:独立子网 + 手动路由(fd 模式不装路由,见文件头)。
	extraName := extraTunName("spx")
	fd := createTunFD(t, extraName, "10.0.2.1/24")
	// 源约束在 SO_BINDTODEVICE 的 oif 上,不与主 TUN 的 from-路由冲突
	if err := exec.Command("ip", "route", "add", tunServerNet, "dev", extraName, "src", "10.0.2.1").Run(); err != nil {
		t.Fatalf("ip route add %s dev %s: %v", tunServerNet, extraName, err)
	}
	if err := eng.AddTunFd(fd, "10.0.2.1/24", "", 1500); err != nil {
		t.Fatalf("AddTunFd: %v", err)
	}

	echo := startTCPEchoOn(t, tunServerIP)
	echoPort := echo.Addr().(*net.TCPAddr).Port

	// 主 TUN 路径
	payload := []byte("hello dual tun main")
	verifyTUNEcho(t, mainName, echoPort, payload)

	// 额外 TUN 路径(热点客户端流量):同样能拨通,说明两路共享同一分流核心
	payload2 := []byte("hello dual tun extra")
	verifyTUNEcho(t, extraName, echoPort, payload2)

	// RemoveTunFd 后额外 TUN 的 fd 被引擎关闭 → SYN 无人应答 → 拨号失败
	if err := eng.RemoveTunFd(fd); err != nil {
		t.Fatalf("RemoveTunFd: %v", err)
	}
	d := net.Dialer{Timeout: 2 * time.Second, Control: bindToTUN(extraName)}
	addr := net.JoinHostPort(tunServerIP, strconv.Itoa(echoPort))
	if c, err := d.Dial("tcp", addr); err == nil {
		c.Close()
		t.Fatal("extra TUN dial still succeeded after RemoveTunFd; teardown did not take effect")
	}
}

// verifyTUNEcho 用绑定指定 tun 的 socket 拨 echo,写 payload 并断言逐字回显。
func verifyTUNEcho(t *testing.T, ifname string, port int, payload []byte) {
	t.Helper()
	c := tunDial(t, ifname, "tcp", port)
	defer c.Close()
	c.SetDeadline(time.Now().Add(15 * time.Second))
	if _, err := c.Write(payload); err != nil {
		t.Fatalf("%s write: %v", ifname, err)
	}
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatalf("%s read: %v", ifname, err)
	}
	if !bytes.Equal(buf, payload) {
		t.Fatalf("%s echo mismatch: got %q want %q", ifname, buf, payload)
	}
}
