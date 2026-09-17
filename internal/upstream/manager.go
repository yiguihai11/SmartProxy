package upstream

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"smartproxy/internal/config"
	"smartproxy/internal/rules"
	"smartproxy/internal/safego"
	"smartproxy/internal/singbox"
	"smartproxy/internal/trace"
)

// transport 区分 TCP 建连与 UDP 关联这两条独立的选路路径。
type transport int

const (
	transportTCP transport = iota
	transportUDP
	// transportCount 是路径总数,用来给 Manager.order 定长。
	transportCount
)

// latencyOf 返回该路径该看哪个电路的延迟样本。TCP 建连看 TCP 电路,UDP 关联看 UDP
// 电路——两条电路的延迟由彼此独立的探测记录(health.go 里 RecordSuccess 与
// RecordUDPSuccess 分别写 health.latency / udpHealth.latency),拿 TCP 的数字给 UDP
// 排序等于用错了尺子:一个 TCP 快 UDP 烂的节点会被派去当中继。
func (t transport) latencyOf(p *Proxy) time.Duration {
	if t == transportUDP {
		return p.udpHealth.Latency()
	}
	return p.health.Latency()
}

// availableFor 按路径自己的电路判定节点能不能进候选集。TCP 路径只看 TCP 熔断器;
// UDP 路径还要求节点本身支持 UDP、且 UDP 熔断器闭合——两个熔断器互相独立,一个 TCP
// 被手工关掉的 udp_only 节点在 UDP 路径上是正经候选,不能因为 TCP 的状态被沉到队尾。
func (t transport) availableFor(p *Proxy) bool {
	if t == transportUDP {
		return p.SupportsUDP() && p.IsUDPAvailable()
	}
	return p.IsAvailable()
}

// rotationState 是单条路径自己的选路状态,两条路径各持一份(Manager.order)。共用会让
// UDP 关联把 TCP 的顺序顶偏(轮转指针)或者把 TCP 的候选带拽走(band 快照),两者都
// 不可复现地取决于当时的流量配比——DNS 走得勤的时候尤其明显。
type rotationState struct {
	// rr 是轮转指针:round_robin 在全体节点上转,latency 只在候选带内转。每建一条
	// 新连接推进一格,负载就是这么摊开的。
	rr atomic.Uint64
	// band 是 latency 策略上一拍的候选带快照(指针身份,不可变),只用来给带缘加
	// 滞回:带内成员要烂过"退出线"才被踢,带外节点够到"进入线"才能进。没有这层,
	// EWMA 在带线附近抖一下成员就进进出出,轮转集合每拍都变,出口 IP 集合反而不稳。
	// 配置重载会重建整个 Proxy 对象,旧快照的身份一个都对不上,自动按当前数据重建。
	band atomic.Pointer[bandSnapshot]
}

// bandSnapshot 是候选带成员的不可变快照,按当时的有效延迟次序存放;选路只认指针身份。
type bandSnapshot struct {
	members []*Proxy
}

// rrStart 推进轮转指针并返回本次起点 [0,n)。取模必须留在 uint64 里:计数器回绕那一拍
// Add(1) 返回 0,Add(1)-1 在 uint64 下下溢成 MaxUint64,先转 int 就是 -1,拿去索引
// 切片直接 panic。前 2^64 次选择与"调用序号 mod n"完全一致,回绕那一拍落在
// (2^64-1) mod n——要数满 2^64 次才看得出偏差,关键是不越界。
func rrStart(st *rotationState, n int) int {
	return int((st.rr.Add(1) - 1) % uint64(n))
}

type Manager struct {
	mu             sync.RWMutex
	aliasMap       map[string]*Proxy
	defaultProxies []*Proxy
	strategy       string
	// order 按 transport 索引(transportTCP / transportUDP),见 rotationState。
	order           [transportCount]rotationState
	healthChecker   *HealthChecker
	dnsUDPPool      *UDPAssociatePool
	healthCfg       config.HealthCheckConf
	staticProxies   []ProxyEntry
	providerProxies map[string][]ProxyEntry
	stopped         bool
	ctx             context.Context
	cancel          context.CancelFunc
	// failover 对冲节奏,零值使用 default 常量;留字段给测试压缩时间。
	dialHedgeDelay     time.Duration
	dialAttemptTimeout time.Duration
	// udpVerifyTimeout 是"未验明正身的 raw 中继"做端到端 DNS 问答的预算,
	// 零值使用 defaultUDPVerifyTimeout;同样留给测试压缩。
	udpVerifyTimeout time.Duration
}

func NewManager(cfg UpstreamConfig) (*Manager, error) {
	ctx, cancel := context.WithCancel(context.Background())
	m := &Manager{
		dnsUDPPool:      NewUDPAssociatePool(4),
		providerProxies: make(map[string][]ProxyEntry),
		ctx:             ctx,
		cancel:          cancel,
	}
	m.staticProxies = cfg.Proxies
	m.healthCfg = cfg.HealthCheck
	m.strategy = cfg.Default
	activeSB := m.rebuildLocked()
	_ = singbox.GlobalEngine().SyncOutbounds(activeSB)
	m.healthChecker = NewHealthChecker(cfg.HealthCheck, m.defaultProxies)
	m.healthChecker.Start()
	m.probeInitialGeo()
	slog.Info("upstream manager initialized", "aliases", len(m.aliasMap), "strategy", m.strategy)
	return m, nil
}

func (m *Manager) Reload(cfg UpstreamConfig) {
	m.mu.Lock()
	if m.stopped {
		m.mu.Unlock()
		return
	}
	// Rebuild creates brand-new Proxy objects whose health is fully automatic, which would
	// silently revert any explicit user disable/enable. Preserve the manual pins (keyed by
	// alias) so a config hot-reload keeps the user's choice.
	pins := m.captureManualPins()
	m.staticProxies = cfg.Proxies
	m.healthCfg = cfg.HealthCheck
	m.strategy = cfg.Default
	activeSB := m.rebuildLocked()
	newProxies := m.defaultProxies
	m.mu.Unlock()

	_ = singbox.GlobalEngine().SyncOutbounds(activeSB)

	if m.dnsUDPPool != nil {
		m.dnsUDPPool.Close()
	}
	m.dnsUDPPool = NewUDPAssociatePool(4)

	// newProxies are freshly built by rebuildFromConfig: their health is zero-value
	// (StateClosed) apart from construction-time default pins, which set state and
	// manual consistently (hev udp_in_tcp TCP-down via applyUDPInTCPDefaults, SS-plugin
	// UDP-down via NewProxy). Do NOT blanket-reset them: reset() would clear a default
	// pin's forced StateOpen back to Closed while leaving manual=&false, reporting the
	// circuit as both "manual" and "available" (the add-node-shows-TCP-up bug).
	// restoreManualPins overlays the PRE-reload user pins for aliases that already existed
	// (Set/ClearManualState keep state and manual in sync); brand-new aliases keep their
	// construction defaults.
	m.restoreManualPins(pins)

	if m.healthChecker != nil {
		m.healthChecker.Reload(cfg.HealthCheck, newProxies)
	}
	m.probeInitialGeo()
	slog.Info("upstream manager reloaded", "aliases", len(m.aliasMap), "strategy", m.strategy)
}

// Stop shuts down the manager's background work: the health checker's per-node check loops
// and the DNS UDP associate pool. It is called from Engine.Stop. Without it, every
// stop/restart (e.g. toggling the Android VPN) leaks one goroutine per proxy node (each
// checkLoop spins on stopCh forever) plus up to four pooled UDP ASSOCIATE connections.
func (m *Manager) Stop() {
	m.mu.Lock()
	if m.stopped {
		m.mu.Unlock()
		return
	}
	m.stopped = true
	cancel := m.cancel
	m.cancel = nil
	m.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	if m.healthChecker != nil {
		m.healthChecker.Stop()
	}
	if m.dnsUDPPool != nil {
		m.dnsUDPPool.Close()
	}
	_ = singbox.GlobalEngine().Close()
}

// circuitPin captures one health circuit's manual pin: whether it is pinned and, if so,
// the forced availability. Both index 0 (TCP) and index 1 (UDP) live in the same array.
// defaultDriven records whether the circuit's construction-time default force-down applied
// on the PRE-reload node (TCP: hev udp_in_tcp; UDP: ss + SIP003 plugin), so a reload that
// newly flips that flag on can let the fresh construction default win instead of overlaying
// a stale pin from when the node had no such default.
type circuitPin struct {
	pinned        bool
	up            bool
	defaultDriven bool
}

type savedNodeState struct {
	url         string
	pins        [2]circuitPin
	countryCode string
	exitIP      string
}

// captureManualPins records each proxy's manual circuit pins and resolved geo info keyed by alias.
// Caller must hold m.mu (any level).
func (m *Manager) captureManualPins() map[string]savedNodeState {
	states := make(map[string]savedNodeState, len(m.aliasMap))
	for alias, p := range m.aliasMap {
		if p == nil {
			continue // "direct" has no health circuit
		}
		tpinned, tup := p.health.ManualPin()
		upinned, uup := p.udpHealth.ManualPin()
		states[alias] = savedNodeState{
			url: p.URL,
			pins: [2]circuitPin{
				{pinned: tpinned, up: tup, defaultDriven: p.tcpDefaultDriven()},
				{pinned: upinned, up: uup, defaultDriven: p.udpDefaultDriven()},
			},
			countryCode: p.CountryCode(),
			exitIP:      p.ExitIP(),
		}
	}
	return states
}

// restoreManualPins re-applies saved manual pins and known geo info to proxies that still exist after a reload.
func (m *Manager) restoreManualPins(states map[string]savedNodeState) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for alias, state := range states {
		p, ok := m.aliasMap[alias]
		if !ok || p == nil {
			continue
		}
		// If the node's URL changed, discard stale geo info so the freshly inferred
		// country code and a subsequent probe trace take effect.
		if p.URL == state.url && (state.countryCode != "" || state.exitIP != "") {
			p.SetGeoInfo(state.countryCode, state.exitIP)
		}
		restore := func(ph *ProxyHealth, cp circuitPin, nowDefaultDriven bool) {
			// Flag just toggled on (was not default-driven, now is): keep the construction
			// default applied by rebuildFromConfig and drop the stale pre-toggle pin.
			if nowDefaultDriven && !cp.defaultDriven {
				return
			}
			if cp.pinned {
				ph.SetManualState(cp.up)
			} else {
				ph.ClearManualState()
			}
		}
		restore(&p.health, state.pins[0], p.tcpDefaultDriven())
		restore(&p.udpHealth, state.pins[1], p.udpDefaultDriven())
	}
}

// rebuildLocked rebuilds aliasMap and defaultProxies from staticProxies + all providerProxies.
// Caller must hold m.mu.Lock(). Returns the map of active sing-box outbounds to sync.
func (m *Manager) rebuildLocked() map[string]json.RawMessage {
	aliasMap := make(map[string]*Proxy)
	aliasMap["direct"] = nil
	reservedAliases := map[string]bool{"direct": true}
	var defaultProxies []*Proxy

	existingByURL := make(map[string]*Proxy, len(m.aliasMap))
	for _, p := range m.aliasMap {
		if p != nil && p.URL != "" {
			existingByURL[p.URL] = p
		}
	}

	var allEntries []ProxyEntry
	allEntries = append(allEntries, m.staticProxies...)
	for _, pEntries := range m.providerProxies {
		allEntries = append(allEntries, pEntries...)
	}

	activeSB := make(map[string]json.RawMessage)

	for i, entry := range allEntries {
		alias := entry.Alias
		if alias == "" {
			alias = fmt.Sprintf("proxy%d", i)
		}
		if entry.URL == "" {
			if !reservedAliases[alias] {
				slog.Warn("proxy without URL skipped", "alias", alias)
			}
			continue
		}
		if reservedAliases[alias] {
			slog.Warn("cannot override reserved alias, skipping", "alias", alias)
			continue
		}
		if _, exists := aliasMap[alias]; exists {
			base := alias
			for count := 2; ; count++ {
				candidate := fmt.Sprintf("%s (%d)", base, count)
				if _, taken := aliasMap[candidate]; !taken {
					alias = candidate
					break
				}
			}
		}

		existing := existingByURL[entry.URL]
		var proxy *Proxy
		if existing != nil && existing.UDPInTCP == entry.UDPInTCP {
			proxy = existing
			proxy.Provider = entry.Provider
		} else {
			var err error
			proxy, err = newProxyParsed(entry.URL)
			if err != nil {
				slog.Warn("failed to create proxy", "url", MaskProxyURL(entry.URL), "error", err)
				continue
			}
			proxy.Provider = entry.Provider
			proxy.UDPInTCP = entry.UDPInTCP || proxy.UDPInTCP
			proxy.applyUDPInTCPDefaults()
			if m.healthCheckEnabledForProxiesLocked(len(allEntries)) {
				proxy.health.SetInitialUnverified()
				proxy.udpHealth.SetInitialUnverified()
			}
		}

		if proxy.CountryCode() == "" {
			if cc := inferCountryCode(alias, proxy.Name, proxy.Host); cc != "" {
				proxy.SetGeoInfo(cc, "")
			}
		}
		aliasMap[alias] = proxy
		defaultProxies = append(defaultProxies, proxy)
		if proxy.singboxTag != "" && len(proxy.singboxRaw) > 0 {
			activeSB[proxy.singboxTag] = proxy.singboxRaw
		}
	}
	m.aliasMap = aliasMap
	m.defaultProxies = defaultProxies
	return activeSB
}

func (m *Manager) healthCheckEnabledForProxiesLocked(totalProxies int) bool {
	if !m.healthCfg.Enabled {
		return false
	}
	if m.healthCfg.AutoDisableSingle && totalProxies <= 1 {
		return false
	}
	return true
}

// SetProviderProxies dynamically registers or updates a set of proxies provided by an
// external provider (e.g. Lantern free nodes). Passing empty entries removes that provider's proxies.
func (m *Manager) SetProviderProxies(provider string, entries []ProxyEntry) {
	m.mu.Lock()
	if m.stopped {
		m.mu.Unlock()
		return
	}
	if m.providerProxies == nil {
		m.providerProxies = make(map[string][]ProxyEntry)
	}
	if len(entries) == 0 {
		delete(m.providerProxies, provider)
	} else {
		copied := make([]ProxyEntry, len(entries))
		for i, e := range entries {
			if e.Provider == "" {
				e.Provider = provider
			}
			copied[i] = e
		}
		m.providerProxies[provider] = copied
	}
	pins := m.captureManualPins()
	activeSB := m.rebuildLocked()
	newProxies := m.defaultProxies
	healthCfg := m.healthCfg
	m.mu.Unlock()

	_ = singbox.GlobalEngine().SyncOutbounds(activeSB)
	m.restoreManualPins(pins)

	if m.healthChecker != nil {
		m.healthChecker.Reload(healthCfg, newProxies)
	}
	m.probeInitialGeo()
	slog.Info("provider proxies updated", "provider", provider, "count", len(entries), "totalProxies", len(newProxies))
}

// RemoveProviderNodes removes specific aliases from provider proxies and rebuilds the active pool.
func (m *Manager) RemoveProviderNodes(aliases []string) int {
	if len(aliases) == 0 {
		return 0
	}
	aliasSet := make(map[string]bool, len(aliases))
	for _, a := range aliases {
		if a != "" {
			aliasSet[a] = true
		}
	}
	m.mu.Lock()
	if m.stopped {
		m.mu.Unlock()
		return 0
	}
	totalRemoved := 0
	for pName, entries := range m.providerProxies {
		var kept []ProxyEntry
		removedHere := 0
		for _, e := range entries {
			if aliasSet[e.Alias] {
				removedHere++
			} else {
				kept = append(kept, e)
			}
		}
		if removedHere > 0 {
			if len(kept) == 0 {
				delete(m.providerProxies, pName)
			} else {
				m.providerProxies[pName] = kept
			}
			totalRemoved += removedHere
		}
	}
	if totalRemoved > 0 {
		pins := m.captureManualPins()
		activeSB := m.rebuildLocked()
		newProxies := m.defaultProxies
		healthCfg := m.healthCfg
		m.mu.Unlock()

		_ = singbox.GlobalEngine().SyncOutbounds(activeSB)
		m.restoreManualPins(pins)
		if m.healthChecker != nil {
			m.healthChecker.Reload(healthCfg, newProxies)
		}
		m.probeInitialGeo()
		slog.Info("provider nodes removed", "removed", totalRemoved, "remaining", len(newProxies))
		return totalRemoved
	}
	m.mu.Unlock()
	return 0
}

type UpstreamConfig struct {
	Default     string
	HealthCheck config.HealthCheckConf
	Proxies     []ProxyEntry
}

type ProxyEntry struct {
	Alias string
	URL   string
	// UDPInTCP carries the node's udp_in_tcp switch from the config entry (see
	// Proxy.UDPInTCP). It is OR-ed with whatever the URL's ?udp_in_tcp=1 query set.
	UDPInTCP bool
	Provider string
}

func (m *Manager) SelectProxy(ctx context.Context, targetIP string, targetPort int, domain string, engine *rules.Engine) (string, *Proxy) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	// 选路发生在某条流的会话建立里:日志必须带 flow id(TUN/SOCKS5 入口注入的 ctx 一路
	// 传到这里),否则 "proxy rule matched" 这条最关键的选路日志会掉号,破坏 grep flow=N
	// 从入口追到转出的整条链。测试传 context.Background() 时 trace.Log 退回 slog.Default。
	ll := trace.Log(ctx)
	if engine != nil {
		alias, matched := engine.MatchProxyRule(targetIP, targetPort, domain)
		if matched {
			ll.Info("proxy rule matched", "alias", alias)
			if strings.EqualFold(alias, "direct") {
				return "direct", nil
			}
			proxy, _ := m.findProxyLocked(alias)
			if proxy != nil {
				return "", proxy
			}
			ll.Warn("alias not found, falling back to default proxy", "alias", alias)
			return "proxy_default", nil
		}
	}
	return "fallback", nil
}

// 多节点 failover 的对冲节奏:第一个节点立即拨号,之后每过 hedgeDelay 前一个还没出结果,
// 就并发拨下一个;单次拨号(含握手+目标 CONNECT)的硬上限 attemptTimeout,只在多节点时
// 生效——单节点没有备胎,保持 proxyDialTimeout 的 10s 容忍,慢目标也不能误杀。
// 默认 1.5s/5s:日志实测健康节点拨号都在 1s 内完成,而死节点会把 SYN 挂到满 10s,
// 没有对冲时用户要干等一个超时才 failover。
const (
	defaultDialHedgeDelay     = 1500 * time.Millisecond
	defaultDialAttemptTimeout = 5 * time.Second
	// defaultUDPVerifyTimeout 是真实流量路径给"未验证 raw 中继"做端到端 DNS 问答的上限:
	// 碰运气回落的 raw 中继包丢进黑洞也无人应答,必须快速失败让选路换下一个候选。
	defaultUDPVerifyTimeout = 3 * time.Second
)

func (m *Manager) ConnectDefault(ctx context.Context, host string, port int) (net.Conn, error) {
	ll := trace.Log(ctx)
	if m.healthChecker != nil && !m.healthChecker.HasAnyTCPAvailable() {
		select {
		// 必须等 TCP 电路自己的就绪信号:UDP 探测先成功时聚合闸门早已关闭,
		// 放过去只能逐个 skip(udp_only/unhealthy)然后硬失败。
		case <-m.healthChecker.FirstTCPProbeDone():
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(800 * time.Millisecond):
		}
	}
	candidates := make([]*Proxy, 0, len(m.defaultProxies))
	for _, proxy := range m.orderedProxies() {
		if proxy.IsUDPOnly() {
			ll.Debug("skipping udp_only proxy for TCP", "url", MaskProxyURL(proxy.URL))
			continue
		}
		if !proxy.IsAvailable() {
			ll.Debug("skipping unhealthy proxy", "url", MaskProxyURL(proxy.URL))
			continue
		}
		candidates = append(candidates, proxy)
	}
	if len(candidates) == 0 {
		return nil, fmt.Errorf("all default upstream proxies failed to connect to %s:%d", host, port)
	}
	if len(candidates) == 1 {
		// 单节点无备胎:不加更紧的超时,行为与历史一致。
		return m.connectOne(ctx, ll, candidates[0], host, port)
	}
	var onWin func(*Proxy)
	var onFail func(*Proxy, error)
	if m.healthChecker != nil {
		onWin = func(p *Proxy) { m.healthChecker.RecordSuccess(p, 0) }
		onFail = func(p *Proxy, err error) { m.healthChecker.RecordFailure(p, err) }
	}
	return m.hedgedDial(ctx, ll, candidates, "default proxy",
		fmt.Sprintf("all default upstream proxies failed to connect to %s:%d", host, port),
		func(ctx context.Context, p *Proxy) (net.Conn, error) {
			return p.Connect(ctx, host, port)
		},
		onWin, onFail,
	)
}

// connectOne 拨单个节点并回写熔断器,保持 failover 改造前的单节点语义。
func (m *Manager) connectOne(ctx context.Context, ll *slog.Logger, proxy *Proxy, host string, port int) (net.Conn, error) {
	ll.Info("trying default proxy", "url", MaskProxyURL(proxy.URL))
	conn, err := proxy.Connect(ctx, host, port)
	if err != nil {
		ll.Warn("default proxy failed", "url", MaskProxyURL(proxy.URL), "error", err)
		if m.healthChecker != nil {
			m.healthChecker.RecordFailure(proxy, err)
		}
		return nil, err
	}
	ll.Info("connected via", "url", MaskProxyURL(proxy.URL))
	if m.healthChecker != nil {
		m.healthChecker.RecordSuccess(proxy, 0)
	}
	return conn, nil
}

type dialResult struct {
	conn  net.Conn
	proxy *Proxy
	err   error
}

// hedgedDial 是 TCP/UDP 共用的错位对冲拨号骨架(TCP/UDP 各自只提供 dial 与熔断器回调):
// 立即拨第一个,之后每隔 hedgeDelay 且前面都没出结果时,追加一个并发拨号;某个在途拨号
// 先失败而后面还有没启动的备胎时,立即提前启动(不等下一个 hedge 窗口)。第一个成功的连接
// 胜出,其余在途拨号随 dialCtx 取消而关闭。赢家产生后的 context.Canceled 不回写熔断器;
// 只有等待结果期间的真实失败(超时/拒连/重置/raw 端到端验证失败)才回调 onFail,让连续
// 死线的节点按 FailuresThreshold 正常跳闸。onWin 不需要时传 nil(UDP 真实流量成功不喂
// 熔断器)。label 用于日志,allFailedMsg 是全灭错误前缀。
func (m *Manager) hedgedDial(
	ctx context.Context,
	ll *slog.Logger,
	candidates []*Proxy,
	label string,
	allFailedMsg string,
	dial func(ctx context.Context, proxy *Proxy) (net.Conn, error),
	onWin func(proxy *Proxy),
	onFail func(proxy *Proxy, err error),
) (net.Conn, error) {
	hedgeDelay := m.dialHedgeDelay
	if hedgeDelay <= 0 {
		hedgeDelay = defaultDialHedgeDelay
	}
	attemptTimeout := m.dialAttemptTimeout
	if attemptTimeout <= 0 {
		attemptTimeout = defaultDialAttemptTimeout
	}

	dialCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	// 容量=候选数:赢家产生后才结束的在途拨号也能无阻塞投递结果后退出,不泄漏 goroutine。
	results := make(chan dialResult, len(candidates))

	launch := func(proxy *Proxy) {
		ll.Info("trying "+label, "url", MaskProxyURL(proxy.URL))
		attemptCtx, attemptCancel := context.WithTimeout(dialCtx, attemptTimeout)
		go func() {
			defer attemptCancel()
			conn, err := dial(attemptCtx, proxy)
			if err != nil {
				select {
				case results <- dialResult{proxy: proxy, err: err}:
				case <-dialCtx.Done():
				}
				return
			}
			select {
			case results <- dialResult{conn: conn, proxy: proxy}:
			case <-dialCtx.Done():
				// 另一个节点已经赢了,这条迟到的成功连接必须关掉,不能悬挂。
				conn.Close()
			}
		}()
	}

	timer := time.NewTimer(hedgeDelay)
	defer timer.Stop()
	launched, failed := 1, 0
	var errs []error
	launch(candidates[0])

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case res := <-results:
			if res.err == nil {
				ll.Info("connected via", "url", MaskProxyURL(res.proxy.URL))
				if onWin != nil {
					onWin(res.proxy)
				}
				return res.conn, nil
			}
			// 赢家产生后 dialCtx 被取消,在途拨号报 Canceled:这时 results 不会再被读到
			// (select 会立刻走 ctx 分支),所以走到这里的都是等待期间的真实失败。
			failed++
			ll.Warn(label+" failed", "url", MaskProxyURL(res.proxy.URL), "error", res.err)
			if onFail != nil {
				onFail(res.proxy, res.err)
			}
			errs = append(errs, res.err)
			if failed == len(candidates) {
				return nil, fmt.Errorf("%s: %w", allFailedMsg, errors.Join(errs...))
			}
			if failed == launched && launched < len(candidates) {
				// 在途的全挂了而备胎还没启动:别等 hedge 窗口,立刻拨下一个。
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				launch(candidates[launched])
				launched++
				if launched < len(candidates) {
					timer.Reset(hedgeDelay)
				}
			}
		case <-timer.C:
			if launched < len(candidates) {
				launch(candidates[launched])
				launched++
				if launched < len(candidates) {
					timer.Reset(hedgeDelay)
				}
			}
		}
	}
}

// orderedProxies 返回按当前策略排好序的节点列表,TCP 侧使用(round_robin 下推进 TCP 的
// 轮转指针)。
func (m *Manager) orderedProxies() []*Proxy {
	return m.orderedProxiesFor(transportTCP)
}

// orderedProxiesUDP 与 orderedProxies 同一套排序,但用的是 UDP 那条路径自己的选路状态
// 和 UDP 电路的延迟样本。UDP 关联不该扰动 TCP 的顺序,也不该拿 TCP 的延迟给自己排序。
func (m *Manager) orderedProxiesUDP() []*Proxy {
	return m.orderedProxiesFor(transportUDP)
}

// orderedProxiesFor 返回按当前策略排好序的节点列表。t 决定用哪条路径的选路状态
// (Manager.order)以及延迟读哪个电路(transport.latencyOf)。
func (m *Manager) orderedProxiesFor(t transport) []*Proxy {
	m.mu.RLock()
	defer m.mu.RUnlock()
	n := len(m.defaultProxies)
	if n <= 1 {
		return m.defaultProxies
	}
	st := &m.order[t]
	switch m.strategy {
	case "round_robin":
		start := rrStart(st, n)
		result := make([]*Proxy, n)
		for i := 0; i < n; i++ {
			result[i] = m.defaultProxies[(start+i)%n]
		}
		return result
	case "random":
		result := make([]*Proxy, n)
		copy(result, m.defaultProxies)
		rand.Shuffle(n, func(i, j int) { result[i], result[j] = result[j], result[i] })
		return result
	case "latency":
		return m.orderByLatency(st, t)
	default:
		return m.defaultProxies
	}
}

// rankedProxy 是一个候选节点及其有效延迟(见 effectiveLatency)。
type rankedProxy struct {
	proxy *Proxy
	eff   time.Duration
}

const (
	// latencyBandRatioNum/Den 是候选带的相对宽度:有效延迟不超过最优值 3/2(1.5 倍)的
	// 节点都算"差不多快",进带。1.5 倍以内的 RTT 差距用户基本无感,死钉最快的那个只会
	// 把流量全压到一台机器上。
	latencyBandRatioNum = 3
	latencyBandRatioDen = 2
	// latencyBandMinMargin 是带线的加法地板。低延迟区里 1.5 倍的相对宽度比测量噪声还窄
	// (best=20ms 时只有 10ms),成员会在带线两侧抖进抖出,所以带线至少宽出 20ms。
	latencyBandMinMargin = 20 * time.Millisecond
	// latencyBandHystNum/Den 是带缘滞回量(相对最优值 1/4,地板同为 latencyBandMinMargin):
	// 带内成员的退出线 = 进入线 + 滞回量。EWMA 在带线附近抖一下踢不掉人,真烂到线外才
	// 出带——候选集合稳定,轮转的出口 IP 集合才稳定。
	latencyBandHystNum = 1
	latencyBandHystDen = 4
)

// orderByLatency 排出 latency 策略的选路次序:先按实测延迟算候选带,带内轮转摊负载,
// 带外按延迟当备胎,不可用的沉底。调用方持 m.mu 读锁;本函数只碰 st(原子字段)与传入
// 的节点,不回调任何拿 m.mu 的函数。
//
// 三个设计点:
//
//  1. 冷启动。未测量(延迟为 0)的节点用"已测量延迟的中位数"占位(见 medianLatency):
//     没数据就不站队,既不白插到已证实的快节点前面,也不会被丢到一个已知很慢的节点
//     后面。全都没测量时全体同分、全在带内,首拍从配置顺序开始轮转——零信息时摊给所有
//     人,比死撞配置第一个合理。
//
//  2. 候选带 + 带内轮转。延迟在最优值 1.5 倍(并有 20ms 加法地板)以内的节点组成候选
//     带,每建一条新连接用轮转指针在带内推进一格起点:正常情况下只有首位会真拨号,流量
//     于是均摊到所有"差不多快"的节点,而不是压死最快的那一个。带外节点按延迟次序接在
//     带后,作为对冲拨号的备胎;带内全灭时它们才轮得上。
//
//  3. 带缘滞回。EWMA 平滑过的延迟仍会在带线附近穿越,没有滞回的话成员每拍进出,轮转
//     集合乱跳,出口 IP 集合比死钉单点还难预测。所以进入用进入线、退出用更宽的退出线
//     (再让 best/4,地板 20ms):带外的要够近才能进,带内的要真烂才被踢。
func (m *Manager) orderByLatency(st *rotationState, t transport) []*Proxy {
	available := make([]*Proxy, 0, len(m.defaultProxies))
	var unavailable []*Proxy
	for _, p := range m.defaultProxies {
		if t.availableFor(p) {
			available = append(available, p)
		} else {
			unavailable = append(unavailable, p)
		}
	}
	if len(available) == 0 {
		// 全线不可用:忘掉旧候选带,原样返回让上层按配置顺序去撞(和 failover 一致)。
		st.band.Store(nil)
		return m.defaultProxies
	}

	placeholder := medianLatency(available, t)
	ranked := make([]rankedProxy, len(available))
	for i, p := range available {
		ranked[i] = rankedProxy{proxy: p, eff: effectiveLatency(p, placeholder, t)}
	}
	// SliceStable + 有效延迟相同即同分,同分的保持配置顺序。
	sort.SliceStable(ranked, func(i, j int) bool { return ranked[i].eff < ranked[j].eff })

	best := ranked[0].eff
	enter := bandEnterCutoff(best)
	leave := bandLeaveCutoff(best)
	prev := st.band.Load()

	// 带缘滞回:带外/新面孔够到进入线才进,上一拍在带内的烂过退出线才出。
	// best 自己 eff 最小,必然入带,候选带永远非空。
	band := make([]*Proxy, 0, len(ranked))
	for _, r := range ranked {
		if r.eff <= enter || (inSnapshot(prev, r.proxy) && r.eff <= leave) {
			band = append(band, r.proxy)
		}
	}
	if prev == nil || !sameBand(prev.members, band) {
		st.band.Store(&bandSnapshot{members: band})
	}

	result := make([]*Proxy, 0, len(m.defaultProxies))
	// 带内按延迟次序轮转起点:每条新连接换一个首位,把流量摊给带内全体成员。
	start := rrStart(st, len(band))
	for i := range band {
		result = append(result, band[(start+i)%len(band)])
	}
	// 带外成员按延迟次序接在后面当对冲备胎。band 是 ranked 的同序子列,双指针跳过即可。
	bi := 0
	for _, r := range ranked {
		if bi < len(band) && band[bi] == r.proxy {
			bi++
			continue
		}
		result = append(result, r.proxy)
	}
	return append(result, unavailable...)
}

// bandEnterCutoff 是带外节点的入带线:best 的 1.5 倍,低延迟区用加法地板托底。
func bandEnterCutoff(best time.Duration) time.Duration {
	margin := best * (latencyBandRatioNum - latencyBandRatioDen) / latencyBandRatioDen
	if margin < latencyBandMinMargin {
		margin = latencyBandMinMargin
	}
	return best + margin
}

// bandLeaveCutoff 是带内成员的出带线,在进入线之外再让一个 best/4(地板同为
// latencyBandMinMargin),给带缘留出滞回。
func bandLeaveCutoff(best time.Duration) time.Duration {
	hyst := best * latencyBandHystNum / latencyBandHystDen
	if hyst < latencyBandMinMargin {
		hyst = latencyBandMinMargin
	}
	return bandEnterCutoff(best) + hyst
}

// inSnapshot 按指针身份判断 p 是否在上一拍的候选带里。
func inSnapshot(snap *bandSnapshot, p *Proxy) bool {
	if snap == nil {
		return false
	}
	for _, q := range snap.members {
		if q == p {
			return true
		}
	}
	return false
}

// sameBand 按指针身份和次序比较两拍的候选带。次序也要求一致:成员没换但内部次序换了,
// 说明最优值易主,快照同样该刷新。
func sameBand(a, b []*Proxy) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// effectiveLatency 返回节点的实测延迟,没测过(0)时用 placeholder 占位。placeholder 由
// medianLatency 给出,保证它只可能在"全体都没测过"时为 0——那种情况下全体同分。
func effectiveLatency(p *Proxy, placeholder time.Duration, t transport) time.Duration {
	if d := t.latencyOf(p); d > 0 {
		return d
	}
	return placeholder
}

// medianLatency 取一组节点实测延迟的中位数,一个都没测过时返回 0。
func medianLatency(proxies []*Proxy, t transport) time.Duration {
	samples := make([]time.Duration, 0, len(proxies))
	for _, p := range proxies {
		if d := t.latencyOf(p); d > 0 {
			samples = append(samples, d)
		}
	}
	if len(samples) == 0 {
		return 0
	}
	sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
	return samples[len(samples)/2]
}

func (m *Manager) Connect(ctx context.Context, host string, port int, domain string, engine *rules.Engine) (net.Conn, string) {
	ll := trace.Log(ctx)
	result, selected := m.SelectProxy(ctx, host, port, domain, engine)
	if result == "direct" {
		return nil, "direct"
	}
	if result == "fallback" || result == "proxy_default" {
		conn, err := m.ConnectDefault(ctx, host, port)
		if err != nil {
			return nil, "failed"
		}
		return conn, "proxy"
	}
	if selected == nil {
		return nil, "failed"
	}
	if selected.IsUDPOnly() {
		ll.Warn("rule selected a udp_only proxy for TCP, connection failed", "url", MaskProxyURL(selected.URL))
		return nil, "failed"
	}
	// An explicit manual "Disable" is honored even by rule routing: a disabled node must
	// never carry traffic, whatever the rule says. Auto-opened circuits (probe failures)
	// are still tried — rules are explicit intent and a live recovery may succeed.
	if selected.health.IsManuallyDisabled() {
		ll.Warn("rule selected a manually-disabled proxy for TCP, connection failed", "url", MaskProxyURL(selected.URL))
		return nil, "failed"
	}
	if !selected.IsAvailable() {
		ll.Warn("selected proxy is unhealthy but still using it due to rule", "alias", MaskProxyURL(selected.URL))
	}
	conn, err := selected.Connect(ctx, host, port)
	if err != nil {
		ll.Error("proxy connect failed", "url", MaskProxyURL(selected.URL), "error", err)
		if m.healthChecker != nil {
			m.healthChecker.RecordFailure(selected, err)
		}
		return nil, "failed"
	}
	if m.healthChecker != nil {
		m.healthChecker.RecordSuccess(selected, 0)
	}
	return conn, "proxy"
}

func (m *Manager) AcquireDNSUDP(ctx context.Context, dnsHost string, dnsPort int) (net.Conn, error) {
	return m.dnsUDPPool.Acquire(ctx, dnsHost, dnsPort, func(ctx context.Context, host string, port int) (net.Conn, error) {
		return m.UDPAssociate(ctx, host, port, "", nil)
	})
}

func (m *Manager) ReleaseDNSUDP(conn net.Conn) {
	m.dnsUDPPool.Release(conn)
}

func (m *Manager) DiscardDNSUDP(conn net.Conn) {
	m.dnsUDPPool.Discard(conn)
}

func (m *Manager) UDPAssociate(ctx context.Context, host string, port int, domain string, engine *rules.Engine) (net.Conn, error) {
	ll := trace.Log(ctx)
	result, selected := m.SelectProxy(ctx, host, port, domain, engine)
	if result == "direct" {
		return nil, fmt.Errorf("UDP direct is not supported")
	}
	if selected != nil {
		// Honor an explicit manual "Disable" even under rule routing, mirroring Connect.
		if selected.udpHealth.IsManuallyDisabled() {
			ll.Warn("rule selected a manually-disabled proxy for UDP, connection failed", "url", MaskProxyURL(selected.URL))
			return nil, fmt.Errorf("proxy %s is manually disabled for UDP", MaskProxyURL(selected.URL))
		}
		ll.Debug("UDPAssociate: using selected proxy by rule",
			"proxy", MaskProxyURL(selected.URL), "target", fmt.Sprintf("%s:%d", host, port))
		conn, err := m.establishUDPRelay(ctx, selected, host, port)
		if err != nil && m.healthChecker != nil {
			m.healthChecker.RecordUDPFailure(selected, err)
		}
		return conn, err
	}
	return m.defaultUDPAssociate(ctx, ll, host, port)
}

// UDPAssociateSelected uses a pre-selected proxy for UDP ASSOCIATE
// (skipping the duplicate SelectProxy match)
func (m *Manager) UDPAssociateSelected(ctx context.Context, host string, port int, selected *Proxy) (net.Conn, error) {
	ll := trace.Log(ctx)
	if selected != nil {
		ll.Debug("UDPAssociateSelected: using pre-selected proxy",
			"proxy", MaskProxyURL(selected.URL), "target", fmt.Sprintf("%s:%d", host, port))
		conn, err := m.establishUDPRelay(ctx, selected, host, port)
		if err != nil && m.healthChecker != nil {
			m.healthChecker.RecordUDPFailure(selected, err)
		}
		return conn, err
	}
	// selected == nil: fall back to default ordered selection.
	return m.defaultUDPAssociate(ctx, ll, host, port)
}

// establishUDPRelay 通过指定节点建立 UDP 中继。ASSOCIATE 标准握手成功按旧例直接记录能力
// 标记;但 rawFallback 碰运气回落出来的 raw 中继(IsUnverifiedRaw)必须补一次真实 DNS
// 问答——本地 DialUDP 永远成功,包丢进黑洞也没人知道,不验证就是假成功:旧代码会立刻
// 返回"成功"、把节点钉成 sticky raw,后面的健康节点连试都不试。验证失败关连接报错,
// 让选路(单节点)或对冲(多节点)继续找下一个。
// 失败一律不在本函数回写熔断器:对冲赢家产生后陪跑候选的 ctx 会被取消,在这里记账会把
// 陪跑取消误记成节点故障。记账归调用方——规则路径在各自入口记,默认路径单节点直接记、
// 多节点走 hedgedDial 的 onFail(只有等待结果期间的真实失败才会触发)。
func (m *Manager) establishUDPRelay(ctx context.Context, proxy *Proxy, host string, port int) (net.Conn, error) {
	conn, err := proxy.UDPAssociate(ctx, host, port)
	if err != nil {
		return nil, err
	}
	if uc, ok := conn.(*UDPProxyConn); ok && uc.IsUnverifiedRaw() {
		dnsServer, domain := m.udpProbeTarget()
		timeout := m.udpVerifyTimeout
		if timeout <= 0 {
			timeout = defaultUDPVerifyTimeout
		}
		if _, verr := verifyUDPRelay(ctx, conn, dnsServer, domain, timeout); verr != nil {
			conn.Close()
			return nil, fmt.Errorf("unverified raw UDP relay failed end-to-end probe: %w", verr)
		}
	}
	// First-detection capability record from real traffic: a raw-only node is learned
	// only after the end-to-end probe above proved it; re-classifies a raw node whose
	// ASSOCIATE recheck just succeeded (raw → standard). A probe finding is never overridden.
	if proxy.needsCapabilityClassify() {
		proxy.classifyUDPCapability(conn)
	}
	return conn, nil
}

// udpProbeTarget returns the DNS server/domain used to prove an unverified raw relay,
// defaulting to the same targets the health probe uses when config leaves them empty.
func (m *Manager) udpProbeTarget() (server, domain string) {
	return m.healthCfg.UDPProbeDNS, m.healthCfg.UDPProbeDomain
}

// defaultUDPAssociate 是无规则命中时的默认 UDP 选路:等 UDP 就绪闸门 → 构建候选(支持
// UDP 且独立 UDP 电路可用)→ 单节点直连、多节点错位对冲。旧实现是纯串行 for 循环,首个
// 节点的 ASSOCIATE 握手被黑洞时每个新关联干等 10s 才试下一个,和 TCP 犯过同一个病。
func (m *Manager) defaultUDPAssociate(ctx context.Context, ll *slog.Logger, host string, port int) (net.Conn, error) {
	if m.healthChecker != nil && !m.healthChecker.HasAnyUDPAvailable() {
		select {
		// 等 UDP 电路自己的就绪信号;TCP 先成功不该把 UDP 入口提前放行。
		case <-m.healthChecker.FirstUDPProbeDone():
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(800 * time.Millisecond):
		}
	}
	candidates := make([]*Proxy, 0)
	for _, proxy := range m.orderedProxiesUDP() {
		if !proxy.SupportsUDP() {
			continue
		}
		if !proxy.IsUDPAvailable() {
			ll.Debug("UDPAssociate: skipping unhealthy proxy", "proxy", MaskProxyURL(proxy.URL))
			continue
		}
		candidates = append(candidates, proxy)
	}
	if len(candidates) == 0 {
		return nil, fmt.Errorf("no default UDP proxy available")
	}
	dial := func(ctx context.Context, p *Proxy) (net.Conn, error) {
		return m.establishUDPRelay(ctx, p, host, port)
	}
	// 单节点无备胎:不套更紧的 attemptTimeout,保持 SOCKS5 层 10s 的历史容忍。
	if len(candidates) == 1 {
		p := candidates[0]
		ll.Debug("UDPAssociate: trying proxy", "proxy", MaskProxyURL(p.URL),
			"target", fmt.Sprintf("%s:%d", host, port))
		conn, err := dial(ctx, p)
		if err != nil {
			ll.Warn("UDP proxy failed", "url", MaskProxyURL(p.URL), "error", err)
			if m.healthChecker != nil {
				m.healthChecker.RecordUDPFailure(p, err)
			}
			return nil, fmt.Errorf("no default UDP proxy available: %w", err)
		}
		ll.Debug("UDPAssociate: proxy succeeded", "proxy", MaskProxyURL(p.URL))
		return conn, nil
	}
	// 真实流量的关联"成功"不喂熔断器(ASSOCIATE 成功或 fast-path raw 都不证明中继活,
	// raw 的证据由 establishUDPRelay 内的 DNS 问答保证);真实失败由 onFail 记账——赢家
	// 产生后陪跑候选的取消走不进这里,不会污染熔断状态。
	var onFail func(*Proxy, error)
	if m.healthChecker != nil {
		onFail = func(p *Proxy, err error) { m.healthChecker.RecordUDPFailure(p, err) }
	}
	return m.hedgedDial(ctx, ll, candidates, "UDP proxy", "no default UDP proxy available", dial, nil, onFail)
}

type ProxyInfo struct {
	Alias string `json:"alias"`
	URL   string `json:"url"`
	// Name is the node's friendly name from the ss:// #fragment (see Proxy.Name);
	// empty for URLs without one.
	Name   string `json:"name"`
	Host   string `json:"host"`
	Port   int    `json:"port"`
	Scheme string `json:"scheme"`
	// UDPInTCP reports whether the node is configured as a hev UDP-in-TCP relay
	// (see Proxy.UDPInTCP). The panel reads this to pre-check the switch when editing.
	UDPInTCP bool `json:"udp_in_tcp"`
	// Mode is the effective mode derived purely from scheme capability plus probe results
	// (see Proxy.EffectiveMode) — the value routing actually uses, so it moves over time.
	Mode string `json:"mode"`
	// UDPCapability is how this node's UDP relay works, auto-detected from probing and real
	// traffic (unknown/standard/raw/none, see Proxy.UDPCapability). unknown means not yet
	// detected — e.g. health check disabled or a non-UDP scheme that is never probed.
	UDPCapability string              `json:"udp_capability"`
	Health        ProxyHealthSnapshot `json:"health"`
	UDPHealth     ProxyHealthSnapshot `json:"udp_health"`
	PingLatency   time.Duration       `json:"ping_latency,omitempty"`
	CountryCode   string              `json:"country_code,omitempty"`
	ExitIP        string              `json:"exit_ip,omitempty"`
	Provider      string              `json:"provider,omitempty"`
}

func (m *Manager) Proxies() []ProxyInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()

	reverseMap := make(map[*Proxy]string, len(m.aliasMap))
	for alias, proxy := range m.aliasMap {
		if proxy != nil {
			reverseMap[proxy] = alias
		}
	}

	infos := make([]ProxyInfo, 0, len(m.defaultProxies))
	for _, proxy := range m.defaultProxies {
		alias := reverseMap[proxy]
		infos = append(infos, ProxyInfo{
			Alias:         alias,
			URL:           proxy.URL,
			Name:          proxy.Name,
			Host:          proxy.Host,
			Port:          proxy.Port,
			Scheme:        string(proxy.Scheme),
			UDPInTCP:      proxy.UDPInTCP,
			Mode:          proxy.EffectiveMode(),
			UDPCapability: string(proxy.UDPCapability()),
			Health:        proxy.health.Snapshot(),
			UDPHealth:     proxy.udpHealth.Snapshot(),
			PingLatency:   proxy.PingLatency(),
			CountryCode:   proxy.CountryCode(),
			ExitIP:        proxy.ExitIP(),
			Provider:      proxy.Provider,
		})
	}
	return infos
}

// findProxyLocked searches for a proxy by alias. If an exact match is not found,
// it falls back to case-insensitive match, and then to matching proxy.Name
// (e.g. for provider nodes where the displayed name omits the [Provider] prefix).
// Caller must hold m.mu (RLock or Lock).
func (m *Manager) findProxyLocked(alias string) (*Proxy, string) {
	if p, ok := m.aliasMap[alias]; ok && p != nil {
		return p, alias
	}
	aliasClean := strings.TrimSpace(alias)
	for k, p := range m.aliasMap {
		if p == nil {
			continue
		}
		if strings.EqualFold(k, aliasClean) {
			return p, k
		}
		if p.Name != "" && strings.EqualFold(p.Name, aliasClean) {
			return p, k
		}
		// If k has a "[Provider] " prefix (e.g. "[Lantern] node-name"), allow matching without the prefix
		if strings.HasPrefix(k, "[") {
			if idx := strings.Index(k, "] "); idx != -1 {
				unprefixed := strings.TrimSpace(k[idx+2:])
				if strings.EqualFold(unprefixed, aliasClean) {
					return p, k
				}
			}
		}
	}
	return nil, ""
}

// ProxyInfo returns the snapshot info for a specific proxy alias.
func (m *Manager) ProxyInfo(alias string) (ProxyInfo, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	proxy, canonicalAlias := m.findProxyLocked(alias)
	if proxy == nil {
		return ProxyInfo{}, false
	}
	return ProxyInfo{
		Alias:         canonicalAlias,
		URL:           proxy.URL,
		Name:          proxy.Name,
		Host:          proxy.Host,
		Port:          proxy.Port,
		Scheme:        string(proxy.Scheme),
		UDPInTCP:      proxy.UDPInTCP,
		Mode:          proxy.EffectiveMode(),
		UDPCapability: string(proxy.UDPCapability()),
		Health:        proxy.health.Snapshot(),
		UDPHealth:     proxy.udpHealth.Snapshot(),
		PingLatency:   proxy.PingLatency(),
		CountryCode:   proxy.CountryCode(),
		ExitIP:        proxy.ExitIP(),
		Provider:      proxy.Provider,
	}, true
}


// SetCircuitHealth pins or releases one (or both) of a proxy's circuits. circuit is
// "tcp", "udp" or "both"; action is "enable" (force up), "disable" (force down) or
// "auto" (release back to automatic health-check control). Pinned circuits stay put
// across probe cycles until released.
func (m *Manager) SetCircuitHealth(alias, circuit, action string) error {
	m.mu.RLock()
	proxy, _ := m.findProxyLocked(alias)
	m.mu.RUnlock()
	if proxy == nil {
		return fmt.Errorf("proxy alias %q not found", alias)
	}
	apply := func(ph *ProxyHealth) {
		switch action {
		case "enable":
			ph.SetManualState(true)
		case "disable":
			ph.SetManualState(false)
		case "auto":
			ph.ClearManualState()
		}
	}
	switch circuit {
	case "tcp":
		apply(&proxy.health)
	case "udp":
		apply(&proxy.udpHealth)
	default: // "both"
		apply(&proxy.health)
		apply(&proxy.udpHealth)
	}
	slog.Info("manual proxy health set", "alias", alias, "circuit", circuit, "action", action)
	return nil
}

// ResetAutoOpenedCircuits is the "one-click recover nodes" action: every circuit the
// health checker auto-opened (probe-failure Open/HalfOpen with no manual pin) is returned
// to closed, so it is immediately usable again and re-validated by the next probe. Manual
// pins — force-up or force-down — are never touched, and recovery stays temporary: another
// probe/traffic failure re-opens the circuit through the normal flow. Returns how many
// circuits were reset.
func (m *Manager) ResetAutoOpenedCircuits() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var n int
	for _, proxy := range m.defaultProxies {
		if proxy.health.resetAutoOpened() {
			n++
		}
		if proxy.udpHealth.resetAutoOpened() {
			n++
		}
	}
	return n
}

// HandleNetworkChange handles an underlying physical network handover (e.g. Wi-Fi <-> Cellular).
// It drains stale pooled UDP sockets, resets circuit breaker failure counts on all proxies
// (preserving explicit manual pins), and triggers an immediate health probe on the new network.
func (m *Manager) HandleNetworkChange() {
	m.mu.RLock()
	allAliases := make([]*Proxy, 0, len(m.aliasMap))
	for _, p := range m.aliasMap {
		allAliases = append(allAliases, p)
	}
	hc := m.healthChecker
	pool := m.dnsUDPPool
	m.mu.RUnlock()

	if pool != nil {
		pool.Close()
	}

	for _, p := range allAliases {
		if p != nil {
			p.health.ResetFailures()
			p.udpHealth.ResetFailures()
		}
	}

	if hc != nil {
		hc.ProbeAll()
	}
	slog.Info("upstream manager handled network change: pool drained, circuits reset, probing all nodes")
}

func (m *Manager) Strategy() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.strategy
}

// TestProxy runs an on-demand, real network test for the given proxy alias and protocol ("ping", "tcp" or "udp").
// Returns the round-trip latency and any error encountered during the probe.
func (m *Manager) TestProxy(ctx context.Context, alias, protocol string) (time.Duration, error) {
	m.mu.RLock()
	proxy, _ := m.findProxyLocked(alias)
	m.mu.RUnlock()
	if proxy == nil {
		return 0, fmt.Errorf("proxy alias %q not found", alias)
	}

	protocol = strings.ToLower(protocol)
	var latency time.Duration
	var err error

	switch protocol {
	case "tcping", "ping":
		start := time.Now()
		conn, dialErr := proxy.dial(ctx)
		if dialErr != nil {
			proxy.SetPingLatency(0)
			return 0, dialErr
		}
		latency = time.Since(start)
		_ = conn.Close()
		proxy.SetPingLatency(latency)
	case "tcp":
		// Probe cdn-cgi/trace directly to resolve real latency, exit IP, and country code
		latency, err = probeTCP(ctx, proxy, "http://cp.cloudflare.com/cdn-cgi/trace")
		if err != nil && m.healthChecker != nil {
			// Fallback to configured health check probe URL if cdn-cgi/trace fails
			latency, err = m.healthChecker.ProbeTCP(ctx, proxy)
		}
		if err == nil {
			proxy.health.UpdateLatency(latency)
			if m.healthChecker != nil {
				m.healthChecker.RecordSuccess(proxy, latency)
			}
		} else {
			if m.healthChecker != nil {
				m.healthChecker.RecordFailure(proxy, err)
			}
		}
	case "udp":
		if !proxy.SchemeSupportsUDP() {
			return 0, fmt.Errorf("proxy scheme %s does not support UDP", proxy.Scheme)
		}
		if m.healthChecker != nil {
			latency, err = m.healthChecker.ProbeUDP(ctx, proxy)
		} else {
			dummyHC := NewHealthChecker(config.HealthCheckConf{}, nil)
			latency, err = dummyHC.ProbeUDP(ctx, proxy)
		}
		if err == nil {
			proxy.udpHealth.UpdateLatency(latency)
			if m.healthChecker != nil {
				m.healthChecker.RecordUDPSuccess(proxy, latency)
			}
		} else {
			if m.healthChecker != nil {
				m.healthChecker.RecordUDPFailure(proxy, err)
			}
		}
	default:
		return 0, fmt.Errorf("invalid protocol %q, must be ping, tcp or udp", protocol)
	}

	return latency, err
}

// ReportDNSUDPError notifies the health checker of a real-traffic DNS failure over UDP
// on the proxy associated with conn.
func (m *Manager) ReportDNSUDPError(conn net.Conn, err error) {
	if m == nil || m.healthChecker == nil || conn == nil || err == nil {
		return
	}
	type proxyCarrier interface {
		Proxy() *Proxy
	}
	if carrier, ok := conn.(proxyCarrier); ok {
		if p := carrier.Proxy(); p != nil {
			m.healthChecker.RecordUDPFailure(p, err)
		}
	}
}

// ReportDNSUDPSuccess notifies the health checker of a successful real-traffic DNS round-trip
// over UDP on the proxy associated with conn.
func (m *Manager) ReportDNSUDPSuccess(conn net.Conn, latency time.Duration) {
	if m == nil || m.healthChecker == nil || conn == nil {
		return
	}
	type proxyCarrier interface {
		Proxy() *Proxy
	}
	if carrier, ok := conn.(proxyCarrier); ok {
		if p := carrier.Proxy(); p != nil {
			m.healthChecker.RecordUDPSuccess(p, latency)
		}
	}
}

// probeInitialGeo asynchronously discovers country codes and exit IPs for all proxies in the background.
func (m *Manager) probeInitialGeo() {
	m.mu.RLock()
	if m.stopped {
		m.mu.RUnlock()
		return
	}
	proxies := make([]*Proxy, len(m.defaultProxies))
	copy(proxies, m.defaultProxies)
	ctx := m.ctx
	m.mu.RUnlock()

	if len(proxies) == 0 || ctx == nil {
		return
	}

	safego.Go("upstream.initialGeo", func() {
		var wg sync.WaitGroup
		for _, p := range proxies {
			if p == nil || (p.ExitIP() != "" && p.CountryCode() != "") {
				continue
			}
			wg.Add(1)
			proxy := p
			safego.Go("upstream.initialGeo.node", func() {
				defer wg.Done()
				probeCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
				defer cancel()
				lat, err := probeTCP(probeCtx, proxy, "http://cp.cloudflare.com/cdn-cgi/trace")
				if err == nil {
					proxy.health.UpdateLatency(lat)
				}
			})
		}
		wg.Wait()
	})
}

