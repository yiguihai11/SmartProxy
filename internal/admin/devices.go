package admin

import (
	"bufio"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// DeviceConn 记录单条活跃网络连接信息。
type DeviceConn struct {
	Proto int    `json:"proto"` // 6=TCP, 17=UDP
	Host  string `json:"host"`
	Port  int    `json:"port"`
	Up    int64  `json:"up"`
	Down  int64  `json:"down"`
}

// TetheredDevice 代表一台连入热点或局域网的下挂设备。
type TetheredDevice struct {
	IP          string       `json:"ip"`
	MAC         string       `json:"mac"`
	Hostname    string       `json:"hostname"`
	ExtraIPs    []string     `json:"extra_ips,omitempty"`
	UpBytes     int64        `json:"up_bytes"`
	DownBytes   int64        `json:"down_bytes"`
	ActiveConns int          `json:"active_conns"`
	UpBps       int64        `json:"up_bps"`
	DownBps     int64        `json:"down_bps"`
	IsBlocked   bool         `json:"is_blocked"`
	IsCurrent   bool         `json:"is_current"` // 当前正在访问控制面板的设备
	Conns       []DeviceConn `json:"conns,omitempty"`
}

// BlockedRecord 记录被拉黑设备信息。
type BlockedRecord struct {
	IP        string `json:"ip,omitempty"`
	MAC       string `json:"mac,omitempty"`
	Hostname  string `json:"hostname,omitempty"`
	BlockedAt int64  `json:"blocked_at"`
}

// TetheringBridge defines hooks provided by Android Kotlin layer via gomobile/AIDL.
type TetheringBridge interface {
	GetTetheredClients() string
	BlockClient(mac string) bool
	UnblockClient(mac string) bool
	GetBlockedClients() string
}

type clientTrafficSample struct {
	up        int64
	down      int64
	sampledAt time.Time
}

type lifetimeTraffic struct {
	up   int64
	down int64
}

type deviceManager struct {
	mu              sync.Mutex
	lastSamples     map[string]clientTrafficSample
	lifetimeTraffic map[string]lifetimeTraffic
	blockedPath     string
	blockedList     []BlockedRecord
	blockedIPMap    map[string]bool
	blockedMACMap   map[string]bool
}

func newDeviceManager(configDir string) *deviceManager {
	dm := &deviceManager{
		lastSamples:     make(map[string]clientTrafficSample),
		lifetimeTraffic: make(map[string]lifetimeTraffic),
		blockedPath:     filepath.Join(configDir, "blocked_devices.json"),
		blockedIPMap:    make(map[string]bool),
		blockedMACMap:   make(map[string]bool),
	}
	dm.loadBlocked()
	return dm
}

func (dm *deviceManager) loadBlocked() {
	if dm.blockedPath == "" {
		return
	}
	data, err := os.ReadFile(dm.blockedPath)
	if err != nil {
		return
	}
	var list []BlockedRecord
	if err := json.Unmarshal(data, &list); err != nil {
		return
	}
	dm.blockedList = list
	dm.blockedIPMap = make(map[string]bool)
	dm.blockedMACMap = make(map[string]bool)
	for _, b := range list {
		if b.IP != "" {
			dm.blockedIPMap[b.IP] = true
		}
		if b.MAC != "" {
			dm.blockedMACMap[strings.ToLower(b.MAC)] = true
		}
	}
}

func (dm *deviceManager) saveBlockedLocked() error {
	if dm.blockedPath == "" {
		return nil
	}
	data, err := json.MarshalIndent(dm.blockedList, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(dm.blockedPath, data, 0644)
}

func (dm *deviceManager) syncBridgeBlocked(macs []string) {
	dm.mu.Lock()
	defer dm.mu.Unlock()
	changed := false
	for _, m := range macs {
		clean := strings.ToLower(strings.TrimSpace(m))
		if clean != "" && !dm.blockedMACMap[clean] {
			dm.blockedMACMap[clean] = true
			dm.blockedList = append(dm.blockedList, BlockedRecord{
				MAC:       clean,
				BlockedAt: time.Now().Unix(),
			})
			changed = true
		}
	}
	if changed {
		_ = dm.saveBlockedLocked()
	}
}

func (dm *deviceManager) isBlocked(ip, mac string) bool {
	dm.mu.Lock()
	defer dm.mu.Unlock()
	if ip != "" && dm.blockedIPMap[ip] {
		return true
	}
	if mac != "" && dm.blockedMACMap[strings.ToLower(mac)] {
		return true
	}
	return false
}

func (dm *deviceManager) block(ip, mac, hostname string) error {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	cleanMac := strings.ToLower(strings.TrimSpace(mac))
	cleanIP := strings.TrimSpace(ip)

	// 检查是否已存在
	for _, b := range dm.blockedList {
		if (cleanIP != "" && b.IP == cleanIP) || (cleanMac != "" && strings.ToLower(b.MAC) == cleanMac) {
			return nil
		}
	}

	record := BlockedRecord{
		IP:        cleanIP,
		MAC:       cleanMac,
		Hostname:  hostname,
		BlockedAt: time.Now().Unix(),
	}
	dm.blockedList = append(dm.blockedList, record)
	if cleanIP != "" {
		dm.blockedIPMap[cleanIP] = true
	}
	if cleanMac != "" {
		dm.blockedMACMap[cleanMac] = true
	}
	return dm.saveBlockedLocked()
}

func (dm *deviceManager) unblock(ip, mac string) error {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	cleanMac := strings.ToLower(strings.TrimSpace(mac))
	cleanIP := strings.TrimSpace(ip)

	var next []BlockedRecord
	for _, b := range dm.blockedList {
		match := false
		if cleanIP != "" && b.IP == cleanIP {
			match = true
		}
		if cleanMac != "" && strings.ToLower(b.MAC) == cleanMac {
			match = true
		}
		if !match {
			next = append(next, b)
		}
	}
	dm.blockedList = next
	dm.blockedIPMap = make(map[string]bool)
	dm.blockedMACMap = make(map[string]bool)
	for _, b := range next {
		if b.IP != "" {
			dm.blockedIPMap[b.IP] = true
		}
		if b.MAC != "" {
			dm.blockedMACMap[strings.ToLower(b.MAC)] = true
		}
	}
	return dm.saveBlockedLocked()
}

func (dm *deviceManager) getBlockedList() []BlockedRecord {
	dm.mu.Lock()
	defer dm.mu.Unlock()
	out := make([]BlockedRecord, len(dm.blockedList))
	copy(out, dm.blockedList)
	return out
}

func (dm *deviceManager) calculateRates(key string, curUp, curDown int64) (upBps, downBps int64) {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	cleanKey := strings.ToLower(strings.TrimSpace(key))
	if cleanKey == "" {
		return 0, 0
	}

	now := time.Now()
	sample, exists := dm.lastSamples[cleanKey]

	// 保持单调递增：若连接关闭导致瞬时统计回落，保持历史已观测最大值，避免累计与速率跳变
	monUp := curUp
	monDown := curDown
	if exists {
		if curUp < sample.up {
			monUp = sample.up
		}
		if curDown < sample.down {
			monDown = sample.down
		}
	}

	// 限制表大小，定期淘汰 1 小时前的旧样本，防止长期运行内存累积
	if len(dm.lastSamples) > 256 {
		for k, s := range dm.lastSamples {
			if now.Sub(s.sampledAt) > 1*time.Hour {
				delete(dm.lastSamples, k)
			}
		}
	}

	dm.lastSamples[cleanKey] = clientTrafficSample{
		up:        monUp,
		down:      monDown,
		sampledAt: now,
	}

	if !exists {
		return 0, 0
	}

	deltaSec := now.Sub(sample.sampledAt).Seconds()
	if deltaSec <= 0.1 {
		return 0, 0
	}

	if monUp >= sample.up {
		upBps = int64(float64(monUp-sample.up) / deltaSec)
	}
	if monDown >= sample.down {
		downBps = int64(float64(monDown-sample.down) / deltaSec)
	}
	return upBps, downBps
}

// readSystemARP parses /proc/net/arp to discover local neighbor IP <-> MAC mappings.
func readSystemARP() map[string]string {
	arpMap := make(map[string]string)
	f, err := os.Open("/proc/net/arp")
	if err != nil {
		return arpMap
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	// Skip header: "IP address HW type Flags HW address Mask Device"
	if scanner.Scan() {
		_ = scanner.Text()
	}
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 4 {
			ip := fields[0]
			flags := fields[2]
			mac := fields[3]
			// flags 0x2 means complete / valid entry, not 00:00:00:00:00:00
			if flags == "0x2" && mac != "00:00:00:00:00:00" && !strings.HasPrefix(mac, "00:00:00") {
				arpMap[ip] = strings.ToLower(mac)
			}
		}
	}
	return arpMap
}

// readDHCPLeases tries reading dnsmasq lease files commonly present on Android and Linux hotspots.
func readDHCPLeases() map[string]string {
	names := make(map[string]string)
	candidates := []string{
		"/data/misc/dhcp/dnsmasq.leases",
		"/data/misc/apexdata/com.android.tethering/misc/dhcp/dnsmasq.leases",
		"/var/lib/misc/dnsmasq.leases",
		"/tmp/dnsmasq.leases",
	}
	for _, path := range candidates {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			fields := strings.Fields(line)
			// Format: <timestamp> <mac> <ip> <hostname> <client-id>
			if len(fields) >= 4 {
				mac := strings.ToLower(fields[1])
				ip := fields[2]
				host := fields[3]
				if host != "*" && host != "" {
					names[mac] = host
					names[ip] = host
				}
			}
		}
	}
	return names
}

// extractClientIP extracts the remote client IP without port or bracket formatting.
func extractClientIP(r *http.Request) string {
	remote := r.RemoteAddr
	host, _, err := net.SplitHostPort(remote)
	if err == nil {
		remote = host
	}
	remote = strings.Trim(remote, "[]")
	return remote
}

func isLocalIP(ip string) bool {
	return ip == "127.0.0.1" || ip == "localhost" || ip == "::1" || ip == ""
}

func isInternalVirtualIP(ip string) bool {
	clean := strings.TrimSpace(ip)
	return clean == "192.0.2.2" || clean == "192.0.2.1" || clean == "2001:db8:9877::1" || clean == "2001:db8:9877::2"
}

func contains(slice []string, val string) bool {
	for _, s := range slice {
		if s == val {
			return true
		}
	}
	return false
}

// handleDevices returns all connected and blocked devices.
func (s *Server) handleDevices(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 保证控制面板访问期间连接监控处于开启状态
	if s.setConnStatsEnabled != nil {
		s.setConnStatsEnabled(true)
	}

	clientIP := extractClientIP(r)
	dm := s.getDeviceManager()

	// 1. 若接入了 Android 硬件 Bridge，同步 Wi-Fi 软热点底层的被拉黑 MAC 清单
	if s.tetheringBridge != nil {
		if rawBlocked := s.tetheringBridge.GetBlockedClients(); rawBlocked != "" {
			var blockedMACs []string
			if err := json.Unmarshal([]byte(rawBlocked), &blockedMACs); err == nil && len(blockedMACs) > 0 {
				dm.syncBridgeBlocked(blockedMACs)
			}
		}
	}

	// 2. 从连接统计分析流量
	type ipTraffic struct {
		conns int
		up    int64
		down  int64
	}
	trafficByIP := make(map[string]*ipTraffic)
	connsByIP := make(map[string][]DeviceConn)

	const (
		shizukuTunIPv4    = "192.0.2.2"
		shizukuTunIPv6    = "2001:db8:9877::2"
		hotspotIPv6Prefix = "2001:db8:9877:"
	)

	if s.connStatsSrc != nil {
		statsJSON := s.connStatsSrc()
		if statsJSON != "" && statsJSON != "{\"apps\":[]}" {
			var parsed struct {
				Apps []struct {
					Conns []struct {
						Proto int32  `json:"proto"`
						Host  string `json:"host"`
						Port  int    `json:"port"`
						SrcIP string `json:"src_ip"`
						Up    int64  `json:"up"`
						Down  int64  `json:"down"`
					} `json:"conns"`
				} `json:"apps"`
				ClientTraffic []struct {
					IP          string `json:"ip"`
					Up          int64  `json:"up"`
					Down        int64  `json:"down"`
					ActiveConns int    `json:"active_conns"`
				} `json:"client_traffic"`
			}
			if err := json.Unmarshal([]byte(statsJSON), &parsed); err == nil {
				// 收集活跃连接明细
				for _, app := range parsed.Apps {
					for _, c := range app.Conns {
						src := strings.TrimSpace(c.SrcIP)
						if src == "" || src == "127.0.0.1" || src == "::1" {
							continue
						}
						connsByIP[src] = append(connsByIP[src], DeviceConn{
							Proto: int(c.Proto),
							Host:  c.Host,
							Port:  c.Port,
							Up:    c.Up,
							Down:  c.Down,
						})
					}
				}
				// 优先使用 ConnStats 单调累计的 client_traffic，连接关闭不掉计数
				for _, ct := range parsed.ClientTraffic {
					src := strings.TrimSpace(ct.IP)
					if src == "" || src == "127.0.0.1" || src == "::1" {
						continue
					}
					trafficByIP[src] = &ipTraffic{
						conns: ct.ActiveConns,
						up:    ct.Up,
						down:  ct.Down,
					}
				}
				// 兼容无 client_traffic 的旧快照
				if len(trafficByIP) == 0 {
					for _, app := range parsed.Apps {
						for _, c := range app.Conns {
							src := strings.TrimSpace(c.SrcIP)
							if src == "" || src == "127.0.0.1" || src == "::1" {
								continue
							}
							item := trafficByIP[src]
							if item == nil {
								item = &ipTraffic{}
								trafficByIP[src] = item
							}
							item.conns++
							item.up += c.Up
							item.down += c.Down
						}
					}
				}
			}
		}
	}

	var devices []TetheredDevice
	hasBridgeClients := false

	// 3. 优先通过 Android 特权/AIDL Bridge 获取系统权威在线客户端
	if s.tetheringBridge != nil {
		rawJSON := s.tetheringBridge.GetTetheredClients()
		if rawJSON != "" {
			var bridgeClients []struct {
				MAC         string       `json:"mac"`
				IP          string       `json:"ip"`
				Hostname    string       `json:"hostname"`
				Type        int          `json:"type"`
				IsRandomMAC bool         `json:"is_random_mac"`
				AssignedIPs []string     `json:"assigned_ips"`
				ExtraIPs    []string     `json:"extra_ips"`
				UpBytes     int64        `json:"up_bytes"`
				DownBytes   int64        `json:"down_bytes"`
				ActiveConns int          `json:"active_conns"`
				UpBps       int64        `json:"up_bps"`
				DownBps     int64        `json:"down_bps"`
				IsBlocked   bool         `json:"is_blocked"`
				Conns       []DeviceConn `json:"conns"`
			}
			if err := json.Unmarshal([]byte(rawJSON), &bridgeClients); err == nil && len(bridgeClients) > 0 {
				hasBridgeClients = true
				for _, bc := range bridgeClients {
					primaryIP := strings.TrimSpace(bc.IP)
					if primaryIP == "" && len(bc.AssignedIPs) > 0 {
						primaryIP = strings.TrimSpace(bc.AssignedIPs[0])
					}
					cleanMAC := strings.ToLower(strings.TrimSpace(bc.MAC))

					allDeviceIPs := make([]string, 0, len(bc.AssignedIPs)+len(bc.ExtraIPs)+1)
					if primaryIP != "" {
						allDeviceIPs = append(allDeviceIPs, primaryIP)
					}
					for _, aip := range bc.AssignedIPs {
						trimmed := strings.TrimSpace(aip)
						if trimmed != "" && trimmed != primaryIP && !contains(allDeviceIPs, trimmed) {
							allDeviceIPs = append(allDeviceIPs, trimmed)
						}
					}
					for _, eip := range bc.ExtraIPs {
						trimmed := strings.TrimSpace(eip)
						if trimmed != "" && trimmed != primaryIP && !contains(allDeviceIPs, trimmed) {
							allDeviceIPs = append(allDeviceIPs, trimmed)
						}
					}

					var up, down int64
					var upBps, downBps int64
					conns := 0

					if bc.UpBytes > 0 || bc.DownBytes > 0 || bc.ActiveConns > 0 || bc.UpBps > 0 || bc.DownBps > 0 {
						up = bc.UpBytes
						down = bc.DownBytes
						conns = bc.ActiveConns
						upBps = bc.UpBps
						downBps = bc.DownBps
						rateKey := cleanMAC
						if rateKey == "" {
							rateKey = primaryIP
						}
						if rateKey != "" {
							dm.mu.Lock()
							dm.lastSamples[rateKey] = clientTrafficSample{
								up:        up,
								down:      down,
								sampledAt: time.Now(),
							}
							dm.mu.Unlock()
						}
					} else {
						// 若仅有 1 个物理客户端，将 Android 内核 TUN NAT (192.0.2.2) 及热点 IPv6 子网临时 SLAAC 流量归属给该设备
						if len(bridgeClients) == 1 {
							if trafficByIP[shizukuTunIPv4] != nil && !contains(allDeviceIPs, shizukuTunIPv4) {
								allDeviceIPs = append(allDeviceIPs, shizukuTunIPv4)
							}
							if trafficByIP[shizukuTunIPv6] != nil && !contains(allDeviceIPs, shizukuTunIPv6) {
								allDeviceIPs = append(allDeviceIPs, shizukuTunIPv6)
							}
							for dip := range trafficByIP {
								if strings.HasPrefix(strings.ToLower(dip), hotspotIPv6Prefix) && !contains(allDeviceIPs, dip) {
									allDeviceIPs = append(allDeviceIPs, dip)
								}
							}
						}

						for _, dip := range allDeviceIPs {
							if tr := trafficByIP[dip]; tr != nil {
								up += tr.up
								down += tr.down
								conns += tr.conns
							}
						}

						rateKey := cleanMAC
						if rateKey == "" {
							rateKey = primaryIP
						}
						upBps, downBps = dm.calculateRates(rateKey, up, down)
					}

					rateKey := cleanMAC
					if rateKey == "" {
						rateKey = primaryIP
					}
					// 保持累计流量单调递增，连接关闭后累计字节不回退
					if rateKey != "" {
						dm.mu.Lock()
						life := dm.lifetimeTraffic[rateKey]
						if life.up > up {
							up = life.up
						}
						if life.down > down {
							down = life.down
						}
						dm.lifetimeTraffic[rateKey] = lifetimeTraffic{up: up, down: down}
						dm.mu.Unlock()
					}

					isBlocked := bc.IsBlocked || dm.isBlocked(primaryIP, cleanMAC)

					isCur := false
					if clientIP != "" {
						if isLocalIP(clientIP) && (primaryIP == "" || isLocalIP(primaryIP)) {
							isCur = true
						} else {
							for _, dip := range allDeviceIPs {
								if dip == clientIP {
									isCur = true
									break
								}
							}
						}
					}

					var extraIPs []string
					for _, aip := range allDeviceIPs {
						if aip != primaryIP && !contains(extraIPs, aip) && aip != shizukuTunIPv4 && aip != shizukuTunIPv6 {
							extraIPs = append(extraIPs, aip)
						}
					}

					var devConns []DeviceConn
					if len(bc.Conns) > 0 {
						devConns = bc.Conns
					} else {
						for _, dip := range allDeviceIPs {
							if cl := connsByIP[dip]; len(cl) > 0 {
								devConns = append(devConns, cl...)
							}
						}
					}

					if isInternalVirtualIP(primaryIP) || bc.Hostname == "热点共享流量池" || bc.Hostname == "热点共享设备" {
						continue
					}

					devices = append(devices, TetheredDevice{
						IP:          primaryIP,
						MAC:         cleanMAC,
						Hostname:    bc.Hostname,
						ExtraIPs:    extraIPs,
						UpBytes:     up,
						DownBytes:   down,
						ActiveConns: conns,
						UpBps:       upBps,
						DownBps:     downBps,
						IsBlocked:   isBlocked,
						IsCurrent:   isCur,
						Conns:       devConns,
					})
				}
			}
		}
	}

	// 4. 回退模式：若无 Bridge，读取 /proc/net/arp，并按 MAC 归一化聚合(避免设备更换 IP 产生重复残留卡片)
	if !hasBridgeClients {
		arpMap := readSystemARP()
		leaseMap := readDHCPLeases()

		type macGroup struct {
			mac       string
			primaryIP string
			hostname  string
			allIPs    []string
		}
		groupsByMAC := make(map[string]*macGroup)

		for ip, mac := range arpMap {
			cleanMAC := strings.ToLower(strings.TrimSpace(mac))
			if cleanMAC == "" {
				cleanMAC = "ip:" + ip
			}
			grp := groupsByMAC[cleanMAC]
			if grp == nil {
				host := leaseMap[cleanMAC]
				if host == "" {
					host = leaseMap[ip]
				}
				grp = &macGroup{
					mac:       strings.TrimPrefix(cleanMAC, "ip:"),
					primaryIP: ip,
					hostname:  host,
					allIPs:    []string{ip},
				}
				groupsByMAC[cleanMAC] = grp
			} else {
				grp.allIPs = append(grp.allIPs, ip)
				if tr := trafficByIP[ip]; tr != nil && tr.conns > 0 {
					grp.primaryIP = ip
				}
				if grp.hostname == "" && leaseMap[ip] != "" {
					grp.hostname = leaseMap[ip]
				}
			}
		}

		// 若仅有 1 个物理客户端，将 Android 内核 TUN NAT (192.0.2.2) 及热点 IPv6 子网流量归属给该设备
		if len(groupsByMAC) == 1 {
			for _, grp := range groupsByMAC {
				if trafficByIP[shizukuTunIPv4] != nil && !contains(grp.allIPs, shizukuTunIPv4) {
					grp.allIPs = append(grp.allIPs, shizukuTunIPv4)
				}
				if trafficByIP[shizukuTunIPv6] != nil && !contains(grp.allIPs, shizukuTunIPv6) {
					grp.allIPs = append(grp.allIPs, shizukuTunIPv6)
				}
				for dip := range trafficByIP {
					if strings.HasPrefix(strings.ToLower(dip), hotspotIPv6Prefix) && !contains(grp.allIPs, dip) {
						grp.allIPs = append(grp.allIPs, dip)
					}
				}
			}
		}

		for _, grp := range groupsByMAC {
			var up, down int64
			conns := 0
			for _, dip := range grp.allIPs {
				if tr := trafficByIP[dip]; tr != nil {
					up += tr.up
					down += tr.down
					conns += tr.conns
				}
			}
			rateKey := grp.mac
			if rateKey == "" {
				rateKey = grp.primaryIP
			}
			upBps, downBps := dm.calculateRates(rateKey, up, down)

			// 保持累计流量单调递增，连接关闭后累计字节不回退
			dm.mu.Lock()
			life := dm.lifetimeTraffic[rateKey]
			if life.up > up {
				up = life.up
			}
			if life.down > down {
				down = life.down
			}
			dm.lifetimeTraffic[rateKey] = lifetimeTraffic{up: up, down: down}
			dm.mu.Unlock()

			isBlocked := dm.isBlocked(grp.primaryIP, grp.mac)
			isCur := (clientIP != "" && (contains(grp.allIPs, clientIP) || (isLocalIP(clientIP) && isLocalIP(grp.primaryIP))))

			var extraIPs []string
			for _, aip := range grp.allIPs {
				if aip != grp.primaryIP && !contains(extraIPs, aip) && aip != shizukuTunIPv4 && aip != shizukuTunIPv6 {
					extraIPs = append(extraIPs, aip)
				}
			}

			var devConns []DeviceConn
			for _, dip := range grp.allIPs {
				if cl := connsByIP[dip]; len(cl) > 0 {
					devConns = append(devConns, cl...)
				}
			}

			if isInternalVirtualIP(grp.primaryIP) || grp.hostname == "热点共享流量池" || grp.hostname == "热点共享设备" {
				continue
			}

			devices = append(devices, TetheredDevice{
				IP:          grp.primaryIP,
				MAC:         grp.mac,
				Hostname:    grp.hostname,
				ExtraIPs:    extraIPs,
				UpBytes:     up,
				DownBytes:   down,
				ActiveConns: conns,
				UpBps:       upBps,
				DownBps:     downBps,
				IsBlocked:   isBlocked,
				IsCurrent:   isCur,
				Conns:       devConns,
			})
		}
	}

	if devices == nil {
		devices = []TetheredDevice{}
	}

	resp := map[string]interface{}{
		"devices":         devices,
		"blocked_devices": dm.getBlockedList(),
		"current_ip":      clientIP,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// handleDevicesDisconnect terminates all active connections for a target client.
func (s *Server) handleDevicesDisconnect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	targetIP := strings.TrimSpace(r.URL.Query().Get("ip"))
	if targetIP == "" {
		http.Error(w, "missing ?ip parameter", http.StatusBadRequest)
		return
	}

	clientIP := extractClientIP(r)
	if targetIP == clientIP {
		http.Error(w, "Cannot disconnect the current device managing the control panel", http.StatusForbidden)
		return
	}
	if isInternalVirtualIP(targetIP) {
		http.Error(w, "Cannot disconnect system internal virtual gateway", http.StatusForbidden)
		return
	}

	killed := 0
	if s.killClientConnections != nil {
		killed = s.killClientConnections(targetIP)
	}

	slog.Info("admin: disconnected client device", "ip", targetIP, "killed", killed)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"status": "ok", "killed": killed})
}

// handleDevicesBlock adds target device to blocklist and drops its connections.
func (s *Server) handleDevicesBlock(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	targetIP := strings.TrimSpace(r.URL.Query().Get("ip"))
	targetMAC := strings.TrimSpace(r.URL.Query().Get("mac"))
	hostname := strings.TrimSpace(r.URL.Query().Get("hostname"))

	if targetIP == "" && targetMAC == "" {
		http.Error(w, "missing ?ip or ?mac parameter", http.StatusBadRequest)
		return
	}

	clientIP := extractClientIP(r)
	if targetIP != "" && targetIP == clientIP {
		http.Error(w, "Cannot block the current device managing the control panel", http.StatusForbidden)
		return
	}
	if isInternalVirtualIP(targetIP) {
		http.Error(w, "Cannot block system internal virtual gateway", http.StatusForbidden)
		return
	}

	dm := s.getDeviceManager()
	if err := dm.block(targetIP, targetMAC, hostname); err != nil {
		http.Error(w, "failed to save block: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// 1. L3/L4 掐断现有连接并丢弃数据包
	if targetIP != "" {
		if s.blockClientIP != nil {
			s.blockClientIP(targetIP)
		}
		if s.killClientConnections != nil {
			s.killClientConnections(targetIP)
		}
	}

	// 2. L2: 若接入了 Android 热点 Bridge 且有 MAC，下发硬件/驱动级 Wi-Fi AP 黑名单踢下线
	if s.tetheringBridge != nil && targetMAC != "" {
		ok := s.tetheringBridge.BlockClient(targetMAC)
		slog.Info("admin: tethering bridge block client", "mac", targetMAC, "ok", ok)
	}

	slog.Info("admin: blocked client device", "ip", targetIP, "mac", targetMAC)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// handleDevicesUnblock removes target device from blocklist.
func (s *Server) handleDevicesUnblock(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	targetIP := strings.TrimSpace(r.URL.Query().Get("ip"))
	targetMAC := strings.TrimSpace(r.URL.Query().Get("mac"))

	if targetIP == "" && targetMAC == "" {
		http.Error(w, "missing ?ip or ?mac parameter", http.StatusBadRequest)
		return
	}

	dm := s.getDeviceManager()
	if err := dm.unblock(targetIP, targetMAC); err != nil {
		http.Error(w, "failed to unblock: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// 1. L3/L4 解除 IP 拦截
	if targetIP != "" && s.unblockClientIP != nil {
		s.unblockClientIP(targetIP)
	}

	// 2. L2: 若接入了 Android 热点 Bridge 且有 MAC，从硬件/驱动级 Wi-Fi AP 黑名单解封
	if s.tetheringBridge != nil && targetMAC != "" {
		ok := s.tetheringBridge.UnblockClient(targetMAC)
		slog.Info("admin: tethering bridge unblock client", "mac", targetMAC, "ok", ok)
	}

	slog.Info("admin: unblocked client device", "ip", targetIP, "mac", targetMAC)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}
