package socks5

import (
	"net"
)

// TrieNode 基数树节点
type TrieNode struct {
	children [2]*TrieNode  // 0 和 1 两个子节点
	isRule   bool          // 是否是规则节点
	action   Action        // 动作类型
	rule     *Rule         // 规则信息
}

// RadixTrie 基数树，用于高效的IP网段匹配
type RadixTrie struct {
	rootIPv4 *TrieNode
	rootIPv6 *TrieNode
}

// NewRadixTrie 创建新的基数树
func NewRadixTrie() *RadixTrie {
	return &RadixTrie{
		rootIPv4: &TrieNode{},
		rootIPv6: &TrieNode{},
	}
}

// Insert 插入IP网段规则
func (t *RadixTrie) Insert(network string, action Action, rule *Rule) error {
	_, ipNet, err := net.ParseCIDR(network)
	if err != nil {
		// 如果不是CIDR格式，尝试作为单个IP处理
		ip := net.ParseIP(network)
		if ip == nil {
			return err
		}

		// 将单个IP转换为/32或/128的网段
		if ip.To4() != nil {
			// IPv4
			network = ip.String() + "/32"
			_, ipNet, err = net.ParseCIDR(network)
		} else {
			// IPv6
			network = ip.String() + "/128"
			_, ipNet, err = net.ParseCIDR(network)
		}
		if err != nil {
			return err
		}
	}

	if ipNet.IP.To4() != nil {
		// IPv4 网络
		t.insertIPv4(ipNet, action, rule)
	} else {
		// IPv6 网络
		t.insertIPv6(ipNet, action, rule)
	}

	return nil
}

// insertIPv4 插入IPv4网段
func (t *RadixTrie) insertIPv4(ipNet *net.IPNet, action Action, rule *Rule) {
	node := t.rootIPv4
	ip := ipNet.IP.To4()
	mask := ipNet.Mask

	// 遍历IP的每一位
	for i := 0; i < 32; i++ {
		if mask[i/8]&(1<<(7-(i%8))) == 0 {
			// 掩码为0的位置停止，这是网段的边界
			break
		}

		bit := getBit(ip[i/8], 7-(i%8))
		if node.children[bit] == nil {
			node.children[bit] = &TrieNode{}
		}
		node = node.children[bit]
	}

	// 设置规则
	node.isRule = true
	node.action = action
	node.rule = rule
}

// insertIPv6 插入IPv6网段
func (t *RadixTrie) insertIPv6(ipNet *net.IPNet, action Action, rule *Rule) {
	node := t.rootIPv6
	ip := ipNet.IP.To16()
	mask := ipNet.Mask

	// 遍历IPv6的每一位
	for i := 0; i < 128; i++ {
		if mask[i/8]&(1<<(7-(i%8))) == 0 {
			// 掩码为0的位置停止，这是网段的边界
			break
		}

		bit := getBit(ip[i/8], 7-(i%8))
		if node.children[bit] == nil {
			node.children[bit] = &TrieNode{}
		}
		node = node.children[bit]
	}

	// 设置规则
	node.isRule = true
	node.action = action
	node.rule = rule
}

// Lookup 查找IP地址的规则
func (t *RadixTrie) Lookup(ipStr string) (Action, bool, *Rule) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return "", false, nil
	}

	if ip.To4() != nil {
		// IPv4 查找
		return t.lookupIPv4(ip.To4())
	} else {
		// IPv6 查找
		return t.lookupIPv6(ip.To16())
	}
}

// lookupIPv4 IPv4查找
func (t *RadixTrie) lookupIPv4(ip net.IP) (Action, bool, *Rule) {
	node := t.rootIPv4
	var lastRule *TrieNode

	// 遍历IP的每一位
	for i := 0; i < 32; i++ {
		bit := getBit(ip[i/8], 7-(i%8))

		if node.children[bit] == nil {
			break
		}

		node = node.children[bit]
		if node.isRule {
			lastRule = node
		}
	}

	if lastRule != nil {
		return lastRule.action, true, lastRule.rule
	}

	return "", false, nil
}

// lookupIPv6 IPv6查找
func (t *RadixTrie) lookupIPv6(ip net.IP) (Action, bool, *Rule) {
	node := t.rootIPv6
	var lastRule *TrieNode

	// 遍历IPv6的每一位
	for i := 0; i < 128; i++ {
		bit := getBit(ip[i/8], 7-(i%8))

		if node.children[bit] == nil {
			break
		}

		node = node.children[bit]
		if node.isRule {
			lastRule = node
		}
	}

	if lastRule != nil {
		return lastRule.action, true, lastRule.rule
	}

	return "", false, nil
}

// getBit 获取字节的指定位
func getBit(b byte, pos int) byte {
	if pos < 0 || pos > 7 {
		return 0
	}
	return (b >> pos) & 1
}

// GetStats 获取基数树统计信息
func (t *RadixTrie) GetStats() (int, int, int) {
	ipv4Nodes := countNodes(t.rootIPv4)
	ipv6Nodes := countNodes(t.rootIPv6)
	rules := countRules(t.rootIPv4) + countRules(t.rootIPv6)

	return ipv4Nodes, ipv6Nodes, rules
}

// countNodes 递归计算节点数量
func countNodes(node *TrieNode) int {
	if node == nil {
		return 0
	}

	count := 1
	count += countNodes(node.children[0])
	count += countNodes(node.children[1])
	return count
}

// countRules 递归计算规则数量
func countRules(node *TrieNode) int {
	if node == nil {
		return 0
	}

	count := 0
	if node.isRule {
		count = 1
	}
	count += countRules(node.children[0])
	count += countRules(node.children[1])
	return count
}