// Package quic 提供 SmartProxy 对 UDP/443 QUIC(HTTP/3) 流做被动识别、短窗嗅探与
// GFW 黑洞自愈判死的核心组件。全部与 I/O 解耦、不持有任何密钥,供 TUN 与 SOCKS5-UDP
// 两条数据通路共享。
//
// 数据流分层:上层 seam(收包循环) 把目标流的客户端 datagram 交给 Sniff 识别 QUIC /
// 抠 SNI/ECH(短窗 HoldMs 内,超窗冻结不再吸收);对落到"直连观察"的目标再挂一个
// Watchdog —— 见 Initial 重传(同 DCID + CRYPTO 与已收重叠)或 timeout_ms 窗口内
// 零服务器回包即判死,回调 seam 写入动态黑名单并把该流热切换到 UDP-capable 上游。
package quic
