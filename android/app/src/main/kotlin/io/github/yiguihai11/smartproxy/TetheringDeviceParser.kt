package io.github.yiguihai11.smartproxy

import io.github.yiguihai11.smartproxy.shizuku.HotspotRoutingConfig
import org.json.JSONArray
import org.json.JSONObject

/**
 * 热点共享设备与流量统计解析器。
 *
 * 负责将 Shizuku 用户服务返回的 JSON（包含通过系统回调/邻居表发现的 clients，以及 Go 引擎采集的连接 conns）
 * 归一化为 TetheredDeviceDetail 列表。
 *
 * 特别处理 Android 内核转发与 IPv6 SLAAC 隐私扩展机制：
 * 1. Android 内核在通过 TUN 转发热点流量时，IPv4 会经 iptables MASQUERADE 重写源 IP 为 TUN 内部 IP
 *    （SHIZUKU_TUN_IP_V4: 192.0.2.2）；
 * 2. 现代操作系统（Android/iOS/Windows）在接收到热点下发的 IPv6 /64 前缀后，会依 RFC 4941/8981 隐私扩展
 *    自主生成多个临时的 SLAAC IPv6 地址发起对外请求。
 *
 * 本解析器基于真实物理设备 (MAC/L2) 为主键进行多维度流量与连接汇聚：
 * 1. 当热点下仅有 1 个真实物理接入设备时，所有源自 TUN NAT 网卡及热点 IPv6 子网（2001:db8:9877::/64）
 *    的临时 SLAAC 连接 100% 归属于该真实客户端，彻底消除「设备显示 0 流量」和「SLAAC 裂变为多个幽灵设备」；
 * 2. 同一物理设备分配的双栈 IPv4/IPv6 以及多个临时 SLAAC 隐私地址全部聚合至该设备名下，并在设备详情中
 *    完整列出所有分配与使用过的 IP 地址；
 * 3. 当有多个物理设备同时接入且存在未匹配到具体 MAC 的汇聚流量时，将其归入「热点共享流量池」，避免用户误判。
 */
object TetheringDeviceParser {

    private val TUN_VIRTUAL_IPS = setOf(
        HotspotRoutingConfig.SHIZUKU_TUN_IP_V4,
        HotspotRoutingConfig.SHIZUKU_TUN_IP_V6,
    )

    private val HOTSPOT_IPV6_PREFIX = HotspotRoutingConfig.SHIZUKU_TUN_ADDR_V6
        .substringBefore('/')
        .let { ip ->
            val parts = ip.split(':')
            if (parts.size >= 3) "${parts[0]}:${parts[1]}:${parts[2]}:" else "2001:db8:9877:"
        }

    private fun isHotspotIpv6Subnet(ip: String): Boolean =
        ip.startsWith(HOTSPOT_IPV6_PREFIX, ignoreCase = true)

    fun parse(statsJson: String?): List<TetheredDeviceDetail> {
        if (statsJson.isNullOrBlank() || statsJson == "{\"apps\":[]}") return emptyList()

        return runCatching {
            val root = JSONObject(statsJson)
            val clientsArr = root.optJSONArray("clients") ?: JSONArray()
            val clientByMac = LinkedHashMap<String, JSONObject>()
            val clientByIp = LinkedHashMap<String, JSONObject>()
            val clientIpsByMac = LinkedHashMap<String, LinkedHashSet<String>>()

            for (i in 0 until clientsArr.length()) {
                val c = clientsArr.getJSONObject(i)
                val ip = c.optString("ip", "").trim()
                val mac = c.optString("mac", "").lowercase().trim()

                val assignedIps = LinkedHashSet<String>()
                val assignedIpsArr = c.optJSONArray("assigned_ips")
                if (assignedIpsArr != null) {
                    for (k in 0 until assignedIpsArr.length()) {
                        val aIp = assignedIpsArr.optString(k, "").trim()
                        if (aIp.isNotEmpty()) assignedIps.add(aIp)
                    }
                }
                if (ip.isNotEmpty()) assignedIps.add(ip)

                if (mac.isNotEmpty()) {
                    val existing = clientByMac[mac]
                    val macIps = clientIpsByMac.getOrPut(mac) { LinkedHashSet() }
                    macIps.addAll(assignedIps)

                    if (existing == null) {
                        clientByMac[mac] = c
                    } else {
                        // 同一物理 MAC 分配了双栈地址时，优先使用 IPv4 作为主展示 IP 聚合
                        val existingIp = existing.optString("ip", "")
                        if (existingIp.contains(':') && !ip.contains(':') && ip.isNotEmpty()) {
                            clientByMac[mac] = c
                        }
                    }
                } else if (ip.isNotEmpty()) {
                    clientIpsByMac.getOrPut(ip.lowercase()) { LinkedHashSet() }.addAll(assignedIps)
                }

                for (aIp in assignedIps) {
                    clientByIp[aIp] = clientByMac[mac] ?: c
                }
            }

            val appsArr = root.optJSONArray("apps") ?: JSONArray()
            val connsBySrcIp = LinkedHashMap<String, ArrayList<ConnStatsRec>>()
            for (i in 0 until appsArr.length()) {
                val a = appsArr.getJSONObject(i)
                val connsArr = a.optJSONArray("conns") ?: JSONArray()
                for (j in 0 until connsArr.length()) {
                    val c = connsArr.getJSONObject(j)
                    val srcIp = c.optString("src_ip", "").trim()
                    if (srcIp.isEmpty()) continue
                    connsBySrcIp.getOrPut(srcIp) { ArrayList() }.add(
                        ConnStatsRec(
                            proto = c.getInt("proto"),
                            host = c.getString("host"),
                            port = c.getInt("port"),
                            up = c.getLong("up"),
                            down = c.getLong("down"),
                            srcIp = srcIp,
                        )
                    )
                }
            }

            // 提取因 Android 内核 NAT 转发（源 IP 改写为 TUN 虚拟网卡）以及未被系统回调即时登记的 SLAAC IPv6 临时地址流量
            val unassignedHotspotConns = ArrayList<ConnStatsRec>()
            for (tunIp in TUN_VIRTUAL_IPS) {
                connsBySrcIp.remove(tunIp)?.let { unassignedHotspotConns.addAll(it) }
            }

            // 识别处于热点 IPv6 子网中但尚未绑定到特定客户端的 SLAAC 连接
            val unmatchedHotspotIps = connsBySrcIp.keys.filter { ip ->
                isHotspotIpv6Subnet(ip) && ip !in clientByIp
            }.toList()

            // 1. 若当前恰好只有 1 个识别到的下游物理客户端（或仅有 1 个已知客户端 IP）：
            //    所有来自 TUN NAT 以及热点 IPv6 子网的流量必然 100% 属于该客户端！
            //    直接将其连接和流量完整归属于该客户端，从源头彻底杜绝「设备显示 0 流量」和「SLAAC 裂变为多个幽灵设备」！
            val singleClientMac = if (clientByMac.size == 1) clientByMac.keys.first() else null
            val singleClientIp = if (singleClientMac != null) {
                clientByMac[singleClientMac]?.optString("ip", "")?.ifEmpty { null }
                    ?: clientIpsByMac[singleClientMac]?.firstOrNull { !it.contains(':') }
                    ?: clientIpsByMac[singleClientMac]?.firstOrNull()
            } else if (clientByIp.values.distinct().size == 1) {
                clientByIp.keys.firstOrNull { !it.contains(':') } ?: clientByIp.keys.firstOrNull()
            } else null

            if (singleClientIp != null) {
                for (slaacIp in unmatchedHotspotIps) {
                    connsBySrcIp.remove(slaacIp)?.let { unassignedHotspotConns.addAll(it) }
                    if (singleClientMac != null) {
                        clientIpsByMac.getOrPut(singleClientMac) { LinkedHashSet() }.add(slaacIp)
                    }
                }

                if (unassignedHotspotConns.isNotEmpty()) {
                    val targetList = connsBySrcIp.getOrPut(singleClientIp) { ArrayList() }
                    for (c in unassignedHotspotConns) {
                        targetList.add(c.copy(srcIp = singleClientIp))
                    }
                }
            } else {
                // 2. 若有多个客户端接入，或尚无任何客户端注册完成：
                //    对于未匹配的 IPv6 SLAAC 连接以及 NAT 连接，汇聚到热点共享流量池，
                //    避免在列表里弹出未知随机 IPv6 裸地址幽灵设备
                for (slaacIp in unmatchedHotspotIps) {
                    connsBySrcIp.remove(slaacIp)?.let { unassignedHotspotConns.addAll(it) }
                }

                if (unassignedHotspotConns.isNotEmpty()) {
                    connsBySrcIp[HotspotRoutingConfig.SHIZUKU_TUN_IP_V4] = unassignedHotspotConns
                }
            }

            val blockedArr = root.optJSONArray("blocked_clients") ?: JSONArray()
            val blockedSet = HashSet<String>()
            for (i in 0 until blockedArr.length()) {
                val b = blockedArr.optString(i, "").trim().lowercase()
                if (b.isNotEmpty()) blockedSet.add(b)
            }

            val list = mutableListOf<TetheredDeviceDetail>()
            val processedIps = HashSet<String>()

            // 1. 优先以真实物理客户端 (MAC) 为主干生成设备详情
            for ((mac, clientObj) in clientByMac) {
                val allDeviceIps = clientIpsByMac[mac].orEmpty().toList()
                val primaryIp = clientObj.optString("ip", "").ifBlank {
                    allDeviceIps.firstOrNull { !it.contains(':') } ?: allDeviceIps.firstOrNull().orEmpty()
                }
                val extraIps = (allDeviceIps + listOf(primaryIp)).filter { it.isNotBlank() && it != primaryIp }.distinct()

                // 收集归属该设备的所有 IP 产生的连接
                val deviceConns = ArrayList<ConnStatsRec>()
                for (devIp in (listOf(primaryIp) + extraIps)) {
                    connsBySrcIp[devIp]?.let { deviceConns.addAll(it) }
                    processedIps.add(devIp)
                }

                val hostname = clientObj.optString("hostname", "")
                val vendor = clientObj.optString("vendor", "")
                val isRandomMac = clientObj.optBoolean("is_random_mac", false)
                val rawOsGuess = clientObj.optString("os_guess", "")
                val tetheringType = clientObj.optInt("type", -1)
                val isBlocked = mac.lowercase() in blockedSet

                val osGuess = when {
                    rawOsGuess.isNotBlank() -> rawOsGuess
                    isRandomMac -> "局域网设备 (私有/随机 MAC)"
                    else -> "局域网接入设备"
                }

                list.add(
                    TetheredDeviceDetail(
                        ip = primaryIp,
                        mac = mac,
                        hostname = hostname,
                        vendor = vendor,
                        isRandomMac = isRandomMac,
                        osGuess = osGuess,
                        tetheringType = tetheringType,
                        upBytes = deviceConns.sumOf { it.up },
                        downBytes = deviceConns.sumOf { it.down },
                        conns = deviceConns,
                        isBlocked = isBlocked,
                        extraIps = extraIps,
                    )
                )
            }

            // 2. 处理无 MAC 但由 clientByIp 注册的客户端（如虚拟适配器）
            for ((ip, clientObj) in clientByIp) {
                if (ip in processedIps) continue
                processedIps.add(ip)

                val conns = connsBySrcIp[ip] ?: emptyList()
                val hostname = clientObj.optString("hostname", "")
                val vendor = clientObj.optString("vendor", "")
                val isRandomMac = clientObj.optBoolean("is_random_mac", false)
                val rawOsGuess = clientObj.optString("os_guess", "")
                val tetheringType = clientObj.optInt("type", -1)

                val osGuess = when {
                    rawOsGuess.isNotBlank() -> rawOsGuess
                    isRandomMac -> "局域网设备 (私有/随机 MAC)"
                    else -> "局域网接入设备"
                }

                list.add(
                    TetheredDeviceDetail(
                        ip = ip,
                        mac = "",
                        hostname = hostname,
                        vendor = vendor,
                        isRandomMac = isRandomMac,
                        osGuess = osGuess,
                        tetheringType = tetheringType,
                        upBytes = conns.sumOf { it.up },
                        downBytes = conns.sumOf { it.down },
                        conns = conns,
                        isBlocked = false,
                    )
                )
            }

            // 3. 处理剩余的连接源 IP（例如多设备 NAT / 热点共享流量池）
            for ((ip, conns) in connsBySrcIp) {
                if (ip in processedIps) continue
                processedIps.add(ip)

                val isTunNat = ip in TUN_VIRTUAL_IPS || ip == HotspotRoutingConfig.SHIZUKU_TUN_IP_V4
                val osGuess = when {
                    isTunNat && clientByMac.size > 1 -> "热点共享汇聚 (多设备 NAT)"
                    isTunNat -> "热点共享客户端 (NAT)"
                    else -> "局域网接入设备"
                }
                val displayHostname = when {
                    isTunNat && clientByMac.size > 1 -> "热点共享流量池"
                    isTunNat -> "热点共享设备"
                    else -> ""
                }

                list.add(
                    TetheredDeviceDetail(
                        ip = ip,
                        mac = "",
                        hostname = displayHostname,
                        vendor = "",
                        isRandomMac = false,
                        osGuess = osGuess,
                        tetheringType = -1,
                        upBytes = conns.sumOf { it.up },
                        downBytes = conns.sumOf { it.down },
                        conns = conns,
                        isBlocked = false,
                    )
                )
            }

            // 4. 处理已被黑名单拦截但当前不在线（未连接）的设备
            val addedMacs = list.map { it.mac.lowercase() }.filter { it.isNotEmpty() }.toSet()
            for (bMac in blockedSet) {
                if (bMac !in addedMacs) {
                    val vendor = io.github.yiguihai11.smartproxy.shizuku.lookupMacVendor(bMac).orEmpty()
                    val isRandom = io.github.yiguihai11.smartproxy.shizuku.isLocallyAdministeredMac(bMac)
                    val osGuess = io.github.yiguihai11.smartproxy.shizuku.inferDeviceOs(null, vendor.ifEmpty { null }, isRandom)
                    list.add(
                        TetheredDeviceDetail(
                            ip = "",
                            mac = bMac,
                            hostname = "",
                            vendor = vendor,
                            isRandomMac = isRandom,
                            osGuess = osGuess,
                            tetheringType = -1,
                            upBytes = 0L,
                            downBytes = 0L,
                            conns = emptyList(),
                            isBlocked = true,
                        )
                    )
                }
            }

            list
        }.getOrDefault(emptyList())
    }
}
