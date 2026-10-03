package io.github.yiguihai11.smartproxy

import io.github.yiguihai11.smartproxy.shizuku.HotspotRoutingConfig
import org.json.JSONArray
import org.json.JSONObject

/**
 * 热点共享设备与流量统计解析器。
 *
 * 负责将 Shizuku 用户服务返回的 JSON（包含通过系统回调/ARP 发现的 clients，以及 Go 引擎采集的连接 conns）
 * 归一化为 TetheredDeviceDetail 列表。
 *
 * 特别处理 Android 内核 NAT 转发机制：
 * Android 的 tetherctrl 链在将热点/USB 共享流量路由至上游 TestNetwork TUN 虚拟网卡时，
 * 会强制执行 iptables MASQUERADE，导致进入代理引擎的所有外接设备数据包源 IP 均被改写为 TUN 虚拟网卡自身的 IP
 * （即 SHIZUKU_TUN_IP_V4: 192.0.2.2 / SHIZUKU_TUN_IP_V6: 2001:db8:9877::1）。
 *
 * 本解析器识别此内核行为：
 * 1. 当热点下仅有 1 个真实物理接入设备时，所有的 NAT 虚拟 IP 流量 100% 归属于该设备，
 *    自动将连接和上下行流量合并至真实客户端名下，并隐藏内部虚拟 IP，杜绝「设备 0 流量」和「虚拟 IP 占位」割裂；
 * 2. 当有多个设备同时接入且共享同一 NAT 网卡时，将聚合流量标识为「热点共享流量池」，避免用户误判为未知异常设备；
 * 3. 当设备使用私有/随机 MAC 且未广播主机名时，明确标注「局域网设备 (私有/随机 MAC)」。
 */
object TetheringDeviceParser {

    private val TUN_VIRTUAL_IPS = setOf(
        HotspotRoutingConfig.SHIZUKU_TUN_IP_V4,
        HotspotRoutingConfig.SHIZUKU_TUN_IP_V6,
    )

    fun parse(statsJson: String?): List<TetheredDeviceDetail> {
        if (statsJson.isNullOrBlank() || statsJson == "{\"apps\":[]}") return emptyList()

        return runCatching {
            val root = JSONObject(statsJson)
            val clientsArr = root.optJSONArray("clients") ?: JSONArray()
            val clientByMac = LinkedHashMap<String, JSONObject>()
            val clientByIp = LinkedHashMap<String, JSONObject>()
            for (i in 0 until clientsArr.length()) {
                val c = clientsArr.getJSONObject(i)
                val ip = c.optString("ip", "")
                val mac = c.optString("mac", "").lowercase().trim()
                if (mac.isNotEmpty()) {
                    val existing = clientByMac[mac]
                    if (existing == null) {
                        clientByMac[mac] = c
                        if (ip.isNotEmpty()) clientByIp[ip] = c
                    } else {
                        // 同一物理 MAC 分配了双栈地址时，优先使用 IPv4 作为主展示 IP 聚合
                        val existingIp = existing.optString("ip", "")
                        if (existingIp.contains(':') && !ip.contains(':') && ip.isNotEmpty()) {
                            clientByIp.remove(existingIp)
                            clientByMac[mac] = c
                            clientByIp[ip] = c
                        }
                    }
                } else if (ip.isNotEmpty()) {
                    clientByIp[ip] = c
                }
            }

            val appsArr = root.optJSONArray("apps") ?: JSONArray()
            val connsBySrcIp = LinkedHashMap<String, ArrayList<ConnStatsRec>>()
            for (i in 0 until appsArr.length()) {
                val a = appsArr.getJSONObject(i)
                val connsArr = a.optJSONArray("conns") ?: JSONArray()
                for (j in 0 until connsArr.length()) {
                    val c = connsArr.getJSONObject(j)
                    val srcIp = c.optString("src_ip", "")
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

            // 提取因 Android 内核 NAT 转发而将源 IP 改写为 TUN 虚拟网卡地址的连接
            val natConns = ArrayList<ConnStatsRec>()
            for (tunIp in TUN_VIRTUAL_IPS) {
                connsBySrcIp.remove(tunIp)?.let { natConns.addAll(it) }
            }

            // 1. 若当前恰好只有 1 个识别到的下游物理客户端，则全部 NAT 流量必然 100% 属于它：
            //    直接将连接和流量归属到该真实客户端 IP 名下，从源头解决分裂问题。
            if (clientByIp.size == 1 && natConns.isNotEmpty()) {
                val singleClientIp = clientByIp.keys.first()
                val targetList = connsBySrcIp.getOrPut(singleClientIp) { ArrayList() }
                for (c in natConns) {
                    targetList.add(c.copy(srcIp = singleClientIp))
                }
            } else if (natConns.isNotEmpty()) {
                // 2. 若有多个客户端接入，或物理客户端尚未注册完成但已有流量到达：
                //    保留聚合记录，但显示为明确的「热点汇聚流量」，不再显示为令人困惑的未知裸 IP
                connsBySrcIp[HotspotRoutingConfig.SHIZUKU_TUN_IP_V4] = natConns
            }

            val blockedArr = root.optJSONArray("blocked_clients") ?: JSONArray()
            val blockedSet = HashSet<String>()
            for (i in 0 until blockedArr.length()) {
                val b = blockedArr.optString(i, "").trim().lowercase()
                if (b.isNotEmpty()) blockedSet.add(b)
            }

            val allIps = (clientByIp.keys + connsBySrcIp.keys).filter { it.isNotBlank() }.toSet()
            val list = mutableListOf<TetheredDeviceDetail>()
            for (ip in allIps) {
                val clientObj = clientByIp[ip]
                val isTunNat = ip in TUN_VIRTUAL_IPS

                val mac = clientObj?.optString("mac", "").orEmpty()
                val hostname = clientObj?.optString("hostname", "").orEmpty()
                val vendor = clientObj?.optString("vendor", "").orEmpty()
                val isRandomMac = clientObj?.optBoolean("is_random_mac", false) ?: false
                val rawOsGuess = clientObj?.optString("os_guess", "").orEmpty()
                val tetheringType = clientObj?.optInt("type", -1) ?: -1
                val conns = connsBySrcIp[ip] ?: emptyList()
                val up = conns.sumOf { it.up }
                val down = conns.sumOf { it.down }
                val isBlocked = mac.isNotBlank() && mac.lowercase() in blockedSet

                val osGuess = when {
                    rawOsGuess.isNotBlank() -> rawOsGuess
                    isTunNat && clientByIp.size > 1 -> "热点共享汇聚 (多设备 NAT)"
                    isTunNat -> "热点共享客户端 (NAT)"
                    isRandomMac -> "局域网设备 (私有/随机 MAC)"
                    else -> "局域网接入设备"
                }

                val displayHostname = when {
                    hostname.isNotBlank() -> hostname
                    isTunNat && clientByIp.size > 1 -> "热点共享流量池"
                    isTunNat -> "热点共享设备"
                    else -> ""
                }

                list.add(
                    TetheredDeviceDetail(
                        ip = ip,
                        mac = mac,
                        hostname = displayHostname,
                        vendor = vendor,
                        isRandomMac = isRandomMac,
                        osGuess = osGuess,
                        tetheringType = tetheringType,
                        upBytes = up,
                        downBytes = down,
                        conns = conns,
                        isBlocked = isBlocked,
                    )
                )
            }

            // 处理已被黑名单拦截但当前不在线（未连接）的设备，确保仍能在管理列表中展示并支持一键解除
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
