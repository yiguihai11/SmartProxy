package io.github.yiguihai11.smartproxy.shizuku

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class TetheringPlatformCompatTest {

    @Test
    fun usesPublicTetheringApiStartingAtApi36() {
        assertEquals(false, isPublicTetheringApiLevel(33))
        assertEquals(false, isPublicTetheringApiLevel(35))
        assertEquals(true, isPublicTetheringApiLevel(36))
        assertEquals(true, isPublicTetheringApiLevel(37))
    }

    @Test
    fun buildsOnlyValidTetheringTypeBits() {
        assertEquals(1, tetheringTypeBit(0))
        assertEquals(1 shl 15, tetheringTypeBit(15))
        assertEquals(0, tetheringTypeBit(-1))
        assertEquals(0, tetheringTypeBit(31))
    }

    @Test
    fun acceptsOnlyTheOwnedUpstreamInterface() {
        assertEquals(true, TetheringPlatformCompat.isProtectedUpstream("testtun17", "testtun17"))
        assertEquals(true, TetheringPlatformCompat.isProtectedUpstream(" testtun17 ", "testtun17"))
        assertEquals(
            false,
            TetheringPlatformCompat.isProtectedUpstream("testtun17, testtun17", "testtun17"),
        )
        assertEquals(
            false,
            TetheringPlatformCompat.isProtectedUpstream("testtun17, testtun17, testtun17", "testtun17"),
        )
        assertEquals(false, TetheringPlatformCompat.isProtectedUpstream("", "testtun17"))
        assertEquals(false, TetheringPlatformCompat.isProtectedUpstream("eth0", "testtun17"))
        assertEquals(
            false,
            TetheringPlatformCompat.isProtectedUpstream("testtun17, eth0", "testtun17"),
        )
    }

    @Test
    fun detectsLocallyAdministeredRandomMac() {
        assertEquals(true, isLocallyAdministeredMac("02:00:00:00:00:00"))
        assertEquals(true, isLocallyAdministeredMac("da:a1:19:22:33:44"))
        assertEquals(true, isLocallyAdministeredMac("f6:44:88:aa:bb:cc"))
        assertEquals(false, isLocallyAdministeredMac("00:1a:11:22:33:44"))
        assertEquals(false, isLocallyAdministeredMac("28:cf:e9:11:22:33"))
        assertEquals(false, isLocallyAdministeredMac(""))
    }

    @Test
    fun mergesSystemAndArpClientsAndPrunesStaleClients() {
        val sysClients = listOf(
            createTetheredClientInfo(mac = "28:cf:e9:dd:ee:01", ip = "192.168.43.10", hostname = "iPhone", tetheringType = 0)
        )
        // arpClients contains the active client plus a stale/disconnected client (e.g. old randomized MAC)
        val arpClients = listOf(
            createTetheredClientInfo(mac = "28:cf:e9:dd:ee:01", ip = "192.168.43.10", hostname = null, tetheringType = -1),
            createTetheredClientInfo(mac = "da:a1:19:dd:ee:02", ip = "192.168.43.20", hostname = null, tetheringType = -1)
        )

        // 1. 当系统已有权威在线列表时，内核 ARP 残留的旧离线设备(da:a1:19:dd:ee:02)坚决丢弃，不被复活
        val merged = mergeTetheredClients(sysClients, arpClients, clientsReceived = true)
        assertEquals(1, merged.size)
        val first = merged.first()
        assertEquals("28:cf:e9:dd:ee:01", first.mac)
        assertEquals("192.168.43.10", first.ip)
        assertEquals("iPhone", first.hostname)
        assertEquals(false, first.isRandomMac)

        // 2. 当系统通知无任何在线设备时 (clientsReceived=true && sysClients.isEmpty)，ARP 缓存残留设备 100% 丢弃
        val allDisconnected = mergeTetheredClients(emptyList(), arpClients, clientsReceived = true)
        assertEquals(0, allDisconnected.size)

        // 3. 降级容灾模式 (未收到系统客户端回调 clientsReceived=false)，允许回退读取 ARP 列表
        val fallback = mergeTetheredClients(emptyList(), arpClients, clientsReceived = false)
        assertEquals(2, fallback.size)
        assertEquals(true, fallback.any { it.mac == "da:a1:19:dd:ee:02" })
    }

    @Test
    fun parseArpLinesFiltersUpstreamGatewayAndMatchesDownstream() {
        val arpContent = """
            IP address       HW type     Flags       HW address            Mask     Device
            192.168.0.1      0x1         0x2         00:11:22:33:44:55     *        wlan0
            192.168.43.15    0x1         0x2         aa:bb:cc:dd:ee:ff     *        ap0
            192.168.43.16    0x1         0x2         11:22:33:44:55:66     *        rndis0
        """.trimIndent()

        // 1. 下游为空（未开启热点/共享）时，不解析任何条目
        assertEquals(emptyList<TetheredClientInfo>(), parseArpLines(arpContent.lineSequence(), emptySet(), setOf("wlan0")))

        // 2. 下游激活 ap0，上游为 wlan0：只保留 ap0 上的设备，192.168.0.1 (wlan0 上游网关) 坚决被过滤
        val parsed = parseArpLines(arpContent.lineSequence(), setOf("ap0"), setOf("wlan0"))
        assertEquals(1, parsed.size)
        assertEquals("192.168.43.15", parsed[0].ip)
        assertEquals("aa:bb:cc:dd:ee:ff", parsed[0].mac)

        // 3. 同时开启 USB 共享 rndis0
        val dual = parseArpLines(arpContent.lineSequence(), setOf("ap0", "rndis0"), setOf("wlan0"))
        assertEquals(2, dual.size)
        assertEquals(true, dual.any { it.ip == "192.168.43.15" })
        assertEquals(true, dual.any { it.ip == "192.168.43.16" })
        assertEquals(false, dual.any { it.ip == "192.168.0.1" })
    }

    @Test
    fun parseNeighborLinesParsesBothIpv4AndIpv6WithDownstreamFiltering() {
        val neighContent = """
            10.121.0.245 dev wlan2 lladdr 32:bb:2e:bf:ab:70 REACHABLE
            2001:db8:9877:0:1829:c468:ddc:a822 dev wlan2 lladdr 32:bb:2e:bf:ab:70 STALE
            2001:db8:9877:0:1a4f:99b:867b:825e dev wlan2 lladdr 32:bb:2e:bf:ab:70 REACHABLE
            192.168.1.1 dev wlan0 lladdr 00:11:22:33:44:55 REACHABLE
            10.121.0.99 dev wlan2 lladdr 00:00:00:00:00:00 FAILED
        """.trimIndent()

        val parsed = parseNeighborLines(neighContent.lineSequence(), setOf("wlan2"), setOf("wlan0"))
        assertEquals(3, parsed.size)
        assertTrue(parsed.all { it.mac == "32:bb:2e:bf:ab:70" })
        assertEquals("10.121.0.245", parsed[0].ip)
        assertEquals("2001:db8:9877:0:1829:c468:ddc:a822", parsed[1].ip)
        assertEquals("2001:db8:9877:0:1a4f:99b:867b:825e", parsed[2].ip)

        // Merging them by MAC aggregates all assigned IPs under the same client
        val merged = mergeTetheredClients(emptyList(), parsed)
        assertEquals(1, merged.size)
        val client = merged.first()
        assertEquals("32:bb:2e:bf:ab:70", client.mac)
        assertEquals("10.121.0.245", client.ip) // Prefers IPv4 as primary IP
        assertEquals(3, client.assignedIps.size)
        assertTrue(client.assignedIps.contains("10.121.0.245"))
        assertTrue(client.assignedIps.contains("2001:db8:9877:0:1829:c468:ddc:a822"))
        assertTrue(client.assignedIps.contains("2001:db8:9877:0:1a4f:99b:867b:825e"))
    }
}
