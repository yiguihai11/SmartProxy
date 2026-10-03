package io.github.yiguihai11.smartproxy

import io.github.yiguihai11.smartproxy.shizuku.HotspotRoutingConfig
import io.github.yiguihai11.smartproxy.shizuku.inferDeviceOs
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

class TetheringDeviceParserTest {

    @Test
    fun singleClientGetsNatTrafficAttributedAndHidesVirtualIp() {
        val statsJson = """
            {
              "clients": [
                {
                  "mac": "da:a1:19:22:33:44",
                  "ip": "192.168.140.204",
                  "hostname": "",
                  "type": 0,
                  "vendor": "",
                  "is_random_mac": true,
                  "os_guess": "局域网设备 (私有/随机 MAC)"
                }
              ],
              "apps": [
                {
                  "uid": 1000,
                  "conns": [
                    {
                      "proto": 6,
                      "host": "example.com",
                      "port": 443,
                      "up": 1024,
                      "down": 4096,
                      "src_ip": "192.0.2.2"
                    }
                  ]
                }
              ]
            }
        """.trimIndent()

        val devices = TetheringDeviceParser.parse(statsJson)
        assertEquals(1, devices.size)

        val dev = devices.first()
        assertEquals("192.168.140.204", dev.ip)
        assertEquals("da:a1:19:22:33:44", dev.mac)
        assertEquals(1024L, dev.upBytes)
        assertEquals(4096L, dev.downBytes)
        assertEquals(1, dev.conns.size)
        assertEquals("192.168.140.204", dev.conns.first().srcIp)
        assertEquals("example.com", dev.conns.first().host)
        assertTrue(devices.none { it.ip == HotspotRoutingConfig.SHIZUKU_TUN_IP_V4 })
    }

    @Test
    fun multipleClientsRetainNatAggregatePool() {
        val statsJson = """
            {
              "clients": [
                {
                  "mac": "da:a1:19:22:33:44",
                  "ip": "192.168.140.204",
                  "hostname": "Phone-A",
                  "type": 0,
                  "vendor": "",
                  "is_random_mac": true,
                  "os_guess": "局域网设备"
                },
                {
                  "mac": "da:a1:19:22:33:55",
                  "ip": "192.168.140.205",
                  "hostname": "Phone-B",
                  "type": 0,
                  "vendor": "",
                  "is_random_mac": true,
                  "os_guess": "局域网设备"
                }
              ],
              "apps": [
                {
                  "uid": 1000,
                  "conns": [
                    {
                      "proto": 6,
                      "host": "api.github.com",
                      "port": 443,
                      "up": 2048,
                      "down": 8192,
                      "src_ip": "192.0.2.2"
                    }
                  ]
                }
              ]
            }
        """.trimIndent()

        val devices = TetheringDeviceParser.parse(statsJson)
        assertEquals(3, devices.size)

        val natDev = devices.firstOrNull { it.ip == HotspotRoutingConfig.SHIZUKU_TUN_IP_V4 }
        org.junit.Assert.assertNotNull(natDev)
        assertEquals(2048L, natDev!!.upBytes)
        assertEquals(8192L, natDev.downBytes)
        assertTrue(natDev.osGuess.contains("NAT"))
    }

    @Test
    fun randomMacInferenceReturnsDescriptiveLabel() {
        assertEquals("局域网设备 (私有/随机 MAC)", inferDeviceOs(null, null, isRandomMac = true))
        assertEquals("未知设备", inferDeviceOs(null, null, isRandomMac = false))
        assertEquals("iOS (iPhone)", inferDeviceOs("iPhone-15", null, isRandomMac = true))
    }

    @Test
    fun blockedClientsFlaggedAndOfflineBlockedDevicesAppended() {
        val statsJson = """
            {
              "clients": [
                {
                  "mac": "12:34:56:78:9a:bc",
                  "ip": "192.168.140.204",
                  "hostname": "Active-Phone",
                  "type": 0,
                  "vendor": "",
                  "is_random_mac": false,
                  "os_guess": "Android"
                },
                {
                  "mac": "aa:bb:cc:dd:ee:01",
                  "ip": "192.168.140.205",
                  "hostname": "Blocked-Phone",
                  "type": 0,
                  "vendor": "",
                  "is_random_mac": false,
                  "os_guess": "Android"
                }
              ],
              "blocked_clients": [
                "aa:bb:cc:dd:ee:01",
                "aa:bb:cc:dd:ee:99"
              ],
              "apps": []
            }
        """.trimIndent()

        val devices = TetheringDeviceParser.parse(statsJson)
        assertEquals(3, devices.size)

        val activeDev = devices.firstOrNull { it.mac == "12:34:56:78:9a:bc" }
        assertNotNull(activeDev)
        assertFalse(activeDev!!.isBlocked)

        val blockedOnlineDev = devices.firstOrNull { it.mac == "aa:bb:cc:dd:ee:01" }
        assertNotNull(blockedOnlineDev)
        assertTrue(blockedOnlineDev!!.isBlocked)
        assertEquals("192.168.140.205", blockedOnlineDev.ip)

        val blockedOfflineDev = devices.firstOrNull { it.mac == "aa:bb:cc:dd:ee:99" }
        assertNotNull(blockedOfflineDev)
        assertTrue(blockedOfflineDev!!.isBlocked)
        assertEquals("", blockedOfflineDev.ip)
    }

    @Test
    fun dualStackIpv4AndIpv6SameClientConsolidatedToOneDevice() {
        val statsJson = """
            {
              "clients": [
                {
                  "mac": "32:bb:2e:bf:ab:70",
                  "ip": "2001:db8:9877:0:1829:c468:ddc:a822",
                  "hostname": "JER-AN20",
                  "type": 0,
                  "vendor": "Huawei",
                  "is_random_mac": false,
                  "os_guess": "Android"
                },
                {
                  "mac": "32:bb:2e:bf:ab:70",
                  "ip": "10.121.0.245",
                  "hostname": "JER-AN20",
                  "type": 0,
                  "vendor": "Huawei",
                  "is_random_mac": false,
                  "os_guess": "Android"
                }
              ],
              "apps": []
            }
        """.trimIndent()

        val devices = TetheringDeviceParser.parse(statsJson)
        assertEquals(1, devices.size)
        val dev = devices.first()
        assertEquals("32:bb:2e:bf:ab:70", dev.mac)
        assertEquals("10.121.0.245", dev.ip) // Prefers IPv4
        assertEquals("JER-AN20", dev.hostname)
    }

    @Test
    fun singleClientGetsNatAndIpv6SlaacPrivacyConnsAggregated() {
        val statsJson = """
            {
              "clients": [
                {
                  "mac": "32:bb:2e:bf:ab:70",
                  "ip": "10.121.0.245",
                  "hostname": "JER-AN20",
                  "type": 0,
                  "vendor": "Huawei",
                  "is_random_mac": true,
                  "os_guess": "Android / HarmonyOS",
                  "assigned_ips": [
                    "10.121.0.245",
                    "2001:db8:9877:0:1829:c468:ddc:a822"
                  ]
                }
              ],
              "apps": [
                {
                  "uid": 1000,
                  "conns": [
                    {
                      "proto": 6,
                      "host": "example.com",
                      "port": 443,
                      "up": 100,
                      "down": 200,
                      "src_ip": "192.0.2.2"
                    },
                    {
                      "proto": 6,
                      "host": "connectivitycheck.platform.hicloud.com",
                      "port": 443,
                      "up": 300,
                      "down": 400,
                      "src_ip": "2001:db8:9877:0:1a4f:99b:867b:825e"
                    },
                    {
                      "proto": 6,
                      "host": "connectivitycheck.platform.hicloud.com",
                      "port": 80,
                      "up": 500,
                      "down": 600,
                      "src_ip": "2001:db8:9877:0:2d34:30c7:e430:da6a"
                    }
                  ]
                }
              ]
            }
        """.trimIndent()

        val devices = TetheringDeviceParser.parse(statsJson)
        // Must be exactly 1 device, never splitting into 3 phantom devices
        assertEquals(1, devices.size)

        val dev = devices.first()
        assertEquals("32:bb:2e:bf:ab:70", dev.mac)
        assertEquals("10.121.0.245", dev.ip)
        assertEquals("JER-AN20", dev.hostname)
        assertEquals(900L, dev.upBytes)
        assertEquals(1200L, dev.downBytes)
        assertEquals(3, dev.conns.size)
        assertTrue(dev.extraIps.contains("2001:db8:9877:0:1829:c468:ddc:a822"))
        assertTrue(dev.extraIps.contains("2001:db8:9877:0:1a4f:99b:867b:825e"))
        assertTrue(dev.extraIps.contains("2001:db8:9877:0:2d34:30c7:e430:da6a"))
    }

    @Test
    fun multipleClientsWithAssignedIpsAndSharedPool() {
        val statsJson = """
            {
              "clients": [
                {
                  "mac": "da:a1:19:22:33:44",
                  "ip": "192.168.140.204",
                  "hostname": "Phone-A",
                  "type": 0,
                  "vendor": "",
                  "is_random_mac": true,
                  "os_guess": "局域网设备",
                  "assigned_ips": [
                    "192.168.140.204",
                    "2001:db8:9877:0:aaaa:bbbb:cccc:dddd"
                  ]
                },
                {
                  "mac": "da:a1:19:22:33:55",
                  "ip": "192.168.140.205",
                  "hostname": "Phone-B",
                  "type": 0,
                  "vendor": "",
                  "is_random_mac": true,
                  "os_guess": "局域网设备",
                  "assigned_ips": [
                    "192.168.140.205",
                    "2001:db8:9877:0:1111:2222:3333:4444"
                  ]
                }
              ],
              "apps": [
                {
                  "uid": 1000,
                  "conns": [
                    {
                      "proto": 6,
                      "host": "a.example.com",
                      "port": 443,
                      "up": 100,
                      "down": 200,
                      "src_ip": "2001:db8:9877:0:aaaa:bbbb:cccc:dddd"
                    },
                    {
                      "proto": 6,
                      "host": "b.example.com",
                      "port": 443,
                      "up": 300,
                      "down": 400,
                      "src_ip": "2001:db8:9877:0:1111:2222:3333:4444"
                    },
                    {
                      "proto": 6,
                      "host": "pool.example.com",
                      "port": 443,
                      "up": 500,
                      "down": 600,
                      "src_ip": "192.0.2.2"
                    }
                  ]
                }
              ]
            }
        """.trimIndent()

        val devices = TetheringDeviceParser.parse(statsJson)
        assertEquals(3, devices.size)

        val devA = devices.firstOrNull { it.mac == "da:a1:19:22:33:44" }
        assertNotNull(devA)
        assertEquals(100L, devA!!.upBytes)
        assertEquals(200L, devA.downBytes)
        assertEquals(1, devA.conns.size)

        val devB = devices.firstOrNull { it.mac == "da:a1:19:22:33:55" }
        assertNotNull(devB)
        assertEquals(300L, devB!!.upBytes)
        assertEquals(400L, devB.downBytes)
        assertEquals(1, devB.conns.size)

        val pool = devices.firstOrNull { it.ip == HotspotRoutingConfig.SHIZUKU_TUN_IP_V4 }
        assertNotNull(pool)
        assertEquals(500L, pool!!.upBytes)
        assertEquals(600L, pool.downBytes)
    }
}
