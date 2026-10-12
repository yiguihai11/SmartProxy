package io.github.yiguihai11.smartproxy

import io.github.yiguihai11.smartproxy.shizuku.HotspotRoutingConfig
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

class TetheringDeviceParserTest {

    @Before
    fun setUp() {
        TetheringDeviceParser.reset()
    }

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
                  "is_random_mac": true
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
    fun multipleClientsExcludeVirtualNatPoolCard() {
        val statsJson = """
            {
              "clients": [
                {
                  "mac": "da:a1:19:22:33:44",
                  "ip": "192.168.140.204",
                  "hostname": "Phone-A",
                  "type": 0,
                  "is_random_mac": true
                },
                {
                  "mac": "da:a1:19:22:33:55",
                  "ip": "192.168.140.205",
                  "hostname": "Phone-B",
                  "type": 0,
                  "is_random_mac": true
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
        assertEquals(2, devices.size)
        assertTrue(devices.none { it.ip == HotspotRoutingConfig.SHIZUKU_TUN_IP_V4 })
        assertTrue(devices.any { it.hostname == "Phone-A" })
        assertTrue(devices.any { it.hostname == "Phone-B" })
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
                  "is_random_mac": false
                },
                {
                  "mac": "aa:bb:cc:dd:ee:01",
                  "ip": "192.168.140.205",
                  "hostname": "Blocked-Phone",
                  "type": 0,
                  "is_random_mac": false
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
                  "is_random_mac": false
                },
                {
                  "mac": "32:bb:2e:bf:ab:70",
                  "ip": "10.121.0.245",
                  "hostname": "JER-AN20",
                  "type": 0,
                  "is_random_mac": false
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
                  "is_random_mac": true,
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
                  "is_random_mac": true,
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
                  "is_random_mac": true,
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

    @Test
    fun rateCalculationAndMonotonicCumulativeProtection() {
        val json1 = """
            {
              "clients": [
                {
                  "mac": "02:00:00:11:22:33",
                  "ip": "192.168.43.100",
                  "hostname": "TestDevice",
                  "type": 0
                }
              ],
              "client_traffic": [
                {
                  "ip": "192.168.43.100",
                  "up": 10000,
                  "down": 50000,
                  "active_conns": 2
                }
              ],
              "apps": []
            }
        """.trimIndent()

        val dev1 = TetheringDeviceParser.parse(json1).first()
        assertEquals(10000L, dev1.upBytes)
        assertEquals(50000L, dev1.downBytes)
        // 首个采样点速率初始化为 0
        assertEquals(0L, dev1.upBps)
        assertEquals(0L, dev1.downBps)

        // 模拟 150 毫秒后产生更多流量
        Thread.sleep(150)
        val json2 = """
            {
              "clients": [
                {
                  "mac": "02:00:00:11:22:33",
                  "ip": "192.168.43.100",
                  "hostname": "TestDevice",
                  "type": 0
                }
              ],
              "client_traffic": [
                {
                  "ip": "192.168.43.100",
                  "up": 20000,
                  "down": 100000,
                  "active_conns": 2
                }
              ],
              "apps": []
            }
        """.trimIndent()

        val dev2 = TetheringDeviceParser.parse(json2).first()
        assertEquals(20000L, dev2.upBytes)
        assertEquals(100000L, dev2.downBytes)
        assertTrue("upBps 应大于 0", dev2.upBps > 0)
        assertTrue("downBps 应大于 0", dev2.downBps > 0)

        // 连接关闭，上报 0 字节时，单调保护确保累计字节不归零，实时速率归零
        Thread.sleep(150)
        val json3 = """
            {
              "clients": [
                {
                  "mac": "02:00:00:11:22:33",
                  "ip": "192.168.43.100",
                  "hostname": "TestDevice",
                  "type": 0
                }
              ],
              "client_traffic": [
                {
                  "ip": "192.168.43.100",
                  "up": 0,
                  "down": 0,
                  "active_conns": 0
                }
              ],
              "apps": []
            }
        """.trimIndent()

        val dev3 = TetheringDeviceParser.parse(json3).first()
        assertEquals("连接关闭后累计上传不得清零", 20000L, dev3.upBytes)
        assertEquals("连接关闭后累计下载不得清零", 100000L, dev3.downBytes)
        assertEquals(0L, dev3.upBps)
        assertEquals(0L, dev3.downBps)
    }

    @Test
    fun parseToJsonOutputsCompleteFieldsForAdminBridge() {
        val json = """
            {
              "clients": [
                {
                  "mac": "d8:a4:91:21:a3:c7",
                  "ip": "10.152.206.152",
                  "hostname": "JER-AN20",
                  "type": 0,
                  "is_random_mac": false,
                  "assigned_ips": [
                    "10.152.206.152",
                    "2001:db8:9877:0:c538:a56a:9a5d:f831",
                    "fe80::1785:5425:3d14:4b4"
                  ]
                }
              ],
              "client_traffic": [
                {
                  "ip": "10.152.206.152",
                  "up": 612966,
                  "down": 3879731,
                  "active_conns": 13
                }
              ],
              "apps": []
            }
        """.trimIndent()

        val jsonStr = TetheringDeviceParser.parseToJson(json)
        val arr = org.json.JSONArray(jsonStr)
        assertEquals(1, arr.length())
        val obj = arr.getJSONObject(0)
        assertEquals("10.152.206.152", obj.getString("ip"))
        assertEquals("d8:a4:91:21:a3:c7", obj.getString("mac"))
        assertEquals("JER-AN20", obj.getString("hostname"))
        assertEquals(612966L, obj.getLong("up_bytes"))
        assertEquals(3879731L, obj.getLong("down_bytes"))
        val extraIps = obj.getJSONArray("extra_ips")
        assertEquals(2, extraIps.length())
        assertEquals("2001:db8:9877:0:c538:a56a:9a5d:f831", extraIps.getString(0))
        assertEquals("fe80::1785:5425:3d14:4b4", extraIps.getString(1))
    }
}

