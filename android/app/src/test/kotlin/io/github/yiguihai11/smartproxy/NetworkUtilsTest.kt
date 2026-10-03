package io.github.yiguihai11.smartproxy

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** 覆盖底层链路筛选规则:哪些网络算「能承载代理流量的物理网卡」。 */
class NetworkUtilsTest {

    private fun underlay(
        isVpn: Boolean = false,
        isNotVpn: Boolean = true,
        isIms: Boolean = false,
        hasInternet: Boolean = false,
        isCellular: Boolean = false,
    ) = UnderlayCapabilities(isVpn, isNotVpn, isIms, hasInternet, isCellular)

    @Test
    fun vpnItselfNeverCountsAsUnderlay() {
        val vpn = underlay(isVpn = true, hasInternet = true)
        assertFalse(vpn.isDataBearingUnderlay(requireInternet = true))
        assertFalse(vpn.isDataBearingUnderlay(requireInternet = false))
    }

    @Test
    fun internetCapableWifiAndCellularCountInBothPasses() {
        val wifi = underlay(hasInternet = true)
        val cellular = underlay(hasInternet = true, isCellular = true)
        assertTrue(wifi.isDataBearingUnderlay(requireInternet = true))
        assertTrue(wifi.isDataBearingUnderlay(requireInternet = false))
        assertTrue(cellular.isDataBearingUnderlay(requireInternet = true))
        assertTrue(cellular.isDataBearingUnderlay(requireInternet = false))
    }

    @Test
    fun imsPdnIsRejectedEvenThoughItIsNotVpn() {
        // 关掉移动数据后常驻的 VoLTE/IMS PDN:非 VPN、带全局 IPv6,但没有 INTERNET。
        val ims = underlay(isIms = true, hasInternet = false, isCellular = true)
        assertFalse(ims.isDataBearingUnderlay(requireInternet = true))
        assertFalse(ims.isDataBearingUnderlay(requireInternet = false))
    }

    @Test
    fun cellularWithoutInternetIsRejectedEvenWithoutImsBits() {
        // 部分机型不发 IMS/MMTEL 能力位,靠「蜂窝 + 无 INTERNET」兜底判定。
        val bareCellular = underlay(hasInternet = false, isCellular = true)
        assertFalse(bareCellular.isDataBearingUnderlay(requireInternet = false))
    }

    @Test
    fun offlineLanWifiStillCountsInTheFallbackPassOnly() {
        // 离线局域网(没有外网的 Wi-Fi)只在兜底扫描里算数。
        val offlineWifi = underlay(hasInternet = false, isCellular = false)
        assertFalse(offlineWifi.isDataBearingUnderlay(requireInternet = true))
        assertTrue(offlineWifi.isDataBearingUnderlay(requireInternet = false))
    }

    @Test
    fun missingNotVpnCapabilityIsRejected() {
        val restricted = underlay(isNotVpn = false, hasInternet = true)
        assertFalse(restricted.isDataBearingUnderlay(requireInternet = true))
    }
}
