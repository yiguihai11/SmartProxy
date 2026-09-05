package io.github.yiguihai11.smartproxy.shizuku

import java.io.Serializable

data class HotspotRoutingSnapshot(
    val running: Boolean = false,
    val vpnMode: Boolean = false,
    val profileName: String = "",
    val ipv6Enabled: Boolean = false,
    val vpnDnsServers: List<String> = emptyList(),
) : Serializable

internal data class HotspotRoutingLaunchConfig(
    val engineContent: String,
    val profileName: String,
    val dnsServers: List<String>,
    val ipv6Enabled: Boolean,
)

internal data class HotspotRoutingParameters(
    val profileName: String,
    val dnsServers: List<String>,
    val ipv6Enabled: Boolean,
)

internal object HotspotRoutingConfig {
    // Upstream v2rayNG shizuku-tethering-compatible test network addresses.
    const val SHIZUKU_TUN_ADDR_V4 = "192.0.2.2/24"
    const val SHIZUKU_TUN_ADDR_V6 = "2001:db8:9877::1/64"
    const val SHIZUKU_TUN_DNS_HINT_V6 = "fdfe:dcba:9877::53"

    fun parametersFromSnapshot(snapshot: HotspotRoutingSnapshot): HotspotRoutingParameters {
        requireRoutableSnapshot(snapshot)
        return HotspotRoutingParameters(
            profileName = snapshot.profileName,
            dnsServers = snapshot.vpnDnsServers,
            ipv6Enabled = snapshot.ipv6Enabled,
        )
    }

    private fun requireRoutableSnapshot(snapshot: HotspotRoutingSnapshot) {
        require(snapshot.running) { "Start SmartProxy before enabling tethering routing" }
        require(snapshot.vpnMode) { "SmartProxy must be running in VPN mode" }
    }
}
