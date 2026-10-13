package io.github.yiguihai11.smartproxy

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * 验证开机自启与网络断开恢复决策逻辑。
 */
class BootAndRecoveryLogicTest {

    private fun shouldAutoStartOnBoot(
        bootAutoStartPref: Boolean,
        vpnDesired: Boolean,
        isVpnAuthValid: Boolean
    ): Boolean {
        if (!bootAutoStartPref) return false
        if (!vpnDesired) return false
        if (!isVpnAuthValid) return false
        return true
    }

    private fun shouldTriggerNetworkRecovery(
        userInitiatedStop: Boolean,
        vpnDesired: Boolean
    ): Boolean {
        val passive = !userInitiatedStop
        return passive && vpnDesired
    }

    private fun canRestoreVpn(
        vpnDesired: Boolean,
        isRunning: Boolean,
        isVpnAuthValid: Boolean,
        hasInternet: Boolean
    ): Boolean {
        if (!vpnDesired) return false
        if (isRunning) return false
        if (!isVpnAuthValid) return false
        if (!hasInternet) return false
        return true
    }

    @Test
    fun bootAutoStart_skippedWhenUserManuallyStoppedBeforeReboot() {
        // 用户开启了开机自启，但在关机/重启前手动关闭了 VPN -> 开机不应该自启
        val start = shouldAutoStartOnBoot(
            bootAutoStartPref = true,
            vpnDesired = false,
            isVpnAuthValid = true
        )
        assertFalse("重启前已手动关闭 VPN，开机不应自启", start)
    }

    @Test
    fun bootAutoStart_succeedsWhenVpnWasActiveBeforeReboot() {
        // 用户开启了开机自启，且重启前 VPN 处于运行中（未手动关闭） -> 开机自启
        val start = shouldAutoStartOnBoot(
            bootAutoStartPref = true,
            vpnDesired = true,
            isVpnAuthValid = true
        )
        assertTrue("重启前 VPN 处于运行状态，开机应自启", start)
    }

    @Test
    fun bootAutoStart_skippedWhenPrefIsDisabled() {
        // 开机自启开关为关，即使重启前 VPN 在运行也不自启
        val start = shouldAutoStartOnBoot(
            bootAutoStartPref = false,
            vpnDesired = true,
            isVpnAuthValid = true
        )
        assertFalse("开机自启开关关闭时，不应自启", start)
    }

    @Test
    fun bootAutoStart_skippedWhenAuthRevoked() {
        // 系统 VPN 授权失效时不自启
        val start = shouldAutoStartOnBoot(
            bootAutoStartPref = true,
            vpnDesired = true,
            isVpnAuthValid = false
        )
        assertFalse("VPN 授权失效时，不应自启", start)
    }

    @Test
    fun networkRecovery_triggeredOnPassiveDisconnectWhenVpnDesired() {
        // 因无网络等原因系统被动断开（非用户主动停止），且期望运行 -> 应触发恢复
        val trigger = shouldTriggerNetworkRecovery(
            userInitiatedStop = false,
            vpnDesired = true
        )
        assertTrue("系统被动断连且期望运行，应触发恢复流程", trigger)
    }

    @Test
    fun networkRecovery_notTriggeredOnUserInitiatedStop() {
        // 用户主动停止 -> 绝不触发恢复
        val trigger = shouldTriggerNetworkRecovery(
            userInitiatedStop = true,
            vpnDesired = false
        )
        assertFalse("用户主动停止，不得触发网络恢复", trigger)
    }

    @Test
    fun attemptRestore_requiresInternetAndValidState() {
        // 无网络时推迟
        assertFalse(canRestoreVpn(vpnDesired = true, isRunning = false, isVpnAuthValid = true, hasInternet = false))
        // 用户已取消时拒绝
        assertFalse(canRestoreVpn(vpnDesired = false, isRunning = false, isVpnAuthValid = true, hasInternet = true))
        // 已经在运行时拒绝
        assertFalse(canRestoreVpn(vpnDesired = true, isRunning = true, isVpnAuthValid = true, hasInternet = true))
        // 条件满足且有网络时拉起
        assertTrue(canRestoreVpn(vpnDesired = true, isRunning = false, isVpnAuthValid = true, hasInternet = true))
    }
}
