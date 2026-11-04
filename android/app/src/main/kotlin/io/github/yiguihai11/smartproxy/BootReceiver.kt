package io.github.yiguihai11.smartproxy

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.net.VpnService

/**
 * 开机自启 + 升级重注册(§4.3):
 * - BOOT_COMPLETED: 系统开机，需用户开启「开机自启」偏好且关机前 VPN 为开启意图 (vpnDesired=true)。
 * - MY_PACKAGE_REPLACED: 本 app 覆盖安装/升级后系统广播。升级属于运行时包替换，
 *   只要升级前 VPN 处于运行意图 (vpnDesired=true)，即自动恢复连接，无需受制于开机自启开关。
 * - VPN 模式: 授权在系统里持久化，VpnService.prepare()==null 说明授权仍在 → 直接起；
 *   非 null = 授权被收回 → 跳过(无法在后台弹授权框)。
 * - 仅代理(SOCKS5)模式(§8)不建 VpnService，无需 VPN 授权，与 MainActivity 的
 *   启动规则一致，不做 prepare() 检查(否则纯 SOCKS5 用户从未授权
 *   或已撤销时，开机自启会被误杀)。
 * - Android 15 确认 specialUse(VPN) 不在 BOOT_COMPLETED 受限 FGS 类型，开机起合法。
 */
class BootReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        val action = intent.action ?: return
        if (action != Intent.ACTION_BOOT_COMPLETED &&
            action != Intent.ACTION_MY_PACKAGE_REPLACED &&
            action != "android.intent.action.QUICKBOOT_POWERON" &&
            action != "com.htc.intent.action.QUICKBOOT_POWERON"
        ) {
            return
        }
        val isBoot = action != Intent.ACTION_MY_PACKAGE_REPLACED
        if (isBoot && !AppPrefs.bootAutoStart(context)) {
            android.util.Log.i("SmartProxyBoot", "BootReceiver: bootAutoStart disabled, skipping boot start.")
            return
        }
        if (!AppPrefs.vpnDesired(context)) {
            android.util.Log.i("SmartProxyBoot", "BootReceiver: VPN was manually stopped before reboot/update, skipping auto-start.")
            return
        }
        val needsVpnAuth = AppPrefs.serviceMode(context) == AppPrefs.MODE_VPN
        if (needsVpnAuth && VpnService.prepare(context) != null) {
            android.util.Log.w("SmartProxyBoot", "BootReceiver: VPN authorization revoked by system, skipping auto-start.")
            return
        }

        // 开机物理网络就绪检查:手机刚开机瞬间 Wi-Fi 可能正在扫描/DHCP，蜂窝数据可能正在分配 IP。
        // 若当前物理网络暂无可用 IP，转入 NetworkRecoveryManager 等待网络连接就绪后自动拉起，避免 VpnService 裸起失败后直接退出。
        val netStatus = NetworkUtils.checkPhysicalNetworkAddresses(context)
        if (!netStatus.isAnyAvailable) {
            android.util.Log.i("SmartProxyBoot", "BootReceiver: Physical network not available yet on boot. Starting NetworkRecoveryManager...")
            NetworkRecoveryManager.startRecovery(context.applicationContext)
            return
        }

        SmartProxyVpnService.start(context)
    }
}
