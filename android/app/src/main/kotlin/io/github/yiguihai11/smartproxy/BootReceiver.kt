package io.github.yiguihai11.smartproxy

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.net.VpnService

/**
 * 开机自启 + 升级重注册(§4.3):
 * - BOOT_COMPLETED:系统开机;MY_PACKAGE_REPLACED:本 app 升级后系统重发,
 *   都读开机自启偏好,开启才继续。
 * - VPN 授权在系统里是持久化的:VpnService.prepare()==null 说明授权仍在 → 直接起;
 *   非 null = 授权被收回 → 跳过(无法在后台弹授权框)。
 * - Android 15 确认 specialUse(VPN) 不在 BOOT_COMPLETED 受限 FGS 类型,开机起合法。
 */
class BootReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        val action = intent.action ?: return
        if (action != Intent.ACTION_BOOT_COMPLETED && action != Intent.ACTION_MY_PACKAGE_REPLACED) {
            return
        }
        if (!AppPrefs.bootAutoStart(context)) return
        if (VpnService.prepare(context) == null) {
            SmartProxyVpnService.start(context)
        }
    }
}
