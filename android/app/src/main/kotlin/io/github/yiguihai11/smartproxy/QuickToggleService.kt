package io.github.yiguihai11.smartproxy

import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch

/**
 * 控制中心磁贴(§Quick Toggle):下拉快捷开关,不进 App 直接启停。
 *
 * - 状态读 SmartProxyVpnService.isRunning(§4.5 唯一状态源)。磁贴只在快捷面板展开时
 *   被系统绑定(onStartListening),收起即 onStopListening,期间 collect 状态流更新,
 *   不做后台常驻轮询。
 * - 点击:在跑 → stop;没跑且授权在(VPN 模式 prepare()==null,或 SOCKS5 模式无需授权)
 *   → 直接 start。首次/授权失效无法在后台弹同意框,收起面板并打开 MainActivity,
 *   带 EXTRA_START_VPN 让它接着走系统授权弹窗,授权回调里自动起服务。
 * - 从磁贴直接起 FGS:点击是显式用户动作,QS 面板展开期间本进程在前台白名单内,
 *   与 BootReceiver 的后台自启不同,specialUse FGS 合法启动(对齐 v2rayNG QSTileService)。
 */
class QuickToggleService : TileService() {

    companion object {
        /** 磁贴未授权跳转:MainActivity 收到后自动走一次启停(触发 VPN 授权框)。 */
        const val EXTRA_START_VPN = "quick_toggle_start_vpn"
    }

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
    private var stateJob: Job? = null

    override fun onStartListening() {
        super.onStartListening()
        stateJob?.cancel()
        stateJob = scope.launch {
            SmartProxyVpnService.isRunning.collect { renderTile(it) }
        }
    }

    override fun onStopListening() {
        stateJob?.cancel()
        stateJob = null
        super.onStopListening()
    }

    private fun renderTile(running: Boolean) {
        val tile = qsTile ?: return
        tile.state = if (running) Tile.STATE_ACTIVE else Tile.STATE_INACTIVE
        // subtitle API 29+;磁贴标签/图标由 manifest 固定为 app_name/白盾牌
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            tile.subtitle = getString(
                if (running) R.string.tile_connected else R.string.tile_disconnected
            )
        }
        tile.updateTile()
    }

    override fun onClick() {
        super.onClick()
        if (SmartProxyVpnService.isRunning.value) {
            SmartProxyVpnService.stop(applicationContext)
            return
        }
        val needConsent = AppPrefs.serviceMode(this) == AppPrefs.MODE_VPN &&
            VpnService.prepare(this) != null
        if (!needConsent) {
            SmartProxyVpnService.start(applicationContext)
            return
        }
        // 必须前台拿授权:收起快捷面板并打开 App,由 MainActivity 接着弹系统授权框
        val intent = Intent(this, MainActivity::class.java)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP)
            .putExtra(EXTRA_START_VPN, true)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            // API 30+:startActivityAndCollapse 只收 PendingIntent
            val pi = PendingIntent.getActivity(
                this, 0, intent,
                PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
            )
            startActivityAndCollapse(pi)
        } else {
            @Suppress("DEPRECATION")
            startActivityAndCollapse(intent)
        }
    }

    override fun onDestroy() {
        scope.cancel()
        super.onDestroy()
    }
}
