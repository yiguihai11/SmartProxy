package io.github.yiguihai11.smartproxy

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.content.pm.PackageManager
import android.net.Uri
import android.os.IBinder
import android.widget.Toast
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.outlined.Refresh
import androidx.compose.material.icons.outlined.Router
import androidx.compose.material.icons.outlined.Security
import androidx.compose.material.icons.outlined.Usb
import androidx.compose.material.icons.outlined.WifiTethering
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.scale
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import io.github.yiguihai11.smartproxy.shizuku.IShizukuTetheringService
import io.github.yiguihai11.smartproxy.shizuku.ITetheringStatusListener
import io.github.yiguihai11.smartproxy.shizuku.ShizukuTetheringService
import io.github.yiguihai11.smartproxy.shizuku.TetheringCoreSync
import io.github.yiguihai11.smartproxy.shizuku.TetheringStatusSnapshot
import io.github.yiguihai11.smartproxy.shizuku.tetheringTypeBit
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import rikka.shizuku.Shizuku
import rikka.shizuku.ShizukuProvider
import java.util.UUID

// Shizuku 官网(简体中文)下载页,未安装 / 版本过旧时由「打开官网下载」按钮引导。
const val ShizukuDownloadUrl = "https://shizuku.rikka.app/zh-hans/"

enum class ShizukuStatus(
    val statusRes: Int,
    val detailsRes: Int?,
) {
    CHECKING(R.string.shizuku_status_checking, null),
    NOT_INSTALLED(R.string.shizuku_status_not_installed, R.string.shizuku_status_open_manager),
    NOT_RUNNING(R.string.shizuku_status_not_running, R.string.shizuku_status_open_manager),
    UNSUPPORTED(R.string.shizuku_status_unsupported, R.string.shizuku_status_update_required),
    PERMISSION_REQUIRED(
        R.string.shizuku_status_permission_required,
        R.string.shizuku_status_permission_hint,
    ),
    PERMISSION_DENIED(
        R.string.shizuku_status_permission_denied,
        R.string.shizuku_status_permission_hint,
    ),
    READY(R.string.shizuku_status_ready, null);

    val canRequestPermission: Boolean
        get() = this == PERMISSION_REQUIRED
}

enum class TetheringOperation {
    NONE,
    CONNECTING,
    CHECKING,
    STARTING_ROUTING,
    STOPPING_ROUTING,
    STARTING_HOTSPOT,
    STOPPING_HOTSPOT;

    val isToggleInProgress: Boolean
        get() = this == STARTING_ROUTING || this == STOPPING_ROUTING ||
            this == STARTING_HOTSPOT || this == STOPPING_HOTSPOT
}

data class TetheringUiState(
    val shizukuStatus: ShizukuStatus = ShizukuStatus.CHECKING,
    val operation: TetheringOperation = TetheringOperation.NONE,
    val routingState: Int = ShizukuTetheringService.ROUTING_STATE_DISABLED,
    val routingDetail: String = "",
    val activeTetheringTypes: Int = ShizukuTetheringService.TETHERING_TYPES_UNKNOWN,
    val ipv6TetheringTypes: Int = ShizukuTetheringService.TETHERING_TYPES_UNKNOWN,
    val ipv6Enabled: Boolean = false,
    val coreRunning: Boolean = false,
    // 与 Shizuku UserService 的 binder 会话在否。断开把 shell 状态全清零但保留 coreRunning:
    // 主 core 是 app 进程自己的,跟 Shizuku binder 生死无关(规格见 TetheringUiStateTest)。
    val serviceConnected: Boolean = false,
    // 服务端 UserService 里存在活着的 routingSession(routingSession != null)。与 routingState 是
    // 两回事:引擎崩溃会把 routingState 置 ERROR 但会话还在(fail-closed 仍能关),所以「会话开」只
    // 看 hasRoutingSession,routingState 只决定文案与可操作性。
    val hasRoutingSession: Boolean = false,
) {
    val routingActive: Boolean
        get() = routingState == ShizukuTetheringService.ROUTING_STATE_ACTIVE
    val routingSessionEnabled: Boolean
        get() = hasRoutingSession
    val hotspotEnabled: Boolean
        get() = activeTetheringTypes >= 0 &&
            activeTetheringTypes and tetheringTypeBit(ShizukuTetheringService.TETHERING_TYPE_WIFI) != 0
    val usbEnabled: Boolean
        get() = activeTetheringTypes >= 0 &&
            activeTetheringTypes and tetheringTypeBit(ShizukuTetheringService.TETHERING_TYPE_USB) != 0
    val tetheringStateKnown: Boolean
        get() = activeTetheringTypes >= 0
}

enum class TetheringIpMode(val labelRes: Int) {
    IPV4_ONLY(R.string.shizuku_tethering_ip_mode_ipv4),
    DUAL_STACK(R.string.shizuku_tethering_ip_mode_dual_stack),
    UNKNOWN(R.string.shizuku_tethering_ip_mode_unknown),
}

fun TetheringUiState.ipMode(type: Int): TetheringIpMode? {
    val bit = tetheringTypeBit(type)
    if (!ipv6Enabled || activeTetheringTypes < 0 || activeTetheringTypes and bit == 0) return null
    if (ipv6TetheringTypes < 0) return TetheringIpMode.UNKNOWN
    return if (ipv6TetheringTypes and bit != 0) {
        TetheringIpMode.DUAL_STACK
    } else {
        TetheringIpMode.IPV4_ONLY
    }
}

/** 连接状态翻转:断开(假)清 UserService 侧 shell 状态;连接(真)只置位、保留现有状态。 */
fun TetheringUiState.withServiceConnection(connected: Boolean): TetheringUiState {
    return if (connected) {
        copy(serviceConnected = true)
    } else {
        copy(
            serviceConnected = false,
            operation = TetheringOperation.NONE,
            routingState = ShizukuTetheringService.ROUTING_STATE_DISABLED,
            routingDetail = "",
            activeTetheringTypes = ShizukuTetheringService.TETHERING_TYPES_UNKNOWN,
            ipv6TetheringTypes = ShizukuTetheringService.TETHERING_TYPES_UNKNOWN,
            hasRoutingSession = false,
        )
    }
}

/** 全量状态快照:替换 shell 状态并清任何在途操作。用于(重)连接后的一次性加载。 */
fun TetheringUiState.withTetheringStatus(
    status: TetheringStatusSnapshot,
    ipv6Enabled: Boolean,
): TetheringUiState = copy(
    operation = TetheringOperation.NONE,
    routingState = status.routingState,
    routingDetail = status.routingDetail,
    activeTetheringTypes = status.activeTetheringTypes,
    ipv6TetheringTypes = status.ipv6TetheringTypes,
    ipv6Enabled = ipv6Enabled,
    hasRoutingSession = status.hasRoutingSession,
)

/**
 * 侧边栏网络共享模态对话框 (Tethering Dialog)
 * 允许用户免 Root 通过 Shizuku 将 Wi-Fi 热点及 USB 网络共享流量通过 SmartProxy 路由转发。
 */
@Composable
fun TetheringDialog(
    onDismiss: () -> Unit,
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val vpnRunning by SmartProxyVpnService.isRunning.collectAsState()

    var state by remember { mutableStateOf(TetheringUiState(coreRunning = vpnRunning)) }
    var tetheringService by remember { mutableStateOf<IShizukuTetheringService?>(null) }
    var operationJob by remember { mutableStateOf<Job?>(null) }
    var operationGeneration by remember { mutableStateOf(0L) }

    fun cancelOperation(): Long {
        operationGeneration++
        operationJob?.cancel()
        operationJob = null
        return operationGeneration
    }

    fun toast(resId: Int) {
        Toast.makeText(context, context.getString(resId), Toast.LENGTH_SHORT).show()
    }

    fun toast(text: String) {
        Toast.makeText(context, text, Toast.LENGTH_SHORT).show()
    }

    val statusListener = remember {
        object : ITetheringStatusListener.Stub() {
            override fun onStatusChanged() {
                scope.launch {
                    val service = tetheringService ?: return@launch
                    val status = withContext(Dispatchers.IO) {
                        runCatching { service.getStatus(state.ipv6Enabled) }.getOrNull()
                    }
                    if (status != null) {
                        state = state.copy(
                            routingState = status.routingState,
                            routingDetail = status.routingDetail,
                            activeTetheringTypes = status.activeTetheringTypes,
                            ipv6TetheringTypes = status.ipv6TetheringTypes,
                            hasRoutingSession = status.hasRoutingSession,
                        )
                    }
                }
            }
        }
    }

    val userServiceArgs = remember { ShizukuTetheringService.createUserServiceArgs() }

    val serviceConnection = remember {
        object : ServiceConnection {
            override fun onServiceConnected(name: ComponentName, binder: IBinder) {
                val service = IShizukuTetheringService.Stub.asInterface(binder)
                tetheringService = service
                runCatching { service.setStatusListener(statusListener) }
                scope.launch {
                    val configJson = ConfigProvider.readConfig(context)
                    val tun = TunConfig.parse(configJson)
                    val ipv6 = tun.inet6 != null
                    val status = withContext(Dispatchers.IO) {
                        runCatching { service.getStatus(ipv6) }.getOrNull()
                    }
                    state = state.withServiceConnection(true)
                    if (status != null) {
                        state = state.withTetheringStatus(status, ipv6Enabled = ipv6)
                        if (status.warning == ShizukuTetheringService.RESULT_UNPROTECTED_UPSTREAM) {
                            toast(R.string.shizuku_tethering_wrong_upstream)
                        }
                    } else {
                        state = state.copy(operation = TetheringOperation.NONE)
                    }
                }
            }

            override fun onServiceDisconnected(name: ComponentName) {
                tetheringService = null
                state = state.withServiceConnection(false)
            }
        }
    }

    suspend fun checkShizukuStatus(): ShizukuStatus = withContext(Dispatchers.IO) {
        if (!runCatching { Shizuku.pingBinder() }.getOrDefault(false)) {
            val installed = try {
                context.packageManager.getApplicationInfo(ShizukuProvider.MANAGER_APPLICATION_ID, 0)
                true
            } catch (_: PackageManager.NameNotFoundException) {
                false
            }
            return@withContext if (installed) ShizukuStatus.NOT_RUNNING else ShizukuStatus.NOT_INSTALLED
        }
        if (runCatching { Shizuku.isPreV11() }.getOrDefault(true)) {
            return@withContext ShizukuStatus.UNSUPPORTED
        }
        val granted = runCatching {
            Shizuku.checkSelfPermission() == PackageManager.PERMISSION_GRANTED
        }.getOrDefault(false)
        if (granted) return@withContext ShizukuStatus.READY
        if (runCatching { Shizuku.shouldShowRequestPermissionRationale() }.getOrDefault(false)) {
            ShizukuStatus.PERMISSION_DENIED
        } else {
            ShizukuStatus.PERMISSION_REQUIRED
        }
    }

    fun refreshAll() {
        scope.launch {
            val shizuku = checkShizukuStatus()
            state = state.copy(shizukuStatus = shizuku, coreRunning = SmartProxyVpnService.isRunning.value)
            if (shizuku == ShizukuStatus.READY) {
                if (tetheringService == null) {
                    state = state.copy(operation = TetheringOperation.CONNECTING)
                    runCatching {
                        Shizuku.bindUserService(userServiceArgs, serviceConnection)
                    }.onFailure {
                        state = state.copy(operation = TetheringOperation.NONE)
                        toast(R.string.shizuku_operation_failed)
                    }
                } else {
                    val service = tetheringService ?: return@launch
                    val configJson = ConfigProvider.readConfig(context)
                    val tun = TunConfig.parse(configJson)
                    val ipv6 = tun.inet6 != null
                    val status = withContext(Dispatchers.IO) {
                        runCatching { service.getStatus(ipv6) }.getOrNull()
                    }
                    if (status != null) {
                        state = state.copy(
                            routingState = status.routingState,
                            routingDetail = status.routingDetail,
                            activeTetheringTypes = status.activeTetheringTypes,
                            ipv6TetheringTypes = status.ipv6TetheringTypes,
                            ipv6Enabled = ipv6,
                            hasRoutingSession = status.hasRoutingSession,
                        )
                    }
                }
            } else {
                if (tetheringService != null) {
                    runCatching {
                        Shizuku.unbindUserService(userServiceArgs, serviceConnection, false)
                    }
                    tetheringService = null
                }
                state = state.withServiceConnection(false)
            }
        }
    }

    // 打开 Shizuku 官网下载页(未安装 / 版本过旧需更新时引导用户自行安装)。
    fun openShizukuDownloadPage() {
        runCatching {
            context.startActivity(
                Intent(Intent.ACTION_VIEW, Uri.parse(ShizukuDownloadUrl))
            )
        }.onFailure {
            toast(R.string.shizuku_operation_failed)
        }
    }

    fun requestPermission() {
        if (state.shizukuStatus.canRequestPermission) {
            runCatching {
                Shizuku.requestPermission(1002)
            }.onFailure {
                toast(R.string.shizuku_operation_failed)
                refreshAll()
            }
        } else if (state.shizukuStatus == ShizukuStatus.READY) {
            refreshAll()
        } else {
            toast(state.shizukuStatus.statusRes)
        }
    }

    fun toggleRouting() {
        val service = tetheringService ?: run {
            toast(R.string.shizuku_operation_failed)
            return
        }
        val enable = !state.routingSessionEnabled
        if (enable && !state.coreRunning) {
            toast(R.string.shizuku_routing_status_start_vpn)
            return
        }

        val gen = cancelOperation()
        state = state.copy(operation = if (enable) TetheringOperation.STARTING_ROUTING else TetheringOperation.STOPPING_ROUTING)

        operationJob = scope.launch {
            try {
                val result = withContext(Dispatchers.IO) {
                    if (enable) {
                        val lease = TetheringCoreSync.getCoreLease() ?: run {
                            return@withContext ShizukuTetheringService.RESULT_ROUTING_FAILED
                        }
                        val launchSnapshot = TetheringCoreSync.getCurrentSnapshot(context, coreRunning = true)
                        if (!launchSnapshot.running) {
                            return@withContext ShizukuTetheringService.RESULT_ROUTING_FAILED
                        }
                        val dnsV4 = AppPrefs.dnsV4(context).ifBlank { AppPrefs.DEFAULT_DNS_V4 }
                        val dnsV6 = AppPrefs.dnsV6(context).ifBlank { AppPrefs.DEFAULT_DNS_V6 }
                        val syncToken = UUID.randomUUID().toString()
                        AppPrefs.setShizukuSyncToken(context, syncToken)
                        service.startRouting(
                            "SmartProxy",
                            arrayOf(dnsV4, dnsV6),
                            state.ipv6Enabled,
                            syncToken,
                            launchSnapshot.launchId,
                            lease,
                        )
                    } else {
                        AppPrefs.setShizukuSyncToken(context, "")
                        service.stopRouting()
                    }
                }
                if (result == ShizukuTetheringService.RESULT_OK) {
                    toast(if (enable) R.string.shizuku_routing_enabled else R.string.shizuku_routing_disabled)
                } else {
                    toast(context.getString(R.string.shizuku_routing_operation_failed, result, context.getString(R.string.shizuku_operation_failed)))
                }
            } catch (e: CancellationException) {
                throw e
            } catch (e: Throwable) {
                toast(R.string.shizuku_operation_failed)
            } finally {
                if (gen == operationGeneration) {
                    state = state.copy(operation = TetheringOperation.NONE)
                    refreshAll()
                }
            }
        }
    }

    fun toggleHotspot() {
        val service = tetheringService ?: run {
            toast(R.string.shizuku_operation_failed)
            return
        }
        val enable = !state.hotspotEnabled
        if (enable && !state.routingActive && !state.coreRunning) {
            toast(R.string.shizuku_routing_status_start_vpn)
            return
        }

        val gen = cancelOperation()
        state = state.copy(operation = if (enable) TetheringOperation.STARTING_HOTSPOT else TetheringOperation.STOPPING_HOTSPOT)

        operationJob = scope.launch {
            try {
                val result = withContext(Dispatchers.IO) {
                    var routingStartedHere = false
                    if (enable && !state.routingActive) {
                        val lease = TetheringCoreSync.getCoreLease() ?: return@withContext ShizukuTetheringService.RESULT_ROUTING_FAILED
                        val launchSnapshot = TetheringCoreSync.getCurrentSnapshot(context, coreRunning = true)
                        if (!launchSnapshot.running) {
                            return@withContext ShizukuTetheringService.RESULT_ROUTING_FAILED
                        }
                        val dnsV4 = AppPrefs.dnsV4(context).ifBlank { AppPrefs.DEFAULT_DNS_V4 }
                        val dnsV6 = AppPrefs.dnsV6(context).ifBlank { AppPrefs.DEFAULT_DNS_V6 }
                        val syncToken = UUID.randomUUID().toString()
                        AppPrefs.setShizukuSyncToken(context, syncToken)
                        val routingResult = service.startRouting(
                            "SmartProxy",
                            arrayOf(dnsV4, dnsV6),
                            state.ipv6Enabled,
                            syncToken,
                            launchSnapshot.launchId,
                            lease,
                        )
                        if (routingResult != ShizukuTetheringService.RESULT_OK) {
                            return@withContext routingResult
                        }
                        routingStartedHere = true
                    }

                    val hotspotResult = service.setWifiHotspotEnabled(enable)
                    if (hotspotResult != ShizukuTetheringService.RESULT_OK && routingStartedHere) {
                        service.stopRouting()
                        AppPrefs.setShizukuSyncToken(context, "")
                    }
                    hotspotResult
                }
                if (result == ShizukuTetheringService.RESULT_OK) {
                    toast(if (enable) R.string.shizuku_hotspot_enabled else R.string.shizuku_hotspot_disabled)
                } else if (result != ShizukuTetheringService.RESULT_UNPROTECTED_UPSTREAM) {
                    toast(context.getString(R.string.shizuku_hotspot_operation_failed, result))
                }
            } catch (e: CancellationException) {
                throw e
            } catch (e: Throwable) {
                toast(R.string.shizuku_operation_failed)
            } finally {
                if (gen == operationGeneration) {
                    state = state.copy(operation = TetheringOperation.NONE)
                    refreshAll()
                }
            }
        }
    }

    val binderReceivedListener = remember {
        Shizuku.OnBinderReceivedListener { refreshAll() }
    }
    val binderDeadListener = remember {
        Shizuku.OnBinderDeadListener {
            tetheringService = null
            refreshAll()
        }
    }
    val permissionResultListener = remember {
        Shizuku.OnRequestPermissionResultListener { req, grantResult ->
            if (req == 1002) {
                if (grantResult == PackageManager.PERMISSION_GRANTED) {
                    toast(R.string.shizuku_permission_granted)
                } else {
                    toast(R.string.shizuku_permission_denied)
                }
                refreshAll()
            }
        }
    }

    DisposableEffect(Unit) {
        Shizuku.addBinderReceivedListenerSticky(binderReceivedListener)
        Shizuku.addBinderDeadListener(binderDeadListener)
        Shizuku.addRequestPermissionResultListener(permissionResultListener)
        refreshAll()
        onDispose {
            cancelOperation()
            Shizuku.removeBinderReceivedListener(binderReceivedListener)
            Shizuku.removeBinderDeadListener(binderDeadListener)
            Shizuku.removeRequestPermissionResultListener(permissionResultListener)
            runCatching { tetheringService?.setStatusListener(null) }
            runCatching {
                Shizuku.unbindUserService(userServiceArgs, serviceConnection, false)
            }
            tetheringService = null
        }
    }

    // 主题色获取 (与 MainActivity 樱花粉保持一致)
    val purpleText = if (ThemeState.isDark) Color(0xFFF6B8CF) else Color(0xFFD66E9B)
    val purpleFill = if (ThemeState.isDark) Color(0xFFC25E87) else Color(0xFFD66E9B) // 白图标/白字填充容器
    val purpleDark = if (ThemeState.isDark) Color(0xFFF8CDDF) else Color(0xFFB3557F)
    val purpleSoft = if (ThemeState.isDark) Color(0xFFE9A8C3) else Color(0xFFE88EAF)
    val greyText = if (ThemeState.isDark) Color(0xFFC9A8B6) else Color(0xFF7A626D)
    val cardSurface = if (ThemeState.isDark) Color(0xFF38262F).copy(alpha = 0.95f) else Color.White.copy(alpha = 0.95f)
    val drawerSurface = if (ThemeState.isDark) Color(0xFF32212A) else Color(0xFFFDF4F7)
    val dividerLine = if (ThemeState.isDark) Color(0xFF4A3741) else Color(0xFFF0DCE5)

    val serviceConnected = tetheringService != null
    // 授权就绪 = Shizuku 授权弹窗点过并允许(READY)。仅 binder 绑上(serviceConnected)不算:
    // 授权前热点/路由开关若可点,用户打开后实际跑不了(操作失败 toast),体验像坏按钮。
    val shizukuReady = state.shizukuStatus == ShizukuStatus.READY

    val routingStatusRes = when {
        state.operation == TetheringOperation.CONNECTING -> R.string.shizuku_routing_status_connecting
        state.operation == TetheringOperation.CHECKING -> R.string.shizuku_routing_status_checking
        state.operation == TetheringOperation.STARTING_ROUTING -> R.string.shizuku_routing_status_starting
        state.operation == TetheringOperation.STOPPING_ROUTING -> R.string.shizuku_routing_status_stopping
        !shizukuReady -> R.string.shizuku_routing_status_need_permission
        !serviceConnected -> R.string.shizuku_routing_status_unavailable
        state.routingState == ShizukuTetheringService.ROUTING_STATE_ACTIVE -> R.string.shizuku_routing_status_active
        state.routingState == ShizukuTetheringService.ROUTING_STATE_STARTING -> R.string.shizuku_routing_status_starting
        state.routingState == ShizukuTetheringService.ROUTING_STATE_STOPPING -> R.string.shizuku_routing_status_stopping
        state.routingState == ShizukuTetheringService.ROUTING_STATE_WAITING -> R.string.shizuku_routing_status_waiting
        state.routingState == ShizukuTetheringService.ROUTING_STATE_ERROR -> R.string.shizuku_routing_status_error
        state.coreRunning -> R.string.shizuku_routing_status_disabled
        else -> R.string.shizuku_routing_status_start_vpn
    }

    val routingToggleEnabled = shizukuReady &&
        serviceConnected &&
        state.operation == TetheringOperation.NONE &&
        when (state.routingState) {
            ShizukuTetheringService.ROUTING_STATE_ACTIVE,
            ShizukuTetheringService.ROUTING_STATE_WAITING -> true
            ShizukuTetheringService.ROUTING_STATE_ERROR ->
                // 会话还在(fail-closed:引擎死但没显式停)→ 允许关掉;否则看主 core 能否重开。
                state.hasRoutingSession || state.coreRunning
            ShizukuTetheringService.ROUTING_STATE_DISABLED -> state.coreRunning
            else -> false
        }

    val hotspotStatusRes = when {
        state.operation == TetheringOperation.CONNECTING -> R.string.shizuku_hotspot_status_connecting
        state.operation == TetheringOperation.CHECKING -> R.string.shizuku_hotspot_status_checking
        state.operation == TetheringOperation.STARTING_HOTSPOT -> R.string.shizuku_hotspot_status_starting
        state.operation == TetheringOperation.STOPPING_HOTSPOT -> R.string.shizuku_hotspot_status_stopping
        !shizukuReady -> R.string.shizuku_hotspot_status_need_permission
        !serviceConnected -> R.string.shizuku_hotspot_status_unavailable
        state.hotspotEnabled && state.routingActive -> R.string.shizuku_hotspot_status_enabled
        state.hotspotEnabled && state.routingState == ShizukuTetheringService.ROUTING_STATE_WAITING ->
            R.string.shizuku_hotspot_status_waiting
        state.hotspotEnabled -> R.string.shizuku_hotspot_status_enabled_direct
        state.tetheringStateKnown -> R.string.shizuku_hotspot_status_disabled
        else -> R.string.shizuku_hotspot_status_unavailable
    }

    val hotspotToggleEnabled = shizukuReady &&
        serviceConnected &&
        state.operation == TetheringOperation.NONE &&
        (state.hotspotEnabled ||
            state.tetheringStateKnown &&
            (state.routingActive || state.coreRunning))

    Dialog(
        onDismissRequest = onDismiss,
        properties = DialogProperties(usePlatformDefaultWidth = false)
    ) {
        Surface(
            shape = RoundedCornerShape(24.dp),
            color = drawerSurface,
            modifier = Modifier
                .padding(16.dp)
                .fillMaxWidth()
        ) {
            Column(
                modifier = Modifier
                    .padding(20.dp)
                    .verticalScroll(rememberScrollState())
            ) {
                // 对话框头部
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Surface(
                        shape = RoundedCornerShape(12.dp),
                        color = purpleFill,
                        modifier = Modifier.size(38.dp)
                    ) {
                        Box(contentAlignment = Alignment.Center) {
                            Icon(
                                imageVector = Icons.Outlined.WifiTethering,
                                contentDescription = null,
                                tint = Color.White,
                                modifier = Modifier.size(22.dp)
                            )
                        }
                    }
                    Spacer(Modifier.width(12.dp))
                    Column(Modifier.weight(1f)) {
                        Text(
                            text = stringResource(R.string.dialog_tethering_title),
                            fontSize = 17.sp,
                            fontWeight = FontWeight.Bold,
                            color = purpleDark
                        )
                        Text(
                            text = stringResource(R.string.drawer_tethering_subtitle),
                            fontSize = 11.sp,
                            color = greyText
                        )
                    }
                    IconButton(
                        onClick = onDismiss,
                        modifier = Modifier.size(32.dp)
                    ) {
                        Icon(
                            imageVector = Icons.Default.Close,
                            contentDescription = stringResource(R.string.cd_back),
                            tint = greyText,
                            modifier = Modifier.size(20.dp)
                        )
                    }
                }

                Spacer(Modifier.height(14.dp))
                HorizontalDivider(color = dividerLine, thickness = 1.dp)
                Spacer(Modifier.height(14.dp))

                // ── 卡片 1: Shizuku 状态 ──────────────────────────
                TetheringSectionCard(
                    icon = Icons.Outlined.Security,
                    title = stringResource(R.string.shizuku_status_title),
                    status = stringResource(state.shizukuStatus.statusRes),
                    statusColor = when (state.shizukuStatus) {
                        ShizukuStatus.READY -> Color(0xFF2EBD85)
                        ShizukuStatus.CHECKING -> Color(0xFFFF8413)
                        else -> Color(0xFFE87C7C)
                    },
                    details = state.shizukuStatus.detailsRes?.let { stringResource(it) },
                    cardColor = cardSurface,
                    titleColor = purpleDark,
                    detailColor = greyText
                ) {
                    // 单行两钮:授权(左) + 刷新(右)。没装 Shizuku 时左钮无授权可请,
                    // 动态换成「下载」引到官网——省掉一条独占整行的下载按钮。
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(top = 8.dp),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        val needDownload = state.shizukuStatus == ShizukuStatus.NOT_INSTALLED
                        OutlinedButton(
                            onClick = {
                                if (needDownload) openShizukuDownloadPage() else requestPermission()
                            },
                            enabled = (needDownload || state.shizukuStatus.canRequestPermission) &&
                                !state.operation.isToggleInProgress,
                            shape = RoundedCornerShape(12.dp),
                            modifier = Modifier.weight(1f).height(40.dp)
                        ) {
                            Text(
                                text = stringResource(
                                    if (needDownload) R.string.shizuku_download_button
                                    else R.string.shizuku_request_permission
                                ),
                                fontSize = 12.sp,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis
                            )
                        }
                        OutlinedButton(
                            onClick = { refreshAll() },
                            enabled = !state.operation.isToggleInProgress,
                            shape = RoundedCornerShape(12.dp),
                            modifier = Modifier.weight(1f).height(40.dp)
                        ) {
                            Icon(
                                imageVector = Icons.Outlined.Refresh,
                                contentDescription = null,
                                modifier = Modifier.size(16.dp)
                            )
                            Spacer(Modifier.width(4.dp))
                            Text(
                                text = stringResource(R.string.shizuku_refresh_permission),
                                fontSize = 12.sp,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis
                            )
                        }
                    }
                }

                Spacer(Modifier.height(10.dp))

                // ── 卡片 2: SmartProxy 网络共享路由 ───────────────────
                TetheringSectionCard(
                    icon = Icons.Outlined.Router,
                    title = stringResource(R.string.shizuku_routing_title),
                    status = stringResource(routingStatusRes),
                    statusColor = when {
                        state.routingActive -> Color(0xFF2EBD85)
                        state.routingState == ShizukuTetheringService.ROUTING_STATE_WAITING -> Color(0xFFFF8413)
                        state.routingState == ShizukuTetheringService.ROUTING_STATE_ERROR -> Color(0xFFE87C7C)
                        else -> greyText
                    },
                    details = state.routingDetail.ifBlank { stringResource(R.string.shizuku_routing_summary) },
                    subDetails = stringResource(R.string.shizuku_routing_rules_disclaimer),
                    checked = state.routingSessionEnabled,
                    toggleEnabled = routingToggleEnabled,
                    onToggle = { toggleRouting() },
                    cardColor = cardSurface,
                    titleColor = purpleDark,
                    detailColor = greyText
                )

                Spacer(Modifier.height(10.dp))

                // ── 卡片 3: Wi-Fi 热点 ───────────────────────────
                val hotspotIpMode = state.ipMode(ShizukuTetheringService.TETHERING_TYPE_WIFI)?.let { stringResource(it.labelRes) }
                TetheringSectionCard(
                    icon = Icons.Outlined.WifiTethering,
                    title = stringResource(R.string.shizuku_hotspot_title),
                    status = stringResource(hotspotStatusRes),
                    statusColor = when {
                        state.hotspotEnabled && state.routingActive -> Color(0xFF2EBD85)
                        state.hotspotEnabled -> Color(0xFFFF8413)
                        else -> greyText
                    },
                    details = hotspotIpMode ?: stringResource(R.string.shizuku_hotspot_summary),
                    checked = state.hotspotEnabled,
                    toggleEnabled = hotspotToggleEnabled,
                    onToggle = { toggleHotspot() },
                    cardColor = cardSurface,
                    titleColor = purpleDark,
                    detailColor = greyText
                )

                // ── 可选: USB 网络共享指示 ────────────────────────
                if (state.usbEnabled) {
                    Spacer(Modifier.height(10.dp))
                    val usbIpMode = state.ipMode(ShizukuTetheringService.TETHERING_TYPE_USB)?.let { stringResource(it.labelRes) }
                    TetheringSectionCard(
                        icon = Icons.Outlined.Usb,
                        title = stringResource(R.string.shizuku_usb_status_enabled),
                        status = usbIpMode.orEmpty(),
                        statusColor = Color(0xFF2EBD85),
                        details = null,
                        cardColor = cardSurface,
                        titleColor = purpleDark,
                        detailColor = greyText
                    )
                }

                Spacer(Modifier.height(16.dp))

                // 底部关闭按钮
                Button(
                    onClick = onDismiss,
                    shape = RoundedCornerShape(14.dp),
                    colors = ButtonDefaults.buttonColors(containerColor = purpleFill),
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(46.dp)
                ) {
                    Text(
                        text = stringResource(R.string.btn_cancel),
                        fontSize = 15.sp,
                        fontWeight = FontWeight.Medium,
                        color = Color.White
                    )
                }
            }
        }
    }
}

@Composable
private fun TetheringSectionCard(
    icon: ImageVector,
    title: String,
    status: String,
    statusColor: Color,
    details: String?,
    subDetails: String? = null,
    checked: Boolean? = null,
    toggleEnabled: Boolean = false,
    onToggle: (() -> Unit)? = null,
    cardColor: Color,
    titleColor: Color,
    detailColor: Color,
    extraContent: (@Composable () -> Unit)? = null
) {
    Surface(
        shape = RoundedCornerShape(16.dp),
        color = cardColor,
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(
            modifier = Modifier.padding(14.dp)
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier.fillMaxWidth()
            ) {
                Icon(
                    imageVector = icon,
                    contentDescription = null,
                    tint = titleColor,
                    modifier = Modifier.size(22.dp)
                )
                Spacer(Modifier.width(10.dp))
                Text(
                    text = title,
                    fontSize = 14.sp,
                    fontWeight = FontWeight.SemiBold,
                    color = titleColor,
                    modifier = Modifier.weight(1f)
                )
                if (checked != null && onToggle != null) {
                    Switch(
                        checked = checked,
                        onCheckedChange = if (toggleEnabled) { { onToggle() } } else null,
                        enabled = toggleEnabled,
                        modifier = Modifier.scale(0.8f),
                        colors = SwitchDefaults.colors(
                            checkedThumbColor = Color.White,
                            checkedTrackColor = Color(0xFF2EBD85),
                            uncheckedThumbColor = Color(0xFF9E9E9E),
                            uncheckedTrackColor = Color(0xFFE0E0E0)
                        )
                    )
                }
            }

            Spacer(Modifier.height(4.dp))
            Text(
                text = status,
                fontSize = 13.sp,
                fontWeight = FontWeight.Medium,
                color = statusColor,
                modifier = Modifier.padding(start = 32.dp)
            )

            if (!details.isNullOrBlank()) {
                Spacer(Modifier.height(4.dp))
                Text(
                    text = details,
                    fontSize = 11.sp,
                    color = detailColor,
                    lineHeight = 15.sp,
                    modifier = Modifier.padding(start = 32.dp)
                )
            }

            if (!subDetails.isNullOrBlank()) {
                Spacer(Modifier.height(2.dp))
                Text(
                    text = subDetails,
                    fontSize = 10.sp,
                    color = detailColor.copy(alpha = 0.75f),
                    lineHeight = 14.sp,
                    modifier = Modifier.padding(start = 32.dp)
                )
            }

            extraContent?.let {
                // 必须用 Column 不是 Box:extraContent 可含多个垂直子元素(Shizuku 卡片的
                // 下载按钮 + 授权/刷新 Row),Box 会把子节点堆叠在同一格,导致按钮视觉重叠、
                // 上层盖住下层点不到。单子元素时 Column 与 Box 表现一致,无副作用。
                Column(Modifier.padding(start = 32.dp)) {
                    it()
                }
            }
        }
    }
}
