package io.github.yiguihai11.smartproxy

import android.Manifest
import android.app.Activity
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.res.Configuration
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.Uri
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.PowerManager
import android.provider.Settings
import android.widget.Toast
import java.net.Inet4Address
import java.net.Inet6Address
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.Animatable
import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.Spring
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.spring
import androidx.compose.animation.core.tween
import androidx.compose.animation.expandVertically
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.scaleIn
import androidx.compose.animation.scaleOut
import androidx.compose.animation.shrinkVertically
import androidx.compose.animation.slideInHorizontally
import androidx.compose.animation.slideOutHorizontally
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.interaction.collectIsPressedAsState
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.KeyboardArrowRight
import androidx.compose.material.icons.filled.AltRoute
import androidx.compose.material.icons.filled.Build
import androidx.compose.material.icons.filled.Dashboard
import androidx.compose.material.icons.filled.KeyboardArrowDown
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.outlined.AltRoute
import androidx.compose.material.icons.outlined.Apps
import androidx.compose.material.icons.outlined.Article
import androidx.compose.material.icons.outlined.BatteryChargingFull
import androidx.compose.material.icons.outlined.BrightnessAuto
import androidx.compose.material.icons.outlined.Build
import androidx.compose.material.icons.outlined.ContentCopy
import androidx.compose.material.icons.outlined.DarkMode
import androidx.compose.material.icons.outlined.Dashboard
import androidx.compose.material.icons.outlined.Dns
import androidx.compose.material.icons.outlined.Info
import androidx.compose.material.icons.outlined.LightMode
import androidx.compose.material.icons.outlined.OpenInBrowser
import androidx.compose.material.icons.outlined.Route
import androidx.compose.material.icons.outlined.Sync
import androidx.compose.material.icons.outlined.PhotoLibrary
import androidx.compose.material.icons.outlined.RestartAlt
import androidx.compose.material.icons.outlined.Timeline
import androidx.compose.material.icons.outlined.Tune
import androidx.compose.material.icons.outlined.Wallpaper
import androidx.compose.material.icons.outlined.WifiTethering
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CenterAlignedTopAppBar
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.rotate
import androidx.compose.ui.draw.scale
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.Shape
import androidx.compose.foundation.layout.BoxScope
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.layout.ContentScale
import androidx.activity.result.PickVisualMediaRequest
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.foundation.border
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.shadow
import dev.chrisbanes.haze.HazeDefaults
import dev.chrisbanes.haze.HazeState
import dev.chrisbanes.haze.hazeSource
import dev.chrisbanes.haze.hazeEffect
import androidx.compose.ui.text.font.Font
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import org.json.JSONObject
import androidx.core.content.ContextCompat
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import io.github.yiguihai11.smartproxy.shizuku.ShizukuShell
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * 首页 = 纯启动器(§4.4),UI 参考 Ultimate VPN Free(com.open.hotspot.vpn.free)
 * 逆向还原的视觉:淡紫渐变背景 + 大圆环进度 + 中心紫渐变球体(球上白色电源字形)。
 *  - 顶部左侧侧边栏按钮:弹出功能抽屉(Apps 应用选择、DNS 服务器、排除路由、服务模式)
 *  - 大圆环球体 = VPN 启停(§4.5,isRunning 驱动);进度弧橙色→黄色,连接时扫一圈
 *  - 状态行:「状态:未连接/连接中/已连接」
 *  - 开关卡:IPv4 / IPv6 拦截(§4.1/§4.2,写 config.json;运行中改 → Go watcher 自动重启)
 *  - 开关卡:开机自启(§4.3)
 *  - 管理面板卡:URL + 复制 + 浏览器选择器 + 二维码(§4.4,仅 VPN 运行时显示)
 * 流量模式 / 应用选择、DNS 服务器 / 排除路由均在侧边栏菜单(§5/§6)。
 */
class MainActivity : ComponentActivity() {

    private val vpnConsent =
        registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
            if (result.resultCode == Activity.RESULT_OK) {
                ensureNotifyPermission()
                SmartProxyVpnService.start(this)
                warnNoUpstream()
            }
        }

    /** Android 13+:VPN 保活通知展示需 POST_NOTIFICATIONS,启动前申请一次(§4.3)。
     *  授权可能晚于 startForeground(首次安装弹框是异步的,FGS 先起、系统压住通知),
     *  授权落定且 VPN 在跑时补刷一次前台通知,让保活通知显示出来。 */
    private val notifyPermission =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
            if (granted && SmartProxyVpnService.isRunning.value) {
                SmartProxyVpnService.refreshForeground(this)
            }
        }

    /** OriginOS 省电引导对话框开关(§8):Compose state,setContent 里读、HomeScreen 渲染;
     *  仅代理模式启动时 maybeRequestBatteryOptimizationExemption 置 true 弹出。 */
    private var batteryDialogVisible by mutableStateOf(false)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // 统一 edge-to-edge(含 Android 15+ 强制生效):背景通铺到系统栏后,
        // 内容列用 safeDrawingPadding 让出状态栏/导航栏,避免顶部与状态栏重叠。
        enableEdgeToEdge()
        setContent {
            // 主题(§7):auto/light/dark,首页右上角切换,持久化 AppPrefs。
            var themeMode by remember { mutableStateOf(AppPrefs.themeMode(this)) }
            // 切换后重设系统条栏图标色(手动深色 + 系统浅色时状态栏图标需变浅)。
            AutoSystemBarStyle(themeMode)
            SmartProxyTheme(mode = themeMode) {
                HomeScreen(
                    onToggleVpn = { onToggleClicked() },
                    themeMode = themeMode,
                    onCycleTheme = {
                        themeMode = cycleThemeMode(themeMode)
                        AppPrefs.setThemeMode(this, themeMode)
                    },
                    batteryDialogVisible = batteryDialogVisible,
                    onBatteryDialogDismiss = { batteryDialogVisible = false },
                    onOpenBatterySettings = { openAppDetailsSettings() }
                )
            }
        }
        handleIntent(intent)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        handleIntent(intent)
    }

    private fun handleIntent(intent: Intent?) {
        if (intent == null) return
        // 控制中心磁贴:VPN 授权缺失时收面板跳过来,落到这里接着弹系统授权框,
        // 用户同意后 vpnConsent 回调自动起服务。post 到本轮之后,等界面与 launcher 就绪。
        if (intent.getBooleanExtra(QuickToggleService.EXTRA_START_VPN, false)) {
            android.os.Handler(android.os.Looper.getMainLooper()).post { onToggleClicked() }
        }
        // 桌面长按快捷方式「管理面板」:面板地址随服务状态变(VPN 模式要等 smartproxy.lan),
        // 静态 shortcut 写不死 URL,在这里现取;取不到说明服务没跑,弹 toast 不做傻事。
        if (intent.getBooleanExtra(EXTRA_OPEN_PANEL, false)) {
            android.os.Handler(android.os.Looper.getMainLooper()).post {
                val url = PanelUrl.url(this)
                if (url != null) openPanel(this, url)
                else Toast.makeText(this, R.string.toast_panel_unavailable, Toast.LENGTH_SHORT).show()
            }
        }
    }

    override fun onResume() {
        super.onResume()
        // 方案 A(温和补挂):Android 14+ 允许用户划掉 specialUse 类型的前台服务通知。
        // 不在划掉瞬间立即重发(那是与平台对抗、且时机不可靠),而是在用户回到 App 时检查——
        // 隧道在跑但保活通知不在了,就补挂一次 startForeground。服务若还活着,这只是重刷
        // 通知;服务已被系统收掉,refreshForeground 守卫(startedEngine)不会空拉起。
        // Android 13+ 需通知权限,未授权时通知本就被压住,补挂无意义,交给授权回调。
        if (SmartProxyVpnService.isRunning.value &&
            ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS)
                == PackageManager.PERMISSION_GRANTED
        ) {
            if (!NotificationHelper.isForegroundNotificationVisible(this)) {
                android.util.Log.i(
                    "SmartProxyVpn",
                    "[MainActivity] onResume: VPN running but keepalive notification gone, reposting foreground."
                )
                SmartProxyVpnService.refreshForeground(this)
            } else {
                NotificationHelper.refresh(this)
            }
        }
        if (!SmartProxyVpnService.isRunning.value && NetworkRecoveryManager.isSuspended(this)) {
            android.util.Log.i("SmartProxyVpn", "[MainActivity] onResume: VPN is suspended waiting for network, checking restore...")
            NetworkRecoveryManager.attemptRestore(this)
        }
        io.github.yiguihai11.smartproxy.shizuku.TetheringCoreSync.onAppForegrounded(this)
    }

    private fun onToggleClicked() {
        val currentRunning = SmartProxyVpnService.isRunning.value
        val isSuspended = NetworkRecoveryManager.isSuspended(this)
        android.util.Log.i("SmartProxyVpn", "[MainActivity] onToggleClicked() called. Current isRunning=$currentRunning, isSuspended=$isSuspended")
        if (currentRunning || isSuspended) {
            android.util.Log.i("SmartProxyVpn", "[MainActivity] User requested STOP. Calling SmartProxyVpnService.stop(this)...")
            SmartProxyVpnService.stop(this)
            return
        }
        val netStatus = NetworkUtils.checkPhysicalNetworkAddresses(this)
        if (!netStatus.isAnyAvailable) {
            Toast.makeText(this, getString(R.string.toast_no_network_start), Toast.LENGTH_SHORT).show()
            return
        }
        // 协议族全关时建不出隧道:Builder 一次 addAddress 都没调,establish() 会抛
        // IllegalArgumentException。establishVpn 里那道同款守卫只 Log.e 后 return false,
        // 服务随即被收掉,用户看到的就是「点了没反应、也没有任何提示」。这里提前把原因说清楚。
        // 用 readConfig(内部 ensureConfig,文件缺失时回落 asset 默认值)而不是 ipv4()/ipv6():
        // 后两者读不到文件会双双返回 false,把「读不到配置」误判成「两个都关了」,会把启动锁死。
        // 仅代理(SOCKS5)模式的 listen 取值为 both/v4/v6,恒有其一,不会命中。
        val tunCfg = TunConfig.parse(ConfigProvider.readConfig(this))
        if (tunCfg.inet4 == null && tunCfg.inet6 == null) {
            android.util.Log.w("SmartProxyVpn", "[MainActivity] Both IPv4 and IPv6 disabled (tun has no address); refusing to start.")
            Toast.makeText(this, getString(R.string.toast_need_ipv46), Toast.LENGTH_SHORT).show()
            return
        }
        // 仅代理(SOCKS5)模式(§8 服务模式)不建 VpnService,无需系统授权。
        if (AppPrefs.serviceMode(this) == AppPrefs.MODE_SOCKS5) {
            android.util.Log.i("SmartProxyVpn", "[MainActivity] serviceMode=SOCKS5, skipping VPN consent. Starting service directly...")
            ensureNotifyPermission()
            SmartProxyVpnService.start(this)
            maybeRequestBatteryOptimizationExemption()
            warnNoUpstream()
            return
        }
        // 首次或授权失效:弹系统授权框;成功后由回调启动服务。
        val intent = VpnService.prepare(this)
        if (intent != null) {
            android.util.Log.i("SmartProxyVpn", "[MainActivity] User requested START. VpnService.prepare() non-null, launching consent dialog...")
            vpnConsent.launch(intent)
        } else {
            android.util.Log.i("SmartProxyVpn", "[MainActivity] User requested START. VpnService.prepare() is null, starting service directly...")
            ensureNotifyPermission()
            SmartProxyVpnService.start(this)
            warnNoUpstream()
        }
    }

    /** 首页开启后(§8):config.json 无上游代理节点则 Toast 提示去管理面板配置。面板的管理
     *  服务随引擎起、绑定 ":AdminPort",要引擎跑起来才可达,所以这里只提示不拦截启动。 */
    private fun warnNoUpstream() {
        if (ConfigProvider.hasUpstreamProxy(this)) return
        android.util.Log.w("SmartProxyVpn", "[MainActivity] No upstream proxy configured, prompting user to configure in panel.")
        Toast.makeText(this, getString(R.string.toast_no_upstream), Toast.LENGTH_LONG).show()
    }

    private fun ensureNotifyPermission() {
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS)
            != PackageManager.PERMISSION_GRANTED
        ) {
            notifyPermission.launch(Manifest.permission.POST_NOTIFICATIONS)
        }
    }

    /** 仅代理(SOCKS5)模式后台连通性依赖系统后台放行(§8):Android M+ 对后台 uid 施加
     *  网络限制,本地 SOCKS/面板监听的回环 SYN-ACK 会按 uid 规则被丢 —— 前台正常、
     *  后台超时(SS 安卓同款现象)。
     *
     *  AOSP 的「忽略电池优化」豁免在 OriginOS(vivo/iQOO)覆盖不到独立的「智能冻结/
     *  后台冻结」省电机制(真机确认:后台仍被掐),且豁免后 isIgnoringBattery
     *  Optimizations=true 会让 OriginOS 引导永远不出现。因此:
     *   - OriginOS 系:弹自定义引导 + 深链本应用详情页(耗电管理→允许后台运行),
     *     不看 AOSP 豁免状态(豁免与否都得引导,受 ask 上限约束);
     *   - 其它厂商:已豁免即跳过;有 Shizuku(shell)则 `dumpsys deviceidle whitelist
     *     +pkg` 静默加白、不弹窗,失败/无 Shizuku 才回退 AOSP「忽略电池优化」系统弹框。
     *  弹框路径受 MAX_BATTERY_OPT_ASKS 次上限约束防误触;Shizuku 静默成功不计次数。 */
    private fun maybeRequestBatteryOptimizationExemption() {
        // OriginOS(vivo/iQOO)智能冻结独立于 AOSP doze 白名单,shell 加白也盖不住,
        // 只能走厂商深链引导。
        if (isOriginOS()) {
            if (AppPrefs.batteryOptAskCount(this) >= MAX_BATTERY_OPT_ASKS) return
            AppPrefs.setBatteryOptAskCount(this, AppPrefs.batteryOptAskCount(this) + 1)
            batteryDialogVisible = true
            return
        }
        val pm = getSystemService(Context.POWER_SERVICE) as PowerManager
        if (pm.isIgnoringBatteryOptimizations(packageName)) return
        // 有 Shizuku(shell uid):免 root 一条 dumpsys 静默进 doze 白名单,不弹系统框;
        // 没装/没授权/命令失败,再回退 AOSP「忽略电池优化」系统弹框。
        if (ShizukuShell.available()) {
            lifecycleScope.launch {
                val ok = withContext(Dispatchers.IO) { ShizukuShell.addBatteryWhitelist(packageName) }
                if (!ok || !pm.isIgnoringBatteryOptimizations(packageName)) {
                    showAospBatteryOptDialog()
                }
            }
            return
        }
        showAospBatteryOptDialog()
    }

    /** AOSP「忽略电池优化」系统弹框,受 MAX_BATTERY_OPT_ASKS 次数上限约束,防误触无限弹。 */
    private fun showAospBatteryOptDialog() {
        if (AppPrefs.batteryOptAskCount(this) >= MAX_BATTERY_OPT_ASKS) return
        AppPrefs.setBatteryOptAskCount(this, AppPrefs.batteryOptAskCount(this) + 1)
        runCatching {
            startActivity(Intent(
                Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS,
                Uri.parse("package:$packageName")
            ))
        }.onFailure {
            android.util.Log.w("SmartProxyVpn", "[MainActivity] Battery-optimization dialog unavailable: ${it.message}")
        }
    }

    /** OriginOS(vivo/iQOO,含 bbk 系)智能冻结独立于 AOSP 豁免,引导到本应用详情页
     *  (耗电管理→允许后台运行)——无公共 Intent 直达省电策略,应用详情页是最可靠入口。
     *  对话框本体是 HomeScreen 里的 M3 AlertDialog,这里只负责跳详情页。 */
    private fun openAppDetailsSettings() {
        runCatching {
            startActivity(Intent(
                Settings.ACTION_APPLICATION_DETAILS_SETTINGS,
                Uri.parse("package:$packageName")
            ))
        }.onFailure {
            android.util.Log.w("SmartProxyVpn", "[MainActivity] App-details settings unavailable: ${it.message}")
        }
    }

    /** OriginOS 判定:厂商 vivo/bbk(iQOO 属 BBK 系,MANUFACTURER 常报 vivo/bbk)。
     *  非 OriginOS 一律走 AOSP 豁免。 */
    private fun isOriginOS(): Boolean {
        val m = (Build.MANUFACTURER ?: "").lowercase()
        val b = (Build.BRAND ?: "").lowercase()
        return m.contains("vivo") || m.contains("bbk") ||
            b.contains("vivo") || b.contains("iqoo")
    }
}

private const val MAX_BATTERY_OPT_ASKS = 3

/** 桌面长按快捷方式「管理面板」跳进 MainActivity 时带的 extra(见 res/xml/shortcuts.xml)。 */
private const val EXTRA_OPEN_PANEL = "shortcut_open_panel"

private fun copyPanelUrl(context: Context, url: String) {
    val cm = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
    cm.setPrimaryClip(ClipData.newPlainText("smartproxy_panel_url", url))
    Toast.makeText(context, context.getString(R.string.toast_copy_url, url), Toast.LENGTH_SHORT).show()
}

/** 点按复制面板账号/密码:只拷原始值(不带"账号:/密码:"前缀),Toast 反馈拷的是哪个。 */
private fun copyPanelCredential(context: Context, value: String, toastRes: Int) {
    val cm = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
    cm.setPrimaryClip(ClipData.newPlainText("smartproxy_panel_auth", value))
    Toast.makeText(context, context.getString(toastRes), Toast.LENGTH_SHORT).show()
}

/** §4.4:点击用 Intent.createChooser 弹浏览器选择器,不锁系统默认浏览器。 */
private fun openPanel(context: Context, url: String) {
    val intent = Intent(Intent.ACTION_VIEW, Uri.parse(url))
    context.startActivity(Intent.createChooser(intent, context.getString(R.string.chooser_open_panel)))
}

/** 抽屉底部「SmartProxy for Android」点击跳转项目主页。 */
private fun openProjectUrl(context: Context) {
    context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(PROJECT_URL)))
}

/** 服务模式名(抽屉副标题 / 对话框下拉项)。注意与流量模式(AppSelectionActivity 的
 *  「仅代理」白名单)区分:这里指引擎运行形态——VPN 隧道 vs 纯 SOCKS5。
 *  非 composable,接收 context 用 getString 取 i18n 文案。 */
private fun serviceModeLabel(context: Context, mode: String): String = when (mode) {
    AppPrefs.MODE_SOCKS5 -> context.getString(R.string.mode_proxy_only)
    else -> context.getString(R.string.mode_vpn_tunnel)
}

private fun tunStackLabel(context: Context, stack: String): String = when (stack) {
    AppPrefs.STACK_LWIP -> context.getString(R.string.stack_lwip)
    else -> context.getString(R.string.stack_gvisor)
}

/** 主题切换图标(§7):auto = 自动(brightness-auto 半亮半暗),light = 太阳,dark = 月亮。
 *  图标随模式变化,标题栏右上钮一眼可见当前主题。 */
private fun themeIcon(mode: String): ImageVector = when (mode) {
    AppPrefs.THEME_LIGHT -> Icons.Outlined.LightMode
    AppPrefs.THEME_DARK -> Icons.Outlined.DarkMode
    else -> Icons.Outlined.BrightnessAuto
}

// ── 主题色(樱花粉强调 + 高级纯净画布)──────────────────────────────
// 浅/深两套(§7):getter 读 ThemeState.isDark 响应式切换,引用处零改动。
// 调色板:浅色强调 #D66E9B(深粉,白内容可读)/深色强调 #F6B8CF(浅粉,深底可读);
// 填充型容器(品牌块/按钮/FAB 的白图标)在深色下用更深一档 #C25E87,浅色沿用强调。
private val PurpleText get() = if (ThemeState.isDark) Color(0xFFF6B8CF) else Color(0xFFD66E9B) // 标题/强调
private val PurpleFill get() = if (ThemeState.isDark) Color(0xFFC25E87) else Color(0xFFD66E9B) // 填充容器(白内容)
private val PurpleDark get() = if (ThemeState.isDark) Color(0xFFF8CDDF) else Color(0xFF3A1525) // 面板标题与正文(高对比深紫，确保高透玻璃上字迹清晰醒目)
private val PurpleSoft get() = if (ThemeState.isDark) Color(0xFFE9A8C3) else Color(0xFFE88EAF) // 弱化箭头
private val StatusConnecting = Color(0xFFFF8413) // 连接中
private val StatusConnected = Color(0xFF2EBD85)  // 已连接
private val GreyText get() = if (ThemeState.isDark) Color(0xFFB59AA6) else Color(0xFF66545F)
private val TrackPink get() = if (ThemeState.isDark) Color(0xFF3B2832) else Color(0xFFF3E5EC) // 圆环轨道
private val ArcOrange = Color(0xFFFF8413)
private val ArcYellow = Color(0xFFFFEB3C)
// 页面画布与表面:浅色下采用通透高级的浅灰白画布(#F8F9FA),深色采用暗夜深灰(#181215),彻底消除补丁感
private val PageBackground get() = if (ThemeState.isDark) Color(0xFF181215) else Color(0xFFF8F9FA)
private val CardSurface get() = if (ThemeState.isDark) Color(0xFF271C22) else Color.White
private val DividerLine get() = if (ThemeState.isDark) Color(0xFF382931) else Color(0xFFEDE8EB)
private val SwitchBorder get() = if (ThemeState.isDark) Color(0xFF45333D) else Color(0xFFE2DCE0)

/** 原版图标字体(assets/fonts/iconfont.ttf,逆向自 Ultimate VPN):电源/菜单/刷新/箭头。 */
private val IconFont = FontFamily(Font(R.font.iconfont))

/** 项目主页(抽屉底部版本行点击跳转)。 */
private const val PROJECT_URL = "https://github.com/yiguihai11/SmartProxy"

/**
 * 服务模式(§8)的可观察 Compose state:SharedPreferences 变化 → OnSharedPreferenceChangeListener
 * → state 更新 → 重组。侧边栏菜单显示条件(分应用代理 / DNS / 排除路由 / 联网状态)、监听开关
 * 副标题等直接读 AppPrefs.serviceMode 的 UI 都依赖它:否则切模式后 drawerContent 被 Compose
 * skipping 跳过,隐藏菜单不恢复、副标题不刷新。返回 () -> Unit 注销,DisposableEffect 管生命周期。
 */
@Composable
private fun rememberServiceMode(): String {
    val context = LocalContext.current
    var serviceMode by remember { mutableStateOf(AppPrefs.serviceMode(context)) }
    DisposableEffect(context) {
        val unregister = AppPrefs.observeServiceMode(context) {
            serviceMode = AppPrefs.serviceMode(context)
        }
        onDispose { unregister() }
    }
    return serviceMode
}

@Composable
private fun rememberTunStack(): String {
    val context = LocalContext.current
    var tunStack by remember { mutableStateOf(AppPrefs.tunStack(context)) }
    DisposableEffect(context) {
        val unregister = AppPrefs.observeServiceMode(context) {
            tunStack = AppPrefs.tunStack(context)
        }
        onDispose { unregister() }
    }
    return tunStack
}

@Composable
private fun HomeScreen(
    onToggleVpn: () -> Unit,
    themeMode: String,
    onCycleTheme: () -> Unit,
    batteryDialogVisible: Boolean,
    onBatteryDialogDismiss: () -> Unit,
    onOpenBatterySettings: () -> Unit
) {
    val context = LocalContext.current

    // 面板账号密码:与 URL 同源(读 listen.admin_auth),onResume 一并刷新,
    // 在面板里改过密码后回首页能取到新值。
    var adminAuth by remember { mutableStateOf(ConfigProvider.adminAuth(context)) }
    val lifecycleOwner = LocalLifecycleOwner.current
    DisposableEffect(lifecycleOwner) {
        val observer = LifecycleEventObserver { _, event ->
            if (event == Lifecycle.Event.ON_RESUME) {
                adminAuth = ConfigProvider.adminAuth(context)
            }
        }
        lifecycleOwner.lifecycle.addObserver(observer)
        onDispose { lifecycleOwner.lifecycle.removeObserver(observer) }
    }

    // DNS / 排除路由 / 服务模式 / 网络共享设置对话框开关
    var showDnsDialog by remember { mutableStateOf(false) }
    var showExcludeDialog by remember { mutableStateOf(false) }
    var showServiceModeDialog by remember { mutableStateOf(false) }
    var showTetheringDialog by remember { mutableStateOf(false) }

    fun applyVpnSettings() {
        if (SmartProxyVpnService.isRunning.value) {
            SmartProxyVpnService.restart(context)
        }
    }

    HomeLauncher(
        adminAuth = adminAuth,
        onToggleVpn = onToggleVpn,
        themeMode = themeMode,
        onCycleTheme = onCycleTheme,
        onOpenApps = {
            context.startActivity(Intent(context, AppSelectionActivity::class.java))
        },
        onOpenDns = { showDnsDialog = true },
        onOpenExclude = { showExcludeDialog = true },
        onOpenServiceMode = { showServiceModeDialog = true },
        onOpenTethering = { showTetheringDialog = true },
        onOpenNetworkStatus = {
            context.startActivity(Intent(context, NetworkStatusActivity::class.java))
        },
        onOpenLogcat = {
            context.startActivity(Intent(context, LogcatActivity::class.java))
        },
        onOpenBatterySettings = onOpenBatterySettings
    )

    if (showTetheringDialog) {
        TetheringDialog(
            onDismiss = { showTetheringDialog = false }
        )
    }

    if (showDnsDialog) {
        DnsDialog(
            initialV4 = AppPrefs.dnsV4(context),
            initialV6 = AppPrefs.dnsV6(context),
            onDismiss = { showDnsDialog = false },
            onSave = { v4, v6 ->
                showDnsDialog = false
                AppPrefs.setDnsV4(context, v4)
                AppPrefs.setDnsV6(context, v6)
                runCatching {
                    smartproxy.mobile.Mobile.setSystemDNS(v4, v6)
                }
                applyVpnSettings()
            }
        )
    }
    if (showExcludeDialog) {
        ExcludeRoutesDialog(
            initialRoutes = AppPrefs.excludedRoutes(context).sorted(),
            onDismiss = { showExcludeDialog = false },
            onSave = { routes ->
                showExcludeDialog = false
                AppPrefs.setExcludedRoutes(context, routes)
                applyVpnSettings()
            }
        )
    }
    if (showServiceModeDialog) {
        ServiceModeDialog(
            initialMode = AppPrefs.serviceMode(context),
            initialStack = AppPrefs.tunStack(context),
            onDismiss = { showServiceModeDialog = false },
            onSave = { mode, stack ->
                showServiceModeDialog = false
                val modeChanged = mode != AppPrefs.serviceMode(context)
                val stackChanged = stack != AppPrefs.tunStack(context)
                AppPrefs.setServiceMode(context, mode)
                AppPrefs.setTunStack(context, stack)
                ConfigProvider.setTunStack(context, stack)
                if (modeChanged || stackChanged) {
                    applyVpnSettings()
                }
            }
        )
    }

    // OriginOS 省电引导(§8):仅代理模式启动时 maybeRequestBatteryOptimizationExemption 置位。
    // 与其它对话框同款 M3 AlertDialog;「去设置」跳应用详情页(耗电管理→允许后台运行)。
    if (batteryDialogVisible) {
        AlertDialog(
            onDismissRequest = onBatteryDialogDismiss,
            title = { Text(stringResource(R.string.battery_title)) },
            text = { Text(stringResource(R.string.battery_message)) },
            confirmButton = {
                TextButton(onClick = {
                    onBatteryDialogDismiss()
                    onOpenBatterySettings()
                }) { Text(stringResource(R.string.battery_settings)) }
            },
            dismissButton = {
                TextButton(onClick = onBatteryDialogDismiss) { Text(stringResource(R.string.battery_dismiss)) }
            }
        )
    }
}

/** 全局背景毛玻璃上下文: 允许各个 GlassCard 直接采样底层流体壁纸进行真实 GPU 模糊 */
private val LocalBackgroundHazeState = staticCompositionLocalOf<HazeState?> { null }

/** 超清丝绸流体极光壁纸画布 (High-Definition Silk Fluid Aurora Canvas) */
@Composable
private fun FluidAmbientCanvas(
    isDark: Boolean,
    modifier: Modifier = Modifier
) {
    Canvas(modifier = modifier) {
        val w = size.width
        val h = size.height

        // 1. 全局柔和基底丝绸光晕过渡 (Base Radiant Silk Gradient)
        drawRect(
            brush = Brush.verticalGradient(
                colors = if (isDark) {
                    listOf(Color(0xFF0F0A14), Color(0xFF08050C), Color(0xFF0C0712))
                } else {
                    listOf(Color(0xFFFFF6F9), Color(0xFFF6F3FC), Color(0xFFEEF6FC))
                }
            )
        )

        // 2. 顶部波浪丝绸流光 (Crimson Sakura Silk Ribbon: 环绕状态栏与顶部电源球体)
        val pathWaveTop = Path().apply {
            moveTo(-0.1f * w, -0.05f * h)
            cubicTo(0.35f * w, 0.02f * h, 0.65f * w, 0.26f * h, 1.15f * w, 0.16f * h)
            lineTo(1.15f * w, -0.05f * h)
            close()
        }
        drawPath(
            path = pathWaveTop,
            brush = Brush.radialGradient(
                colors = if (isDark) {
                    listOf(
                        Color(0xFF9E1D56).copy(alpha = 0.80f),
                        Color(0xFF6B1238).copy(alpha = 0.45f),
                        Color.Transparent
                    )
                } else {
                    listOf(
                        Color(0xFFFF3B6C).copy(alpha = 0.55f),
                        Color(0xFFFF758C).copy(alpha = 0.38f),
                        Color(0xFFFFB0C0).copy(alpha = 0.16f),
                        Color.Transparent
                    )
                },
                center = Offset(w * 0.70f, h * 0.12f),
                radius = w * 0.95f
            )
        )

        // 3. 中部左侧丝绸巨浪 (Royal Lavender & Electric Violet Silk Wave: 横贯开关卡片底部，提供鲜明折射流光)
        val pathWaveMid = Path().apply {
            moveTo(-0.15f * w, 0.28f * h)
            cubicTo(0.40f * w, 0.38f * h, 0.75f * w, 0.48f * h, 0.25f * w, 0.70f * h)
            cubicTo(0.05f * w, 0.78f * h, -0.1f * w, 0.65f * h, -0.15f * w, 0.50f * h)
            close()
        }
        drawPath(
            path = pathWaveMid,
            brush = Brush.radialGradient(
                colors = if (isDark) {
                    listOf(
                        Color(0xFF6D28D9).copy(alpha = 0.75f),
                        Color(0xFF4C1D95).copy(alpha = 0.40f),
                        Color.Transparent
                    )
                } else {
                    listOf(
                        Color(0xFF7C3AED).copy(alpha = 0.50f),
                        Color(0xFF9333EA).copy(alpha = 0.32f),
                        Color(0xFFC084FC).copy(alpha = 0.15f),
                        Color.Transparent
                    )
                },
                center = Offset(w * 0.25f, h * 0.45f),
                radius = w * 0.85f
            )
        )

        // 4. 中下部右侧清透冰海丝绸 (Ocean Mint Aquamarine Ribbon: 穿透管理面板卡片)
        val pathWaveOcean = Path().apply {
            moveTo(1.15f * w, 0.45f * h)
            cubicTo(0.60f * w, 0.60f * h, 0.35f * w, 0.75f * w, 0.80f * w, 0.92f * h)
            lineTo(1.15f * w, 0.92f * h)
            close()
        }
        drawPath(
            path = pathWaveOcean,
            brush = Brush.radialGradient(
                colors = if (isDark) {
                    listOf(
                        Color(0xFF0284C7).copy(alpha = 0.70f),
                        Color(0xFF0369A1).copy(alpha = 0.35f),
                        Color.Transparent
                    )
                } else {
                    listOf(
                        Color(0xFF0284C7).copy(alpha = 0.46f),
                        Color(0xFF06B6D4).copy(alpha = 0.28f),
                        Color(0xFF67E8F9).copy(alpha = 0.12f),
                        Color.Transparent
                    )
                },
                center = Offset(w * 0.85f, h * 0.70f),
                radius = w * 0.90f
            )
        )

        // 5. 底部暖阳金琥珀焦散流体 (Golden Amber Sunset Glow: 照亮悬浮胶囊导航栏)
        drawCircle(
            brush = Brush.radialGradient(
                colors = if (isDark) {
                    listOf(
                        Color(0xFF8C3415).copy(alpha = 0.65f),
                        Color(0xFF4A1809).copy(alpha = 0.25f),
                        Color.Transparent
                    )
                } else {
                    listOf(
                        Color(0xFFF59E0B).copy(alpha = 0.42f),
                        Color(0xFFFBBF24).copy(alpha = 0.22f),
                        Color(0xFFFDE68A).copy(alpha = 0.10f),
                        Color.Transparent
                    )
                },
                center = Offset(w * 0.50f, h * 0.96f),
                radius = w * 0.80f
            ),
            center = Offset(w * 0.50f, h * 0.96f),
            radius = w * 0.80f
        )
    }
}

/**
 * 真·液态晶莹玻璃卡片容器 (True Liquid Glass Card)
 *
 * 核心光学指标:
 * 1. 真实 GPU 背景模糊 (Haze Backdrop Blur): 采样底层丝绸壁纸产生 24dp 柔美雾化
 * 2. 92% 超高通透率晶莹次表面 (Crystalline Refractive Surface): 腹部仅保留 4%~8% 微白，彻底告别“白纸贴纸感”
 * 3. 0.75dp 晶体斜切单向高光棱镜边 (Prism Rim Highlight): 顶部聚光 80% 白微光，四周顺滑淡出
 * 4. 0.8dp 极细镜面反射闪光 (Top Specular Glint): 模拟苹果 VisionOS 玻璃表面的镜面折射
 * 5. 极微无重力悬浮焦散 (Weightless Caustic Ambient): 消除生硬的黑脏阴影
 */
@Composable
private fun GlassCard(
    modifier: Modifier = Modifier,
    shape: Shape = RoundedCornerShape(22.dp),
    isHighlighted: Boolean = false,
    content: @Composable BoxScope.() -> Unit
) {
    val isDark = ThemeState.isDark
    val bgHazeState = LocalBackgroundHazeState.current

    // 1. 晶莹次表面折射渐变 (92%~96% 高度通透，绝不遮挡底层丝绸流光)
    val surfaceBrush = if (isDark) {
        if (isHighlighted) {
            Brush.verticalGradient(
                listOf(
                    Color.White.copy(alpha = 0.15f),
                    Color(0xFF1E101D).copy(alpha = 0.35f),
                    Color(0xFF281426).copy(alpha = 0.50f)
                )
            )
        } else {
            Brush.verticalGradient(
                listOf(
                    Color.White.copy(alpha = 0.08f),
                    Color(0xFF120A14).copy(alpha = 0.22f),
                    Color(0xFF1A0E1C).copy(alpha = 0.36f)
                )
            )
        }
    } else {
        if (isHighlighted) {
            Brush.verticalGradient(
                listOf(
                    Color.White.copy(alpha = 0.28f),
                    Color.White.copy(alpha = 0.08f), // 高通透腹部
                    Color.White.copy(alpha = 0.18f)
                )
            )
        } else {
            Brush.verticalGradient(
                listOf(
                    Color.White.copy(alpha = 0.18f),
                    Color.White.copy(alpha = 0.04f), // 极清透腹部: 让底层鲜活的丝绸波浪完全穿透晶莹玻璃!
                    Color.White.copy(alpha = 0.12f)
                )
            )
        }
    }

    // 2. 晶体斜切棱镜高光边 (0.75dp 极细边框: 顶部明亮聚光 -> 两侧快速过渡 -> 底部融入背景)
    val borderBrush = Brush.verticalGradient(
        listOf(
            Color.White.copy(alpha = if (isDark) 0.45f else 0.80f),
            Color.White.copy(alpha = if (isDark) 0.15f else 0.20f),
            if (isHighlighted) PurpleText.copy(alpha = 0.35f) else Color.White.copy(alpha = if (isDark) 0.04f else 0.06f)
        )
    )

    // 3. 悬浮焦散微光投影 (告别系统黑阴影，呈现悬浮晶莹感)
    val spotColor = when {
        isDark -> Color(0x33000000)
        isHighlighted -> Color(0x18D66E9B)
        else -> Color(0x108A3D5E)
    }

    val hazeModifier = if (bgHazeState != null) {
        Modifier.hazeEffect(
            state = bgHazeState,
            style = HazeDefaults.style(
                backgroundColor = (if (isDark) Color(0xFF140A15) else Color.White).copy(
                    alpha = if (isDark) 0.30f else 0.10f
                ),
                blurRadius = 24.dp,
                noiseFactor = 0.012f
            )
        )
    } else Modifier

    Box(
        modifier = modifier
            .shadow(
                elevation = if (isHighlighted) 3.dp else 1.5.dp,
                shape = shape,
                ambientColor = Color(0x04000000),
                spotColor = spotColor
            )
            .clip(shape)
            .then(hazeModifier)
            .background(surfaceBrush)
            .border(0.75.dp, borderBrush, shape)
    ) {
        // 4. 顶部极细镜面反射闪光 (Specular Glint)
        Box(
            modifier = Modifier
                .align(Alignment.TopCenter)
                .fillMaxWidth(0.75f)
                .height(1.dp)
                .background(
                    Brush.horizontalGradient(
                        listOf(
                            Color.Transparent,
                            Color.White.copy(alpha = if (isDark) 0.35f else 0.70f),
                            Color.Transparent
                        )
                    )
                )
        )

        content()
    }
}

/** 组样式卡片容器(真液态玻璃质感分组) */
@Composable
private fun SettingsGroupCard(
    modifier: Modifier = Modifier,
    content: @Composable () -> Unit
) {
    GlassCard(
        shape = RoundedCornerShape(22.dp),
        isHighlighted = false,
        modifier = modifier.fillMaxWidth()
    ) {
        Column(modifier = Modifier.fillMaxWidth()) {
            content()
        }
    }
}

/** 分组行条目(带图标色块、副标题、徽标与弹性按压反馈) */
@Composable
private fun SettingsRowItem(
    icon: ImageVector,
    iconTint: Color = PurpleText,
    iconBg: Color = PurpleSoft.copy(alpha = 0.15f),
    title: String,
    subtitle: String,
    badgeText: String? = null,
    onClick: () -> Unit
) {
    val haptic = LocalHapticFeedback.current
    val interactionSource = remember { MutableInteractionSource() }
    val isPressed by interactionSource.collectIsPressedAsState()
    val scale by animateFloatAsState(
        targetValue = if (isPressed) 0.975f else 1f,
        animationSpec = spring(
            dampingRatio = Spring.DampingRatioMediumBouncy,
            stiffness = Spring.StiffnessLow
        ),
        label = "settingsRowScale"
    )

    Row(
        modifier = Modifier
            .fillMaxWidth()
            .scale(scale)
            .clickable(
                interactionSource = interactionSource,
                indication = null
            ) {
                haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                onClick()
            }
            .padding(horizontal = 16.dp, vertical = 13.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Surface(
            shape = RoundedCornerShape(12.dp),
            color = iconBg,
            modifier = Modifier.size(38.dp)
        ) {
            Box(contentAlignment = Alignment.Center) {
                Icon(
                    imageVector = icon,
                    contentDescription = null,
                    tint = iconTint,
                    modifier = Modifier.size(20.dp)
                )
            }
        }
        Spacer(Modifier.width(14.dp))
        Column(Modifier.weight(1f)) {
            Text(
                text = title,
                fontSize = 15.sp,
                color = PurpleDark,
                fontWeight = FontWeight.SemiBold
            )
            Spacer(Modifier.height(2.dp))
            Text(
                text = subtitle,
                fontSize = 12.sp,
                color = GreyText,
                maxLines = 2,
                overflow = TextOverflow.Ellipsis
            )
        }
        if (!badgeText.isNullOrBlank()) {
            Spacer(Modifier.width(8.dp))
            Surface(
                shape = RoundedCornerShape(8.dp),
                color = PurpleSoft.copy(alpha = 0.14f)
            ) {
                Text(
                    text = badgeText,
                    fontSize = 11.sp,
                    fontWeight = FontWeight.Medium,
                    color = PurpleDark,
                    modifier = Modifier.padding(horizontal = 7.dp, vertical = 3.dp)
                )
            }
        }
        Spacer(Modifier.width(6.dp))
        Icon(
            imageVector = Icons.AutoMirrored.Filled.KeyboardArrowRight,
            contentDescription = null,
            tint = PurpleSoft.copy(alpha = 0.7f),
            modifier = Modifier.size(18.dp)
        )
    }
}

/** 快捷操作胶囊 Chip(按压弹性与微光边框) */
@Composable
private fun QuickActionChip(
    icon: ImageVector,
    label: String,
    enabled: Boolean = true,
    onClick: () -> Unit
) {
    val haptic = LocalHapticFeedback.current
    val interactionSource = remember { MutableInteractionSource() }
    val isPressed by interactionSource.collectIsPressedAsState()
    val scale by animateFloatAsState(
        targetValue = if (isPressed && enabled) 0.93f else 1f,
        animationSpec = spring(dampingRatio = Spring.DampingRatioMediumBouncy, stiffness = Spring.StiffnessLow),
        label = "chipScale"
    )

    val isDark = ThemeState.isDark
    val bgHazeState = LocalBackgroundHazeState.current
    val chipHazeModifier = if (bgHazeState != null) {
        Modifier.hazeEffect(
            state = bgHazeState,
            style = HazeDefaults.style(
                backgroundColor = (if (isDark) Color(0xFF160B18) else Color.White).copy(
                    alpha = if (isDark) 0.35f else 0.12f
                ),
                blurRadius = 20.dp,
                noiseFactor = 0.01f
            )
        )
    } else Modifier

    val chipSurfaceBrush = if (isDark) {
        Brush.verticalGradient(
            listOf(
                Color.White.copy(alpha = if (enabled) 0.16f else 0.08f),
                Color(0xFF160B18).copy(alpha = if (enabled) 0.35f else 0.15f)
            )
        )
    } else {
        Brush.verticalGradient(
            listOf(
                Color.White.copy(alpha = if (enabled) 0.25f else 0.12f),
                Color.White.copy(alpha = if (enabled) 0.05f else 0.02f),
                Color.White.copy(alpha = if (enabled) 0.15f else 0.08f)
            )
        )
    }
    val chipBorderBrush = Brush.verticalGradient(
        listOf(
            Color.White.copy(alpha = if (isDark) 0.40f else 0.80f),
            if (enabled) PurpleText.copy(alpha = 0.25f) else Color.White.copy(alpha = 0.10f),
            Color.Transparent
        )
    )

    Box(
        modifier = Modifier
            .scale(scale)
            .shadow(
                elevation = if (enabled) 2.dp else 0.5.dp,
                shape = RoundedCornerShape(16.dp),
                ambientColor = Color(0x04000000),
                spotColor = if (isDark) Color.Black else Color(0x108A3D5E)
            )
            .clip(RoundedCornerShape(16.dp))
            .then(chipHazeModifier)
            .background(chipSurfaceBrush)
            .border(0.75.dp, chipBorderBrush, RoundedCornerShape(16.dp))
            .alpha(if (enabled) 1f else 0.55f)
            .clickable(
                interactionSource = interactionSource,
                indication = null,
                enabled = enabled
            ) {
                haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                onClick()
            }
    ) {
        // 顶部微高光闪光
        Box(
            modifier = Modifier
                .align(Alignment.TopCenter)
                .fillMaxWidth(0.80f)
                .height(1.dp)
                .background(
                    Brush.horizontalGradient(
                        listOf(
                            Color.Transparent,
                            Color.White.copy(alpha = if (isDark) 0.35f else 0.80f),
                            Color.Transparent
                        )
                    )
                )
        )
        Row(
            modifier = Modifier.padding(horizontal = 14.dp, vertical = 9.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Icon(
                imageVector = icon,
                contentDescription = null,
                tint = if (enabled) PurpleText else GreyText,
                modifier = Modifier.size(15.dp)
            )
            Spacer(Modifier.width(6.dp))
            Text(
                text = label,
                fontSize = 12.sp,
                fontWeight = FontWeight.SemiBold,
                color = if (enabled) PurpleDark else GreyText
            )
        }
    }
}

/** 活跃节点信息胶囊(实时节点名、延迟与选路策略，点击节点刷新测速，点击策略徽标展开下拉菜单选择调度策略) */
@Composable
private fun ActiveNodePill(
    nodeName: String,
    latencyMs: Long,
    strategy: String,
    onReprobe: () -> Unit,
    onSelectStrategy: (String) -> Unit
) {
    val haptic = LocalHapticFeedback.current
    val context = LocalContext.current

    var rotationTarget by remember { mutableStateOf(0f) }
    val animatedRotation by animateFloatAsState(
        targetValue = rotationTarget,
        animationSpec = tween(durationMillis = 650, easing = FastOutSlowInEasing),
        label = "nodePillRotate"
    )

    val pingColor = when {
        latencyMs <= 0 -> GreyText
        latencyMs < 100 -> StatusConnected
        latencyMs < 250 -> StatusConnecting
        else -> Color(0xFFE53935)
    }

    GlassCard(
        shape = RoundedCornerShape(20.dp),
        isHighlighted = latencyMs > 0,
        modifier = Modifier
    ) {
        Row(
            modifier = Modifier.padding(horizontal = 8.dp, vertical = 5.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            // 节点名称与测速区域：点击触发并发对冲测速与选路
            val probeInteraction = remember { MutableInteractionSource() }
            val isProbePressed by probeInteraction.collectIsPressedAsState()
            val probeScale by animateFloatAsState(
                targetValue = if (isProbePressed) 0.96f else 1f,
                animationSpec = spring(dampingRatio = Spring.DampingRatioMediumBouncy, stiffness = Spring.StiffnessLow),
                label = "nodeProbeScale"
            )

            Row(
                modifier = Modifier
                    .scale(probeScale)
                    .clickable(
                        interactionSource = probeInteraction,
                        indication = null
                    ) {
                        haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                        rotationTarget += 360f
                        onReprobe()
                    }
                    .padding(horizontal = 4.dp, vertical = 2.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Box(
                    contentAlignment = Alignment.Center,
                    modifier = Modifier.size(14.dp)
                ) {
                    Box(Modifier.size(12.dp).background(StatusConnected.copy(alpha = 0.25f), CircleShape))
                    Box(Modifier.size(6.dp).background(StatusConnected, CircleShape))
                }
                Spacer(Modifier.width(6.dp))
                Text(
                    text = nodeName.ifBlank { stringResource(R.string.node_direct) },
                    fontSize = 12.sp,
                    fontWeight = FontWeight.SemiBold,
                    color = PurpleDark,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.widthIn(max = 160.dp)
                )
                if (latencyMs > 0) {
                    Spacer(Modifier.width(6.dp))
                    Surface(
                        shape = RoundedCornerShape(6.dp),
                        color = pingColor.copy(alpha = 0.14f)
                    ) {
                        Text(
                            text = "${latencyMs}ms",
                            fontSize = 11.sp,
                            fontWeight = FontWeight.Bold,
                            color = pingColor,
                            modifier = Modifier.padding(horizontal = 5.dp, vertical = 2.dp)
                        )
                    }
                }
                Spacer(Modifier.width(6.dp))
                Icon(
                    imageVector = Icons.Outlined.Sync,
                    contentDescription = stringResource(R.string.cd_refresh),
                    tint = PurpleSoft,
                    modifier = Modifier
                        .size(15.dp)
                        .rotate(animatedRotation)
                )
            }

            // 调度策略徽标：点击展开下拉菜单选择调度算法 (最低延迟 / 故障转移 / 负载轮询 / 随机)
            if (strategy.isNotBlank()) {
                Spacer(Modifier.width(4.dp))
                var menuExpanded by remember { mutableStateOf(false) }
                val stratInteraction = remember { MutableInteractionSource() }
                val isStratPressed by stratInteraction.collectIsPressedAsState()
                val stratScale by animateFloatAsState(
                    targetValue = if (isStratPressed) 0.94f else 1f,
                    animationSpec = spring(dampingRatio = Spring.DampingRatioMediumBouncy, stiffness = Spring.StiffnessLow),
                    label = "nodeStratScale"
                )

                Box {
                    Surface(
                        shape = RoundedCornerShape(10.dp),
                        color = PurpleSoft.copy(alpha = 0.15f),
                        modifier = Modifier
                            .scale(stratScale)
                            .clickable(
                                interactionSource = stratInteraction,
                                indication = null
                            ) {
                                haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                                menuExpanded = true
                            }
                    ) {
                        Row(
                            modifier = Modifier.padding(horizontal = 7.dp, vertical = 3.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Text(
                                text = NotificationHelper.getStrategyDisplayName(context, strategy),
                                fontSize = 11.sp,
                                fontWeight = FontWeight.SemiBold,
                                color = PurpleDark
                            )
                            Spacer(Modifier.width(2.dp))
                            Icon(
                                imageVector = Icons.Filled.KeyboardArrowDown,
                                contentDescription = stringResource(R.string.notification_action_strategy),
                                tint = PurpleDark,
                                modifier = Modifier.size(13.dp)
                            )
                        }
                    }

                    DropdownMenu(
                        expanded = menuExpanded,
                        onDismissRequest = { menuExpanded = false },
                        shape = RoundedCornerShape(16.dp),
                        containerColor = if (ThemeState.isDark) Color(0xFF281C23) else Color.White.copy(alpha = 0.95f),
                        border = BorderStroke(
                            1.dp,
                            Brush.verticalGradient(
                                listOf(
                                    Color.White.copy(alpha = if (ThemeState.isDark) 0.40f else 0.90f),
                                    DividerLine.copy(alpha = 0.40f)
                                )
                            )
                        )
                    ) {
                        val strategies = listOf(
                            "latency" to stringResource(R.string.notification_strategy_latency),
                            "failover" to stringResource(R.string.notification_strategy_failover),
                            "round_robin" to stringResource(R.string.notification_strategy_round_robin),
                            "random" to stringResource(R.string.notification_strategy_random)
                        )
                        strategies.forEach { (key, label) ->
                            val isSelected = strategy.equals(key, ignoreCase = true)
                            DropdownMenuItem(
                                text = {
                                    Text(
                                        text = label,
                                        fontSize = 14.sp,
                                        fontWeight = if (isSelected) FontWeight.Bold else FontWeight.Normal,
                                        color = if (isSelected) PurpleText else PurpleDark
                                    )
                                },
                                trailingIcon = {
                                    if (isSelected) {
                                        Icon(
                                            imageVector = Icons.Filled.Check,
                                            contentDescription = null,
                                            tint = PurpleText,
                                            modifier = Modifier.size(18.dp)
                                        )
                                    }
                                },
                                onClick = {
                                    haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                                    menuExpanded = false
                                    onSelectStrategy(key)
                                }
                            )
                        }
                    }
                }
            }
        }
    }
}

/** 悬浮式胶囊底部导航栏 (Floating Capsule Dock) - 真·液态毛玻璃 (通透模糊 + 晶莹棱镜边框 + 顶部镜面高光) */
@Composable
private fun FloatingCapsuleBar(
    selectedTab: Int,
    onSelectTab: (Int) -> Unit,
    hazeState: HazeState,
    isCompact: Boolean = false,
    modifier: Modifier = Modifier
) {
    val haptic = LocalHapticFeedback.current
    val isDark = ThemeState.isDark

    Box(
        modifier = modifier
            .navigationBarsPadding()
            .padding(horizontal = if (isCompact) 12.dp else 24.dp, vertical = if (isCompact) 6.dp else 10.dp)
            .shadow(
                elevation = 14.dp,
                shape = RoundedCornerShape(32.dp),
                ambientColor = if (isDark) Color.Black else Color(0x18000000),
                spotColor = if (isDark) Color.Black else Color(0x358A3D5E)
            )
            .clip(RoundedCornerShape(32.dp))
            .border(
                1.2.dp,
                Brush.verticalGradient(
                    listOf(
                        Color.White.copy(alpha = if (isDark) 0.60f else 0.95f),
                        Color.White.copy(alpha = if (isDark) 0.22f else 0.40f),
                        Color.Transparent
                    )
                ),
                shape = RoundedCornerShape(32.dp)
            ),
        contentAlignment = Alignment.Center
    ) {
        // 液态玻璃模糊背景层 (通透度提升至 28% 白，让底层滑过的流体极光产生梦幻折射)
        Box(
            modifier = Modifier
                .matchParentSize()
                .hazeEffect(
                    state = hazeState,
                    style = HazeDefaults.style(
                        backgroundColor = (if (isDark) Color(0xFF140B10) else Color.White).copy(
                            alpha = if (isDark) 0.40f else 0.28f
                        ),
                        blurRadius = 32.dp,
                        noiseFactor = 0.015f
                    )
                )
                .background(
                    Brush.verticalGradient(
                        listOf(
                            if (isDark) Color.White.copy(alpha = 0.16f) else Color.White.copy(alpha = 0.50f),
                            if (isDark) Color.White.copy(alpha = 0.03f) else Color.White.copy(alpha = 0.15f),
                            Color.Transparent
                        )
                    )
                )
        )

        // 顶部高光弧线闪光 (Top Specular Rim Glint)
        Box(
            modifier = Modifier
                .align(Alignment.TopCenter)
                .fillMaxWidth(0.70f)
                .height(1.5.dp)
                .background(
                    Brush.horizontalGradient(
                        listOf(
                            Color.Transparent,
                            Color.White.copy(alpha = if (isDark) 0.50f else 0.95f),
                            Color.Transparent
                        )
                    )
                )
        )

        Row(
            modifier = Modifier.padding(horizontal = 8.dp, vertical = 6.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            val tabs = listOf(
                Triple(0, Icons.Outlined.Dashboard to Icons.Filled.Dashboard, stringResource(R.string.tab_dashboard)),
                Triple(1, Icons.Outlined.AltRoute to Icons.Filled.AltRoute, stringResource(R.string.tab_routing)),
                Triple(2, Icons.Outlined.Build to Icons.Filled.Build, stringResource(R.string.tab_tools))
            )
            tabs.forEach { (index, icons, title) ->
                val isSelected = selectedTab == index
                val interactionSource = remember { MutableInteractionSource() }
                val isPressed by interactionSource.collectIsPressedAsState()
                val scale by animateFloatAsState(
                    targetValue = if (isPressed) 0.92f else 1f,
                    animationSpec = spring(dampingRatio = Spring.DampingRatioMediumBouncy, stiffness = Spring.StiffnessLow),
                    label = "tabScale$index"
                )
                val pillBg by animateColorAsState(
                    targetValue = if (isSelected) PurpleFill else Color.Transparent,
                    animationSpec = tween(220),
                    label = "tabPillBg$index"
                )
                val contentColor by animateColorAsState(
                    targetValue = if (isSelected) Color.White else GreyText,
                    animationSpec = tween(220),
                    label = "tabContentColor$index"
                )

                Surface(
                    shape = RoundedCornerShape(24.dp),
                    color = pillBg,
                    border = if (isSelected) {
                        BorderStroke(
                            1.dp,
                            Brush.verticalGradient(
                                listOf(
                                    Color.White.copy(alpha = 0.60f),
                                    Color.Transparent
                                )
                            )
                        )
                    } else null,
                    shadowElevation = if (isSelected) 3.dp else 0.dp,
                    modifier = Modifier
                        .scale(scale)
                        .clickable(
                            interactionSource = interactionSource,
                            indication = null
                        ) {
                            if (selectedTab != index) {
                                haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                                onSelectTab(index)
                            }
                        }
                ) {
                    Row(
                        modifier = Modifier.padding(
                            horizontal = if (isCompact) 12.dp else 16.dp,
                            vertical = if (isCompact) 7.dp else 9.dp
                        ),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Icon(
                            imageVector = if (isSelected) icons.second else icons.first,
                            contentDescription = title,
                            tint = contentColor,
                            modifier = Modifier.size(if (isCompact) 17.dp else 19.dp)
                        )
                        AnimatedVisibility(
                            visible = isSelected,
                            enter = fadeIn(animationSpec = tween(150)) + expandVertically(),
                            exit = fadeOut(animationSpec = tween(150)) + shrinkVertically()
                        ) {
                            Row {
                                Spacer(Modifier.width(if (isCompact) 4.dp else 6.dp))
                                Text(
                                    text = title,
                                    fontSize = if (isCompact) 12.sp else 13.sp,
                                    fontWeight = FontWeight.Bold,
                                    color = contentColor
                                )
                            }
                        }
                    }
                }
            }
        }
    }
}

/** 屏幕自适应布局模型 (适配小屏/矮屏、标准手机、平板/折叠大屏及横屏模式) */
data class AdaptiveLayoutInfo(
    val screenWidthDp: Dp,
    val screenHeightDp: Dp,
    val isLandscape: Boolean,
    val isCompact: Boolean,
    val isTablet: Boolean,
    val orbSize: Dp,
    val contentHorizontalPadding: Dp
)

@Composable
private fun rememberAdaptiveLayoutInfo(): AdaptiveLayoutInfo {
    val configuration = LocalConfiguration.current
    val width = configuration.screenWidthDp.dp
    val height = configuration.screenHeightDp.dp
    val isLandscape = configuration.orientation == Configuration.ORIENTATION_LANDSCAPE
    val isCompact = width < 360.dp || (height < 640.dp && !isLandscape)
    val isTablet = width >= 600.dp

    // 动态圆环尺寸:
    // 横屏模式受限于纵向视口高度 (通常 360dp - 410dp)，圆环缩至 150dp - 180dp
    // 小屏/矮屏设备动态收缩至 172dp - 196dp，避免挤占下方卡片
    // 平板/宽折叠屏适度放大至 244dp，与 580dp 容器完美呼应
    // 主流机型保持经典的 220dp - 228dp 舒适视觉比例
    val orbSize = when {
        isLandscape -> (height * 0.44f).coerceIn(148.dp, 185.dp)
        isCompact -> (width * 0.54f).coerceIn(168.dp, 196.dp)
        isTablet -> 244.dp
        else -> (width * 0.58f).coerceIn(200.dp, 230.dp)
    }

    val contentHorizPadding = if (isCompact) 14.dp else 20.dp

    return remember(width, height, isLandscape, isCompact, isTablet, orbSize, contentHorizPadding) {
        AdaptiveLayoutInfo(
            screenWidthDp = width,
            screenHeightDp = height,
            isLandscape = isLandscape,
            isCompact = isCompact,
            isTablet = isTablet,
            orbSize = orbSize,
            contentHorizontalPadding = contentHorizPadding
        )
    }
}

/** 首页主体内容:全新旗舰级三标签设计(仪表盘、规则分流、系统工具)+ 悬浮导航胶囊 */
@Composable
private fun HomeLauncher(
    adminAuth: Pair<String, String>?,
    onToggleVpn: () -> Unit,
    themeMode: String,
    onCycleTheme: () -> Unit,
    onOpenApps: () -> Unit,
    onOpenDns: () -> Unit,
    onOpenExclude: () -> Unit,
    onOpenServiceMode: () -> Unit,
    onOpenTethering: () -> Unit,
    onOpenNetworkStatus: () -> Unit,
    onOpenLogcat: () -> Unit,
    onOpenBatterySettings: () -> Unit
) {
    val context = LocalContext.current
    val adaptive = rememberAdaptiveLayoutInfo()
    val running by SmartProxyVpnService.isRunning.collectAsState()

    var selectedTab by rememberSaveable { mutableIntStateOf(0) }

    val serviceMode = rememberServiceMode()
    val tunStack = rememberTunStack()

    val socksMode = serviceMode == AppPrefs.MODE_SOCKS5
    val vpnIntercept = !socksMode

    var networkStatus by remember { mutableStateOf(NetworkUtils.checkPhysicalNetworkAddresses(context)) }

    fun refreshNetworkStatus(): NetworkAddressStatus {
        val fresh = NetworkUtils.checkPhysicalNetworkAddresses(context)
        networkStatus = fresh
        return fresh
    }

    DisposableEffect(context) {
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
        val cb = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) { refreshNetworkStatus() }
            override fun onLost(network: Network) { refreshNetworkStatus() }
            override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) { refreshNetworkStatus() }
            override fun onLinkPropertiesChanged(network: Network, linkProperties: LinkProperties) { refreshNetworkStatus() }
        }
        refreshNetworkStatus()
        runCatching { cm?.registerDefaultNetworkCallback(cb) }
        onDispose { runCatching { cm?.unregisterNetworkCallback(cb) } }
    }

    val lifecycleOwner = LocalLifecycleOwner.current
    LaunchedEffect(lifecycleOwner) {
        lifecycleOwner.lifecycle.repeatOnLifecycle(Lifecycle.State.RESUMED) {
            while (true) {
                refreshNetworkStatus()
                delay(2000)
            }
        }
    }

    var ipv4 by remember(socksMode) { mutableStateOf(
        if (!networkStatus.hasV4) false
        else if (socksMode) AppPrefs.socksListen(context) != AppPrefs.SOCKS_LISTEN_V6
        else ConfigProvider.ipv4(context)
    ) }
    var ipv6 by remember(socksMode) { mutableStateOf(
        if (!networkStatus.hasV6) false
        else if (socksMode) AppPrefs.socksListen(context) != AppPrefs.SOCKS_LISTEN_V4
        else ConfigProvider.ipv6(context)
    ) }

    val currentSocksListen = if (socksMode) {
        when {
            ipv4 && ipv6 -> AppPrefs.SOCKS_LISTEN_BOTH
            ipv6 -> AppPrefs.SOCKS_LISTEN_V6
            else -> AppPrefs.SOCKS_LISTEN_V4
        }
    } else {
        AppPrefs.SOCKS_LISTEN_BOTH
    }

    val panelUrl = PanelUrl.url(
        context = context,
        serviceMode = serviceMode,
        socksListen = currentSocksListen
    )

    LaunchedEffect(networkStatus, socksMode) {
        if (networkStatus.hasV6 && !ipv6 && AppPrefs.autoDisabledV6(context)) {
            ipv6 = true
            AppPrefs.setAutoDisabledV6(context, false)
            if (vpnIntercept) {
                ConfigProvider.setIpv6(context, true)
            } else if (AppPrefs.socksListen(context) == AppPrefs.SOCKS_LISTEN_V4) {
                AppPrefs.setSocksListen(context, AppPrefs.SOCKS_LISTEN_BOTH)
            }
            if (running) {
                SmartProxyVpnService.restart(context)
            }
        }
        if (networkStatus.hasV4 && !ipv4 && AppPrefs.autoDisabledV4(context)) {
            ipv4 = true
            AppPrefs.setAutoDisabledV4(context, false)
            if (vpnIntercept) {
                ConfigProvider.setIpv4(context, true)
            } else if (AppPrefs.socksListen(context) == AppPrefs.SOCKS_LISTEN_V6) {
                AppPrefs.setSocksListen(context, AppPrefs.SOCKS_LISTEN_BOTH)
            }
            if (running) {
                SmartProxyVpnService.restart(context)
            }
        }
        if (!networkStatus.hasV6 && ipv6) {
            ipv6 = false
            AppPrefs.setAutoDisabledV6(context, true)
            if (vpnIntercept) {
                ConfigProvider.setIpv6(context, false)
            } else {
                AppPrefs.setSocksListen(context, AppPrefs.SOCKS_LISTEN_V4)
                val json = ConfigProvider.readConfig(context)
                val dns = json.optJSONObject("dns") ?: org.json.JSONObject().also { json.put("dns", it) }
                dns.put("filter_aaaa", true)
                ConfigProvider.writeConfig(context, json)
            }
            if (running) {
                SmartProxyVpnService.restart(context)
            }
        }
        if (!networkStatus.hasV4 && ipv4) {
            ipv4 = false
            AppPrefs.setAutoDisabledV4(context, true)
            if (vpnIntercept) {
                ConfigProvider.setIpv4(context, false)
            } else {
                AppPrefs.setSocksListen(context, AppPrefs.SOCKS_LISTEN_V6)
            }
            if (running) {
                SmartProxyVpnService.restart(context)
            }
        }
    }
    var bootAuto by remember { mutableStateOf(AppPrefs.bootAutoStart(context)) }

    var speedMeterOn by remember { mutableStateOf(AppPrefs.speedMeterEnabled(context)) }
    var showUsageAccessDialog by remember { mutableStateOf(false) }
    val overlayPermLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) {
        if (Settings.canDrawOverlays(context)) {
            speedMeterOn = true
            AppPrefs.setSpeedMeterEnabled(context, true)
            if (running) SpeedMeterOverlay.autoShow(context)
            if (SpeedMeterOverlay.needsUsageAccess(context)) showUsageAccessDialog = true
        } else {
            speedMeterOn = false
        }
    }

    val sweep = remember { Animatable(0f) }
    LaunchedEffect(running) {
        sweep.animateTo(if (running) 360f else 0f, animationSpec = tween(1200))
    }
    val connecting = running && sweep.value < 355f

    var nowMs by remember { mutableStateOf(System.currentTimeMillis()) }
    LaunchedEffect(running) {
        if (running) {
            while (true) {
                nowMs = System.currentTimeMillis()
                delay(1000)
            }
        }
    }
    val elapsedMs = if (running) nowMs - SmartProxyVpnService.startedAt else 0L

    // 活跃节点与选路策略实时轮询 (1.5s 内存级无开销)
    var activeNodeName by remember { mutableStateOf("") }
    var activeNodeLatency by remember { mutableStateOf(0L) }
    var activeStrategy by remember { mutableStateOf("") }

    LaunchedEffect(running) {
        if (running) {
            while (true) {
                runCatching {
                    val raw = smartproxy.mobile.Mobile.getActiveNodeStatus()
                    if (raw.isNotBlank()) {
                        val json = JSONObject(raw)
                        val v4 = json.optString("v4_node")
                        val v6 = json.optString("v6_node")
                        activeNodeName = when {
                            v4.isNotBlank() -> v4
                            v6.isNotBlank() -> v6
                            else -> ""
                        }
                        activeNodeLatency = if (v4.isNotBlank()) json.optLong("v4_latency_ms", 0L) else json.optLong("v6_latency_ms", 0L)
                        activeStrategy = json.optString("strategy", "")
                    }
                }
                delay(1500)
            }
        } else {
            activeNodeName = ""
            activeNodeLatency = 0L
            activeStrategy = ""
        }
    }

    fun reprobeNodes() {
        val reprobeIntent = Intent(context, SmartProxyVpnService::class.java)
            .setAction(NotificationHelper.ACTION_REFRESH_NODES)
        context.startService(reprobeIntent)
        Toast.makeText(context, context.getString(R.string.toast_reprobe_started), Toast.LENGTH_SHORT).show()
    }

    fun selectStrategy(target: String) {
        val stratIntent = Intent(context, SmartProxyVpnService::class.java)
            .setAction(NotificationHelper.ACTION_SET_STRATEGY)
            .putExtra(NotificationHelper.EXTRA_STRATEGY, target)
        context.startService(stratIntent)
        smartproxy.mobile.Mobile.setUpstreamStrategy(target)
        ConfigProvider.setUpstreamStrategy(context, target)
        activeStrategy = target
        reprobeNodes()
    }

    val bgHazeState = remember { HazeState() }
    val contentHazeState = remember { HazeState() }

    val coroutineScope = rememberCoroutineScope()
    var wallpaperVersion by remember { mutableIntStateOf(0) }
    var customWallpaperBitmap by remember { mutableStateOf<ImageBitmap?>(null) }
    var showWallpaperDialog by remember { mutableStateOf(false) }
    var isCustomWp by remember { mutableStateOf(AppPrefs.isCustomWallpaperEnabled(context)) }

    LaunchedEffect(wallpaperVersion) {
        isCustomWp = AppPrefs.isCustomWallpaperEnabled(context)
        val bmp = withContext(Dispatchers.IO) {
            WallpaperHelper.loadWallpaperBitmap(context)
        }
        customWallpaperBitmap = bmp?.asImageBitmap()
    }

    val photoPickerLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.PickVisualMedia()
    ) { uri ->
        if (uri != null) {
            runCatching {
                context.contentResolver.takePersistableUriPermission(
                    uri,
                    Intent.FLAG_GRANT_READ_URI_PERMISSION
                )
            }
            val initialStream = runCatching { context.contentResolver.openInputStream(uri) }.getOrNull()
            val appContext = context.applicationContext
            coroutineScope.launch {
                val success = withContext(Dispatchers.IO) {
                    WallpaperHelper.saveWallpaper(appContext, uri, initialStream)
                }
                if (success) {
                    wallpaperVersion++
                    Toast.makeText(appContext, appContext.getString(R.string.wallpaper_toast_saved), Toast.LENGTH_SHORT).show()
                } else {
                    Toast.makeText(appContext, appContext.getString(R.string.wallpaper_toast_fail), Toast.LENGTH_SHORT).show()
                }
            }
        }
    }

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(PageBackground)
    ) {
        // ── 背景壁纸画布 (采样源：自定义相册壁纸 / 超清丝绸流体极光) ───────
        Box(
            modifier = Modifier
                .fillMaxSize()
                .hazeSource(state = bgHazeState)
        ) {
            val bmp = customWallpaperBitmap
            if (bmp != null) {
                Image(
                    bitmap = bmp,
                    contentDescription = null,
                    contentScale = ContentScale.Crop,
                    modifier = Modifier.fillMaxSize()
                )
                // 深色模式下铺设一层微透明遮罩，保证文字与玻璃卡片的高对比度辨识度
                if (ThemeState.isDark) {
                    Box(
                        modifier = Modifier
                            .fillMaxSize()
                            .background(Color.Black.copy(alpha = 0.25f))
                    )
                }
            } else {
                FluidAmbientCanvas(
                    isDark = ThemeState.isDark,
                    modifier = Modifier.fillMaxSize()
                )
            }
        }

        CompositionLocalProvider(LocalBackgroundHazeState provides bgHazeState) {
            Column(
                modifier = Modifier.fillMaxSize()
            ) {
            // ── 顶部标题栏 ──────────────────────────────
            CenterAlignedTopAppBar(
                title = {
                    AnimatedContent(
                        targetState = selectedTab,
                        transitionSpec = {
                            fadeIn(animationSpec = tween(200)) togetherWith fadeOut(animationSpec = tween(150))
                        },
                        label = "topBarTitle"
                    ) { tab ->
                        val titleText = when (tab) {
                            1 -> stringResource(R.string.tab_routing)
                            2 -> stringResource(R.string.tab_tools)
                            else -> "SmartProxy"
                        }
                        Text(
                            text = titleText,
                            fontSize = 18.sp,
                            fontWeight = FontWeight.Bold,
                            color = PurpleText
                        )
                    }
                },
                actions = {
                    IconButton(onClick = onCycleTheme) {
                        Icon(
                            imageVector = themeIcon(themeMode),
                            contentDescription = stringResource(R.string.cd_theme_mode, themeModeLabel(context, themeMode)),
                            tint = PurpleText,
                            modifier = Modifier.size(22.dp)
                        )
                    }
                },
                windowInsets = WindowInsets(0, 0, 0, 0),
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = Color.Transparent,
                    titleContentColor = PurpleText,
                    actionIconContentColor = PurpleText
                ),
                modifier = Modifier.statusBarsPadding()
            )

            // ── 主体内容与底部悬浮胶囊 ──────────────────────────────
            Box(
                modifier = Modifier
                    .weight(1f)
                    .fillMaxWidth(),
                contentAlignment = Alignment.TopCenter
            ) {
                Column(
                    modifier = Modifier
                        .fillMaxHeight()
                        .widthIn(max = 580.dp)
                        .fillMaxWidth()
                        .hazeSource(state = contentHazeState)
                        .verticalScroll(rememberScrollState())
                        .padding(horizontal = adaptive.contentHorizontalPadding, vertical = 6.dp)
                        .padding(bottom = 110.dp),
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    AnimatedContent(
                        targetState = selectedTab,
                        transitionSpec = {
                            if (targetState > initialState) {
                                (fadeIn(animationSpec = tween(220)) + slideInHorizontally { width -> (width * 0.08f).toInt() })
                                    .togetherWith(fadeOut(animationSpec = tween(160)) + slideOutHorizontally { width -> (-width * 0.08f).toInt() })
                            } else {
                                (fadeIn(animationSpec = tween(220)) + slideInHorizontally { width -> (-width * 0.08f).toInt() })
                                    .togetherWith(fadeOut(animationSpec = tween(160)) + slideOutHorizontally { width -> (width * 0.08f).toInt() })
                            }
                        },
                        label = "tabContentTransition"
                    ) { tab ->
                        when (tab) {
                            0 -> {
                                // ── 仪表盘 Tab ──────────────────────────────
                                Column(
                                    modifier = Modifier.fillMaxWidth(),
                                    horizontalAlignment = Alignment.CenterHorizontally
                                ) {
                                    Spacer(Modifier.height(if (adaptive.isCompact || adaptive.isLandscape) 4.dp else 10.dp))

                                    val startEnabled = running || networkStatus.isAnyAvailable
                                    ConnectOrb(
                                        running = running,
                                        connecting = connecting,
                                        sweep = sweep.value,
                                        elapsedMs = elapsedMs,
                                        enabled = startEnabled,
                                        orbSize = adaptive.orbSize,
                                        onDisabledClick = {
                                            refreshNetworkStatus()
                                            Toast.makeText(context, context.getString(R.string.toast_no_network_start), Toast.LENGTH_SHORT).show()
                                        },
                                        onToggleVpn = { refreshNetworkStatus(); onToggleVpn() }
                                    )

                                    Spacer(Modifier.height(if (adaptive.isCompact || adaptive.isLandscape) 8.dp else 14.dp))

                                    // 活跃节点信息胶囊
                                    AnimatedVisibility(
                                        visible = running,
                                        enter = fadeIn(animationSpec = tween(220)) + expandVertically(),
                                        exit = fadeOut(animationSpec = tween(180)) + shrinkVertically()
                                    ) {
                                        Column(horizontalAlignment = Alignment.CenterHorizontally) {
                                            ActiveNodePill(
                                                nodeName = activeNodeName,
                                                latencyMs = activeNodeLatency,
                                                strategy = activeStrategy,
                                                onReprobe = { reprobeNodes() },
                                                onSelectStrategy = { strat -> selectStrategy(strat) }
                                            )
                                            Spacer(Modifier.height(16.dp))
                                        }
                                    }

                                    // 快捷操作胶囊横排 (精选非重复核心入口)
                                    Row(
                                        modifier = Modifier
                                            .fillMaxWidth()
                                            .horizontalScroll(rememberScrollState()),
                                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                                    ) {
                                        QuickActionChip(
                                            icon = Icons.Outlined.OpenInBrowser,
                                            label = stringResource(R.string.chip_panel),
                                            enabled = running && panelUrl != null,
                                            onClick = { if (panelUrl != null) openPanel(context, panelUrl) }
                                        )
                                        if (serviceMode == AppPrefs.MODE_VPN) {
                                            QuickActionChip(
                                                icon = Icons.Outlined.Apps,
                                                label = stringResource(R.string.chip_apps),
                                                enabled = true,
                                                onClick = onOpenApps
                                            )
                                            QuickActionChip(
                                                icon = Icons.Outlined.WifiTethering,
                                                label = stringResource(R.string.chip_tethering),
                                                enabled = true,
                                                onClick = onOpenTethering
                                            )
                                        }
                                        QuickActionChip(
                                            icon = Icons.Outlined.Article,
                                            label = stringResource(R.string.drawer_logcat),
                                            enabled = true,
                                            onClick = onOpenLogcat
                                        )
                                    }

                                    Spacer(Modifier.height(if (adaptive.isCompact || adaptive.isLandscape) 10.dp else 18.dp))

                                    // 2x2 便当开关网格
                                    Row(modifier = Modifier.fillMaxWidth()) {
                                        SwitchCard(
                                            title = if (vpnIntercept) stringResource(R.string.home_ipv4_intercept) else stringResource(R.string.home_ipv4_listen),
                                            subtitle = when {
                                                !networkStatus.hasV4 -> stringResource(R.string.home_ipv4_no_address)
                                                vpnIntercept -> stringResource(R.string.home_ipv4_intercept_sub)
                                                else -> stringResource(R.string.home_ipv4_listen_sub)
                                            },
                                            checked = ipv4 && networkStatus.hasV4,
                                            enabled = networkStatus.hasV4,
                                            isCompact = adaptive.isCompact,
                                            onDisabledClick = {
                                                Toast.makeText(context, context.getString(R.string.toast_no_ipv4_address), Toast.LENGTH_SHORT).show()
                                            },
                                            onCheckedChange = { v ->
                                                if (!refreshNetworkStatus().hasV4) {
                                                    Toast.makeText(context, context.getString(R.string.toast_no_ipv4_address), Toast.LENGTH_SHORT).show()
                                                    return@SwitchCard
                                                }
                                                if (!v && !ipv6) {
                                                    Toast.makeText(context, context.getString(R.string.toast_need_ipv46), Toast.LENGTH_SHORT).show()
                                                    return@SwitchCard
                                                }
                                                ipv4 = v
                                                AppPrefs.setAutoDisabledV4(context, false)
                                                if (vpnIntercept) {
                                                    ConfigProvider.setIpv4(context, v)
                                                } else {
                                                    AppPrefs.setSocksListen(context, when {
                                                        v && ipv6 -> AppPrefs.SOCKS_LISTEN_BOTH
                                                        v -> AppPrefs.SOCKS_LISTEN_V4
                                                        else -> AppPrefs.SOCKS_LISTEN_V6
                                                    })
                                                }
                                                SmartProxyVpnService.restart(context)
                                            },
                                            modifier = Modifier.weight(1f)
                                        )
                                        Spacer(Modifier.width(8.dp))
                                        SwitchCard(
                                            title = if (vpnIntercept) stringResource(R.string.home_ipv6_intercept) else stringResource(R.string.home_ipv6_listen),
                                            subtitle = when {
                                                !networkStatus.hasV6 -> stringResource(R.string.home_ipv6_no_address)
                                                vpnIntercept -> stringResource(R.string.home_ipv6_intercept_sub)
                                                else -> stringResource(R.string.home_ipv6_listen_sub)
                                            },
                                            checked = ipv6 && networkStatus.hasV6,
                                            enabled = networkStatus.hasV6,
                                            isCompact = adaptive.isCompact,
                                            onDisabledClick = {
                                                Toast.makeText(context, context.getString(R.string.toast_no_ipv6_address), Toast.LENGTH_SHORT).show()
                                            },
                                            onCheckedChange = { v ->
                                                if (!refreshNetworkStatus().hasV6) {
                                                    Toast.makeText(context, context.getString(R.string.toast_no_ipv6_address), Toast.LENGTH_SHORT).show()
                                                    return@SwitchCard
                                                }
                                                if (!v && !ipv4) {
                                                    Toast.makeText(context, context.getString(R.string.toast_need_ipv46), Toast.LENGTH_SHORT).show()
                                                    return@SwitchCard
                                                }
                                                ipv6 = v
                                                AppPrefs.setAutoDisabledV6(context, false)
                                                if (vpnIntercept) {
                                                    ConfigProvider.setIpv6(context, v)
                                                } else {
                                                    AppPrefs.setSocksListen(context, when {
                                                        ipv4 && v -> AppPrefs.SOCKS_LISTEN_BOTH
                                                        v -> AppPrefs.SOCKS_LISTEN_V6
                                                        else -> AppPrefs.SOCKS_LISTEN_V4
                                                    })
                                                    val json = ConfigProvider.readConfig(context)
                                                    val dns = json.optJSONObject("dns") ?: org.json.JSONObject().also { json.put("dns", it) }
                                                    dns.put("filter_aaaa", !v)
                                                    ConfigProvider.writeConfig(context, json)
                                                }
                                                SmartProxyVpnService.restart(context)
                                            },
                                            modifier = Modifier.weight(1f)
                                        )
                                    }

                                    Row(modifier = Modifier.fillMaxWidth()) {
                                        SwitchCard(
                                            title = stringResource(R.string.home_boot_autostart),
                                            subtitle = if (serviceMode == AppPrefs.MODE_VPN)
                                                stringResource(R.string.home_boot_autostart_sub_vpn) else stringResource(R.string.home_boot_autostart_sub_socks),
                                            checked = bootAuto,
                                            isCompact = adaptive.isCompact,
                                            onCheckedChange = { v ->
                                                bootAuto = v
                                                AppPrefs.setBootAutoStart(context, v)
                                            },
                                            modifier = Modifier.weight(1f)
                                        )
                                        Spacer(Modifier.width(8.dp))
                                        SwitchCard(
                                            title = stringResource(R.string.home_speed_meter),
                                            subtitle = stringResource(R.string.home_speed_meter_sub),
                                            checked = speedMeterOn,
                                            enabled = !socksMode,
                                            isCompact = adaptive.isCompact,
                                            onDisabledClick = {
                                                Toast.makeText(context, context.getString(R.string.toast_speed_meter_vpn_only), Toast.LENGTH_SHORT).show()
                                            },
                                            onCheckedChange = { want ->
                                                if (want) {
                                                    if (Settings.canDrawOverlays(context)) {
                                                        speedMeterOn = true
                                                        AppPrefs.setSpeedMeterEnabled(context, true)
                                                        if (running) {
                                                            SpeedMeterOverlay.autoShow(context)
                                                            NotificationHelper.refresh(context)
                                                        }
                                                        if (SpeedMeterOverlay.needsUsageAccess(context)) showUsageAccessDialog = true
                                                    } else {
                                                        Toast.makeText(context, context.getString(R.string.speed_meter_perm_needed), Toast.LENGTH_LONG).show()
                                                        val intent = Intent(
                                                            Settings.ACTION_MANAGE_OVERLAY_PERMISSION,
                                                            Uri.parse("package:${context.packageName}")
                                                        )
                                                        runCatching { overlayPermLauncher.launch(intent) }
                                                            .onFailure { runCatching { context.startActivity(intent) } }
                                                    }
                                                } else {
                                                    speedMeterOn = false
                                                    AppPrefs.setSpeedMeterEnabled(context, false)
                                                    SpeedMeterOverlay.hide()
                                                    if (running) {
                                                        NotificationHelper.refresh(context)
                                                    }
                                                }
                                            },
                                            modifier = Modifier.weight(1f)
                                        )
                                    }

                                    Spacer(Modifier.height(16.dp))

                                    // 管理面板卡片
                                    AnimatedVisibility(
                                        visible = running && panelUrl != null,
                                        enter = fadeIn(animationSpec = spring(stiffness = Spring.StiffnessMediumLow)) +
                                                expandVertically(animationSpec = spring(dampingRatio = Spring.DampingRatioLowBouncy, stiffness = Spring.StiffnessMediumLow)),
                                        exit = fadeOut(animationSpec = tween(180)) +
                                               shrinkVertically(animationSpec = tween(220))
                                    ) {
                                        if (panelUrl != null) {
                                            PanelCard(
                                                url = panelUrl,
                                                auth = adminAuth,
                                                onCopy = { url -> copyPanelUrl(context, url) }
                                            )
                                            Spacer(Modifier.height(8.dp))
                                        }
                                    }
                                }
                            }
                            1 -> {
                                // ── 规则分流 Tab ──────────────────────────────
                                Column(modifier = Modifier.fillMaxWidth()) {
                                    if (serviceMode == AppPrefs.MODE_VPN) {
                                        Spacer(Modifier.height(10.dp))
                                        Text(
                                            text = stringResource(R.string.settings_group_rules),
                                            fontSize = 12.sp,
                                            fontWeight = FontWeight.SemiBold,
                                            color = PurpleSoft,
                                            modifier = Modifier.padding(horizontal = 6.dp, vertical = 4.dp)
                                        )
                                        Spacer(Modifier.height(4.dp))
                                        SettingsGroupCard {
                                            val isBypass = AppPrefs.globalMode(context)
                                            val count = AppPrefs.selectedApps(context).size
                                            val appSub = if (isBypass) {
                                                context.getString(R.string.appsel_bypass_desc) + " (已选 $count)"
                                            } else {
                                                context.getString(R.string.appsel_proxy_desc) + " (已选 $count)"
                                            }
                                            val appBadge = if (isBypass) stringResource(R.string.appsel_mode_bypass) else stringResource(R.string.appsel_mode_proxy)
                                            SettingsRowItem(
                                                icon = Icons.Outlined.Apps,
                                                title = stringResource(R.string.drawer_apps),
                                                subtitle = appSub,
                                                badgeText = appBadge,
                                                onClick = onOpenApps
                                            )
                                            HorizontalDivider(color = DividerLine.copy(alpha = 0.45f), thickness = 0.8.dp)

                                            val d4 = AppPrefs.dnsV4(context)
                                            val d6 = AppPrefs.dnsV6(context)
                                            val dnsSub = if (d4.isBlank() && d6.isBlank()) {
                                                "默认内置反污染 (223.5.5.5 / 2400:3200::1)"
                                            } else {
                                                "${d4.ifBlank { "默认" }} · ${d6.ifBlank { "默认" }}"
                                            }
                                            SettingsRowItem(
                                                icon = Icons.Outlined.Dns,
                                                title = stringResource(R.string.drawer_dns),
                                                subtitle = dnsSub,
                                                onClick = onOpenDns
                                            )
                                            HorizontalDivider(color = DividerLine.copy(alpha = 0.45f), thickness = 0.8.dp)

                                            val routes = AppPrefs.excludedRoutes(context)
                                            val routeSub = if (routes.isEmpty()) stringResource(R.string.drawer_exclude_subtitle)
                                            else "已配置 ${routes.size} 条直连路由网段"
                                            SettingsRowItem(
                                                icon = Icons.Outlined.Route,
                                                title = stringResource(R.string.drawer_exclude),
                                                subtitle = routeSub,
                                                badgeText = if (routes.isNotEmpty()) "${routes.size}" else null,
                                                onClick = onOpenExclude
                                            )
                                        }
                                        Spacer(Modifier.height(20.dp))
                                    } else {
                                        Spacer(Modifier.height(10.dp))
                                    }

                                    Text(
                                        text = stringResource(R.string.settings_group_engine),
                                        fontSize = 12.sp,
                                        fontWeight = FontWeight.SemiBold,
                                        color = PurpleSoft,
                                        modifier = Modifier.padding(horizontal = 6.dp, vertical = 4.dp)
                                    )
                                    Spacer(Modifier.height(4.dp))
                                    SettingsGroupCard {
                                        val modeSub = if (serviceMode == AppPrefs.MODE_VPN) {
                                            "${serviceModeLabel(context, serviceMode)} (${tunStackLabel(context, tunStack)})"
                                        } else {
                                            serviceModeLabel(context, serviceMode)
                                        }
                                        SettingsRowItem(
                                            icon = Icons.Outlined.Tune,
                                            title = stringResource(R.string.drawer_service_mode),
                                            subtitle = stringResource(R.string.drawer_service_mode_subtitle, modeSub),
                                            onClick = onOpenServiceMode
                                        )
                                    }
                                }
                            }
                            2 -> {
                                // ── 系统工具 Tab ──────────────────────────────
                                Column(modifier = Modifier.fillMaxWidth()) {
                                    Spacer(Modifier.height(10.dp))
                                    Text(
                                        text = stringResource(R.string.settings_group_diagnostics),
                                        fontSize = 12.sp,
                                        fontWeight = FontWeight.SemiBold,
                                        color = PurpleSoft,
                                        modifier = Modifier.padding(horizontal = 6.dp, vertical = 4.dp)
                                    )
                                    Spacer(Modifier.height(4.dp))
                                    SettingsGroupCard {
                                        if (serviceMode == AppPrefs.MODE_VPN) {
                                            SettingsRowItem(
                                                icon = Icons.Outlined.WifiTethering,
                                                title = stringResource(R.string.drawer_tethering),
                                                subtitle = stringResource(R.string.drawer_tethering_subtitle),
                                                onClick = onOpenTethering
                                            )
                                            HorizontalDivider(color = DividerLine.copy(alpha = 0.45f), thickness = 0.8.dp)
                                        }

                                        if (serviceMode == AppPrefs.MODE_VPN && running && AppPrefs.globalMode(context)) {
                                            SettingsRowItem(
                                                icon = Icons.Outlined.Timeline,
                                                title = stringResource(R.string.drawer_network_status),
                                                subtitle = stringResource(R.string.drawer_network_status_subtitle),
                                                onClick = onOpenNetworkStatus
                                            )
                                            HorizontalDivider(color = DividerLine.copy(alpha = 0.45f), thickness = 0.8.dp)
                                        }

                                        SettingsRowItem(
                                            icon = Icons.Outlined.Article,
                                            title = stringResource(R.string.drawer_logcat),
                                            subtitle = stringResource(R.string.drawer_logcat_subtitle),
                                            onClick = onOpenLogcat
                                        )
                                    }

                                    Spacer(Modifier.height(20.dp))
                                    Text(
                                        text = stringResource(R.string.settings_group_appearance),
                                        fontSize = 12.sp,
                                        fontWeight = FontWeight.SemiBold,
                                        color = PurpleSoft,
                                        modifier = Modifier.padding(horizontal = 6.dp, vertical = 4.dp)
                                    )
                                    Spacer(Modifier.height(4.dp))
                                    SettingsGroupCard {
                                        SettingsRowItem(
                                            icon = themeIcon(themeMode),
                                            title = stringResource(R.string.settings_theme_title),
                                            subtitle = stringResource(R.string.settings_theme_subtitle, themeModeLabel(context, themeMode)),
                                            onClick = onCycleTheme
                                        )
                                        HorizontalDivider(color = DividerLine.copy(alpha = 0.45f), thickness = 0.8.dp)
                                        SettingsRowItem(
                                            icon = Icons.Outlined.Wallpaper,
                                            title = stringResource(R.string.settings_wallpaper_title),
                                            subtitle = if (isCustomWp) stringResource(R.string.settings_wallpaper_custom) else stringResource(R.string.settings_wallpaper_default),
                                            badgeText = if (isCustomWp) stringResource(R.string.settings_wallpaper_badge_custom) else null,
                                            onClick = { showWallpaperDialog = true }
                                        )
                                    }

                                    Spacer(Modifier.height(20.dp))
                                    Text(
                                        text = stringResource(R.string.settings_group_about),
                                        fontSize = 12.sp,
                                        fontWeight = FontWeight.SemiBold,
                                        color = PurpleSoft,
                                        modifier = Modifier.padding(horizontal = 6.dp, vertical = 4.dp)
                                    )
                                    Spacer(Modifier.height(4.dp))
                                    SettingsGroupCard {
                                        SettingsRowItem(
                                            icon = Icons.Outlined.BatteryChargingFull,
                                            title = stringResource(R.string.tools_battery_title),
                                            subtitle = stringResource(R.string.tools_battery_subtitle),
                                            onClick = onOpenBatterySettings
                                        )
                                        HorizontalDivider(color = DividerLine.copy(alpha = 0.45f), thickness = 0.8.dp)
                                        SettingsRowItem(
                                            icon = Icons.Outlined.Info,
                                            title = stringResource(R.string.tools_about_title),
                                            subtitle = stringResource(R.string.tools_about_subtitle) + " · 访问 GitHub",
                                            onClick = { openProjectUrl(context) }
                                        )
                                    }
                                }
                            }
                        }
                    }
                }

                // 悬浮式胶囊底部导航栏
                FloatingCapsuleBar(
                    selectedTab = selectedTab,
                    onSelectTab = { selectedTab = it },
                    hazeState = contentHazeState,
                    isCompact = adaptive.isCompact,
                    modifier = Modifier.align(Alignment.BottomCenter)
                )
            }
        }
        }

        // 「使用情况访问权限」说明对话框(M3)
        if (showUsageAccessDialog) {
            AlertDialog(
                onDismissRequest = { showUsageAccessDialog = false },
                title = { Text(stringResource(R.string.usage_access_dialog_title)) },
                text = { Text(stringResource(R.string.usage_access_dialog_message)) },
                confirmButton = {
                    TextButton(onClick = {
                        showUsageAccessDialog = false
                        SpeedMeterOverlay.openUsageAccessSettings(context)
                    }) { Text(stringResource(R.string.usage_access_dialog_ok)) }
                },
                dismissButton = {
                    TextButton(onClick = { showUsageAccessDialog = false }) {
                        Text(stringResource(R.string.usage_access_dialog_cancel))
                    }
                }
            )
        }

        // 「背景壁纸设置」对话框 (M3)
        if (showWallpaperDialog) {
            AlertDialog(
                onDismissRequest = { showWallpaperDialog = false },
                title = { Text(stringResource(R.string.wallpaper_dialog_title), fontWeight = FontWeight.Bold) },
                text = {
                    Column(modifier = Modifier.fillMaxWidth()) {
                        Text(
                            text = stringResource(R.string.wallpaper_dialog_desc),
                            fontSize = 14.sp,
                            color = GreyText,
                            lineHeight = 20.sp
                        )
                        Spacer(Modifier.height(18.dp))
                        OutlinedButton(
                            onClick = {
                                showWallpaperDialog = false
                                photoPickerLauncher.launch(
                                    PickVisualMediaRequest(ActivityResultContracts.PickVisualMedia.ImageOnly)
                                )
                            },
                            modifier = Modifier.fillMaxWidth(),
                            shape = RoundedCornerShape(14.dp)
                        ) {
                            Icon(Icons.Outlined.PhotoLibrary, contentDescription = null, modifier = Modifier.size(18.dp))
                            Spacer(Modifier.width(8.dp))
                            Text(stringResource(R.string.wallpaper_action_pick))
                        }
                        if (isCustomWp) {
                            Spacer(Modifier.height(10.dp))
                            OutlinedButton(
                                onClick = {
                                    showWallpaperDialog = false
                                    WallpaperHelper.clearWallpaper(context)
                                    wallpaperVersion++
                                    Toast.makeText(context, context.getString(R.string.wallpaper_toast_reset), Toast.LENGTH_SHORT).show()
                                },
                                modifier = Modifier.fillMaxWidth(),
                                shape = RoundedCornerShape(14.dp),
                                colors = ButtonDefaults.outlinedButtonColors(contentColor = Color(0xFFE53935))
                            ) {
                                Icon(Icons.Outlined.RestartAlt, contentDescription = null, modifier = Modifier.size(18.dp))
                                Spacer(Modifier.width(8.dp))
                                Text(stringResource(R.string.wallpaper_action_reset))
                            }
                        }
                    }
                },
                confirmButton = {},
                dismissButton = {
                    TextButton(onClick = { showWallpaperDialog = false }) {
                        Text(stringResource(R.string.usage_access_dialog_cancel))
                    }
                }
            )
        }
    }
}

/** DNS 候选数据:当前真实网络(Wi-Fi / 移动数据,跳过 VPN)的原生 DNS,按族分列。 */
private data class NetworkDnsCandidates(val v4: List<String>, val v6: List<String>)

/** 读系统当前网络原生 DNS:ConnectivityManager.allNetworks 跳过 TRANSPORT_VPN,
 *  聚合其余网络的 LinkProperties.getDnsServers() 去重。IPv6 剥掉 zone index
 *  (hostAddress 会带 %wlan0,不剥会过不了 isValidIpLiteral 的纯字面量校验)。
 *  读不到(无网络 / 无权限 / 异常)返回空列表 → 对话框隐藏候选段。normal 权限
 *  ACCESS_NETWORK_STATE 声明即授予,异常走 runCatching 静默降级。
 *  @Suppress("DEPRECATION"):API 33 起 getAllNetworks() 标废弃,但没有同步替代——
 *  getActiveNetwork() 在 VPN 运行时返回 VPN 自己(读不到底层真实 DNS),而
 *  registerNetworkCallback 是异步常驻,不适合一次性候选查询;枚举全网络并跳过
 *  TRANSPORT_VPN 仍是此场景唯一正确做法,抑制并注明。 */
@Suppress("DEPRECATION")
private fun currentNetworkDns(context: Context): NetworkDnsCandidates {
    val v4 = LinkedHashSet<String>()
    val v6 = LinkedHashSet<String>()
    runCatching {
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        for (net in cm.allNetworks) {
            val caps = cm.getNetworkCapabilities(net) ?: continue
            if (caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) continue // 只要原生真实 DNS
            val link = cm.getLinkProperties(net) ?: continue
            for (addr in link.dnsServers) {
                if (addr.isLoopbackAddress || addr.isAnyLocalAddress) continue
                val host = addr.hostAddress?.substringBefore('%') ?: continue
                if (addr is Inet4Address) v4.add(host) else if (addr is Inet6Address) v6.add(host)
            }
        }
    }
    return NetworkDnsCandidates(v4.toList(), v6.toList())
}

/** DNS 服务器设置对话框(§6):启动 VPN 时 addDnsServer 注入的 IPv4 / IPv6,留空 = 默认。
 *  推荐填国内 DNS:引擎拦截所有 DNS 查询,对国内 DNS 直连查询并做反污染检测
 *  (只有它可能回污染答案),国外域名自动回退国外 DNS 走代理;填国外 DNS 也能用,
 *  但查询走上游代理需上游支持 UDP。改动后需重启 VPN 生效。
 *  候选(currentNetworkDns):各输入框正下方横排本族当前网络原生 DNS,点选填入
 *  (DNS 每族单服务器,点选 = 替换);无候选则该位置留空。
 *  实时跟随:默认网络回调监听网络切换(Wi-Fi/移动数据/VPN 起停),变了就重读。 */
@Composable
private fun DnsDialog(
    initialV4: String,
    initialV6: String,
    onDismiss: () -> Unit,
    onSave: (v4: String, v6: String) -> Unit
) {
    var v4 by remember { mutableStateOf(initialV4) }
    var v6 by remember { mutableStateOf(initialV6) }
    val context = LocalContext.current
    // 候选实时跟随网络切换:默认网络变化(Wi-Fi↔移动数据、VPN 起停等)触发重读;
    // 内容没变不写 state,避免无谓重组。对话框关闭自动注销回调。
    var candidates by remember { mutableStateOf(currentNetworkDns(context)) }
    val refreshCandidates = {
        val fresh = currentNetworkDns(context)
        if (fresh != candidates) candidates = fresh
    }
    DisposableEffect(context) {
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val cb = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) = refreshCandidates()
            override fun onLost(network: Network) = refreshCandidates()
            override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) = refreshCandidates()
            override fun onLinkPropertiesChanged(network: Network, linkProperties: LinkProperties) = refreshCandidates()
        }
        runCatching { cm.registerDefaultNetworkCallback(cb) }
        onDispose { runCatching { cm.unregisterNetworkCallback(cb) } }
    }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.drawer_dns)) },
        text = {
            Column {
                OutlinedTextField(
                    value = v4,
                    onValueChange = { v4 = it },
                    label = { Text("IPv4") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )
                Spacer(Modifier.height(6.dp))
                // IPv4 候选:当前网络原生 IPv4 DNS,横排胶囊(溢出横向滚动),点选填入。
                if (candidates.v4.isNotEmpty()) {
                    DnsChipRow(candidates.v4) { v4 = it }
                    Spacer(Modifier.height(6.dp))
                }
                OutlinedTextField(
                    value = v6,
                    onValueChange = { v6 = it },
                    label = { Text("IPv6") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )
                Spacer(Modifier.height(6.dp))
                // IPv6 候选:当前网络原生 IPv6 DNS,横排胶囊(溢出横向滚动),点选填入。
                if (candidates.v6.isNotEmpty()) {
                    DnsChipRow(candidates.v6) { v6 = it }
                    Spacer(Modifier.height(6.dp))
                }
                Text(
                    text = stringResource(R.string.dialog_dns_help),
                    fontSize = 12.sp,
                    color = GreyText
                )
            }
        },
        confirmButton = {
            TextButton(onClick = {
                // 非法地址会让 establish 阶段 addDnsServer 抛异常 → VPN 起不来,保存前拦掉。
                if (v4.isBlank() || isValidIpLiteral(v4)) {
                    if (v6.isBlank() || isValidIpLiteral(v6)) {
                        onSave(v4.trim(), v6.trim())
                        return@TextButton
                    }
                }
                Toast.makeText(context, context.getString(R.string.toast_invalid_dns), Toast.LENGTH_SHORT).show()
            }) { Text(stringResource(R.string.btn_save)) }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text(stringResource(R.string.btn_cancel)) } }
    )
}

/** DNS 候选横排胶囊行:当前网络原生 DNS 的多个地址并排一排(不换行,溢出横向滚动),
 *  点击填入对应族字段(替换)。用 M3 原生 AssistChip(辅助完成「填 DNS」这个动作,
 *  自带胶囊造型/边框/按压态),只显示裸地址,无族前缀(已放在对应输入框下方)。 */
@Composable
private fun DnsChipRow(addresses: List<String>, onPick: (String) -> Unit) {
    Row(
        verticalAlignment = Alignment.CenterVertically,
        modifier = Modifier.fillMaxWidth().horizontalScroll(rememberScrollState())
    ) {
        addresses.forEach { addr ->
            AssistChip(
                onClick = { onPick(addr) },
                label = { Text(addr) },
                modifier = Modifier.padding(end = 6.dp)
            )
        }
    }
}

/** 排除路由默认项:回环段。仅供空输入框的灰色占位提示——需要回环直连(SOCKS :1080 /
 *  管理面板不被隧道拦截)的用户自行填入;留空保存 = 纯真空,不排除任何路由。 */
private const val DEFAULT_EXCLUDE_ROUTE = "127.0.0.1/8"

/** 排除路由设置对话框(API 33+ builder.excludeRoute):每行一个 CIDR,不走 VPN 隧道直连。 */
@Composable
private fun ExcludeRoutesDialog(
    initialRoutes: List<String>,
    onDismiss: () -> Unit,
    onSave: (Set<String>) -> Unit
) {
    // 纯真空:空列表打开即空输入框,留空保存 = 不排除任何路由;回环默认 127.0.0.1/8
    // 只在输入框空着时以灰色占位提示(placeholder),不是真实内容,不会随保存写入。
    val initialText = initialRoutes.joinToString("\n")
    var text by remember { mutableStateOf(initialText) }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.dialog_exclude_title)) },
        text = {
            Column {
                OutlinedTextField(
                    value = text,
                    onValueChange = { text = it },
                    label = { Text(stringResource(R.string.dialog_exclude_hint)) },
                    placeholder = {
                        // 空态灰色提示(禁用观感):127.0.0.1/8 只是参考,输入任何内容即消失,
                        // 不随保存写入,保证纯真空可存可保。
                        Text(
                            text = DEFAULT_EXCLUDE_ROUTE,
                            fontSize = 13.sp,
                            color = GreyText
                        )
                    },
                    modifier = Modifier.fillMaxWidth().height(160.dp)
                )
                Spacer(Modifier.height(8.dp))
                Text(
                    text = stringResource(R.string.dialog_exclude_help),
                    fontSize = 12.sp,
                    color = GreyText
                )
            }
        },
        confirmButton = {
            TextButton(onClick = {
                onSave(text.lines().map { it.trim() }.filter { it.isNotBlank() }.toSet())
            }) { Text(stringResource(R.string.btn_save)) }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text(stringResource(R.string.btn_cancel)) } }
    )
}

/** 服务模式与协议栈设置对话框(§8):模态下拉选 VPN 隧道 / 仅代理(SOCKS5)以及 TUN 协议栈。
 *  改动由调用方落盘,运行中切换自动重启生效。未 Root 设备仅支持 gVisor。 */
@Composable
private fun ServiceModeDialog(
    initialMode: String,
    initialStack: String,
    onDismiss: () -> Unit,
    onSave: (String, String) -> Unit
) {
    var selectedMode by remember { mutableStateOf(initialMode) }
    var selectedStack by remember { mutableStateOf(if (initialStack == AppPrefs.STACK_LWIP) AppPrefs.STACK_LWIP else AppPrefs.STACK_GVISOR) }
    var modeExpanded by remember { mutableStateOf(false) }
    var stackExpanded by remember { mutableStateOf(false) }
    val context = LocalContext.current
    val modeOptions = listOf(AppPrefs.MODE_VPN, AppPrefs.MODE_SOCKS5)
    val stackOptions = listOf(AppPrefs.STACK_GVISOR, AppPrefs.STACK_LWIP)

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.drawer_service_mode)) },
        text = {
            Column {
                Text(
                    text = stringResource(R.string.drawer_service_mode),
                    fontSize = 12.sp,
                    color = GreyText,
                    modifier = Modifier.padding(bottom = 6.dp)
                )
                // 服务模式下拉
                Box {
                    Surface(
                        onClick = { modeExpanded = !modeExpanded },
                        shape = RoundedCornerShape(14.dp),
                        color = MaterialTheme.colorScheme.surfaceVariant,
                        border = BorderStroke(1.dp, DividerLine),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Row(
                            modifier = Modifier.padding(horizontal = 14.dp, vertical = 14.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Text(
                                serviceModeLabel(context, selectedMode),
                                fontSize = 14.sp,
                                color = PurpleDark,
                                modifier = Modifier.weight(1f)
                            )
                            Icon(
                                Icons.Filled.KeyboardArrowDown,
                                contentDescription = stringResource(R.string.cd_choose_service_mode),
                                tint = PurpleSoft,
                                modifier = Modifier.size(20.dp)
                            )
                        }
                    }
                    DropdownMenu(expanded = modeExpanded, onDismissRequest = { modeExpanded = false }) {
                        modeOptions.forEach { mode ->
                            DropdownMenuItem(
                                text = { Text(serviceModeLabel(context, mode)) },
                                onClick = {
                                    selectedMode = mode
                                    modeExpanded = false
                                }
                            )
                        }
                    }
                }

                Spacer(Modifier.height(14.dp))

                // 协议栈选择 (TUN Stack):仅在 VPN 隧道模式可用
                val isVpn = selectedMode == AppPrefs.MODE_VPN
                Text(
                    text = stringResource(R.string.service_stack_title),
                    fontSize = 12.sp,
                    color = if (isVpn) GreyText else GreyText.copy(alpha = 0.5f),
                    modifier = Modifier.padding(bottom = 6.dp)
                )
                Box {
                    Surface(
                        onClick = { if (isVpn) stackExpanded = !stackExpanded },
                        shape = RoundedCornerShape(14.dp),
                        color = if (isVpn) MaterialTheme.colorScheme.surfaceVariant else MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f),
                        border = BorderStroke(1.dp, DividerLine),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Row(
                            modifier = Modifier.padding(horizontal = 14.dp, vertical = 14.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Text(
                                tunStackLabel(context, selectedStack),
                                fontSize = 14.sp,
                                color = if (isVpn) PurpleDark else GreyText,
                                modifier = Modifier.weight(1f)
                            )
                            Icon(
                                Icons.Filled.KeyboardArrowDown,
                                contentDescription = stringResource(R.string.cd_choose_tun_stack),
                                tint = if (isVpn) PurpleSoft else GreyText,
                                modifier = Modifier.size(20.dp)
                            )
                        }
                    }
                    DropdownMenu(expanded = stackExpanded && isVpn, onDismissRequest = { stackExpanded = false }) {
                        stackOptions.forEach { stack ->
                            DropdownMenuItem(
                                text = {
                                    Text(tunStackLabel(context, stack))
                                },
                                onClick = {
                                    selectedStack = stack
                                    stackExpanded = false
                                }
                            )
                        }
                    }
                }

                Spacer(Modifier.height(10.dp))
                Text(
                    text = stringResource(R.string.dialog_service_help),
                    fontSize = 12.sp,
                    color = GreyText
                )
            }
        },
        confirmButton = {
            TextButton(onClick = { onSave(selectedMode, selectedStack) }) {
                Text(stringResource(R.string.btn_save))
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text(stringResource(R.string.btn_cancel))
            }
        }
    )
}

/** DNS 必须是数字字面量(纯语法校验,不触发 DNS 解析)。拦在保存前:非法地址会让
 *  establish 阶段 addDnsServer 抛异常 → VPN 起不来。格式仍宽松,真正严格解析在 Builder。 */
private fun isValidIpLiteral(s: String): Boolean {
    val v = s.trim()
    if (v.isEmpty()) return true
    return if (':' in v) {
        // IPv6:1-7 个冒号、仅十六进制字符,允许 :: 压缩(粗校验)
        v.count { it == ':' } in 1..7 &&
            v.all { it.isDigit() || it == ':' || it in 'a'..'f' || it in 'A'..'F' }
    } else {
        // IPv4:4 段点分十进制,每段 0-255
        val octets = v.split('.')
        octets.size == 4 &&
            octets.all { o -> o.isNotEmpty() && o.length <= 3 && o.all(Char::isDigit) && o.toInt() <= 255 }
    }
}

/** 连接时长格式化:HH:MM:SS(对齐效果图 00:12:34)。 */
private fun formatElapsed(ms: Long): String {
    val totalSec = (ms / 1000).coerceAtLeast(0)
    return String.format("%02d:%02d:%02d", totalSec / 3600, (totalSec % 3600) / 60, totalSec % 60)
}

/**
 * 首页核心大圆环(高质感动效版):
 * 1. 物理阻尼按压弹性缩放 (spring 阻尼感)
 * 2. 连接中的流光顺滑旋转 (Continuous orbiting sweep arc)
 * 3. 已连接时的双层动态声呐/雷达扩散脉冲水波纹 (Dual-layer sonar pulse wave)
 * 4. 电源键与连接状态的平滑形变过渡 (AnimatedContent scale + crossfade)
 * 5. 机械级触觉震动反馈 (HapticFeedback)
 */
@Composable
private fun ConnectOrb(
    running: Boolean,
    connecting: Boolean,
    sweep: Float,
    elapsedMs: Long,
    enabled: Boolean = true,
    orbSize: Dp = 228.dp,
    onDisabledClick: (() -> Unit)? = null,
    onToggleVpn: () -> Unit
) {
    val haptic = LocalHapticFeedback.current
    val interactionSource = remember { MutableInteractionSource() }
    val isPressed by interactionSource.collectIsPressedAsState()

    // 比例缩放因子 (以设计基准 228.dp 为 1.0f)
    val scaleFactor = (orbSize.value / 228f).coerceIn(0.65f, 1.25f)

    // 物理弹性按压缩放动效:按压时 0.93f,松开以 Spring 弹性回弹
    val orbScale by animateFloatAsState(
        targetValue = if (isPressed && enabled) 0.93f else 1f,
        animationSpec = spring(
            dampingRatio = Spring.DampingRatioMediumBouncy,
            stiffness = Spring.StiffnessLow
        ),
        label = "orbScale"
    )

    // 雷达光晕脉冲与旋转流光周期
    val infiniteTransition = rememberInfiniteTransition(label = "orbEffects")
    val pulseFraction by infiniteTransition.animateFloat(
        initialValue = 0f,
        targetValue = 1f,
        animationSpec = infiniteRepeatable(
            animation = tween(2400, easing = LinearEasing),
            repeatMode = RepeatMode.Restart
        ),
        label = "orbPulseFraction"
    )
    val spinAngle by infiniteTransition.animateFloat(
        initialValue = 0f,
        targetValue = 360f,
        animationSpec = infiniteRepeatable(
            animation = tween(2000, easing = LinearEasing),
            repeatMode = RepeatMode.Restart
        ),
        label = "orbSpinAngle"
    )

    Box(
        contentAlignment = Alignment.Center,
        modifier = Modifier
            .size(orbSize)
            .scale(orbScale)
            .clickable(
                interactionSource = interactionSource,
                indication = null
            ) {
                if (!enabled && !running) {
                    onDisabledClick?.invoke()
                } else {
                    haptic.performHapticFeedback(HapticFeedbackType.LongPress)
                    onToggleVpn()
                }
            }
            .alpha(if (!enabled && !running) 0.45f else 1f)
    ) {
        Canvas(modifier = Modifier.fillMaxSize()) {
            val stroke = (12f * scaleFactor).dp.toPx()
            val radius = (size.minDimension - stroke * 2.8f) / 2f
            val center = this.center

            // 1. 已连接时的双层雷达光晕扩散波纹
            if (running && !connecting) {
                val waveRadius1 = radius + stroke * (0.6f + pulseFraction * 1.5f)
                val waveAlpha1 = ((1f - pulseFraction).coerceIn(0f, 1f) * 0.25f)
                drawCircle(
                    color = StatusConnected.copy(alpha = waveAlpha1),
                    radius = waveRadius1,
                    style = Stroke(width = stroke * (1f - pulseFraction * 0.5f).coerceAtLeast(0.2f))
                )

                val fraction2 = (pulseFraction + 0.5f) % 1f
                val waveRadius2 = radius + stroke * (0.6f + fraction2 * 1.5f)
                val waveAlpha2 = ((1f - fraction2).coerceIn(0f, 1f) * 0.20f)
                drawCircle(
                    color = StatusConnected.copy(alpha = waveAlpha2),
                    radius = waveRadius2,
                    style = Stroke(width = stroke * (1f - fraction2 * 0.5f).coerceAtLeast(0.2f))
                )
            }

            // 2. 底轨
            drawCircle(color = TrackPink, radius = radius, style = Stroke(width = stroke))

            // 3. 进度弧:连接中带有流光旋转,连接完成定格在整圈满弧
            if (connecting) {
                drawArc(
                    brush = Brush.sweepGradient(listOf(ArcOrange, ArcYellow, ArcOrange)),
                    startAngle = -90f + spinAngle,
                    sweepAngle = sweep.coerceAtLeast(60f),
                    useCenter = false,
                    topLeft = Offset(center.x - radius, center.y - radius),
                    size = Size(radius * 2f, radius * 2f),
                    style = Stroke(width = stroke, cap = StrokeCap.Round)
                )
            } else if (running && sweep > 0f) {
                drawArc(
                    brush = Brush.sweepGradient(listOf(ArcOrange, ArcYellow, ArcOrange)),
                    startAngle = -90f,
                    sweepAngle = sweep,
                    useCenter = false,
                    topLeft = Offset(center.x - radius, center.y - radius),
                    size = Size(radius * 2f, radius * 2f),
                    style = Stroke(width = stroke, cap = StrokeCap.Round)
                )
            }
        }

        // 中心状态平滑过渡 (AnimatedContent)
        AnimatedContent(
            targetState = running,
            transitionSpec = {
                (fadeIn(animationSpec = tween(350)) + scaleIn(animationSpec = spring(stiffness = Spring.StiffnessMediumLow), initialScale = 0.88f))
                    .togetherWith(fadeOut(animationSpec = tween(250)) + scaleOut(animationSpec = tween(250), targetScale = 1.12f))
            },
            label = "orbCenterTransition"
        ) { isRunningState ->
            if (!isRunningState) {
                // 未连接:电源球体
                val powerBtnSize = (126f * scaleFactor).dp
                Box(
                    modifier = Modifier.size(powerBtnSize),
                    contentAlignment = Alignment.Center
                ) {
                    Image(
                        painter = painterResource(R.drawable.progress_btn_normal),
                        contentDescription = null,
                        modifier = Modifier.fillMaxSize()
                    )
                    Text(
                        text = "\ue640", // 原版电源(dianyuan),白色
                        fontFamily = IconFont,
                        fontSize = (42f * scaleFactor).sp,
                        color = Color.White
                    )
                }
            } else {
                // 连接中/已连接:呼吸状态点 + 标题 + 连接时长
                val dotColor = if (connecting) StatusConnecting else StatusConnected
                val statusText = if (connecting) stringResource(R.string.home_connecting)
                else stringResource(R.string.home_connected)

                val haloAlpha = if (!connecting) {
                    val breath = rememberInfiniteTransition(label = "connectedDotBreath")
                    breath.animateFloat(
                        initialValue = 0.28f,
                        targetValue = 0.05f,
                        animationSpec = infiniteRepeatable(
                            animation = tween(850, easing = LinearEasing),
                            repeatMode = RepeatMode.Reverse
                        ),
                        label = "connectedDotHaloAlpha"
                    ).value
                } else 0.28f

                Column(
                    horizontalAlignment = Alignment.CenterHorizontally,
                    modifier = Modifier.padding(horizontal = 8.dp)
                ) {
                    // 状态点(带呼吸光晕)
                    val dotContainerSize = (28f * scaleFactor).coerceAtLeast(20f).dp
                    val dotHaloSize = (24f * scaleFactor).coerceAtLeast(16f).dp
                    val dotInnerSize = (12f * scaleFactor).coerceAtLeast(8f).dp
                    Box(
                        contentAlignment = Alignment.Center,
                        modifier = Modifier.size(dotContainerSize)
                    ) {
                        Box(Modifier.size(dotHaloSize).background(dotColor.copy(alpha = haloAlpha), CircleShape))
                        Box(Modifier.size(dotInnerSize).background(dotColor, CircleShape))
                    }
                    Spacer(Modifier.height((10f * scaleFactor).coerceAtLeast(4f).dp))
                    Text(
                        text = statusText,
                        fontSize = (17f * scaleFactor).coerceAtLeast(13f).sp,
                        fontWeight = FontWeight.Bold,
                        color = PurpleDark
                    )
                    if (!connecting) {
                        Spacer(Modifier.height((6f * scaleFactor).coerceAtLeast(2f).dp))
                        Surface(
                            shape = RoundedCornerShape(12.dp),
                            color = PurpleSoft.copy(alpha = 0.12f),
                            modifier = Modifier.padding(horizontal = 4.dp)
                        ) {
                            Text(
                                text = formatElapsed(elapsedMs),
                                fontSize = (16f * scaleFactor).coerceAtLeast(12f).sp,
                                fontWeight = FontWeight.Bold,
                                color = PurpleDark,
                                modifier = Modifier.padding(
                                    horizontal = (10f * scaleFactor).coerceAtLeast(6f).dp,
                                    vertical = (3f * scaleFactor).coerceAtLeast(2f).dp
                                )
                            )
                        }
                    }
                }
            }
        }
    }
}

/** 液态玻璃圆角卡片开关(微交互物理弹性、晶莹半透明玻璃质感、微光高光边框与触觉反馈)。 */
@Composable
private fun SwitchCard(
    title: String,
    subtitle: String,
    checked: Boolean,
    enabled: Boolean = true,
    isCompact: Boolean = false,
    onDisabledClick: (() -> Unit)? = null,
    onCheckedChange: (Boolean) -> Unit,
    modifier: Modifier = Modifier
) {
    val haptic = LocalHapticFeedback.current
    val interactionSource = remember { MutableInteractionSource() }
    val isPressed by interactionSource.collectIsPressedAsState()

    // 按压弹性物理缩放
    val scale by animateFloatAsState(
        targetValue = if (isPressed && enabled) 0.965f else 1f,
        animationSpec = spring(
            dampingRatio = Spring.DampingRatioMediumBouncy,
            stiffness = Spring.StiffnessLow
        ),
        label = "switchCardScale"
    )

    // 禁用态点击处理
    val tapModifier = if (!enabled && onDisabledClick != null) {
        Modifier.clickable(
            interactionSource = interactionSource,
            indication = null
        ) {
            haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
            onDisabledClick()
        }
    } else Modifier

    GlassCard(
        shape = RoundedCornerShape(20.dp),
        isHighlighted = checked && enabled,
        modifier = modifier
            .fillMaxWidth()
            .padding(vertical = 4.dp)
            .scale(scale)
            .then(tapModifier)
    ) {
        Row(
            modifier = Modifier.padding(
                horizontal = if (isCompact) 12.dp else 16.dp,
                vertical = if (isCompact) 9.dp else 11.dp
            ),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(Modifier.weight(1f)) {
                Text(
                    text = title,
                    fontSize = if (isCompact) 13.5.sp else 15.sp,
                    color = if (enabled) PurpleDark else GreyText,
                    fontWeight = FontWeight.SemiBold
                )
                Spacer(Modifier.height(2.dp))
                Text(
                    text = subtitle,
                    fontSize = if (isCompact) 11.sp else 12.sp,
                    color = GreyText,
                    lineHeight = if (isCompact) 14.sp else 15.sp
                )
            }
            Switch(
                checked = checked,
                onCheckedChange = { newVal ->
                    haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                    onCheckedChange(newVal)
                },
                enabled = enabled,
                colors = SwitchDefaults.colors(
                    checkedThumbColor = Color.White,
                    checkedTrackColor = PurpleText,
                    uncheckedThumbColor = Color.White,
                    uncheckedTrackColor = DividerLine,
                    uncheckedBorderColor = SwitchBorder
                )
            )
        }
    }
}


/** 管理面板入口卡:URL(点击复制) + 账号密码提示(点击复制) + 二维码展开。 */
@Composable
private fun PanelCard(url: String?, auth: Pair<String, String>?, onCopy: (String) -> Unit) {
    val context = LocalContext.current
    val haptic = LocalHapticFeedback.current

    GlassCard(
        shape = RoundedCornerShape(24.dp),
        isHighlighted = false,
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 4.dp)
    ) {
        Column(Modifier.padding(16.dp)) {
            // 二维码太占版面:默认收起,卡片底部居中箭头展开/收起;箭头随状态旋转 180°。
            var showQr by remember { mutableStateOf(false) }
            val rotation by animateFloatAsState(
                targetValue = if (showQr) 180f else 0f,
                animationSpec = spring(
                    dampingRatio = Spring.DampingRatioMediumBouncy,
                    stiffness = Spring.StiffnessMediumLow
                ),
                label = "qrArrow"
            )
            Text(
                text = stringResource(R.string.panel_title),
                fontSize = 16.sp,
                fontWeight = FontWeight.Bold,
                color = PurpleDark
            )
            if (url != null) {
                Spacer(Modifier.height(6.dp))
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(8.dp))
                        .clickable {
                            haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                            onCopy(url)
                        }
                        .padding(vertical = 4.dp, horizontal = 2.dp)
                ) {
                    Text(
                        text = url,
                        fontSize = 13.sp,
                        color = PurpleDark,
                        fontWeight = FontWeight.Medium,
                        modifier = Modifier.weight(1f, fill = false)
                    )
                    Spacer(Modifier.width(8.dp))
                    Icon(
                        imageVector = Icons.Outlined.ContentCopy,
                        contentDescription = stringResource(R.string.panel_copy),
                        tint = PurpleSoft,
                        modifier = Modifier.size(15.dp)
                    )
                }
                if (auth != null) {
                    Spacer(Modifier.height(4.dp))
                    Column {
                        Text(
                            stringResource(R.string.panel_user, auth.first),
                            fontSize = 12.sp,
                            color = GreyText,
                            modifier = Modifier
                                .fillMaxWidth()
                                .clickable {
                                    haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                                    copyPanelCredential(context, auth.first, R.string.toast_copy_user)
                                }
                                .padding(vertical = 4.dp)
                        )
                        Text(
                            stringResource(R.string.panel_pass, auth.second),
                            fontSize = 12.sp,
                            color = GreyText,
                            modifier = Modifier
                                .fillMaxWidth()
                                .clickable {
                                    haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                                    copyPanelCredential(context, auth.second, R.string.toast_copy_pass)
                                }
                                .padding(vertical = 4.dp)
                        )
                    }
                }
                val qr = remember(url) { QrHelper.generate(url, 512) }
                AnimatedVisibility(
                    visible = showQr,
                    enter = fadeIn(animationSpec = tween(200)) +
                            expandVertically(animationSpec = spring(dampingRatio = Spring.DampingRatioLowBouncy)),
                    exit = fadeOut(animationSpec = tween(150)) +
                           shrinkVertically(animationSpec = spring(dampingRatio = Spring.DampingRatioNoBouncy))
                ) {
                    Column(
                        horizontalAlignment = Alignment.CenterHorizontally,
                        modifier = Modifier.fillMaxWidth().padding(top = 8.dp)
                    ) {
                        if (qr != null) {
                            Image(
                                bitmap = qr.asImageBitmap(),
                                contentDescription = stringResource(R.string.cd_panel_qr),
                                modifier = Modifier
                                    .size(180.dp)
                                    .clickable {
                                        haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                                        onCopy(url)
                                    }
                            )
                            Text(
                                text = stringResource(R.string.panel_scan_hint),
                                fontSize = 12.sp,
                                color = GreyText,
                                textAlign = TextAlign.Center
                            )
                        }
                    }
                }
                // 卡片底部居中的展开/收起箭头;仅在有二维码可展时显示。
                IconButton(
                    onClick = {
                        haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                        showQr = !showQr
                    },
                    modifier = Modifier
                        .align(Alignment.CenterHorizontally)
                        .size(28.dp)
                ) {
                    Icon(
                        imageVector = Icons.Filled.KeyboardArrowDown,
                        contentDescription = if (showQr) stringResource(R.string.cd_qr_collapse) else stringResource(R.string.cd_qr_expand),
                        tint = PurpleSoft,
                        modifier = Modifier.size(22.dp).rotate(rotation)
                    )
                }
            } else {
                Text(
                    text = stringResource(R.string.panel_no_url),
                    fontSize = 13.sp,
                    color = GreyText
                )
            }
        }
    }
}
