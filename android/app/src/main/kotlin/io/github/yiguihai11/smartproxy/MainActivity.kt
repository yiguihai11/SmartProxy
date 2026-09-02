package io.github.yiguihai11.smartproxy

import android.Manifest
import android.app.Activity
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
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
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.Animatable
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.tween
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.KeyboardArrowRight
import androidx.compose.material.icons.filled.KeyboardArrowDown
import androidx.compose.material.icons.filled.Menu
import androidx.compose.material.icons.outlined.BrightnessAuto
import androidx.compose.material.icons.outlined.DarkMode
import androidx.compose.material.icons.outlined.LightMode
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CenterAlignedTopAppBar
import androidx.compose.material3.DrawerValue
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalDrawerSheet
import androidx.compose.material3.ModalNavigationDrawer
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.material3.rememberDrawerState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.rotate
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.Font
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.lifecycle.lifecycleScope
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
                == PackageManager.PERMISSION_GRANTED &&
            !NotificationHelper.isForegroundNotificationVisible(this)
        ) {
            android.util.Log.i(
                "SmartProxyVpn",
                "[MainActivity] onResume: VPN running but keepalive notification gone, reposting foreground."
            )
            SmartProxyVpnService.refreshForeground(this)
        }
        io.github.yiguihai11.smartproxy.shizuku.TetheringCoreSync.onAppForegrounded(this)
    }

    private fun onToggleClicked() {
        val currentRunning = SmartProxyVpnService.isRunning.value
        android.util.Log.i("SmartProxyVpn", "[MainActivity] onToggleClicked() called. Current isRunning=$currentRunning")
        if (currentRunning) {
            android.util.Log.i("SmartProxyVpn", "[MainActivity] User requested STOP. Calling SmartProxyVpnService.stop(this)...")
            SmartProxyVpnService.stop(this)
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
        if (Build.VERSION.SDK_INT >= 33 &&
            ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS)
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
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) return
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

private fun copyPanelUrl(context: Context, url: String) {
    val cm = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
    cm.setPrimaryClip(ClipData.newPlainText("smartproxy_panel_url", url))
    Toast.makeText(context, context.getString(R.string.toast_copy_url, url), Toast.LENGTH_SHORT).show()
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

/** 主题切换图标(§7):auto = 自动(brightness-auto 半亮半暗),light = 太阳,dark = 月亮。
 *  图标随模式变化,标题栏右上钮一眼可见当前主题。 */
private fun themeIcon(mode: String): ImageVector = when (mode) {
    AppPrefs.THEME_LIGHT -> Icons.Outlined.LightMode
    AppPrefs.THEME_DARK -> Icons.Outlined.DarkMode
    else -> Icons.Outlined.BrightnessAuto
}

// ── 主题色(樱花粉,从紫色系整体换色)──────────────────────────────
// 浅/深两套(§7):getter 读 ThemeState.isDark 响应式切换,引用处零改动。
// 调色板:浅色强调 #D66E9B(深粉,白内容可读)/深色强调 #F6B8CF(浅粉,深底可读);
// 填充型容器(品牌块/按钮/FAB 的白图标)在深色下用更深一档 #C25E87,浅色沿用强调。
private val PurpleText get() = if (ThemeState.isDark) Color(0xFFF6B8CF) else Color(0xFFD66E9B) // 标题/强调
private val PurpleFill get() = if (ThemeState.isDark) Color(0xFFC25E87) else Color(0xFFD66E9B) // 填充容器(白内容)
private val PurpleDark get() = if (ThemeState.isDark) Color(0xFFF8CDDF) else Color(0xFFB3557F) // 面板文字
private val PurpleSoft get() = if (ThemeState.isDark) Color(0xFFE9A8C3) else Color(0xFFE88EAF) // 弱化箭头
private val StatusConnecting = Color(0xFFFF8413) // 连接中
private val StatusConnected = Color(0xFF2EBD85)  // 已连接
private val GreyText get() = if (ThemeState.isDark) Color(0xFFC9A8B6) else Color(0xFF7A626D)
private val TrackPink get() = if (ThemeState.isDark) Color(0xFF5A3A48) else Color(0xFFFAD4E3) // 圆环轨道
private val ArcOrange = Color(0xFFFF8413)
private val ArcYellow = Color(0xFFFFEB3C)
// 表面/分隔/开关轨道:深色模式换深色变体,保证卡片与抽屉不刺眼。
private val CardSurface get() = if (ThemeState.isDark) Color(0xFF38262F).copy(alpha = 0.90f) else Color.White.copy(alpha = 0.90f)
private val DrawerSurface get() = if (ThemeState.isDark) Color(0xFF32212A) else Color(0xFFFDF4F7)
private val DividerLine get() = if (ThemeState.isDark) Color(0xFF4A3741) else Color(0xFFF0DCE5)
private val SwitchBorder get() = if (ThemeState.isDark) Color(0xFF5A4250) else Color(0xFFE3C8D3)

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
private fun HomeScreen(
    onToggleVpn: () -> Unit,
    themeMode: String,
    onCycleTheme: () -> Unit,
    batteryDialogVisible: Boolean,
    onBatteryDialogDismiss: () -> Unit,
    onOpenBatterySettings: () -> Unit
) {
    val context = LocalContext.current
    val drawerState = rememberDrawerState(initialValue = DrawerValue.Closed)
    val scope = rememberCoroutineScope()

    // 面板 URL:局域网 IP 变化时在 onResume 刷新(§4.4 注意)。
    var panelUrl by remember { mutableStateOf(PanelUrl.url(context)) }
    // 面板账号密码:与 URL 同源(读 listen.admin_auth),onResume 一并刷新,
    // 在面板里改过密码后回首页能取到新值。
    var adminAuth by remember { mutableStateOf(ConfigProvider.adminAuth(context)) }
    val lifecycleOwner = LocalLifecycleOwner.current
    DisposableEffect(lifecycleOwner) {
        val observer = LifecycleEventObserver { _, event ->
            if (event == Lifecycle.Event.ON_RESUME) {
                panelUrl = PanelUrl.url(context)
                adminAuth = ConfigProvider.adminAuth(context)
            }
        }
        lifecycleOwner.lifecycle.addObserver(observer)
        onDispose { lifecycleOwner.lifecycle.removeObserver(observer) }
    }

    // DNS / 排除路由 / 服务模式 / 网络共享设置对话框开关(侧边栏菜单打开,§6 / §8)。
    var showDnsDialog by remember { mutableStateOf(false) }
    var showExcludeDialog by remember { mutableStateOf(false) }
    var showServiceModeDialog by remember { mutableStateOf(false) }
    var showTetheringDialog by remember { mutableStateOf(false) }

    // DNS / 排除路由在 establish() 时固化(读 AppPrefs),改了要重建 VpnService 才生效;
    // 两者是 App 层设置,Go watcher 不感知。VPN 在跑则显式重建(SmartProxyVpnService.restart
    // 主线程原子停→建);未在跑时只落盘,下次启动自然生效。
    fun applyVpnSettings() {
        if (SmartProxyVpnService.isRunning.value) {
            SmartProxyVpnService.restart(context)
        }
    }

    ModalNavigationDrawer(
        drawerState = drawerState,
        drawerContent = {
            AppDrawerContent(
                onOpenApps = {
                    scope.launch { drawerState.close() }
                    context.startActivity(Intent(context, AppSelectionActivity::class.java))
                },
                onOpenDns = {
                    scope.launch { drawerState.close() }
                    showDnsDialog = true
                },
                onOpenExclude = {
                    scope.launch { drawerState.close() }
                    showExcludeDialog = true
                },
                onOpenServiceMode = {
                    scope.launch { drawerState.close() }
                    showServiceModeDialog = true
                },
                onOpenTethering = {
                    scope.launch { drawerState.close() }
                    showTetheringDialog = true
                },
                onOpenNetworkStatus = {
                    scope.launch { drawerState.close() }
                    context.startActivity(Intent(context, NetworkStatusActivity::class.java))
                },
                onOpenLogcat = {
                    scope.launch { drawerState.close() }
                    context.startActivity(Intent(context, LogcatActivity::class.java))
                }
            )
        }
    ) {
        HomeLauncher(
            panelUrl = panelUrl,
            adminAuth = adminAuth,
            onToggleVpn = onToggleVpn,
            onOpenDrawer = { scope.launch { drawerState.open() } },
            themeMode = themeMode,
            onCycleTheme = onCycleTheme
        )
    }

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
            initial = AppPrefs.serviceMode(context),
            onDismiss = { showServiceModeDialog = false },
            onSave = { mode ->
                showServiceModeDialog = false
                AppPrefs.setServiceMode(context, mode)
                applyVpnSettings()
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

/** 侧边栏抽屉菜单内容 */
@Composable
private fun AppDrawerContent(
    onOpenApps: () -> Unit,
    onOpenDns: () -> Unit,
    onOpenExclude: () -> Unit,
    onOpenServiceMode: () -> Unit,
    onOpenTethering: () -> Unit,
    onOpenLogcat: () -> Unit,
    onOpenNetworkStatus: () -> Unit
) {
    val context = LocalContext.current
    // 服务模式做成可观察 state(见 rememberServiceMode):切模式后抽屉菜单/副标题实时刷新,
    // 否则 drawerContent 被 Compose 跳过(skipping),隐藏菜单不恢复、副标题不更新(§8)。
    val serviceMode = rememberServiceMode()
    // 联网状态门控 = VPN 运行中 && 仅绕过(黑名单)模式:仅绕过下应用分流行为与「联网状态」
    // 的按应用维度展示最相关;白名单模式隐藏入口(设计定稿 §6.1)。
    val vpnRunning by SmartProxyVpnService.isRunning.collectAsState()

    ModalDrawerSheet(
        drawerContainerColor = DrawerSurface,
        drawerShape = RoundedCornerShape(topEnd = 24.dp, bottomEnd = 24.dp),
        modifier = Modifier.width(300.dp)
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .safeDrawingPadding()
                .padding(20.dp)
        ) {
            // 抽屉头部品牌区
            Row(verticalAlignment = Alignment.CenterVertically) {
                Surface(
                    shape = RoundedCornerShape(14.dp),
                    color = PurpleFill,
                    modifier = Modifier.size(46.dp)
                ) {
                    Box(contentAlignment = Alignment.Center) {
                        Text(
                            text = "\ue640", // 电源/VPN 图形
                            fontFamily = IconFont,
                            fontSize = 24.sp,
                            color = Color.White
                        )
                    }
                }
                Spacer(Modifier.width(14.dp))
                Column {
                    Text(
                        text = "SmartProxy",
                        fontSize = 18.sp,
                        fontWeight = FontWeight.Bold,
                        color = PurpleDark
                    )
                    Text(
                        text = stringResource(R.string.drawer_tagline),
                        fontSize = 12.sp,
                        color = GreyText
                    )
                }
            }

            Spacer(Modifier.height(20.dp))
            HorizontalDivider(color = DividerLine, thickness = 1.dp)
            Spacer(Modifier.height(16.dp))

            Text(
                text = stringResource(R.string.drawer_section_menu),
                fontSize = 12.sp,
                fontWeight = FontWeight.SemiBold,
                color = PurpleSoft,
                modifier = Modifier.padding(horizontal = 4.dp, vertical = 4.dp)
            )
            Spacer(Modifier.height(6.dp))

            // 侧边栏菜单项：分应用代理 (Apps)(per-app 分流走 VpnService.Builder、禁止联网
            // 走 TUN 数据路径,仅 VPN 隧道模式生效;仅代理 SOCKS5 无 VpnService,入口一并
            // 隐藏(§8)。规则仍留在 AppPrefs,切回 VPN 模式照常生效。)
            if (serviceMode == AppPrefs.MODE_VPN) {
                DrawerMenuItem(
                    title = stringResource(R.string.drawer_apps),
                    subtitle = stringResource(R.string.drawer_apps_subtitle),
                    onClick = onOpenApps
                )
            }

            // 侧边栏菜单项：DNS 服务器(builder.addDnsServer,仅 VPN 隧道模式生效;仅代理
            // SOCKS5 无 VpnService,注入不发生,入口一并隐藏(§6.1))。设置存 AppPrefs,
            // 切换服务模式不丢,回 VPN 模式照常注入。
            if (serviceMode == AppPrefs.MODE_VPN) {
                DrawerMenuItem(
                    title = stringResource(R.string.drawer_dns),
                    subtitle = stringResource(R.string.drawer_dns_subtitle),
                    onClick = onOpenDns
                )
            }

            // 侧边栏菜单项：排除路由(builder.excludeRoute,仅 VPN 隧道模式 + API 33+ 特性;
            // 仅代理 SOCKS5 无 VpnService,excludeRoute 不生效,入口一并隐藏(§6.1))。
            if (serviceMode == AppPrefs.MODE_VPN && Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                DrawerMenuItem(
                    title = stringResource(R.string.drawer_exclude),
                    subtitle = stringResource(R.string.drawer_exclude_subtitle),
                    onClick = onOpenExclude
                )
            }

            // 侧边栏菜单项：服务模式(VPN 隧道 / 仅代理 SOCKS5,§8)。副标题实时显示当前模式。
            DrawerMenuItem(
                title = stringResource(R.string.drawer_service_mode),
                subtitle = stringResource(R.string.drawer_service_mode_subtitle, serviceModeLabel(context, serviceMode)),
                onClick = onOpenServiceMode
            )

            // 侧边栏菜单项：网络共享 (Shizuku 免 Root 共享代理至热点/USB, Android 13+ 支持)。
            // 只挂 TUN 数据路径(Shizuku 读 TUN fd 转发到热点),仅代理(SOCKS5)模式无 TUN 可
            // 共享,入口一并隐藏(§6.1)。
            if (serviceMode == AppPrefs.MODE_VPN && Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                DrawerMenuItem(
                    title = stringResource(R.string.drawer_tethering),
                    subtitle = stringResource(R.string.drawer_tethering_subtitle),
                    onClick = onOpenTethering
                )
            }

            // 侧边栏菜单项：联网状态(仅 VPN 隧道服务模式 + 仅绕过 + 运行中才出现;懒采集,页面开才统计)
            // 连接监控只挂在 TUN 数据路径,仅代理(SOCKS5)模式监控恒空,入口一并隐藏(§6.1)。
            if (serviceMode == AppPrefs.MODE_VPN && vpnRunning && AppPrefs.globalMode(context)) {
                DrawerMenuItem(
                    title = stringResource(R.string.drawer_network_status),
                    subtitle = stringResource(R.string.drawer_network_status_subtitle),
                    onClick = onOpenNetworkStatus
                )
            }

            // 侧边栏菜单项：日志查看(本进程 logcat,Debug 级)
            DrawerMenuItem(
                title = stringResource(R.string.drawer_logcat),
                subtitle = stringResource(R.string.drawer_logcat_subtitle),
                onClick = onOpenLogcat
            )

            Spacer(Modifier.weight(1f))

            // 底部版本与架构信息(版本行可点击打开项目主页)
            Box(
                modifier = Modifier.fillMaxWidth(),
                contentAlignment = Alignment.Center
            ) {
                Text(
                    text = "SmartProxy for Android",
                    fontSize = 12.sp,
                    color = PurpleSoft,
                    textAlign = TextAlign.Center,
                    modifier = Modifier.clickable { openProjectUrl(context) }
                )
            }
            Spacer(Modifier.height(4.dp))
            Text(
                text = stringResource(R.string.drawer_footer_tagline),
                fontSize = 11.sp,
                color = GreyText.copy(alpha = 0.7f),
                textAlign = TextAlign.Center,
                modifier = Modifier.fillMaxWidth()
            )
        }
    }
}

/** 侧边栏菜单按钮项 */
@Composable
private fun DrawerMenuItem(
    title: String,
    subtitle: String,
    onClick: () -> Unit
) {
    Card(
        onClick = onClick,
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(containerColor = CardSurface),
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 5.dp)
    ) {
        Row(
            modifier = Modifier.padding(horizontal = 16.dp, vertical = 12.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(Modifier.weight(1f)) {
                Text(title, fontSize = 15.sp, color = PurpleDark, fontWeight = FontWeight.Medium)
                Text(subtitle, fontSize = 12.sp, color = GreyText)
            }
            Icon(
                imageVector = Icons.AutoMirrored.Filled.KeyboardArrowRight,
                contentDescription = null,
                tint = PurpleSoft,
                modifier = Modifier.size(20.dp)
            )
        }
    }
}

/** 首页主体内容(抽屉 HomeScreen 的内层):背景 + 标题栏(左菜单按钮开抽屉)+ 状态行 +
 *  圆环 + 开关卡 + 面板卡(仅 VPN 运行时显示)。侧边栏功能(Apps / DNS / 排除路由)在 HomeScreen 抽屉。 */
@Composable
private fun HomeLauncher(
    panelUrl: String?,
    adminAuth: Pair<String, String>?,
    onToggleVpn: () -> Unit,
    onOpenDrawer: () -> Unit,
    themeMode: String,
    onCycleTheme: () -> Unit
) {
    val context = LocalContext.current
    val running by SmartProxyVpnService.isRunning.collectAsState()

    // 服务模式做成可观察 state(见 rememberServiceMode):切模式后监听开关的语义副标题
    // (开机自启文案等)实时刷新,否则 HomeLauncher 组合被跳过时读旧值(§8)。
    val serviceMode = rememberServiceMode()

    // 开关语义随服务模式(§8):VPN 隧道 = 拦截(tun.inet4/6_address,config.json 真源);
    // 仅代理(SOCKS5) = 监听(AppPrefs.socksListen → listen.host,首页与面板同源)。
    // remember 以 socksMode 为 key:切换服务模式时重新读真源,不残留旧模式的显示态。
    val socksMode = serviceMode == AppPrefs.MODE_SOCKS5
    var ipv4 by remember(socksMode) { mutableStateOf(
        if (socksMode) AppPrefs.socksListen(context) != AppPrefs.SOCKS_LISTEN_V6
        else ConfigProvider.ipv4(context)
    ) }
    var ipv6 by remember(socksMode) { mutableStateOf(
        if (socksMode) AppPrefs.socksListen(context) != AppPrefs.SOCKS_LISTEN_V4
        else ConfigProvider.ipv6(context)
    ) }
    var bootAuto by remember { mutableStateOf(AppPrefs.bootAutoStart(context)) }

    // 悬浮网速计开关(首页右侧半卡,与开机自启各占半宽):仅 VPN 隧道模式有意义 —— 按应用
    // 统计只挂 TUN 数据路径,仅代理(SOCKS5)模式禁用置灰。开启需悬浮窗权限:无权限先跳
    // 系统设置授权,返回回调按授权结果置位;已授权且 VPN 在跑则立即显示胶囊,否则只落盘,
    // 下次连接由服务 autoShow 拉起。关闭即撤胶囊。socksMode 下 enabled=false 点卡片弹提示。
    var speedMeterOn by remember { mutableStateOf(AppPrefs.speedMeterEnabled(context)) }
    // 悬浮窗授权回调里/开关开启时:缺「使用情况访问权限」就弹 M3 说明对话框(见下方 Box 内)。
    var showUsageAccessDialog by remember { mutableStateOf(false) }
    val overlayPermLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) {
        // 系统悬浮窗设置页不回传 resultCode,直接按当前授权状态定夺:授权了才真正打开。
        if (Settings.canDrawOverlays(context)) {
            speedMeterOn = true
            AppPrefs.setSpeedMeterEnabled(context, true)
            if (running) SpeedMeterOverlay.autoShow(context)
            // 前台应用判定还需「使用情况访问权限」:顺带引导(不阻塞,未授权退回流量最大)。
            if (SpeedMeterOverlay.needsUsageAccess(context)) showUsageAccessDialog = true
        } else {
            speedMeterOn = false // 用户未授权:开关回弹为关
        }
    }

    // 连接进度弧:运行中扫 0→360°,扫完前状态显示"连接中"。
    val sweep = remember { Animatable(0f) }
    LaunchedEffect(running) {
        sweep.animateTo(if (running) 360f else 0f, animationSpec = tween(1200))
    }
    val connecting = running && sweep.value < 355f

    // 连接时长(§圆环):每秒 tick,读服务端会话启动时刻算 elapsed。running 变 false 时
    // LaunchedEffect 重启不进入循环,计时停;重建(fullTeardown=false)不重置 startedAt。
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

    Box(modifier = Modifier.fillMaxSize()) {
        if (ThemeState.isDark) {
            // 深色模式(§7):樱花粉深色渐变,夜间不刺眼。
            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .background(
                        Brush.verticalGradient(listOf(Color(0xFF2B1A22), Color(0xFF3D2430)))
                    )
            )
        } else {
            // 浅色背景(樱花粉):原 bg_main.jpg 图换成同源代码渐变,顶部同样色系。
            // 原图只有 10×100(淡紫上下渐变),代码渐变更高清、天然适配任意屏幕。
            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .background(
                        Brush.verticalGradient(listOf(Color(0xFFFFF5F9), Color(0xFFFCE0EC)))
                    )
            )
        }
        Column(
            modifier = Modifier
                .fillMaxSize()
                .safeDrawingPadding()
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 20.dp, vertical = 16.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            // ── 标题栏:M3 CenterAlignedTopAppBar(左菜单按钮 + 居中标题 + 右上主题切换)。
            // windowInsets=0 交给外层 safeDrawingPadding 统一让位,避免双份状态栏 inset;
            // 容器透明保留首页渐变,icon/标题色沿用品牌紫。 ──
            CenterAlignedTopAppBar(
                title = {
                    Text(
                        text = "SmartProxy",
                        fontSize = 18.sp,
                        fontWeight = FontWeight.Bold,
                        color = PurpleText
                    )
                },
                navigationIcon = {
                    IconButton(onClick = onOpenDrawer) {
                        Icon(Icons.Filled.Menu, contentDescription = stringResource(R.string.cd_open_menu), tint = PurpleText)
                    }
                },
                // 主题切换钮(§7):按模式显太阳/月亮/自动图标,点击循环切换(auto→浅→深),
                // 图标随模式变化,状态一目了然。
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
                // centerAlignedTopAppBarColors 已废弃(官方提示用 topAppBarColors 代替),
                // 两者返回同型 TopAppBarColors,行为一致。
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = Color.Transparent,
                    navigationIconContentColor = PurpleText,
                    titleContentColor = PurpleText,
                    actionIconContentColor = PurpleText
                )
            )
            Spacer(Modifier.height(24.dp))

            // ── 大圆环 + 中心状态区 ──────────────────────────────
            // 未连接:中心电源球体;连接中/已连接:状态点+文字+时长。状态显示并入
            // 圆环中心(§效果图),不再单独状态行。点按整环启停。
            ConnectOrb(
                running = running,
                connecting = connecting,
                sweep = sweep.value,
                elapsedMs = elapsedMs,
                onToggleVpn = onToggleVpn
            )
            Spacer(Modifier.height(30.dp))

            // ── 开关卡:IPv4 / IPv6 左右各半;开机自启(Apps 已移至侧边栏菜单)──
            // 语义随服务模式(§8):VPN 隧道 = 拦截(tun.inet4/6_address);仅代理(SOCKS5) =
            // 监听(AppPrefs.socksListen → listen.host:双开/只 v6="::"、只 v4="0.0.0.0"。
            // Go net.Listen 对 "::" 默认双栈,只 v6 实际仍收 v4-mapped,与双开等价)。
            // 守卫:两个族不能同时关 —— VPN 的 VpnService.Builder 至少要一个 addAddress,
            // 否则 establish() 抛 IllegalArgumentException;仅代理也要有监听地址。
            // 运行中改都走显式重建(Go watcher 自动重启已删除);restart() 自带 isRunning
            // 守卫,未在跑只落盘。拦在开关这一层,checked 是受控 state,不更新即回弹。
            val vpnIntercept = !socksMode
            Row(modifier = Modifier.fillMaxWidth()) {
                SwitchCard(
                    title = if (vpnIntercept) stringResource(R.string.home_ipv4_intercept) else stringResource(R.string.home_ipv4_listen),
                    subtitle = if (vpnIntercept) stringResource(R.string.home_ipv4_intercept_sub) else stringResource(R.string.home_ipv4_listen_sub),
                    checked = ipv4,
                    onCheckedChange = { v ->
                        if (!v && !ipv6) {
                            Toast.makeText(context, context.getString(R.string.toast_need_ipv46), Toast.LENGTH_SHORT).show()
                            return@SwitchCard
                        }
                        ipv4 = v
                        if (vpnIntercept) {
                            // 写 config.json tun.inet4_address(§4.6),运行中显式重建才生效。
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
                    subtitle = if (vpnIntercept) stringResource(R.string.home_ipv6_intercept_sub) else stringResource(R.string.home_ipv6_listen_sub),
                    checked = ipv6,
                    onCheckedChange = { v ->
                        if (!v && !ipv4) {
                            Toast.makeText(context, context.getString(R.string.toast_need_ipv46), Toast.LENGTH_SHORT).show()
                            return@SwitchCard
                        }
                        ipv6 = v
                        if (vpnIntercept) {
                            ConfigProvider.setIpv6(context, v)
                        } else {
                            AppPrefs.setSocksListen(context, when {
                                ipv4 && v -> AppPrefs.SOCKS_LISTEN_BOTH
                                v -> AppPrefs.SOCKS_LISTEN_V6
                                else -> AppPrefs.SOCKS_LISTEN_V4
                            })
                        }
                        SmartProxyVpnService.restart(context)
                    },
                    modifier = Modifier.weight(1f)
                )
            }
            // 开机自启 | 悬浮网速计:与上面 IPv4/IPv6 同款「左右各半」布局。悬浮网速计仅
            // VPN 隧道模式可用(按应用统计挂 TUN 数据路径),仅代理 SOCKS5 模式整卡置灰,
            // 点了 Toast 提示;开启时若还没悬浮窗权限走系统授权,授权成功才真正置位。
            Row(modifier = Modifier.fillMaxWidth()) {
                SwitchCard(
                    title = stringResource(R.string.home_boot_autostart),
                    subtitle = if (serviceMode == AppPrefs.MODE_VPN)
                        stringResource(R.string.home_boot_autostart_sub_vpn) else stringResource(R.string.home_boot_autostart_sub_socks),
                    checked = bootAuto,
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
                    onDisabledClick = {
                        Toast.makeText(context, context.getString(R.string.toast_speed_meter_vpn_only), Toast.LENGTH_SHORT).show()
                    },
                    onCheckedChange = { want ->
                        if (want) {
                            if (Settings.canDrawOverlays(context)) {
                                speedMeterOn = true
                                AppPrefs.setSpeedMeterEnabled(context, true)
                                if (running) SpeedMeterOverlay.autoShow(context)
                                // 前台应用判定需「使用情况访问权限」:引导授权(不阻塞,未授权退回流量最大)。
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
                        }
                    },
                    modifier = Modifier.weight(1f)
                )
            }
            Spacer(Modifier.height(24.dp))

            // ── 管理面板卡(服务运行中且面板可达才显示)。panelUrl==null 涵盖两种:
            //  admin_port 空(引擎没开面板)、VPN 模式拿不到局域网 IP——都不给死链/空卡。
            //  仅代理模式 URL=127.0.0.1,QR 跨设备扫到的是扫描机自己,只能本机开面板;
            //  VPN 模式 smartproxy.lan 可跨设备扫 QR。────────
            if (running && panelUrl != null) {
                PanelCard(url = panelUrl, auth = adminAuth, onCopy = { url -> copyPanelUrl(context, url) }, onOpen = { url -> openPanel(context, url) })
                Spacer(Modifier.height(8.dp))
            }
        }

        // 「使用情况访问权限」说明对话框(M3):开启悬浮网速计且前台应用判定缺权限时弹出。
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

/** 排除路由默认项:回环段——VPN 隧道内本地服务(SOCKS :1080 / 管理面板)留在本机。
 *  仅当用户排除列表为空时预填进输入框;已有自定义路由则不打扰。 */
private const val DEFAULT_EXCLUDE_ROUTE = "127.0.0.1/8"

/** 排除路由设置对话框(API 33+ builder.excludeRoute):每行一个 CIDR,不走 VPN 隧道直连。 */
@Composable
private fun ExcludeRoutesDialog(
    initialRoutes: List<String>,
    onDismiss: () -> Unit,
    onSave: (Set<String>) -> Unit
) {
    // 空列表 → 预填默认回环排除(用户可删可改);非空 → 原样显示现有路由。
    val initialText = if (initialRoutes.isEmpty()) DEFAULT_EXCLUDE_ROUTE else initialRoutes.joinToString("\n")
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

/** 服务模式设置对话框(§8):模态下拉选 VPN 隧道 / 仅代理(SOCKS5)。仅代理 = 不启动
 *  VPN 模式,仅用引擎 SOCKS5(:1080,全接口双栈,局域网可访问)。改动由调用方落盘,
 *  运行中切换自动重启生效。 */
@Composable
private fun ServiceModeDialog(
    initial: String,
    onDismiss: () -> Unit,
    onSave: (String) -> Unit
) {
    var selected by remember { mutableStateOf(initial) }
    var expanded by remember { mutableStateOf(false) }
    val context = LocalContext.current
    val options = listOf(AppPrefs.MODE_VPN, AppPrefs.MODE_SOCKS5)
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.drawer_service_mode)) },
        text = {
            Column {
                // 下拉:点击 Surface 展开稳定版 DropdownMenu。不用 ExposedDropdownMenuBox——
                // 其 ExposedDropdownMenuAnchorType 在低版本 material3 没有(CI 实测 BOM 解析
                // 的版本即缺),稳定版 DropdownMenu 全版本兼容。
                Box {
                    Surface(
                        onClick = { expanded = !expanded },
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
                                serviceModeLabel(context, selected),
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
                    DropdownMenu(expanded = expanded, onDismissRequest = { expanded = false }) {
                        options.forEach { mode ->
                            DropdownMenuItem(
                                text = { Text(serviceModeLabel(context, mode)) },
                                onClick = {
                                    selected = mode
                                    expanded = false
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
        confirmButton = { TextButton(onClick = { onSave(selected) }) { Text(stringResource(R.string.btn_save)) } },
        dismissButton = { TextButton(onClick = onDismiss) { Text(stringResource(R.string.btn_cancel)) } }
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

/** 大圆环:浅粉轨道 + 橙→黄渐变进度弧 + 中心状态区。点按整环启停。
 *  未连接:中心为电源球体(1:1 原版素材 progress_btn_normal.png + 白色电源字形,保持原样);
 *  连接中/已连接:中心换成 状态点(橙/绿)+ 状态文字 + 连接时长(§圆环效果图样式)。 */
@Composable
private fun ConnectOrb(
    running: Boolean,
    connecting: Boolean,
    sweep: Float,
    elapsedMs: Long,
    onToggleVpn: () -> Unit
) {
    Box(
        contentAlignment = Alignment.Center,
        modifier = Modifier
            .size(214.dp)
            .clickable { onToggleVpn() }
    ) {
        Canvas(modifier = Modifier.fillMaxSize()) {
            val stroke = 12.dp.toPx()
            val radius = (size.minDimension - stroke) / 2f
            val center = this.center
            // 浅粉轨道(整圈)
            drawCircle(color = TrackPink, radius = radius, style = Stroke(width = stroke))
            // 进度弧:橙色→黄色,连接时从顶开始顺时针扫过;未连接为 0。
            if (sweep > 0f) {
                drawArc(
                    brush = Brush.sweepGradient(listOf(ArcOrange, ArcYellow)),
                    startAngle = -90f,
                    sweepAngle = sweep,
                    useCenter = false,
                    topLeft = Offset(center.x - radius, center.y - radius),
                    size = Size(radius * 2f, radius * 2f),
                    style = Stroke(width = stroke, cap = StrokeCap.Round)
                )
            }
        }
        if (!running) {
            // 未连接:电源球体(启停点击区域是整个圆环,点哪都触发)。
            Box(
                modifier = Modifier.size(121.dp),
                contentAlignment = Alignment.Center
            ) {
                Image(
                    painter = painterResource(R.drawable.progress_btn_normal),
                    contentDescription = null,
                    modifier = Modifier.fillMaxSize()
                )
                Text(
                    text = "\ue640",                     // 原版电源(dianyuan),白色
                    fontFamily = IconFont,
                    fontSize = 40.sp,
                    color = Color.White
                )
            }
        } else {
            // 连接中/已连接:状态点 + 文字 + 连接时长。
            val dotColor = if (connecting) StatusConnecting else StatusConnected
            val statusText = if (connecting) stringResource(R.string.home_connecting)
            else stringResource(R.string.home_connected)
            // 已连接绿点呼吸动画:光晕 alpha 在 0.22 ↔ 0.05 间往复(约 1.6s 一个周期),
            // 模拟"心跳"提示运行中;连接中橙点保持静态。
            val haloAlpha = if (!connecting) {
                val breath = rememberInfiniteTransition(label = "connectedDotBreath")
                breath.animateFloat(
                    initialValue = 0.22f,
                    targetValue = 0.05f,
                    animationSpec = infiniteRepeatable(
                        animation = tween(800, easing = LinearEasing),
                        repeatMode = RepeatMode.Reverse
                    ),
                    label = "connectedDotHaloAlpha"
                ).value
            } else 0.22f
            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                // 状态点(带一圈同色光晕,对齐效果图)
                Box(
                    contentAlignment = Alignment.Center,
                    modifier = Modifier.size(26.dp)
                ) {
                    Box(Modifier.size(22.dp).background(dotColor.copy(alpha = haloAlpha), CircleShape))
                    Box(Modifier.size(11.dp).background(dotColor, CircleShape))
                }
                Spacer(Modifier.height(10.dp))
                Text(statusText, fontSize = 17.sp, fontWeight = FontWeight.Bold, color = PurpleDark)
                if (!connecting) {
                    Spacer(Modifier.height(5.dp))
                    Text(
                        formatElapsed(elapsedMs),
                        fontSize = 17.sp,
                        fontWeight = FontWeight.Bold,
                        color = GreyText
                    )
                }
            }
        }
    }
}

/** 白色圆角卡片开关(紫色强调)。 */
@Composable
private fun SwitchCard(
    title: String,
    subtitle: String,
    checked: Boolean,
    enabled: Boolean = true,
    onDisabledClick: (() -> Unit)? = null,
    onCheckedChange: (Boolean) -> Unit,
    modifier: Modifier = Modifier
) {
    // 禁用态(onDisabledClick 提供):开关置灰不可拨,整卡可点弹提示(拦截开关在仅代理
    // 模式点不动,Toast 提示仅 VPN 隧道模式生效;enabled=true 时本 modifier 为空,零开销)。
    val tapModifier = if (!enabled && onDisabledClick != null) {
        Modifier.clickable { onDisabledClick() }
    } else Modifier
    Card(
        shape = RoundedCornerShape(20.dp),
        colors = CardDefaults.cardColors(containerColor = CardSurface),
        modifier = modifier
            .fillMaxWidth()
            .padding(vertical = 4.dp)
            .then(tapModifier)
    ) {
        Row(
            modifier = Modifier.padding(horizontal = 16.dp, vertical = 10.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(Modifier.weight(1f)) {
                Text(title, fontSize = 16.sp, color = if (enabled) PurpleDark else GreyText, fontWeight = FontWeight.Medium)
                Text(subtitle, fontSize = 12.sp, color = GreyText)
            }
            Switch(
                checked = checked,
                onCheckedChange = onCheckedChange,
                enabled = enabled,
                // ON/OFF 对比分明:ON = 实心紫轨道 + 白拇指;OFF = 浅紫灰轨道 + 白拇指。
                // 此前 ON 轨道用默认浅紫(≈#E8DEF8)+ 中紫拇指,白卡上浅紫对浅紫糊成一团。
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


/** 管理面板入口卡:URL + 账号密码提示 + 复制 + 浏览器选择器;二维码默认折叠,点卡片
 *  底部居中箭头展开(§4.4)。auth 非空(admin_auth 启用)时在 URL 下方显示登录凭据。 */
@Composable
private fun PanelCard(url: String?, auth: Pair<String, String>?, onCopy: (String) -> Unit, onOpen: (String) -> Unit) {
    Card(
        shape = RoundedCornerShape(24.dp),
        colors = CardDefaults.cardColors(containerColor = CardSurface),
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 4.dp)
    ) {
        Column(Modifier.padding(16.dp)) {
            // 二维码太占版面:默认收起,卡片底部居中箭头展开/收起;箭头随状态旋转 180°。
            var showQr by remember { mutableStateOf(false) }
            val rotation by animateFloatAsState(
                targetValue = if (showQr) 180f else 0f,
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
                Text(url, fontSize = 13.sp, color = GreyText)
                if (auth != null) {
                    Spacer(Modifier.height(6.dp))
                    // 出厂随机密码人手记不住:长按选中即可复制账号/密码(不进 URL、不进 QR)。
                    SelectionContainer {
                        Column {
                            Text(stringResource(R.string.panel_user, auth.first), fontSize = 12.sp, color = GreyText)
                            Text(stringResource(R.string.panel_pass, auth.second), fontSize = 12.sp, color = GreyText)
                        }
                    }
                }
                Spacer(Modifier.height(10.dp))
                Row {
                    OutlinedButton(onClick = { onCopy(url) }, modifier = Modifier.weight(1f)) {
                        Text(stringResource(R.string.panel_copy))
                    }
                    Spacer(Modifier.width(8.dp))
                    Button(onClick = { onOpen(url) }, modifier = Modifier.weight(1f)) {
                        Text(stringResource(R.string.panel_open))
                    }
                }
                Spacer(Modifier.height(12.dp))
                val qr = remember(url) { QrHelper.generate(url, 512) }
                // QR 块整体折叠:AnimatedVisibility 包住图片+提示,展开/收起平滑;
                // qr 照常生成(不为 null 才渲染),退出动画期间图片不会提前消失。
                // 内层 Column fillMaxWidth + CenterHorizontally:180dp 图在卡片内真正居中。
                AnimatedVisibility(visible = showQr) {
                    Column(
                        horizontalAlignment = Alignment.CenterHorizontally,
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        if (qr != null) {
                            Image(
                                bitmap = qr.asImageBitmap(),
                                contentDescription = stringResource(R.string.cd_panel_qr),
                                modifier = Modifier
                                    .size(180.dp)
                                    .clickable { onOpen(url) }
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
                    onClick = { showQr = !showQr },
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
