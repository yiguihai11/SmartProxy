package io.github.yiguihai11.smartproxy

import android.Manifest
import android.app.Activity
import android.app.AlertDialog
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.PowerManager
import android.provider.Settings
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.Animatable
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.tween
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
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
import androidx.compose.material3.Button
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
import androidx.compose.ui.layout.ContentScale
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
import kotlinx.coroutines.launch

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
                    }
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
     *   - 其它厂商:AOSP「忽略电池优化」系统弹框,已豁免即跳过。
     *  已引导满 MAX_BATTERY_OPT_ASKS 次则整体跳过,防误触无限弹。 */
    private fun maybeRequestBatteryOptimizationExemption() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) return
        if (AppPrefs.batteryOptAskCount(this) >= MAX_BATTERY_OPT_ASKS) return
        val pm = getSystemService(Context.POWER_SERVICE) as PowerManager
        if (!isOriginOS() && pm.isIgnoringBatteryOptimizations(packageName)) return
        AppPrefs.setBatteryOptAskCount(this, AppPrefs.batteryOptAskCount(this) + 1)
        if (isOriginOS()) {
            originOSBatteryGuidance()
        } else {
            runCatching {
                startActivity(Intent(
                    Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS,
                    Uri.parse("package:$packageName")
                ))
            }.onFailure {
                android.util.Log.w("SmartProxyVpn", "[MainActivity] Battery-optimization dialog unavailable: ${it.message}")
            }
        }
    }

    /** OriginOS(vivo/iQOO,含 bbk 系)智能冻结独立于 AOSP 豁免,引导到本应用详情页
     *  (耗电管理→允许后台运行)——无公共 Intent 直达省电策略,应用详情页是最可靠入口。 */
    private fun originOSBatteryGuidance() {
        val intent = Intent(
            Settings.ACTION_APPLICATION_DETAILS_SETTINGS,
            Uri.parse("package:$packageName")
        )
        AlertDialog.Builder(this)
            .setTitle(getString(R.string.battery_title))
            .setMessage(getString(R.string.battery_message))
            .setPositiveButton(getString(R.string.battery_settings)) { _, _ ->
                runCatching { startActivity(intent) }.onFailure {
                    android.util.Log.w("SmartProxyVpn", "[MainActivity] App-details settings unavailable: ${it.message}")
                }
            }
            .setNegativeButton(getString(R.string.battery_dismiss), null)
            .show()
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

// ── 主题色(逆向自 Ultimate VPN Free 的 colors.xml)──────────────────────
// 浅/深两套(§7):getter 读 ThemeState.isDark 响应式切换,引用处零改动。
private val PurpleText get() = if (ThemeState.isDark) Color(0xFFC9A9E8) else Color(0xFF7850AA) // 标题/强调
private val PurpleDark get() = if (ThemeState.isDark) Color(0xFFD7C3EE) else Color(0xFF613D8D) // 面板文字
private val PurpleSoft get() = if (ThemeState.isDark) Color(0xFFAA92CC) else Color(0xFF9A80BA) // 弱化箭头
private val StatusIdle = Color(0xFFE87C7C)       // 未连接(状态语义色,两主题一致)
private val StatusConnecting = Color(0xFFFF8413) // 连接中
private val StatusConnected = Color(0xFF2EBD85)  // 已连接
private val GreyText get() = if (ThemeState.isDark) Color(0xFFB3A9C0) else Color(0xFF666666)
private val TrackPurple = Color(0xFFC9AFE0)      // 圆环浅紫轨道(圆环底,两主题一致)
private val ArcOrange = Color(0xFFFF8413)
private val ArcYellow = Color(0xFFFFEB3C)
// 表面/分隔/开关轨道:深色模式换深色变体,保证卡片与抽屉不刺眼。
private val CardSurface get() = if (ThemeState.isDark) Color(0xFF2B2436).copy(alpha = 0.90f) else Color.White.copy(alpha = 0.90f)
private val DrawerSurface get() = if (ThemeState.isDark) Color(0xFF241D2E) else Color(0xFFF9F7FC)
private val DividerLine get() = if (ThemeState.isDark) Color(0xFF3A3146) else Color(0xFFE2DCE8)
private val SwitchBorder get() = if (ThemeState.isDark) Color(0xFF4A4254) else Color(0xFFC9C0D4)

/** 原版图标字体(assets/fonts/iconfont.ttf,逆向自 Ultimate VPN):电源/菜单/刷新/箭头。 */
private val IconFont = FontFamily(Font(R.font.iconfont))

/** 项目主页(抽屉底部版本行点击跳转)。 */
private const val PROJECT_URL = "https://github.com/yiguihai11/SmartProxy"

/**
 * 服务模式(§8)的可观察 Compose state:SharedPreferences 变化 → OnSharedPreferenceChangeListener
 * → state 更新 → 重组。侧边栏菜单显示条件(代理应用 / DNS / 排除路由 / 联网状态)、监听开关
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
private fun HomeScreen(onToggleVpn: () -> Unit, themeMode: String, onCycleTheme: () -> Unit) {
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

    // DNS / 排除路由 / 服务模式设置对话框开关(侧边栏菜单打开,§6 / §8)。
    var showDnsDialog by remember { mutableStateOf(false) }
    var showExcludeDialog by remember { mutableStateOf(false) }
    var showServiceModeDialog by remember { mutableStateOf(false) }

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
                onOpenLogcat = {
                    scope.launch { drawerState.close() }
                    context.startActivity(Intent(context, LogcatActivity::class.java))
                },
                onOpenNetworkStatus = {
                    scope.launch { drawerState.close() }
                    context.startActivity(Intent(context, NetworkStatusActivity::class.java))
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
}

/** 侧边栏抽屉菜单内容 */
@Composable
private fun AppDrawerContent(
    onOpenApps: () -> Unit,
    onOpenDns: () -> Unit,
    onOpenExclude: () -> Unit,
    onOpenServiceMode: () -> Unit,
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
                    color = PurpleText,
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

            // 侧边栏菜单项：代理应用 (Apps)(per-app 分流走 VpnService.Builder、禁止联网
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
    Surface(
        shape = RoundedCornerShape(16.dp),
        color = CardSurface,
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 5.dp)
            .clickable(onClick = onClick)
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

    // 连接进度弧:运行中扫 0→360°,扫完前状态显示"连接中"。
    val sweep = remember { Animatable(0f) }
    LaunchedEffect(running) {
        sweep.animateTo(if (running) 360f else 0f, animationSpec = tween(1200))
    }
    val connecting = running && sweep.value < 355f

    Box(modifier = Modifier.fillMaxSize()) {
        if (ThemeState.isDark) {
            // 深色模式(§7):浅紫渐变图换深色渐变,夜间不刺眼。
            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .background(
                        Brush.verticalGradient(listOf(Color(0xFF1B1426), Color(0xFF2E213E)))
                    )
            )
        } else {
            // 1:1 原版背景:全屏 bg_main.jpg(淡紫渐变)+ 顶部 280dp bg_home_top 装饰。
            Image(
                painter = painterResource(R.drawable.bg_main),
                contentDescription = null,
                modifier = Modifier.fillMaxSize(),
                contentScale = ContentScale.Crop
            )
            Image(
                painter = painterResource(R.drawable.bg_home_top),
                contentDescription = null,
                modifier = Modifier
                    .fillMaxWidth()
                    .height(280.dp),
                contentScale = ContentScale.FillBounds
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
            // ── 标题栏:左侧菜单按钮(开侧边栏抽屉)+ 居中标题 + 右上主题切换(§7) ──
            Box(Modifier.fillMaxWidth()) {
                IconButton(
                    onClick = onOpenDrawer,
                    modifier = Modifier.align(Alignment.CenterStart)
                ) {
                    Icon(Icons.Filled.Menu, contentDescription = stringResource(R.string.cd_open_menu), tint = PurpleText)
                }
                Text(
                    text = "SmartProxy",
                    fontSize = 18.sp,
                    fontWeight = FontWeight.Bold,
                    color = PurpleText,
                    textAlign = TextAlign.Center,
                    modifier = Modifier.align(Alignment.Center)
                )
                // 主题切换钮(§7):按模式显太阳/月亮/自动图标,点击循环切换(auto→浅→深),
                // 图标随模式变化,状态一目了然。
                IconButton(
                    onClick = onCycleTheme,
                    modifier = Modifier.align(Alignment.CenterEnd)
                ) {
                    Icon(
                        imageVector = themeIcon(themeMode),
                        contentDescription = stringResource(R.string.cd_theme_mode, themeModeLabel(context, themeMode)),
                        tint = PurpleText,
                        modifier = Modifier.size(22.dp)
                    )
                }
            }
            Spacer(Modifier.height(18.dp))

            // ── 状态行:「状态: 未连接/连接中/已连接」────────────────
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(stringResource(R.string.home_status), fontSize = 18.sp, color = GreyText)
                Spacer(Modifier.width(8.dp))
                Text(
                    text = when {
                        !running -> stringResource(R.string.home_disconnected)
                        connecting -> stringResource(R.string.home_connecting)
                        else -> stringResource(R.string.home_connected)
                    },
                    fontSize = 18.sp,
                    fontWeight = FontWeight.Bold,
                    color = when {
                        !running -> StatusIdle
                        connecting -> StatusConnecting
                        else -> StatusConnected
                    }
                )
            }
            Spacer(Modifier.height(24.dp))

            // ── 大圆环 + 中心紫渐变球体(带白色电源字形) ────────────────
            ConnectOrb(running = running, sweep = sweep.value, onToggleVpn = onToggleVpn)
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
            SwitchCard(
                title = stringResource(R.string.home_boot_autostart),
                subtitle = if (serviceMode == AppPrefs.MODE_VPN)
                    stringResource(R.string.home_boot_autostart_sub_vpn) else stringResource(R.string.home_boot_autostart_sub_socks),
                checked = bootAuto,
                onCheckedChange = { v ->
                    bootAuto = v
                    AppPrefs.setBootAutoStart(context, v)
                },
                modifier = Modifier.fillMaxWidth()
            )
            Spacer(Modifier.height(24.dp))

            // ── 管理面板卡(服务运行中显示)。仅代理模式 URL=127.0.0.1,QR 跨设备扫到的是
            // 扫描机自己,只能本机开面板;VPN 模式 smartproxy.lan 可跨设备扫 QR。────────
            if (running) {
                PanelCard(url = panelUrl, auth = adminAuth, onCopy = { url -> copyPanelUrl(context, url) }, onOpen = { url -> openPanel(context, url) })
                Spacer(Modifier.height(8.dp))
            }
        }
    }
}

/** DNS 服务器设置对话框(§6):启动 VPN 时 addDnsServer 注入的 IPv4 / IPv6,留空 = 默认。
 *  必须填国内 DNS:引擎截获 DNS 查询做国内外域名检测/分流,国外 DNS 截不到且报错
 *  (no default UDP proxy available)。 */
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
                Spacer(Modifier.height(10.dp))
                OutlinedTextField(
                    value = v6,
                    onValueChange = { v6 = it },
                    label = { Text("IPv6") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )
                Spacer(Modifier.height(8.dp))
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

/** 排除路由设置对话框(API 33+ builder.excludeRoute):每行一个 CIDR,不走 VPN 隧道直连。 */
@Composable
private fun ExcludeRoutesDialog(
    initialRoutes: List<String>,
    onDismiss: () -> Unit,
    onSave: (Set<String>) -> Unit
) {
    var text by remember { mutableStateOf(initialRoutes.joinToString("\n")) }
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

/** 大圆环:浅紫轨道 + 橙→黄渐变进度弧 + 中心紫渐变球体(球上白色电源字形)。 */
@Composable
private fun ConnectOrb(running: Boolean, sweep: Float, onToggleVpn: () -> Unit) {
    Box(contentAlignment = Alignment.Center, modifier = Modifier.size(214.dp)) {
        Canvas(modifier = Modifier.fillMaxSize()) {
            val stroke = 12.dp.toPx()
            val radius = (size.minDimension - stroke) / 2f
            val center = this.center
            // 浅紫轨道(整圈)
            drawCircle(color = TrackPurple, radius = radius, style = Stroke(width = stroke))
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
        // 中心球体:1:1 原版素材(progress_btn_normal.png,紫渐变高光球)+
        // 图标字体白色电源字形(原版 @dimen/x40=40sp、@color/white),点按启停。
        Box(
            modifier = Modifier
                .size(121.dp)
                .clickable { onToggleVpn() },
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
    Surface(
        shape = RoundedCornerShape(20.dp),
        color = CardSurface,
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
    Surface(
        shape = RoundedCornerShape(24.dp),
        color = CardSurface,
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
                    Text(stringResource(R.string.panel_user, auth.first), fontSize = 12.sp, color = GreyText)
                    Text(stringResource(R.string.panel_pass, auth.second), fontSize = 12.sp, color = GreyText)
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
