package io.github.yiguihai11.smartproxy

import android.Manifest
import android.app.Activity
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.net.VpnService
import android.os.Build
import android.os.Bundle
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
        Toast.makeText(this, "未配置上游代理节点,流量无法转发,请到管理面板配置", Toast.LENGTH_LONG).show()
    }

    private fun ensureNotifyPermission() {
        if (Build.VERSION.SDK_INT >= 33 &&
            ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS)
                != PackageManager.PERMISSION_GRANTED
        ) {
            notifyPermission.launch(Manifest.permission.POST_NOTIFICATIONS)
        }
    }
}

private fun copyPanelUrl(context: Context, url: String) {
    val cm = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
    cm.setPrimaryClip(ClipData.newPlainText("smartproxy_panel_url", url))
    Toast.makeText(context, "已复制: $url", Toast.LENGTH_SHORT).show()
}

/** §4.4:点击用 Intent.createChooser 弹浏览器选择器,不锁系统默认浏览器。 */
private fun openPanel(context: Context, url: String) {
    val intent = Intent(Intent.ACTION_VIEW, Uri.parse(url))
    context.startActivity(Intent.createChooser(intent, "选择浏览器打开管理面板"))
}

/** 抽屉底部「SmartProxy for Android」点击跳转项目主页。 */
private fun openProjectUrl(context: Context) {
    context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(PROJECT_URL)))
}

/** 服务模式名(抽屉副标题 / 对话框下拉项)。注意与流量模式(AppSelectionActivity 的
 *  「仅代理」白名单)区分:这里指引擎运行形态——VPN 隧道 vs 纯 SOCKS5。 */
private fun serviceModeLabel(mode: String): String = when (mode) {
    AppPrefs.MODE_SOCKS5 -> "仅代理 (SOCKS5)"
    else -> "VPN 隧道"
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
    onOpenServiceMode: () -> Unit
) {
    val context = LocalContext.current
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
                        text = "智能分流代理",
                        fontSize = 12.sp,
                        color = GreyText
                    )
                }
            }

            Spacer(Modifier.height(20.dp))
            HorizontalDivider(color = DividerLine, thickness = 1.dp)
            Spacer(Modifier.height(16.dp))

            Text(
                text = "功能菜单",
                fontSize = 12.sp,
                fontWeight = FontWeight.SemiBold,
                color = PurpleSoft,
                modifier = Modifier.padding(horizontal = 4.dp, vertical = 4.dp)
            )
            Spacer(Modifier.height(6.dp))

            // 侧边栏菜单项：代理应用 (Apps)
            DrawerMenuItem(
                title = "代理应用 (Apps)",
                subtitle = "选择各应用的代理 / 绕过规则",
                onClick = onOpenApps
            )

            // 侧边栏菜单项：DNS 服务器(启动时 addDnsServer 注入的 v4/v6)
            DrawerMenuItem(
                title = "DNS 服务器",
                subtitle = "启动时注入的 IPv4 / IPv6 DNS",
                onClick = onOpenDns
            )

            // 侧边栏菜单项：排除路由(builder.excludeRoute,API 33+ 特性,低版本不显示)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                DrawerMenuItem(
                    title = "排除路由",
                    subtitle = "不走 VPN 隧道直连的网段 (API 33+)",
                    onClick = onOpenExclude
                )
            }

            // 侧边栏菜单项：服务模式(VPN 隧道 / 仅代理 SOCKS5,§8)。副标题实时显示当前模式。
            DrawerMenuItem(
                title = "服务模式",
                subtitle = "当前: ${serviceModeLabel(AppPrefs.serviceMode(context))}",
                onClick = onOpenServiceMode
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
                text = "Go 内核 · 轻量高效",
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

    // v4/v6 拦截:config.json 真源(§4.6,Go 面板与首页共写同一文件);开机自启仍是 AppPrefs。
    var ipv4 by remember { mutableStateOf(ConfigProvider.ipv4(context)) }
    var ipv6 by remember { mutableStateOf(ConfigProvider.ipv6(context)) }
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
                    Icon(Icons.Filled.Menu, contentDescription = "打开菜单", tint = PurpleText)
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
                        contentDescription = "主题模式:${themeModeLabel(themeMode)}",
                        tint = PurpleText,
                        modifier = Modifier.size(22.dp)
                    )
                }
            }
            Spacer(Modifier.height(18.dp))

            // ── 状态行:「状态: 未连接/连接中/已连接」────────────────
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text("状态:", fontSize = 18.sp, color = GreyText)
                Spacer(Modifier.width(8.dp))
                Text(
                    text = when {
                        !running -> "未连接"
                        connecting -> "连接中…"
                        else -> "已连接"
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
            Row(modifier = Modifier.fillMaxWidth()) {
                SwitchCard(
                    title = "IPv4 拦截", subtitle = "接管 IPv4 流量", checked = ipv4,
                    onCheckedChange = { v ->
                        ipv4 = v
                        // 写 config.json tun.inet4_address(§4.6):运行中显式重建才生效
                        // (Go watcher 自动重启已删除)。restart() 自带 isRunning 守卫,未在跑只落盘。
                        ConfigProvider.setIpv4(context, v)
                        SmartProxyVpnService.restart(context)
                    },
                    modifier = Modifier.weight(1f)
                )
                Spacer(Modifier.width(8.dp))
                SwitchCard(
                    title = "IPv6 拦截", subtitle = "接管 IPv6 流量", checked = ipv6,
                    onCheckedChange = { v ->
                        ipv6 = v
                        ConfigProvider.setIpv6(context, v)
                        SmartProxyVpnService.restart(context)
                    },
                    modifier = Modifier.weight(1f)
                )
            }
            SwitchCard(
                title = "开机自启", subtitle = "开机后自动启动 VPN(需已授权)", checked = bootAuto,
                onCheckedChange = { v ->
                    bootAuto = v
                    AppPrefs.setBootAutoStart(context, v)
                },
                modifier = Modifier.fillMaxWidth()
            )
            Spacer(Modifier.height(24.dp))

            // ── 管理面板卡(仅 VPN 运行时显示:连接后才有可扫的 QR 面板)────────
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
        title = { Text("DNS 服务器") },
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
                    text = "启动 VPN 时注入的 DNS(addDnsServer),留空 = 默认。\n须填国内 DNS(默认 223.5.5.5 / 2400:3200::1):引擎要截获\nDNS 查询做国内外域名检测分流,国外 DNS 截不到且报错。\n修改后需重启 VPN 生效。",
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
                Toast.makeText(context, "DNS 地址格式不正确", Toast.LENGTH_SHORT).show()
            }) { Text("保存") }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("取消") } }
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
        title = { Text("排除路由 (API 33+)") },
        text = {
            Column {
                OutlinedTextField(
                    value = text,
                    onValueChange = { text = it },
                    label = { Text("每行一个 CIDR,如 192.168.1.0/24") },
                    modifier = Modifier.fillMaxWidth().height(160.dp)
                )
                Spacer(Modifier.height(8.dp))
                Text(
                    text = "这些网段不走 VPN 隧道(分隧道直连);修改后需重启 VPN 生效。",
                    fontSize = 12.sp,
                    color = GreyText
                )
            }
        },
        confirmButton = {
            TextButton(onClick = {
                onSave(text.lines().map { it.trim() }.filter { it.isNotBlank() }.toSet())
            }) { Text("保存") }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("取消") } }
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
    val options = listOf(AppPrefs.MODE_VPN, AppPrefs.MODE_SOCKS5)
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("服务模式") },
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
                                serviceModeLabel(selected),
                                fontSize = 14.sp,
                                color = PurpleDark,
                                modifier = Modifier.weight(1f)
                            )
                            Icon(
                                Icons.Filled.KeyboardArrowDown,
                                contentDescription = "选择服务模式",
                                tint = PurpleSoft,
                                modifier = Modifier.size(20.dp)
                            )
                        }
                    }
                    DropdownMenu(expanded = expanded, onDismissRequest = { expanded = false }) {
                        options.forEach { mode ->
                            DropdownMenuItem(
                                text = { Text(serviceModeLabel(mode)) },
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
                    text = "VPN 隧道:接管系统流量智能分流(默认)。\n仅代理:不启动 VPN 模式,仅运行引擎 SOCKS5 代理(:1080,局域网可访问)。\n运行中切换将自动重启生效。",
                    fontSize = 12.sp,
                    color = GreyText
                )
            }
        },
        confirmButton = { TextButton(onClick = { onSave(selected) }) { Text("保存") } },
        dismissButton = { TextButton(onClick = onDismiss) { Text("取消") } }
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
    onCheckedChange: (Boolean) -> Unit,
    modifier: Modifier = Modifier
) {
    Surface(
        shape = RoundedCornerShape(20.dp),
        color = CardSurface,
        modifier = modifier
            .fillMaxWidth()
            .padding(vertical = 4.dp)
    ) {
        Row(
            modifier = Modifier.padding(horizontal = 16.dp, vertical = 10.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(Modifier.weight(1f)) {
                Text(title, fontSize = 16.sp, color = PurpleDark, fontWeight = FontWeight.Medium)
                Text(subtitle, fontSize = 12.sp, color = GreyText)
            }
            Switch(
                checked = checked,
                onCheckedChange = onCheckedChange,
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
                text = "管理面板",
                fontSize = 16.sp,
                fontWeight = FontWeight.Bold,
                color = PurpleDark
            )
            if (url != null) {
                Spacer(Modifier.height(6.dp))
                Text(url, fontSize = 13.sp, color = GreyText)
                if (auth != null) {
                    Spacer(Modifier.height(6.dp))
                    Text("登录账号: ${auth.first}", fontSize = 12.sp, color = GreyText)
                    Text("登录密码: ${auth.second}", fontSize = 12.sp, color = GreyText)
                }
                Spacer(Modifier.height(10.dp))
                Row {
                    OutlinedButton(onClick = { onCopy(url) }, modifier = Modifier.weight(1f)) {
                        Text("复制地址")
                    }
                    Spacer(Modifier.width(8.dp))
                    Button(onClick = { onOpen(url) }, modifier = Modifier.weight(1f)) {
                        Text("用浏览器打开")
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
                                contentDescription = "管理面板二维码",
                                modifier = Modifier
                                    .size(180.dp)
                                    .clickable { onOpen(url) }
                            )
                            Text(
                                text = "扫码打开,或点击上方用浏览器",
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
                        contentDescription = if (showQr) "收起二维码" else "展开二维码",
                        tint = PurpleSoft,
                        modifier = Modifier.size(22.dp).rotate(rotation)
                    )
                }
            } else {
                Text(
                    text = "未获取到局域网地址\n请连接 Wi-Fi 后重试",
                    fontSize = 13.sp,
                    color = GreyText
                )
            }
        }
    }
}
