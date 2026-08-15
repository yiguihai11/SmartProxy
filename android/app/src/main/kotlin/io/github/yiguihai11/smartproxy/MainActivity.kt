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
import android.os.Handler
import android.os.Looper
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.Animatable
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.Image
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
import androidx.compose.material3.Button
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.draw.rotate
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalLifecycleOwner
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

/**
 * 首页 = 纯启动器(§4.4),UI 参考 Ultimate VPN Free(com.open.hotspot.vpn.free)
 * 逆向还原的视觉:淡紫渐变背景 + 大圆环进度 + 中心紫渐变球体(球上白色电源字形)。
 *  - 大圆环球体 = VPN 启停(§4.5,isRunning 驱动);进度弧橙色→黄色,连接时扫一圈
 *  - 状态行:「状态:未连接/连接中/已连接」
 *  - 开关卡:IPv4 / IPv6 拦截(§4.1/§4.2,写 AppPrefs;运行中改 → 重启 VPN)
 *  - 开关卡:开机自启(§4.3)+ Apps 应用选择入口(§5 应用内化)→ AppSelectionActivity
 *  - 管理面板卡:URL + 复制 + 浏览器选择器 + 二维码(§4.4)
 * 流量模式 / 应用选择在应用内(§5),不在首页;DNS 只在 Web 面板(§4.4)。
 */
class MainActivity : ComponentActivity() {

    private val vpnConsent =
        registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
            if (result.resultCode == Activity.RESULT_OK) {
                ensureNotifyPermission()
                SmartProxyVpnService.start(this)
            }
        }

    /** Android 13+:VPN 保活通知展示需 POST_NOTIFICATIONS,启动前申请一次(§4.3)。 */
    private val notifyPermission =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) { }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // 统一 edge-to-edge(含 Android 15+ 强制生效):背景通铺到系统栏后,
        // 内容列用 safeDrawingPadding 让出状态栏/导航栏,避免顶部与状态栏重叠。
        enableEdgeToEdge()
        setContent {
            MaterialTheme {
                HomeLauncher(onToggleVpn = { onToggleClicked() })
            }
        }
    }

    private fun onToggleClicked() {
        if (SmartProxyVpnService.isRunning.value) {
            SmartProxyVpnService.stop(this)
            return
        }
        // 首次或授权失效:弹系统授权框;成功后由回调启动服务。
        val intent = VpnService.prepare(this)
        if (intent != null) {
            vpnConsent.launch(intent)
        } else {
            ensureNotifyPermission()
            SmartProxyVpnService.start(this)
        }
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

/** 正在运行时空翻 v4/v6:停掉旧会话再按新偏好重启(§4.4 改动→重启生效,约 2-3s 断连)。 */
private fun restartVpn(context: Context) {
    if (!SmartProxyVpnService.isRunning.value) return
    SmartProxyVpnService.stop(context)
    Handler(Looper.getMainLooper()).postDelayed({
        SmartProxyVpnService.start(context)
    }, 500)
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

// ── 主题色(逆向自 Ultimate VPN Free 的 colors.xml)──────────────────────
private val PurpleText = Color(0xFF7850AA)       // 标题/强调
private val PurpleDark = Color(0xFF613D8D)       // 面板文字
private val PurpleSoft = Color(0xFF9A80BA)       // 弱化箭头
private val StatusIdle = Color(0xFFE87C7C)       // 未连接
private val StatusConnecting = Color(0xFFFF8413) // 连接中
private val StatusConnected = Color(0xFF2EBD85)  // 已连接
private val GreyText = Color(0xFF666666)
private val TrackPurple = Color(0xFFC9AFE0)      // 圆环浅紫轨道
private val ArcOrange = Color(0xFFFF8413)
private val ArcYellow = Color(0xFFFFEB3C)

/** 原版图标字体(assets/fonts/iconfont.ttf,逆向自 Ultimate VPN):电源/菜单/刷新/箭头。 */
private val IconFont = FontFamily(Font(R.font.iconfont))

@Composable
private fun HomeLauncher(onToggleVpn: () -> Unit) {
    val context = LocalContext.current
    val running by SmartProxyVpnService.isRunning.collectAsState()

    // v4/v6 拦截:config.json 真源(§4.6,Go 面板与首页共写同一文件);开机自启仍是 AppPrefs。
    var ipv4 by remember { mutableStateOf(ConfigProvider.ipv4(context)) }
    var ipv6 by remember { mutableStateOf(ConfigProvider.ipv6(context)) }
    var bootAuto by remember { mutableStateOf(AppPrefs.bootAutoStart(context)) }

    // 面板 URL:局域网 IP 变化时在 onResume 刷新(§4.4 注意)。
    var panelUrl by remember { mutableStateOf(PanelUrl.url(context)) }
    val lifecycleOwner = LocalLifecycleOwner.current
    DisposableEffect(lifecycleOwner) {
        val observer = LifecycleEventObserver { _, event ->
            if (event == Lifecycle.Event.ON_RESUME) panelUrl = PanelUrl.url(context)
        }
        lifecycleOwner.lifecycle.addObserver(observer)
        onDispose { lifecycleOwner.lifecycle.removeObserver(observer) }
    }

    // 连接进度弧:运行中扫 0→360°,扫完前状态显示"连接中"。
    val sweep = remember { Animatable(0f) }
    LaunchedEffect(running) {
        sweep.animateTo(if (running) 360f else 0f, animationSpec = tween(1200))
    }
    val connecting = running && sweep.value < 355f

    Box(modifier = Modifier.fillMaxSize()) {
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
        Column(
            modifier = Modifier
                .fillMaxSize()
                .safeDrawingPadding()
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 20.dp, vertical = 16.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            // ── 标题栏(居中标题;原版左菜单/右刷新仅装饰,无功能,已移除)──
            Text(
                text = "SmartProxy",
                fontSize = 18.sp,
                fontWeight = FontWeight.Bold,
                color = PurpleText,
                textAlign = TextAlign.Center,
                modifier = Modifier.fillMaxWidth()
            )
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

            // ── 开关卡(自适应宫格:v4 / v6 左右各半,开机自启 + Apps 左右各半)──
            Row(modifier = Modifier.fillMaxWidth()) {
                SwitchCard(
                    title = "IPv4 拦截", subtitle = "接管 IPv4 流量", checked = ipv4,
                    onCheckedChange = { v ->
                        ipv4 = v
                        ConfigProvider.setIpv4(context, v)   // 写 config.json tun.inet4_address(§4.6)
                        restartVpn(context)
                    },
                    modifier = Modifier.weight(1f)
                )
                Spacer(Modifier.width(8.dp))
                SwitchCard(
                    title = "IPv6 拦截", subtitle = "接管 IPv6 流量", checked = ipv6,
                    onCheckedChange = { v ->
                        ipv6 = v
                        ConfigProvider.setIpv6(context, v)   // 写 config.json tun.inet6_address(§4.6)
                        restartVpn(context)
                    },
                    modifier = Modifier.weight(1f)
                )
            }
            Row(modifier = Modifier.fillMaxWidth()) {
                SwitchCard(
                    title = "开机自启", subtitle = "开机后自动启动 VPN(需已授权)", checked = bootAuto,
                    onCheckedChange = { v ->
                        bootAuto = v
                        AppPrefs.setBootAutoStart(context, v)
                    },
                    modifier = Modifier.weight(1f)
                )
                Spacer(Modifier.width(8.dp))
                AppsCard(
                    title = "Apps", subtitle = "选择代理应用",
                    onClick = { context.startActivity(Intent(context, AppSelectionActivity::class.java)) },
                    modifier = Modifier.weight(1f)
                )
            }
            Spacer(Modifier.height(24.dp))

            // ── 管理面板卡(URL + 复制 + 浏览器选择器 + 二维码)────────
            PanelCard(url = panelUrl, onCopy = { url -> copyPanelUrl(context, url) }, onOpen = { url -> openPanel(context, url) })
            Spacer(Modifier.height(8.dp))
        }
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
        color = Color.White.copy(alpha = 0.90f),
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
                    uncheckedTrackColor = Color(0xFFE2DCE8),
                    uncheckedBorderColor = Color(0xFFC9C0D4)
                )
            )
        }
    }
}

/** 应用选择入口卡(§5 应用内化):整卡可点,进 AppSelectionActivity。 */
@Composable
private fun AppsCard(title: String, subtitle: String, onClick: () -> Unit, modifier: Modifier = Modifier) {
    Surface(
        shape = RoundedCornerShape(20.dp),
        color = Color.White.copy(alpha = 0.90f),
        modifier = modifier
            .fillMaxWidth()
            .padding(vertical = 4.dp)
            .clickable(onClick = onClick)
    ) {
        Row(
            modifier = Modifier.padding(horizontal = 16.dp, vertical = 10.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(Modifier.weight(1f)) {
                Text(title, fontSize = 16.sp, color = PurpleDark, fontWeight = FontWeight.Medium)
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

/** 管理面板入口卡:URL + 复制 + 浏览器选择器;二维码默认折叠,点卡片底部居中箭头展开(§4.4)。 */
@Composable
private fun PanelCard(url: String?, onCopy: (String) -> Unit, onOpen: (String) -> Unit) {
    Surface(
        shape = RoundedCornerShape(24.dp),
        color = Color.White.copy(alpha = 0.90f),
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
