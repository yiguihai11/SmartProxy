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
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.core.Animatable
import androidx.compose.animation.core.tween
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
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
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
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalLifecycleOwner
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver

/**
 * 首页 = 纯启动器(§4.4),UI 参考 Ultimate VPN Free(com.open.hotspot.vpn.free)
 * 逆向还原的视觉:淡紫渐变背景 + 大圆环进度 + 中心紫渐变球体电源按钮。
 *  - 大圆环球体 = VPN 启停(§4.5,isRunning 驱动);进度弧橙色→黄色,连接时扫一圈
 *  - 状态行:「状态:未连接/连接中/已连接」
 *  - 开关卡:IPv4 / IPv6 拦截 + 开机自启(§4.1/§4.3,写 AppPrefs;运行中改 → 重启 VPN)
 *  - 管理面板卡:URL + 复制 + 浏览器选择器 + 二维码(§4.4)
 * 流量模式 / 应用选择 / DNS 不在首页,只在 Web 面板(§4.4)。
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
private val OrangeAccent = Color(0xFFFFAC56)     // 标题右刷新
private val StatusIdle = Color(0xFFE87C7C)       // 未连接
private val StatusConnecting = Color(0xFFFF8413) // 连接中
private val StatusConnected = Color(0xFF2EBD85)  // 已连接
private val GreyText = Color(0xFF666666)
private val TrackPurple = Color(0xFFC9AFE0)      // 圆环浅紫轨道
private val OrbTop = Color(0xFFB38DE6)           // 球体上
private val OrbBottom = Color(0xFF7952AD)        // 球体下
private val ArcOrange = Color(0xFFFF8413)
private val ArcYellow = Color(0xFFFFEB3C)

@Composable
private fun HomeLauncher(onToggleVpn: () -> Unit) {
    val context = LocalContext.current
    val running by SmartProxyVpnService.isRunning.collectAsState()

    // v4/v6 / 开机自启:AppPrefs 为唯一偏好,首页只读/写。
    var ipv4 by remember { mutableStateOf(AppPrefs.ipv4(context)) }
    var ipv6 by remember { mutableStateOf(AppPrefs.ipv6(context)) }
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

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(Brush.verticalGradient(listOf(Color(0xFFFBF8FF), Color(0xFFCEB4F3))))
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 20.dp, vertical = 16.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            // ── 标题栏(紫粗体 + 橙色刷新)────────────────────────────
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = "SmartProxy",
                    fontSize = 18.sp,
                    fontWeight = FontWeight.Bold,
                    color = PurpleText,
                    modifier = Modifier.weight(1f)
                )
                Text(
                    text = "⟳",
                    fontSize = 20.sp,
                    color = OrangeAccent,
                    modifier = Modifier.clickable { panelUrl = PanelUrl.url(context) }
                )
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

            // ── 大圆环 + 中心紫渐变球体电源按钮 ──────────────────────
            ConnectOrb(running = running, sweep = sweep.value, onToggleVpn = onToggleVpn)
            Spacer(Modifier.height(30.dp))

            // ── 开关卡(IPv4 / IPv6 / 开机自启)────────────────────────
            SwitchCard("IPv4 拦截", "接管 IPv4 流量", ipv4) { v ->
                ipv4 = v
                AppPrefs.setIpv4(context, v)
                restartVpn(context)
            }
            SwitchCard("IPv6 拦截", "接管 IPv6 流量", ipv6) { v ->
                ipv6 = v
                AppPrefs.setIpv6(context, v)
                restartVpn(context)
            }
            SwitchCard("开机自启", "开机后自动启动 VPN(需已授权)", bootAuto) { v ->
                bootAuto = v
                AppPrefs.setBootAutoStart(context, v)
            }
            Spacer(Modifier.height(24.dp))

            // ── 管理面板卡(URL + 复制 + 浏览器选择器 + 二维码)────────
            PanelCard(url = panelUrl, onCopy = { url -> copyPanelUrl(context, url) }, onOpen = { url -> openPanel(context, url) })
            Spacer(Modifier.height(8.dp))
        }
    }
}

/** 大圆环:浅紫轨道 + 橙→黄渐变进度弧 + 中心紫渐变球体电源按钮。 */
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
        // 中心球体:紫渐变 + 白色电源符号,点按启停。
        Box(
            modifier = Modifier
                .size(132.dp)
                .shadow(12.dp, CircleShape)
                .clip(CircleShape)
                .background(Brush.verticalGradient(listOf(OrbTop, OrbBottom)))
                .clickable { onToggleVpn() },
            contentAlignment = Alignment.Center
        ) {
            PowerIcon(size = 56.dp)
        }
    }
}

/** 白色电源符号(Canvas 手绘:带顶部缺口的下半圆 + 中轴竖线)。 */
@Composable
private fun PowerIcon(size: androidx.compose.ui.unit.Dp, color: Color = Color.White) {
    Canvas(Modifier.size(size)) {
        val stroke = this.size.minDimension * 0.10f
        val r = this.size.minDimension * 0.27f
        val c = this.center
        drawArc(
            color = color,
            startAngle = 300f,          // 顶部留 60° 缺口(12 点方向)
            sweepAngle = 300f,
            useCenter = false,
            topLeft = Offset(c.x - r, c.y - r),
            size = Size(r * 2f, r * 2f),
            style = Stroke(width = stroke, cap = StrokeCap.Round)
        )
        drawLine(
            color = color,
            start = Offset(c.x, c.y - this.size.minDimension * 0.40f),
            end = Offset(c.x, c.y + this.size.minDimension * 0.14f),
            strokeWidth = stroke,
            cap = StrokeCap.Round
        )
    }
}

/** 白色圆角卡片开关(紫色强调)。 */
@Composable
private fun SwitchCard(
    title: String,
    subtitle: String,
    checked: Boolean,
    onCheckedChange: (Boolean) -> Unit
) {
    Surface(
        shape = RoundedCornerShape(20.dp),
        color = Color.White.copy(alpha = 0.90f),
        modifier = Modifier
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
                colors = SwitchDefaults.colors(checkedThumbColor = PurpleText)
            )
        }
    }
}

/** 管理面板入口卡:URL + 复制 + 浏览器选择器 + 二维码(§4.4)。 */
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
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    text = "管理面板",
                    fontSize = 16.sp,
                    fontWeight = FontWeight.Bold,
                    color = PurpleDark
                )
                Spacer(Modifier.weight(1f))
                Text("▸", fontSize = 18.sp, color = PurpleSoft)
            }
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
                if (qr != null) {
                    Image(
                        bitmap = qr.asImageBitmap(),
                        contentDescription = "管理面板二维码",
                        modifier = Modifier
                            .size(180.dp)
                            .align(Alignment.CenterHorizontally)
                            .clickable { onOpen(url) }
                    )
                    Text(
                        text = "扫码打开,或点击上方用浏览器",
                        fontSize = 12.sp,
                        color = GreyText,
                        textAlign = TextAlign.Center,
                        modifier = Modifier.align(Alignment.CenterHorizontally)
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
