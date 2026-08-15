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
import androidx.compose.foundation.Image
import androidx.compose.foundation.clickable
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
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalLifecycleOwner
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver

/**
 * 首页 = 纯启动器(§4.4 产品形态):
 *  - VPN 启停按钮 + 状态(§4.5 状态机,isRunning 驱动)
 *  - IPv4/IPv6 拦截开关(§4.1,写 AppPrefs;运行中改 → 重启 VPN 生效)
 *  - 开机自启开关(§4.3,写 AppPrefs,BootReceiver 消费)
 *  - 管理面板入口:URL(https://<手机IP>:port)+ 复制 + 点击弹浏览器选择器 + 二维码
 * 不再含模式 / 应用选择 / DNS —— 这些只在 Web 面板(§4.4)。
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
                Surface(Modifier.fillMaxSize()) {
                    HomeLauncher(onToggleVpn = { onToggleClicked() })
                }
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

    val qr = remember(panelUrl) { panelUrl?.let { QrHelper.generate(it, 512) } }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        // ── VPN 状态 + 启停 ──────────────────────────────────────────
        Text(
            text = if (running) "运行中" else "未运行",
            fontSize = 22.sp
        )
        Spacer(Modifier.height(24.dp))
        Button(
            onClick = onToggleVpn,
            modifier = Modifier.fillMaxWidth()
        ) {
            Text(if (running) "停止 VPN" else "启动 VPN")
        }
        Spacer(Modifier.height(28.dp))

        // ── 拦截开关 + 开机自启 ───────────────────────────────────────
        SwitchRow("IPv4 拦截", "接管 IPv4 流量", ipv4) { v ->
            ipv4 = v
            AppPrefs.setIpv4(context, v)
            restartVpn(context)
        }
        SwitchRow("IPv6 拦截", "接管 IPv6 流量", ipv6) { v ->
            ipv6 = v
            AppPrefs.setIpv6(context, v)
            restartVpn(context)
        }
        SwitchRow("开机自启", "开机后自动启动 VPN(需已授权)", bootAuto) { v ->
            bootAuto = v
            AppPrefs.setBootAutoStart(context, v)
        }
        Spacer(Modifier.height(20.dp))
        HorizontalDivider()

        // ── 管理面板入口(§4.4)────────────────────────────────────────
        Text(
            text = "管理面板",
            modifier = Modifier.padding(vertical = 12.dp),
            style = MaterialTheme.typography.titleMedium
        )
        val url = panelUrl
        if (url != null) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    text = url,
                    fontSize = 13.sp,
                    modifier = Modifier.weight(1f)
                )
                Spacer(Modifier.width(8.dp))
                OutlinedButton(onClick = { copyPanelUrl(context, url) }) {
                    Text("复制")
                }
            }
            Text(
                text = "点击下方打开,可选择浏览器",
                fontSize = 12.sp,
                modifier = Modifier.padding(top = 4.dp)
            )
            Spacer(Modifier.height(12.dp))
            if (qr != null) {
                Image(
                    bitmap = qr.asImageBitmap(),
                    contentDescription = "管理面板二维码",
                    modifier = Modifier
                        .size(200.dp)
                        .clickable { openPanel(context, url) }
                )
            }
        } else {
            Text(
                text = "未获取到局域网地址\n请连接 Wi-Fi 后重试",
                fontSize = 13.sp,
                textAlign = TextAlign.Center
            )
        }
        Spacer(Modifier.height(8.dp))
    }
}

@Composable
private fun SwitchRow(
    title: String,
    subtitle: String,
    checked: Boolean,
    onCheckedChange: (Boolean) -> Unit
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Column(Modifier.weight(1f)) {
            Text(title, fontSize = 16.sp)
            Text(subtitle, fontSize = 12.sp)
        }
        Switch(checked = checked, onCheckedChange = onCheckedChange)
    }
}
