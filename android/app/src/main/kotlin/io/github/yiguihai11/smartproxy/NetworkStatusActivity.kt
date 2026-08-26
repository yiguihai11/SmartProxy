package io.github.yiguihai11.smartproxy

import android.os.Bundle
import android.util.Log
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
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
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.KeyboardArrowDown
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.rotate
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject

/**
 * 联网状态页(侧边栏「联网状态」,仅绕过模式 + VPN 运行中):按应用分组显示实时连接明细。
 *
 *  - 懒开关:onCreate 打开采集(Mobile.setConnStatsEnabled(true)),onDestroy 关闭;
 *    页面以外引擎零开销(连接监控只在 enabled 时登记/计数)。
 *  - 每秒轮询 Mobile.getConnectionStats()(gomobile 调用阻塞调用线程,走 Dispatchers.IO;
 *    与 [[gomobile-error-throws]] 约定一致,error 走异常抛)。
 *  - 首个数据到 → loading 消失;空 = "暂无联网应用"(无活动的 app 天然不进表)。
 *  - 组头:应用图标 + 名 + ↑/↓ 实时网速(δ(当前-上次)/1s,KB/s);点击展开连接明细。
 *  - 连接行:host(域名或 IP):端口 + TCP/UDP 徽标 + 累计上下行;smart TCP 才显示域名,
 *    UDP / 非 smart 一律 IP(引擎设计定稿,零新增解析开销)。
 *  - UID→包名/图标:懒解析 + 缓存(复用 AppEnumerator 图标缓存),只解快照里出现的 app。
 */

/** 轮询快照的数据模型(字段与 internal/tun/stats.go 快照 JSON 对齐)。 */
private data class ConnStatsRec(val proto: Int, val host: String, val port: Int, val up: Long, val down: Long)
private data class AppStats(val uid: Int, val up: Long, val down: Long, val conns: List<ConnStatsRec>)
private data class AppItem(
    val uid: Int,
    val label: String,
    val icon: ImageBitmap?,
    val upBps: Long,
    val downBps: Long,
    val conns: List<ConnStatsRec>
)
private data class AppMeta(val label: String, val icon: ImageBitmap?)

class NetworkStatusActivity : ComponentActivity() {

    private companion object {
        private const val TAG = "SmartProxyVpn"
    }

    /** 当前快照(带 δ 网速),Compose 读它渲染。 */
    private var appItems by mutableStateOf<List<AppItem>>(emptyList())
    private var loaded by mutableStateOf(false)
    private var error by mutableStateOf<String?>(null)
    private var expandedUids by mutableStateOf<Set<Int>>(emptySet())

    /** 上次轮询的 app 累计基准(算 δ 网速);uid 表 + 图标缓存在轮询线程访问。 */
    private val prevTotals = HashMap<Int, Pair<Long, Long>>()
    private val metaCache = HashMap<Int, AppMeta>()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // 懒开关:页面打开即采集;onDestroy 关闭,不开页面引擎零开销。
        runCatching { smartproxy.mobile.Mobile.setConnStatsEnabled(true) }
            .onFailure { Log.e(TAG, "[NetworkStatus] setConnStatsEnabled(true) failed", it) }
        enableEdgeToEdge()
        setContent {
            AutoSystemBarStyle(AppPrefs.themeMode(this))
            SmartProxyTheme(mode = AppPrefs.themeMode(this)) {
                MaterialTheme(colorScheme = NetworkStatusColors) {
                    // 每秒轮询:bridge 调用 + JSON 解析 + UID→图标解码都放 IO(阻塞调用),
                    // 状态写入回主线程。runCatching 兜底,循环不因单次失败退出。
                    val poll: suspend () -> Unit = {
                        val parsed = withContext(Dispatchers.IO) {
                            runCatching {
                                val json = smartproxy.mobile.Mobile.getConnectionStats()
                                buildItems(parseConnStats(json))
                            }.getOrNull()
                        }
                        if (parsed == null) {
                            error = "读取连接数据失败"
                        } else {
                            appItems = parsed
                            loaded = true
                            error = null
                        }
                    }
                    NetworkStatusScreen(
                        appItems = appItems,
                        loaded = loaded,
                        error = error,
                        expandedUids = expandedUids,
                        onToggleExpand = { uid ->
                            expandedUids = if (uid in expandedUids) expandedUids - uid else expandedUids + uid
                        },
                        onPoll = poll,
                        onBack = { finish() }
                    )
                }
            }
        }
    }

    override fun onDestroy() {
        // 页面关闭即停采集:引擎恢复零开销;轮询 LaunchedEffect 随 composition 一并取消。
        runCatching { smartproxy.mobile.Mobile.setConnStatsEnabled(false) }
            .onFailure { Log.e(TAG, "[NetworkStatus] setConnStatsEnabled(false) failed", it) }
        super.onDestroy()
    }

    /** 解析 Go 快照 JSON → List<AppStats>。字段与 internal/tun/stats.go 快照结构对齐。 */
    private fun parseConnStats(json: String): List<AppStats> {
        val root = JSONObject(json)
        val appsArr = root.optJSONArray("apps") ?: JSONArray()
        val out = ArrayList<AppStats>(appsArr.length())
        for (i in 0 until appsArr.length()) {
            val a = appsArr.getJSONObject(i)
            val connsArr = a.optJSONArray("conns") ?: JSONArray()
            val conns = ArrayList<ConnStatsRec>(connsArr.length())
            for (j in 0 until connsArr.length()) {
                val c = connsArr.getJSONObject(j)
                conns += ConnStatsRec(
                    proto = c.getInt("proto"),
                    host = c.getString("host"),
                    port = c.getInt("port"),
                    up = c.getLong("up"),
                    down = c.getLong("down")
                )
            }
            out += AppStats(
                uid = a.getInt("uid"),
                up = a.getLong("up"),
                down = a.getLong("down"),
                conns = conns
            )
        }
        return out
    }

    /** AppStats + 上次基准 → AppItem(带 δ 网速)。消失的 app 清旧基准,重现时 δ 不虚高。 */
    private fun buildItems(apps: List<AppStats>): List<AppItem> {
        val currentUids = apps.mapTo(HashSet()) { it.uid }
        prevTotals.keys.retainAll(currentUids)
        return apps.map { app ->
            val prev = prevTotals[app.uid]
            val upBps = if (prev == null) 0L else (app.up - prev.first).coerceAtLeast(0L)
            val downBps = if (prev == null) 0L else (app.down - prev.second).coerceAtLeast(0L)
            prevTotals[app.uid] = app.up to app.down
            val meta = metaFor(app.uid)
            AppItem(app.uid, meta.label, meta.icon, upBps, downBps, app.conns)
        }
    }

    /** uid → 应用名/图标(懒解析 + 缓存);共享 uid 取第一个包,失败回退 "UID x"。 */
    private fun metaFor(uid: Int): AppMeta = metaCache.getOrPut(uid) {
        runCatching {
            val pm = packageManager
            val pkg = pm.getPackagesForUid(uid)?.firstOrNull()
            if (pkg == null) {
                AppMeta("UID $uid", null)
            } else {
                val ai = pm.getApplicationInfo(pkg, 0)
                val label = pm.getApplicationLabel(ai)?.toString() ?: pkg
                AppMeta(label, AppEnumerator.iconBitmap(this, pkg))
            }
        }.getOrElse { AppMeta("UID $uid", null) }
    }
}

// ── 主题色(对齐首页 / 应用选择页紫色系,深色同源)──────────────────────
private val PurpleText get() = if (ThemeState.isDark) Color(0xFFC9A9E8) else Color(0xFF7850AA)
private val PurpleSoft get() = if (ThemeState.isDark) Color(0xFFAA92CC) else Color(0xFF9A80BA)
private val GreyText get() = if (ThemeState.isDark) Color(0xFFB3A9C0) else Color(0xFF666666)
private val TextDark get() = if (ThemeState.isDark) Color(0xFFE6E2EC) else Color(0xFF222222)
private val SoftBg get() = if (ThemeState.isDark) Color(0xFF16111E) else Color(0xFFF3F0F8)
private val PlaceholderBg get() = if (ThemeState.isDark) Color(0xFF2A2234) else Color(0xFFEEEAF6)
private val CardBg get() = if (ThemeState.isDark) Color(0xFF2B2436) else Color.White
private val UpGreen = Color(0xFF4CAF50)
private val DownBlue = Color(0xFF3E7BFA)
private val TcpBadge = Color(0xFF7B5FA6)
private val UdpBadge = Color(0xFF3E7BFA)

private val NetworkStatusColors get() =
    if (ThemeState.isDark) darkColorScheme(primary = PurpleText)
    else lightColorScheme(primary = PurpleText)

/** 网速:δ 字节/1s → B/s / KB/s / MB/s。 */
private fun formatSpeed(bps: Long): String = when {
    bps >= 1048576 -> "%.1f MB/s".format(bps / 1048576.0)
    bps >= 1024 -> "%.1f KB/s".format(bps / 1024.0)
    else -> "$bps B/s"
}

/** 累计字节:显示 B / KB / MB。 */
private fun formatBytes(bytes: Long): String = when {
    bytes >= 1048576 -> "%.1f MB".format(bytes / 1048576.0)
    bytes >= 1024 -> "%.1f KB".format(bytes / 1024.0)
    else -> "$bytes B"
}

/** host 可能是 IPv6 字面量,带冒号时补方括号避免 :port 歧义。 */
private fun hostPort(host: String, port: Int): String =
    if (host.contains(':')) "[$host]:$port" else "$host:$port"

@Composable
private fun NetworkStatusScreen(
    appItems: List<AppItem>,
    loaded: Boolean,
    error: String?,
    expandedUids: Set<Int>,
    onToggleExpand: (Int) -> Unit,
    onPoll: suspend () -> Unit,
    onBack: () -> Unit
) {
    // 每秒轮询;页面销毁 composition 取消,循环自然停。
    LaunchedEffect(Unit) {
        while (true) {
            onPoll()
            delay(1000)
        }
    }

    Box(modifier = Modifier.fillMaxSize().background(SoftBg)) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .safeDrawingPadding()
                .padding(horizontal = 16.dp)
        ) {
            // ── 顶栏:返回 + 标题 ────────────────────────────────
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp)
            ) {
                IconButton(onClick = onBack) {
                    Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "返回", tint = PurpleText)
                }
                Spacer(Modifier.width(4.dp))
                Text("联网状态", fontSize = 20.sp, fontWeight = FontWeight.Bold, color = PurpleText)
            }
            Spacer(Modifier.height(8.dp))

            when {
                // 首帧:loading + 信息提示(首个数据到才消失)。
                !loaded -> Column(
                    Modifier.fillMaxWidth().weight(1f),
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.Center
                ) {
                    CircularProgressIndicator(color = PurpleText)
                    Spacer(Modifier.height(12.dp))
                    Text("正在采集连接数据…", fontSize = 13.sp, color = GreyText)
                }
                error != null -> Column(
                    Modifier.fillMaxWidth().weight(1f),
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.Center
                ) {
                    Text(error!!, fontSize = 13.sp, color = Color(0xFFFF6B6B))
                }
                appItems.isEmpty() -> Column(
                    Modifier.fillMaxWidth().weight(1f),
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.Center
                ) {
                    Text("暂无联网应用", fontSize = 14.sp, fontWeight = FontWeight.Medium, color = TextDark)
                    Spacer(Modifier.height(6.dp))
                    Text("应用联网后会自动出现在这里", fontSize = 12.sp, color = GreyText)
                }
                else -> LazyColumn(modifier = Modifier.weight(1f)) {
                    items(appItems, key = { it.uid }) { item ->
                        AppGroup(
                            item = item,
                            expanded = item.uid in expandedUids,
                            onToggle = { onToggleExpand(item.uid) }
                        )
                    }
                }
            }

            // ── 底部提示:懒采集 + 每秒刷新 ──────────────────────
            Spacer(Modifier.height(8.dp))
            Text(
                "仅显示有联网活动的应用 · 每秒刷新 · 关闭页面即停止采集",
                fontSize = 11.sp,
                color = GreyText,
                textAlign = TextAlign.Center,
                modifier = Modifier.fillMaxWidth()
            )
            Spacer(Modifier.height(8.dp))
        }
    }
}

/** 应用组:图标 + 名 + ↑/↓ 网速;整行点击展开/收起连接明细。 */
@Composable
private fun AppGroup(item: AppItem, expanded: Boolean, onToggle: () -> Unit) {
    Surface(
        shape = RoundedCornerShape(16.dp),
        color = CardBg,
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 4.dp)
    ) {
        Column {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier
                    .fillMaxWidth()
                    .clickable(onClick = onToggle)
                    .padding(horizontal = 12.dp, vertical = 10.dp)
            ) {
                if (item.icon != null) {
                    Image(
                        bitmap = item.icon,
                        contentDescription = null,
                        modifier = Modifier.size(36.dp).clip(RoundedCornerShape(8.dp))
                    )
                } else {
                    Box(
                        modifier = Modifier.size(36.dp).clip(RoundedCornerShape(8.dp)).background(PlaceholderBg),
                        contentAlignment = Alignment.Center
                    ) {
                        Text(item.label.take(1).uppercase(), color = GreyText, fontSize = 14.sp)
                    }
                }
                Spacer(Modifier.width(10.dp))
                Column(Modifier.weight(1f)) {
                    Text(
                        item.label,
                        fontSize = 14.sp,
                        color = TextDark,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                    Text(
                        "${item.conns.size} 条连接",
                        fontSize = 11.sp,
                        color = GreyText,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                }
                Column(horizontalAlignment = Alignment.End) {
                    Text("↑ ${formatSpeed(item.upBps)}", fontSize = 12.sp, color = UpGreen)
                    Text("↓ ${formatSpeed(item.downBps)}", fontSize = 12.sp, color = DownBlue)
                }
                Spacer(Modifier.width(8.dp))
                Icon(
                    imageVector = Icons.Filled.KeyboardArrowDown,
                    contentDescription = if (expanded) "收起连接" else "展开连接",
                    tint = PurpleSoft,
                    modifier = Modifier.size(20.dp).rotate(if (expanded) 180f else 0f)
                )
            }
            AnimatedVisibility(visible = expanded) {
                Column(Modifier.padding(start = 12.dp, end = 12.dp, bottom = 8.dp)) {
                    if (item.conns.isEmpty()) {
                        Text("暂无连接明细", fontSize = 11.sp, color = GreyText, modifier = Modifier.padding(vertical = 4.dp))
                    } else {
                        item.conns.forEach { conn -> ConnRow(conn) }
                    }
                }
            }
        }
    }
}

/** 连接明细行:TCP/UDP 徽标 + host:port + 累计上下行。 */
@Composable
private fun ConnRow(conn: ConnStatsRec) {
    Row(
        verticalAlignment = Alignment.CenterVertically,
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 5.dp)
    ) {
        Surface(
            color = if (conn.proto == 17) UdpBadge else TcpBadge,
            shape = RoundedCornerShape(4.dp)
        ) {
            Text(
                text = if (conn.proto == 17) "UDP" else "TCP",
                color = Color.White,
                fontSize = 9.sp,
                fontWeight = FontWeight.Bold,
                modifier = Modifier.padding(horizontal = 5.dp, vertical = 2.dp)
            )
        }
        Spacer(Modifier.width(10.dp))
        Column {
            Text(
                hostPort(conn.host, conn.port),
                fontSize = 13.sp,
                color = TextDark,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )
            Text(
                "↑ ${formatBytes(conn.up)} · ↓ ${formatBytes(conn.down)}",
                fontSize = 11.sp,
                color = GreyText,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )
        }
    }
}
