package io.github.yiguihai11.smartproxy

import android.os.Bundle
import android.util.Log
import android.widget.Toast
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
import androidx.compose.material.icons.filled.Block
import androidx.compose.material.icons.filled.KeyboardArrowDown
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.rotate
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject

/**
 * 联网状态页(侧边栏「联网状态」,仅绕过模式 + VPN 运行中):按应用分组显示实时连接明细。
 *
 *  - 懒开关:onResume 打开采集(Mobile.setConnStatsEnabled(true));onPause 停轮询但采集
 *    延迟 5 秒才关(快速切换回来数据仍在,超时才清空引擎统计表),引擎只在 enabled 时登记/计数。
 *  - 每秒轮询 Mobile.getConnectionStats()(gomobile 调用阻塞调用线程,走 Dispatchers.IO;
 *    与 [[gomobile-error-throws]] 约定一致,error 走异常抛)。
 *  - 首个数据到 → loading 消失;空 = "暂无联网应用"(无活动的 app 天然不进表)。
 *  - 消失节奏:引擎对「最后流量后 5 秒」的连接做 idle 清扫(连接无流量 5 秒后淡出,
 *    字节并入该 app 累计);展开查看某应用时引擎 pin 它 —— 正在查看的明细无流量
 *    也不消失,收起 / 切到别处才按 5s 宽限淡出。
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

    /** 页面是否处于前台(onResume/onPause 驱动):离开页面(返回/切后台)即 false,
     *  停采集 + 停轮询;回到前台恢复。后台零 CPU/零引擎开销。 */
    private var active by mutableStateOf(false)

    /** 上次轮询的 app 累计基准(算 δ 网速);uid 表 + 图标缓存在轮询线程访问。 */
    private val prevTotals = HashMap<Int, Pair<Long, Long>>()
    private val metaCache = HashMap<Int, AppMeta>()

    /** 待确认封禁的连接(点连接行的封禁图标后置位,确认框消失时清空)。 */
    private var pendingBlock by mutableStateOf<ConnStatsRec?>(null)

    /** 当前 pin 到引擎的 uid(-1 = 无):最近展开的应用。展开即 pin —— 正在查看的
     *  应用连接无流量也不被引擎淡出;收起该应用 / 展开别的才解除。 */
    private var pinnedUid by mutableStateOf(-1)

    /** onPause 排起的「延迟关采集」任务:离开页面先不立刻清空统计,给 5 秒宽限,
     *  5 秒内切回来则取消它、数据原样保留;超时才真正 setConnStatsEnabled(false) 清表。 */
    private var statsCloseJob: Job? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            val scope = rememberCoroutineScope()
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
                            error = getString(R.string.net_read_fail)
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
                        active = active,
                        onToggleExpand = { uid ->
                            val expanded = uid !in expandedUids
                            expandedUids = if (expanded) expandedUids + uid else expandedUids - uid
                            // pin 跟随「正在查看」的应用:展开即 pin(明细不因无流量淡出),
                            // 收起且正 pin 着它才解除;收起别的应用不影响当前 pin(允许多开,保最新)。
                            val newPin = when {
                                expanded -> uid
                                pinnedUid == uid -> -1
                                else -> pinnedUid
                            }
                            if (newPin != pinnedUid) {
                                pinnedUid = newPin
                                runCatching { smartproxy.mobile.Mobile.setConnStatsPin(newPin) }
                                    .onFailure { Log.e(TAG, "[NetworkStatus] setConnStatsPin failed", it) }
                            }
                        },
                        onBlockConn = { conn -> pendingBlock = conn },
                        onPoll = poll,
                        onBack = { finish() }
                    )
                    // 封禁确认框:持久化 ACL + 掐断现有连接是破坏性操作,弹框确认再执行。
                    pendingBlock?.let { conn ->
                        AlertDialog(
                            onDismissRequest = { pendingBlock = null },
                            title = { Text(stringResource(R.string.net_block_title)) },
                            text = {
                                Text(
                                    "${hostPort(conn.host, conn.port)}\n\n" +
                                            stringResource(R.string.net_block_message)
                                )
                            },
                            confirmButton = {
                                TextButton(onClick = {
                                    val target = conn.host
                                    pendingBlock = null
                                    scope.launch {
                                        val result = withContext(Dispatchers.IO) {
                                            runCatching { smartproxy.mobile.Mobile.blockConnection(target) }
                                        }
                                        result
                                            .onSuccess { Toast.makeText(this@NetworkStatusActivity, getString(R.string.toast_blocked, target), Toast.LENGTH_SHORT).show() }
                                            .onFailure { e ->
                                                Toast.makeText(this@NetworkStatusActivity, getString(R.string.toast_block_fail, e.message), Toast.LENGTH_SHORT).show()
                                            }
                                    }
                                }) { Text(stringResource(R.string.btn_block)) }
                            },
                            dismissButton = {
                                TextButton(onClick = { pendingBlock = null }) { Text(stringResource(R.string.btn_cancel)) }
                            }
                        )
                    }
                }
            }
        }
    }

    /** 回到前台:取消未触发的延迟关采集 + 开采集 + 恢复轮询。 */
    override fun onResume() {
        super.onResume()
        active = true
        statsCloseJob?.cancel() // 5 秒宽限内切回来:取消延迟清空,统计原样保留
        statsCloseJob = null
        runCatching { smartproxy.mobile.Mobile.setConnStatsEnabled(true) }
            .onFailure { Log.e(TAG, "[NetworkStatus] setConnStatsEnabled(true) failed", it) }
        // 后台延迟关采集可能已把引擎 pin 复位(-1):回来按当前展开状态重新 pin,
        // 防正在查看的应用因 pin 失同步而无流量淡出(-1 时是 no-op)。
        runCatching { smartproxy.mobile.Mobile.setConnStatsPin(pinnedUid) }
            .onFailure { Log.e(TAG, "[NetworkStatus] setConnStatsPin failed", it) }
    }

    /** 离开页面(返回上个页 / 切后台 / 被覆盖):停轮询,但采集延迟 5 秒再关。
     *  原来 onPause 立刻 setConnStatsEnabled(false) 会瞬时清空整张统计表 —— 快速切换
     *  (返回 <1s 再进来)回来就一片空白。现在轮询已随 active=false 停止,引擎只在 5 秒
     *  宽限耗尽仍处于后台时才真正关采集清表;宽限内 onResume 回来则数据仍在。
     *  不手动清 prevTotals:超时清表后恢复累计从 0 重计,buildItems 的 coerceAtLeast(0)
     *  会把旧基准的负 δ 钳成 0,天然不虚高;且 prevTotals 只由 IO 线程的 buildItems 写,
     *  主线程勿动,避免并发写。 */
    override fun onPause() {
        active = false
        statsCloseJob = lifecycleScope.launch {
            delay(5_000)
            if (!active) { // 5 秒后仍不在前台才真正清空
                runCatching { smartproxy.mobile.Mobile.setConnStatsEnabled(false) }
                    .onFailure { Log.e(TAG, "[NetworkStatus] delayed setConnStatsEnabled(false) failed", it) }
            }
        }
        super.onPause()
    }

    override fun onDestroy() {
        statsCloseJob?.cancel() // 取消未触发的延迟任务,防销毁后仍碰 Mobile
        statsCloseJob = null
        // 兜底(正常 onPause 已延迟关闭 / 宽限内销毁):确保销毁后引擎零开销;轮询随 composition 一并取消。
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
private val BlockRed = Color(0xFFE53935)

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
    active: Boolean,
    onToggleExpand: (Int) -> Unit,
    onBlockConn: (ConnStatsRec) -> Unit,
    onPoll: suspend () -> Unit,
    onBack: () -> Unit
) {
    // 每秒轮询;key 绑 active —— active=false(返回/切后台)即取消循环,回前台重启。
    LaunchedEffect(active) {
        while (active) {
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
                    Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = stringResource(R.string.cd_back), tint = PurpleText)
                }
                Spacer(Modifier.width(4.dp))
                Text(stringResource(R.string.drawer_network_status), fontSize = 20.sp, fontWeight = FontWeight.Bold, color = PurpleText)
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
                    Text(stringResource(R.string.net_loading), fontSize = 13.sp, color = GreyText)
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
                    Text(stringResource(R.string.net_empty), fontSize = 14.sp, fontWeight = FontWeight.Medium, color = TextDark)
                    Spacer(Modifier.height(6.dp))
                    Text(stringResource(R.string.net_empty_sub), fontSize = 12.sp, color = GreyText)
                }
                else -> LazyColumn(modifier = Modifier.weight(1f)) {
                    items(appItems, key = { it.uid }) { item ->
                        AppGroup(
                            item = item,
                            expanded = item.uid in expandedUids,
                            onToggle = { onToggleExpand(item.uid) },
                            onBlockConn = onBlockConn
                        )
                    }
                }
            }

            // ── 底部提示:懒采集 + 每秒刷新 ──────────────────────
            Spacer(Modifier.height(8.dp))
            Text(
                stringResource(R.string.net_footer),
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
private fun AppGroup(item: AppItem, expanded: Boolean, onToggle: () -> Unit, onBlockConn: (ConnStatsRec) -> Unit) {
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
                        stringResource(R.string.net_conn_count, item.conns.size),
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
                    contentDescription = if (expanded) stringResource(R.string.cd_collapse_conn) else stringResource(R.string.cd_expand_conn),
                    tint = PurpleSoft,
                    modifier = Modifier.size(20.dp).rotate(if (expanded) 180f else 0f)
                )
            }
            AnimatedVisibility(visible = expanded) {
                Column(Modifier.padding(start = 12.dp, end = 12.dp, bottom = 8.dp)) {
                    if (item.conns.isEmpty()) {
                        Text(stringResource(R.string.net_conn_empty), fontSize = 11.sp, color = GreyText, modifier = Modifier.padding(vertical = 4.dp))
                    } else {
                        item.conns.forEach { conn -> ConnRow(conn, onBlock = { onBlockConn(conn) }) }
                    }
                }
            }
        }
    }
}

/** 连接明细行:TCP/UDP 徽标 + host:port + 累计上下行 + 封禁按钮(加入 ACL 并掐断)。 */
@Composable
private fun ConnRow(conn: ConnStatsRec, onBlock: () -> Unit) {
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
        Column(Modifier.weight(1f)) {
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
        IconButton(onClick = onBlock, modifier = Modifier.size(28.dp)) {
            Icon(
                Icons.Filled.Block,
                contentDescription = stringResource(R.string.cd_block_target),
                tint = BlockRed,
                modifier = Modifier.size(16.dp)
            )
        }
    }
}
