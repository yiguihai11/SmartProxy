package io.github.yiguihai11.smartproxy

import android.os.Bundle
import android.util.Log
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
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
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * 日志查看页(侧边栏「日志查看」):调 logcat 命令读 App 自己的 Kotlin 层日志
 * (SmartProxyVpn tag),详细到 Debug 级。
 *
 * - 命令:logcat -d -v threadtime -s SmartProxyVpn:V
 *   故意不带 --pid:logd 对无 READ_LOGS 的调用方只回本 UID 的条目,天然只有本 App
 *   的日志,且跨进程重启(pid 变化)的历史都在;--pid 只捞当前进程代,进程重启后
 *   会整页空白。-s 只留 Kotlin 层 tag,Go 引擎的 GoLog 不混入(本页定位 = App 自己
 *   的日志)。
 * - 打开时写一条 SmartProxyVpn 标记日志,保证首次 dump 至少有一行可验证管线。
 * - 自动刷新:默认开,2s 一次 dump(io.logcat 是一次性 dump,非流式,简单可靠)。
 * - 行数上限 2000,超出丢最旧;底部跟随(用户手动上翻时暂停跟随)。
 */
class LogcatActivity : ComponentActivity() {

    companion object {
        private const val TAG = "SmartProxyVpn"
        private const val MAX_LINES = 2000
        private const val REFRESH_MS = 2000L
    }

    private var autoRefresh by mutableStateOf(true)
    private var lines by mutableStateOf<List<String>>(emptyList())
    private var error by mutableStateOf<String?>(null)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // 标记日志:保证首次 dump 缓冲里至少有一条本 App 的日志,可验证查看管线。
        Log.i(TAG, "[Logcat] 查看器已打开")
        enableEdgeToEdge()
        setContent {
            AutoSystemBarStyle(AppPrefs.themeMode(this))
            SmartProxyTheme(mode = AppPrefs.themeMode(this)) {
                MaterialTheme(colorScheme = LogcatColors) {
                    val listState = rememberLazyListState()
                    val scope = rememberCoroutineScope()

                    // 自动刷新循环:开时每 2s dump 一次;关时只靠手动刷新按钮。
                    LaunchedEffect(autoRefresh) {
                        while (autoRefresh) {
                            refresh()
                            delay(REFRESH_MS)
                        }
                    }
                    // 底部跟随:刷新后若用户仍在底部附近(或手动刷新),滚到底;用户上翻则停。
                    LaunchedEffect(lines.size) {
                        val total = listState.layoutInfo.totalItemsCount
                        if (total > 0) {
                            val visibleLast = listState.layoutInfo.visibleItemsInfo.lastOrNull()?.index ?: 0
                            if (visibleLast >= total - 3) {
                                listState.scrollToItem(total - 1)
                            }
                        }
                    }

                    LogcatScreen(
                        lines = lines,
                        autoRefresh = autoRefresh,
                        error = error,
                        listState = listState,
                        onToggleAutoRefresh = { autoRefresh = !autoRefresh },
                        onManualRefresh = { scope.launch { refresh() } },
                        onBack = { finish() }
                    )
                }
            }
        }
    }

    /** dump logcat(IO 线程执行),结果并入 lines(上限裁剪)。 */
    private suspend fun refresh() {
        val result = withContext(Dispatchers.IO) {
            runCatching {
                // 不带 --pid、只留本 App 的 Kotlin tag:详见类注释。logd 对无 READ_LOGS
                // 的调用方只回本 UID 条目,天然只有本 App 日志,跨进程代都可见。
                val process = Runtime.getRuntime().exec(
                    arrayOf("logcat", "-d", "-v", "threadtime", "-s", "SmartProxyVpn:V")
                )
                process.inputStream.bufferedReader().use { it.readText() }
            }
        }
        result
            .onSuccess { text ->
                val newLines = text.lines().filter { it.isNotBlank() }
                lines = (lines + newLines).takeLast(MAX_LINES)
                error = null
            }
            .onFailure { e ->
                error = e.message
            }
    }
}

// ── 主题色(对齐首页紫色系,同 AppSelectionActivity 模式)─────────────
private val PurpleText get() = if (ThemeState.isDark) Color(0xFFC9A9E8) else Color(0xFF7850AA)
private val GreyText get() = if (ThemeState.isDark) Color(0xFFB3A9C0) else Color(0xFF666666)
private val TextDark get() = if (ThemeState.isDark) Color(0xFFE6E2EC) else Color(0xFF222222)
private val SoftBg get() = if (ThemeState.isDark) Color(0xFF16111E) else Color(0xFFF3F0F8)
private val CardBg get() = if (ThemeState.isDark) Color(0xFF2B2436) else Color.White

private val LogcatColors get() =
    if (ThemeState.isDark) darkColorScheme(primary = PurpleText)
    else lightColorScheme(primary = PurpleText)

@Composable
private fun LogcatScreen(
    lines: List<String>,
    autoRefresh: Boolean,
    error: String?,
    listState: androidx.compose.foundation.lazy.LazyListState,
    onToggleAutoRefresh: () -> Unit,
    onManualRefresh: () -> Unit,
    onBack: () -> Unit
) {
    Box(modifier = Modifier.fillMaxSize().background(SoftBg)) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .safeDrawingPadding()
                .padding(horizontal = 16.dp)
        ) {
            // ── 顶栏:返回 + 标题 + 手动刷新 ─────────────────────
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp)
            ) {
                IconButton(onClick = onBack) {
                    Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "返回", tint = PurpleText)
                }
                Spacer(Modifier.width(4.dp))
                Text("日志查看", fontSize = 20.sp, fontWeight = FontWeight.Bold, color = PurpleText)
                Spacer(Modifier.weight(1f))
                IconButton(onClick = onManualRefresh) {
                    Icon(Icons.Filled.Refresh, contentDescription = "立即刷新", tint = PurpleText)
                }
            }
            Spacer(Modifier.height(4.dp))

            // ── 自动刷新开关 + 状态 ─────────────────────────────
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier.fillMaxWidth()
            ) {
                Text("自动刷新", fontSize = 13.sp, color = TextDark)
                Spacer(Modifier.width(8.dp))
                Switch(
                    checked = autoRefresh,
                    onCheckedChange = { onToggleAutoRefresh() },
                    colors = SwitchDefaults.colors(
                        checkedTrackColor = PurpleText,
                        checkedThumbColor = Color.White
                    )
                )
                Spacer(Modifier.weight(1f))
                Text(
                    "${lines.size} 行",
                    fontSize = 12.sp,
                    color = GreyText,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
            }
            Spacer(Modifier.height(6.dp))

            // ── 日志正文:等宽字体,Debug 级 ─────────────────────
            LazyColumn(
                state = listState,
                modifier = Modifier
                    .fillMaxWidth()
                    .weight(1f)
                    .background(CardBg, RoundedCornerShape(14.dp))
                    .padding(horizontal = 10.dp, vertical = 8.dp)
            ) {
                itemsIndexed(lines) { _, line ->
                    Text(
                        line,
                        fontSize = 11.sp,
                        fontFamily = FontFamily.Monospace,
                        color = TextDark,
                        maxLines = Int.MAX_VALUE
                    )
                }
            }

            if (lines.isEmpty() && error == null) {
                Text(
                    "暂无日志 — 连接 VPN 后 SmartProxyVpn 日志会出现在这里",
                    fontSize = 12.sp,
                    color = GreyText,
                    modifier = Modifier.padding(vertical = 6.dp)
                )
            }
            if (error != null) {
                Text(
                    "读取日志失败: $error",
                    fontSize = 12.sp,
                    color = Color(0xFFFF6B6B),
                    modifier = Modifier.padding(vertical = 6.dp)
                )
            }
            Spacer(Modifier.height(8.dp))
        }
    }
}
