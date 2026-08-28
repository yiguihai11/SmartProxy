package io.github.yiguihai11.smartproxy

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.util.Log
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.background
import androidx.compose.foundation.combinedClickable
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
import androidx.compose.foundation.lazy.LazyListState
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Share
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
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
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.FileProvider
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * 日志查看页(侧边栏「日志查看」):调 logcat 命令读 App 自己的 Kotlin 层日志
 * (SmartProxyVpn tag),详细到 Debug 级,外加 AndroidRuntime/System.err 抓崩溃栈。
 * 参考 v2rayNG LogcatViewModel 的做法:同为 exec logcat -d 一次性 dump,非进程内缓冲。
 *
 * - 命令:logcat -d -v threadtime -s SmartProxyVpn:V AndroidRuntime:W System.err
 *   故意不带 --pid:logd 对无 READ_LOGS 的调用方只回本 UID 的条目,天然只有本 App
 *   的日志,且跨进程重启(pid 变化)的历史都在;--pid 只捞当前进程代,进程重启后
 *   会整页空白。-s 只留 Kotlin 层 tag + App 崩溃栈(AndroidRuntime/System.err),Go
 *   引擎的 GoLog 不混入 —— 本页定位 = App 自己的日志;Go 核心日志走 logcat GoLog
 *   tag,需要时 adb logcat -s GoLog 查看。
 * - 打开时写一条 SmartProxyVpn 标记日志,保证首次 dump 至少有一行可验证管线。
 * - 自动刷新:默认开,2s 一次 dump(logcat -d 是一次性 dump,非流式,简单可靠);
 *   手动刷新为右下角 FAB。
 * - 搜索:顶栏放大镜展开输入框,内存关键字过滤(不重新读 logcat)。
 * - 复制/分享:复制全部(长按单行复制该行);分享导出为 txt 走 FileProvider。
 * - 清空:执行 logcat -c 清系统缓冲,并清空本页。
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
    private var showSearch by mutableStateOf(false)
    private var searchQuery by mutableStateOf("")

    /** 显示行 = 全部行经关键字过滤(内存过滤,不重新读 logcat)。 */
    private val visibleLines: List<String>
        get() = if (searchQuery.isBlank()) lines
                else lines.filter { it.contains(searchQuery, ignoreCase = true) }

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

                    // 自动刷新循环:开时每 2s dump 一次;关时只靠 FAB 手动刷新。
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
                        lines = visibleLines,
                        totalLines = lines.size,
                        autoRefresh = autoRefresh,
                        error = error,
                        listState = listState,
                        showSearch = showSearch,
                        searchQuery = searchQuery,
                        onToggleAutoRefresh = { autoRefresh = !autoRefresh },
                        onManualRefresh = { scope.launch { refresh() } },
                        onToggleSearch = {
                            showSearch = !showSearch
                            if (!showSearch) searchQuery = ""
                        },
                        onSearchQueryChange = { searchQuery = it },
                        onCopyAll = { copyText(visibleLines.joinToString("\n")) },
                        onShare = { shareText(visibleLines.joinToString("\n")) },
                        onClear = { scope.launch { clearLogcat() } },
                        onLongPressLine = { copyText(it) },
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
                // 不带 --pid、只留本 App 的 Kotlin tag + 崩溃栈:详见类注释。logd 对无
                // READ_LOGS 的调用方只回本 UID 条目,天然只有本 App 日志,跨进程代都可见。
                val process = Runtime.getRuntime().exec(
                    arrayOf(
                        "logcat", "-d", "-v", "threadtime",
                        "-s", "SmartProxyVpn:V", "AndroidRuntime:W", "System.err"
                    )
                )
                process.inputStream.bufferedReader().use { it.readText() }
            }
        }
        result
            .onSuccess { text ->
                val newLines = text.lines().filter { it.isNotBlank() }
                // 替换而非追加:logcat -d 每次返回完整缓冲,追加会把历史行连同
                // "beginning of main" 头每轮重复一遍(列表全是重复项、信息一直跳)。
                lines = newLines.takeLast(MAX_LINES)
                error = null
            }
            .onFailure { e ->
                error = e.message
            }
    }

    /** logcat -c 清系统缓冲,并清空本页。 */
    private suspend fun clearLogcat() {
        withContext(Dispatchers.IO) {
            runCatching {
                val p = Runtime.getRuntime().exec(arrayOf("logcat", "-c"))
                p.waitFor()
            }
        }
        lines = emptyList()
        error = null
    }

    private fun copyText(text: String) {
        (getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager)?.setPrimaryClip(
            ClipData.newPlainText(getString(R.string.logcat_clip_label), text)
        )
    }

    /** 导出当前日志为 txt 并经系统分享面板发出(FileProvider 暴露 cacheDir/shared_logs)。 */
    private fun shareText(text: String) {
        lifecycleScope.launch {
            val pair = withContext(Dispatchers.IO) {
                runCatching {
                    val dir = File(cacheDir, "shared_logs").apply { mkdirs() }
                    dir.listFiles()?.forEach { it.delete() }
                    val name =
                        "smartproxy_log_${SimpleDateFormat("yyyy-MM-dd_HH-mm-ss", Locale.US).format(Date())}.txt"
                    val f = File(dir, name)
                    f.writeText(text, Charsets.UTF_8)
                    FileProvider.getUriForFile(this@LogcatActivity, "$packageName.cache", f) to name
                }.getOrNull()
            }
            val uri = pair?.first
            val name = pair?.second
            if (uri == null || name == null) {
                error = getString(R.string.logcat_export_fail)
                return@launch
            }
            val send = Intent(Intent.ACTION_SEND).apply {
                type = "text/plain"
                putExtra(Intent.EXTRA_STREAM, uri)
                putExtra(Intent.EXTRA_SUBJECT, name)
                putExtra(Intent.EXTRA_TITLE, name)
                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                clipData = ClipData.newUri(contentResolver, name, uri)
            }
            startActivity(Intent.createChooser(send, getString(R.string.cd_share_logs)))
        }
    }
}

// ── 主题色(对齐首页樱花粉色系,同 AppSelectionActivity 模式)─────────────
private val PurpleText get() = if (ThemeState.isDark) Color(0xFFF6B8CF) else Color(0xFFD66E9B)
private val PurpleFill get() = if (ThemeState.isDark) Color(0xFFC25E87) else Color(0xFFD66E9B) // FAB 等白图标填充
private val GreyText get() = if (ThemeState.isDark) Color(0xFFC9A8B6) else Color(0xFF7A626D)
private val TextDark get() = if (ThemeState.isDark) Color(0xFFF3E3EA) else Color(0xFF3A2A31)
private val SoftBg get() = if (ThemeState.isDark) Color(0xFF2B1A22) else Color(0xFFFFF5F9)
private val CardBg get() = if (ThemeState.isDark) Color(0xFF38262F) else Color.White

private val LogcatColors get() =
    if (ThemeState.isDark) darkColorScheme(primary = PurpleText)
    else lightColorScheme(primary = PurpleText)

@OptIn(ExperimentalFoundationApi::class)
@Composable
private fun LogcatScreen(
    lines: List<String>,
    totalLines: Int,
    autoRefresh: Boolean,
    error: String?,
    listState: LazyListState,
    showSearch: Boolean,
    searchQuery: String,
    onToggleAutoRefresh: () -> Unit,
    onManualRefresh: () -> Unit,
    onToggleSearch: () -> Unit,
    onSearchQueryChange: (String) -> Unit,
    onCopyAll: () -> Unit,
    onShare: () -> Unit,
    onClear: () -> Unit,
    onLongPressLine: (String) -> Unit,
    onBack: () -> Unit
) {
    Box(modifier = Modifier.fillMaxSize().background(SoftBg)) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .safeDrawingPadding()
                .padding(horizontal = 16.dp)
        ) {
            // ── 顶栏:返回 + 标题 + 搜索/复制/分享/清空 ─────────────
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp)
            ) {
                if (showSearch) {
                    IconButton(onClick = onToggleSearch) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = stringResource(R.string.cd_exit_search), tint = PurpleText)
                    }
                    OutlinedTextField(
                        value = searchQuery,
                        onValueChange = onSearchQueryChange,
                        placeholder = { Text(stringResource(R.string.logcat_search_placeholder), fontSize = 13.sp) },
                        singleLine = true,
                        modifier = Modifier.weight(1f)
                    )
                } else {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = stringResource(R.string.cd_back), tint = PurpleText)
                    }
                    Spacer(Modifier.width(4.dp))
                    Text(stringResource(R.string.logcat_title), fontSize = 20.sp, fontWeight = FontWeight.Bold, color = PurpleText)
                    Spacer(Modifier.weight(1f))
                    IconButton(onClick = onToggleSearch) {
                        Icon(Icons.Filled.Search, contentDescription = stringResource(R.string.cd_search), tint = PurpleText)
                    }
                    IconButton(onClick = onCopyAll) {
                        Icon(Icons.Filled.ContentCopy, contentDescription = stringResource(R.string.cd_copy_all), tint = PurpleText)
                    }
                    IconButton(onClick = onShare) {
                        Icon(Icons.Filled.Share, contentDescription = stringResource(R.string.cd_share_logs), tint = PurpleText)
                    }
                    IconButton(onClick = onClear) {
                        Icon(Icons.Filled.Delete, contentDescription = stringResource(R.string.cd_clear), tint = PurpleText)
                    }
                }
            }
            Spacer(Modifier.height(4.dp))

            // ── 自动刷新开关 + 状态 ─────────────────────────────
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier.fillMaxWidth()
            ) {
                Text(stringResource(R.string.logcat_auto_refresh), fontSize = 13.sp, color = TextDark)
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
                    if (searchQuery.isBlank())
                        stringResource(R.string.logcat_count, totalLines)
                    else
                        stringResource(R.string.logcat_count_filtered, lines.size, totalLines),
                    fontSize = 12.sp,
                    color = GreyText,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
            }
            Spacer(Modifier.height(6.dp))

            // ── 日志正文:等宽字体,Debug 级;长按复制单行 ─────────
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
                        maxLines = Int.MAX_VALUE,
                        modifier = Modifier.combinedClickable(
                            onClick = {},
                            onLongClick = { onLongPressLine(line) }
                        )
                    )
                }
            }

            if (lines.isEmpty() && error == null) {
                Text(
                    if (searchQuery.isBlank())
                        stringResource(R.string.logcat_empty)
                    else
                        stringResource(R.string.logcat_empty_search),
                    fontSize = 12.sp,
                    color = GreyText,
                    modifier = Modifier.padding(vertical = 6.dp)
                )
            }
            if (error != null) {
                Text(
                    stringResource(R.string.logcat_read_fail, error),
                    fontSize = 12.sp,
                    color = Color(0xFFFF6B6B),
                    modifier = Modifier.padding(vertical = 6.dp)
                )
            }
            Spacer(Modifier.height(8.dp))
        }

        // ── FAB:手动刷新(自动刷新关闭时使用) ──────────────────
        FloatingActionButton(
            onClick = onManualRefresh,
            containerColor = PurpleFill,
            contentColor = Color.White,
            modifier = Modifier
                .align(Alignment.BottomEnd)
                .padding(16.dp)
        ) {
            Icon(Icons.Filled.Refresh, contentDescription = stringResource(R.string.cd_refresh))
        }
    }
}
