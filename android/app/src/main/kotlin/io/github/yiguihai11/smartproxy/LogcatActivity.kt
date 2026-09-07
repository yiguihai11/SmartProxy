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
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyListState
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.ArrowDropDown
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Share
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Tab
import androidx.compose.material3.TabRow
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
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
import org.json.JSONArray
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * 日志查看页(侧边栏「日志查看」):两个 tab,各管各的日志源与等级设置。
 *
 *  - **Android tab**:App 自己的 Kotlin 层日志(SmartProxyVpn tag),exec logcat -d 一次性
 *    dump(参考 v2rayNG LogcatViewModel)。等级是「抓取设置」——logcat -s SmartProxyVpn:<pri>
 *    在 logd 侧设阈值(DEBUG→V/INFO→I/WARN→W/ERROR→E),选中档及以上才由 logd 输出,
 *    非客户端过滤;选择持久化 AppPrefs。另固定带 AndroidRuntime:W/System.err 抓崩溃栈。
 *    故意不带 --pid:logd 对无 READ_LOGS 的调用方只回本 UID 条目,天然只有本 App 日志,
 *    且跨进程重启(pid 变)的历史都在。
 *
 *  - **Go engine tab**:Go 引擎 slog 日志,走 gomobile 桥 Mobile.getGoLogs() 直读 Go 进程内
 *    logbuf 环形缓冲(与控制面板 GET /logs 同源同一块 buffer,含真实 level)。**不碰 logcat**:
 *    gomobile 把 os.Stdout 全标成 logcat I 优先级(x/mobile mobileinit_android.go:
 *    stdout→ANDROID_LOG_INFO),Go slog 各档日志在 logd 里全是 I,logcat tag 优先级过滤对它
 *    完全失效。等级设置写 config.json 的 log_level → fsnotify 热重载 applyLogLevel(生产端
 *    阈值,决定引擎是否产出该档日志);显示端再按选中档阈值过滤一遍——logbuf 里调高等级前
 *    已缓存的低级日志不会被生产端回溯清掉,客户端过滤让「设 ERROR 就只看 ERROR」对历史立即
 *    生效,与 Android tab 的设啥看啥体验对齐。
 *
 * 通用:自动刷新默认开(2s 一次,仅轮询当前 tab,切走不空转);手动刷新为右下角 FAB;
 * 搜索为顶栏内存关键字过滤;复制全部(长按单行复制该行);分享导出 txt 走 FileProvider;
 * 清空按 tab 分流(logcat -c / 清 Go logbuf)。行数上限 2000,超出丢最旧;底部跟随
 * (用户上翻时暂停跟随)。
 */
class LogcatActivity : ComponentActivity() {

    companion object {
        private const val TAG = "SmartProxyVpn"
        private const val MAX_LINES = 2000
        private const val REFRESH_MS = 2000L
        const val TAB_ANDROID = 0
        const val TAB_GO = 1

        /** Android tab:Go slog 级别 → logcat tag 优先级阈值(选中档及以上才由 logd 输出)。 */
        private fun androidLogcatPriority(level: String): String = when (level) {
            AppPrefs.LOG_LEVEL_INFO -> "I"
            AppPrefs.LOG_LEVEL_WARN -> "W"
            AppPrefs.LOG_LEVEL_ERROR -> "E"
            else -> "V" // DEBUG(默认):V 收全部
        }

        /** Go tab:slog 级别序号(DEBUG<INFO<WARN<ERROR),用于按阈值过滤 logbuf 历史条目。 */
        private fun levelRank(level: String): Int = when (level) {
            AppPrefs.LOG_LEVEL_DEBUG -> 0
            AppPrefs.LOG_LEVEL_INFO -> 1
            AppPrefs.LOG_LEVEL_WARN -> 2
            AppPrefs.LOG_LEVEL_ERROR -> 3
            else -> 1 // 未知按 INFO
        }
    }

    /** Go logbuf 一条(对应 Go logbuf.LogEntry / 面板 /logs 的 JSON 元素)。 */
    private data class GoLogEntry(val id: Long, val time: String, val level: String, val msg: String)

    private var currentTab by mutableStateOf(TAB_ANDROID)

    // ── Android tab 状态 ──
    // 注意:这些字段的初值不能在声明处调 AppPrefs/ConfigProvider(this)——属性初始化器在
    // Activity 构造期跑,此时 base context 尚未 attach(mBase==null),getSharedPreferences/
    // filesDir 直接 NPE 闪退。context 相关初值统一在 onCreate 里读(那时 context 已 attach)。
    private var autoRefresh by mutableStateOf(true)
    private var logLevel by mutableStateOf(AppPrefs.LOG_LEVEL_DEBUG)
    private var lines by mutableStateOf<List<String>>(emptyList())

    // ── Go tab 状态(等级真源是 config.json 的 log_level,不存 AppPrefs——那是 Go 引擎字段)──
    private var goAutoRefresh by mutableStateOf(true)
    private var goLogLevel by mutableStateOf(AppPrefs.LOG_LEVEL_INFO)
    private var goEntries by mutableStateOf<List<GoLogEntry>>(emptyList())

    private var error by mutableStateOf<String?>(null)
    private var showSearch by mutableStateOf(false)
    private var searchQuery by mutableStateOf("")

    /** Android 显示行 = logcat dump 行经关键字过滤。 */
    private val visibleAndroidLines: List<String>
        get() = filterSearch(lines)

    /** Go 显示行 = logbuf 条目先按等级阈值(>= 选中档)过滤历史,再格式化成行,再关键字过滤。 */
    private val visibleGoLines: List<String>
        get() = filterSearch(
            goEntries
                .filter { levelRank(it.level) >= levelRank(goLogLevel) }
                .map { "${it.time}  ${it.level.padEnd(5)}  ${it.msg}" }
        )

    /** Go 等级过滤后、关键字过滤前的行数(计数 x/y 的 y)。 */
    private val goLevelCount: Int
        get() = goEntries.count { levelRank(it.level) >= levelRank(goLogLevel) }

    /** 当前 tab 关键字过滤后的可见行(复制/分享/计数用)。 */
    private val currentVisibleLines: List<String>
        get() = if (currentTab == TAB_GO) visibleGoLines else visibleAndroidLines

    private fun filterSearch(src: List<String>): List<String> =
        if (searchQuery.isBlank()) src
        else src.filter { it.contains(searchQuery, ignoreCase = true) }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // context 相关初值在 onCreate 读(此时 base context 已 attach,见字段声明处注释):
        // Android tab 等级来自 AppPrefs,Go tab 等级来自 config.json 的 log_level。
        logLevel = AppPrefs.logcatLogLevel(this)
        goLogLevel = ConfigProvider.goLogLevel(this)
        // 标记日志:保证首次 dump 缓冲里至少有一条本 App 的日志,可验证查看管线。
        Log.i(TAG, "[Logcat] 查看器已打开")
        enableEdgeToEdge()
        setContent {
            AutoSystemBarStyle(AppPrefs.themeMode(this))
            SmartProxyTheme(mode = AppPrefs.themeMode(this)) {
                MaterialTheme(colorScheme = LogcatColors) {
                    val listStateAndroid = rememberLazyListState()
                    val listStateGo = rememberLazyListState()
                    val scope = rememberCoroutineScope()

                    // 轮询:进入某 tab 立即刷一次,随后该 tab 自动刷新开则每 2s 轮询、关则停;
                    // 切 tab / 切开关都重启此 effect——后台 tab 不空转。
                    LaunchedEffect(currentTab, autoRefresh, goAutoRefresh) {
                        while (true) {
                            if (currentTab == TAB_GO) {
                                refreshGo()
                                if (!goAutoRefresh) break
                            } else {
                                refreshAndroid()
                                if (!autoRefresh) break
                            }
                            delay(REFRESH_MS)
                        }
                    }
                    // 底部跟随:刷新后若用户仍在底部附近则滚到底,上翻则停(两个列表各自)。
                    LaunchedEffect(lines.size) { followBottom(listStateAndroid) }
                    LaunchedEffect(goEntries.size) { followBottom(listStateGo) }

                    LogcatScreen(
                        currentTab = currentTab,
                        onTabChange = { currentTab = it },
                        // Android
                        androidLines = visibleAndroidLines,
                        androidTotal = lines.size,
                        androidListState = listStateAndroid,
                        autoRefresh = autoRefresh,
                        logLevel = logLevel,
                        onToggleAutoRefresh = { autoRefresh = !autoRefresh },
                        onLogLevelChange = { level ->
                            logLevel = level
                            AppPrefs.setLogcatLogLevel(this@LogcatActivity, level)
                            scope.launch { refreshAndroid() } // 抓取阈值变了,立即按新 logcat 命令抓
                        },
                        // Go
                        goLines = visibleGoLines,
                        goTotal = goLevelCount,
                        goListState = listStateGo,
                        goAutoRefresh = goAutoRefresh,
                        goLogLevel = goLogLevel,
                        onToggleGoAutoRefresh = { goAutoRefresh = !goAutoRefresh },
                        onGoLogLevelChange = { level ->
                            // 生产端设置:写 config.log_level → 引擎热重载 applyLogLevel;
                            // 显示端阈值过滤随 goLogLevel state 立即生效(含历史缓冲),无需重新拉取。
                            goLogLevel = level
                            ConfigProvider.setGoLogLevel(this@LogcatActivity, level)
                        },
                        // 共用
                        isSearching = searchQuery.isNotBlank(),
                        error = error,
                        showSearch = showSearch,
                        searchQuery = searchQuery,
                        onToggleSearch = {
                            showSearch = !showSearch
                            if (!showSearch) searchQuery = ""
                        },
                        onSearchQueryChange = { searchQuery = it },
                        onCopyAll = { copyText(currentVisibleLines.joinToString("\n")) },
                        onShare = { shareText(currentVisibleLines.joinToString("\n")) },
                        onClear = {
                            scope.launch { if (currentTab == TAB_GO) clearGoLogs() else clearLogcat() }
                        },
                        onManualRefresh = {
                            scope.launch { if (currentTab == TAB_GO) refreshGo() else refreshAndroid() }
                        },
                        onLongPressLine = { copyText(it) },
                        onBack = { finish() }
                    )
                }
            }
        }
    }

    /** 刷新后若用户仍在列表底部附近则滚到底;上翻(可见末行离底 >3)则保持不动。 */
    private suspend fun followBottom(ls: LazyListState) {
        val total = ls.layoutInfo.totalItemsCount
        if (total > 0) {
            val visibleLast = ls.layoutInfo.visibleItemsInfo.lastOrNull()?.index ?: 0
            if (visibleLast >= total - 3) ls.scrollToItem(total - 1)
        }
    }

    // ── Android tab:exec logcat -d dump(IO 线程),结果替换 lines(上限裁剪)。 ──
    private suspend fun refreshAndroid() {
        val result = withContext(Dispatchers.IO) {
            runCatching {
                // 不带 --pid、只留本 App 的 Kotlin tag + 崩溃栈:详见类注释。logd 对无
                // READ_LOGS 的调用方只回本 UID 条目,天然只有本 App 日志,跨进程代都可见。
                val process = Runtime.getRuntime().exec(
                    arrayOf(
                        "logcat", "-d", "-v", "threadtime",
                        "-s", "SmartProxyVpn:${androidLogcatPriority(logLevel)}", "AndroidRuntime:W", "System.err"
                    )
                )
                try {
                    val text = process.inputStream.bufferedReader().use { it.readText() }
                    process.waitFor()
                    text
                } finally {
                    runCatching { process.destroy() }
                }
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
            .onFailure { e -> error = e.message }
    }

    // ── Go tab:gomobile 桥读 logbuf 环形缓冲快照(与面板 /logs 同源),IO 线程解析 JSON。 ──
    private suspend fun refreshGo() {
        val result = withContext(Dispatchers.IO) {
            runCatching {
                val arr = JSONArray(smartproxy.mobile.Mobile.getGoLogs())
                (0 until arr.length()).map { i ->
                    val o = arr.getJSONObject(i)
                    GoLogEntry(
                        id = o.getLong("id"),
                        time = o.optString("time"),
                        level = o.optString("level").ifBlank { "INFO" },
                        msg = o.optString("message")
                    )
                }
            }
        }
        result
            .onSuccess { entries ->
                goEntries = entries.takeLast(MAX_LINES)
                error = null
            }
            .onFailure { e -> error = e.message }
    }

    /** Android tab 清空:logcat -c 清系统缓冲,并清空本页。 */
    private suspend fun clearLogcat() {
        withContext(Dispatchers.IO) {
            runCatching {
                val p = Runtime.getRuntime().exec(arrayOf("logcat", "-c"))
                try {
                    p.waitFor()
                } finally {
                    runCatching { p.destroy() }
                }
            }
        }
        lines = emptyList()
        error = null
    }

    /** Go tab 清空:清 Go logbuf 环形缓冲(对应面板 POST /logs/clear)。 */
    private suspend fun clearGoLogs() {
        withContext(Dispatchers.IO) { runCatching { smartproxy.mobile.Mobile.clearGoLogs() } }
        goEntries = emptyList()
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

/** 两个 tab 可选日志级别(与 Go slog 一致:DEBUG/INFO/WARN/ERROR,无 VERBOSE)。 */
private val LOG_LEVELS = listOf(
    AppPrefs.LOG_LEVEL_DEBUG,
    AppPrefs.LOG_LEVEL_INFO,
    AppPrefs.LOG_LEVEL_WARN,
    AppPrefs.LOG_LEVEL_ERROR
)

@OptIn(ExperimentalFoundationApi::class)
@Composable
private fun LogcatScreen(
    currentTab: Int,
    onTabChange: (Int) -> Unit,
    // Android tab
    androidLines: List<String>,
    androidTotal: Int,
    androidListState: LazyListState,
    autoRefresh: Boolean,
    logLevel: String,
    onToggleAutoRefresh: () -> Unit,
    onLogLevelChange: (String) -> Unit,
    // Go tab
    goLines: List<String>,
    goTotal: Int,
    goListState: LazyListState,
    goAutoRefresh: Boolean,
    goLogLevel: String,
    onToggleGoAutoRefresh: () -> Unit,
    onGoLogLevelChange: (String) -> Unit,
    // 共用
    isSearching: Boolean,
    error: String?,
    showSearch: Boolean,
    searchQuery: String,
    onToggleSearch: () -> Unit,
    onSearchQueryChange: (String) -> Unit,
    onCopyAll: () -> Unit,
    onShare: () -> Unit,
    onClear: () -> Unit,
    onManualRefresh: () -> Unit,
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
            // ── 顶栏:M3 TopAppBar(返回 + 标题 + 搜索/复制/分享/清空;搜索模式标题位换成
            // 输入框)。windowInsets=0 交给外层 safeDrawingPadding 统一让位,容器透明保留 SoftBg。 ──
            TopAppBar(
                title = {
                    if (showSearch) {
                        OutlinedTextField(
                            value = searchQuery,
                            onValueChange = onSearchQueryChange,
                            placeholder = { Text(stringResource(R.string.logcat_search_placeholder), fontSize = 13.sp) },
                            singleLine = true,
                            modifier = Modifier.fillMaxWidth()
                        )
                    } else {
                        Text(stringResource(R.string.logcat_title), fontSize = 20.sp, fontWeight = FontWeight.Bold, color = PurpleText)
                    }
                },
                navigationIcon = {
                    if (showSearch) {
                        IconButton(onClick = onToggleSearch) {
                            Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = stringResource(R.string.cd_exit_search), tint = PurpleText)
                        }
                    } else {
                        IconButton(onClick = onBack) {
                            Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = stringResource(R.string.cd_back), tint = PurpleText)
                        }
                    }
                },
                actions = {
                    if (!showSearch) {
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
                },
                windowInsets = WindowInsets(0, 0, 0, 0),
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = Color.Transparent,
                    navigationIconContentColor = PurpleText,
                    titleContentColor = PurpleText,
                    actionIconContentColor = PurpleText
                )
            )

            // ── Tab:Android logcat / Go 引擎 slog ──
            TabRow(
                selectedTabIndex = currentTab,
                containerColor = Color.Transparent,
                contentColor = PurpleText,
                divider = {}
            ) {
                Tab(
                    selected = currentTab == LogcatActivity.TAB_ANDROID,
                    onClick = { onTabChange(LogcatActivity.TAB_ANDROID) },
                    text = { Text(stringResource(R.string.logcat_tab_android), fontSize = 13.sp) }
                )
                Tab(
                    selected = currentTab == LogcatActivity.TAB_GO,
                    onClick = { onTabChange(LogcatActivity.TAB_GO) },
                    text = { Text(stringResource(R.string.logcat_tab_go), fontSize = 13.sp) }
                )
            }
            Spacer(Modifier.height(4.dp))

            if (currentTab == LogcatActivity.TAB_GO) {
                LogPane(
                    lines = goLines,
                    totalLines = goTotal,
                    isSearching = isSearching,
                    emptyText = stringResource(R.string.logcat_empty_go),
                    error = error,
                    listState = goListState,
                    autoRefresh = goAutoRefresh,
                    logLevel = goLogLevel,
                    onToggleAutoRefresh = onToggleGoAutoRefresh,
                    onLevelChange = onGoLogLevelChange,
                    onLongPressLine = onLongPressLine
                )
            } else {
                LogPane(
                    lines = androidLines,
                    totalLines = androidTotal,
                    isSearching = isSearching,
                    emptyText = stringResource(R.string.logcat_empty),
                    error = error,
                    listState = androidListState,
                    autoRefresh = autoRefresh,
                    logLevel = logLevel,
                    onToggleAutoRefresh = onToggleAutoRefresh,
                    onLevelChange = onLogLevelChange,
                    onLongPressLine = onLongPressLine
                )
            }
        }

        // ── FAB:手动刷新(当前 tab;自动刷新关闭时使用) ──────────────────
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

/**
 * 单个日志 tab 的主体:自动刷新开关 + 日志等级「设置」下拉 + 行数,下面是等宽日志列表。
 * 两个 tab 共用同一布局,差异全由入参注入(数据源、等级、回调、空态文案)。
 */
@OptIn(ExperimentalFoundationApi::class)
@Composable
private fun LogPane(
    lines: List<String>,
    totalLines: Int,
    isSearching: Boolean,
    emptyText: String,
    error: String?,
    listState: LazyListState,
    autoRefresh: Boolean,
    logLevel: String,
    onToggleAutoRefresh: () -> Unit,
    onLevelChange: (String) -> Unit,
    onLongPressLine: (String) -> Unit
) {
    Column(modifier = Modifier.fillMaxSize()) {
        // ── 自动刷新开关 + 日志等级设置 + 行数 ─────────────────────────────
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
            Spacer(Modifier.width(8.dp))
            // 日志等级「设置」:Android tab 改 logcat 抓取阈值;Go tab 改引擎 config.log_level。
            var levelMenuOpen by remember { mutableStateOf(false) }
            Box {
                TextButton(
                    onClick = { levelMenuOpen = true },
                    contentPadding = PaddingValues(horizontal = 8.dp, vertical = 0.dp)
                ) {
                    Text(logLevel, fontSize = 12.sp, color = PurpleText, fontWeight = FontWeight.Medium)
                    Icon(
                        Icons.Filled.ArrowDropDown,
                        contentDescription = stringResource(R.string.logcat_level),
                        tint = PurpleText
                    )
                }
                DropdownMenu(
                    expanded = levelMenuOpen,
                    onDismissRequest = { levelMenuOpen = false }
                ) {
                    LOG_LEVELS.forEach { level ->
                        DropdownMenuItem(
                            text = {
                                Text(
                                    level,
                                    fontWeight = if (level == logLevel) FontWeight.Bold else FontWeight.Normal,
                                    color = TextDark
                                )
                            },
                            onClick = {
                                levelMenuOpen = false
                                onLevelChange(level)
                            }
                        )
                    }
                }
            }
            Spacer(Modifier.weight(1f))
            Text(
                if (isSearching) stringResource(R.string.logcat_count_filtered, lines.size, totalLines)
                else stringResource(R.string.logcat_count, totalLines),
                fontSize = 12.sp,
                color = GreyText,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )
        }
        Spacer(Modifier.height(6.dp))

        // ── 日志正文:等宽字体;长按复制单行 ─────────
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
                if (isSearching) stringResource(R.string.logcat_empty_search) else emptyText,
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
}
