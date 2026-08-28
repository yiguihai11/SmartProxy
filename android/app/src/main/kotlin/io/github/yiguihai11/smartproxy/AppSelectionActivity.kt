package io.github.yiguihai11.smartproxy

import android.os.Build
import android.os.Bundle
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
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Block
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.derivedStateOf
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.text.Collator
import java.util.Locale

/**
 * 应用选择页(§5 应用内化,替代 Web 面板的流量模式+应用选择):
 *  - 流量模式:仅代理(白名单)/ 仅绕过(黑名单,默认)两选一
 *  - 应用列表:行内 tab(全部/用户/系统)+ 搜索 + 方形图标 + label/pkg/uid +
 *    勾选框 + 状态角标(仅代理下勾选=绿"仅代理",仅绕过下勾选=红"已排除",
 *    拦截=红"已拦截联网")+「禁止联网」拦截按钮(仅绕过模式,§5 第一期,API 29+ 才显示)
 *  - 排序:已选优先,其余按拼音 label(Collator CHINA,§8#1)
 *  - 保存:sockstun 式返回自动保存(onDestroy 批写 AppPrefs),不自动重启,
 *    改动在下次连接生效;UI 底部有提示。
 *  - §8#6 空名单约束:仅代理模式至少勾 1 个应用,否则阻止切换/取消并 Toast。
 *
 * 状态挂在 Activity 字段(by mutableStateOf):Compose 写、onDestroy 读,
 * 保证"返回自动保存"拿到的总是最新勾选。
 */
class AppSelectionActivity : ComponentActivity() {

    /** 流量模式:true = 仅绕过(黑名单,默认),false = 仅代理(白名单)。 */
    private var mode by mutableStateOf(true)

    /** 勾选的应用包名集合(语义随模式翻转:仅代理=白名单 / 仅绕过=黑名单)。 */
    private var selected by mutableStateOf<Set<String>>(emptySet())

    /** 「禁止联网」拦截的应用包名集合(§5 第一期仅在仅绕过/黑名单模式可用,与 selected 互斥)。 */
    private var blocked by mutableStateOf<Set<String>>(emptySet())

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        mode = AppPrefs.globalMode(this)
        selected = AppPrefs.selectedApps(this)
        blocked = AppPrefs.blockedApps(this)
        enableEdgeToEdge()
        setContent {
            // 主题(§7):与首页同源(同一份 AppPrefs.themeMode + 深色色板)。
            AutoSystemBarStyle(AppPrefs.themeMode(this))
            SmartProxyTheme(mode = AppPrefs.themeMode(this)) {
                MaterialTheme(colorScheme = AppSelectionColors) {
                    AppSelectionScreen(
                        mode = mode,
                        selected = selected,
                        blocked = blocked,
                        onModeChange = { newMode -> changeMode(newMode) },
                        onToggle = { pkg, checked -> toggle(pkg, checked) },
                        onToggleBlock = { pkg -> toggleBlock(pkg) },
                        onBack = { finish() }
                    )
                }
            }
        }
    }

    /** 切模式;仅代理 + 空名单阻止(§8#6,防"全部直连"裸奔)。
     *  命名 changeMode 而非 setMode:避免与 mode 属性生成的 JVM setter(setMode(Z)V)冲突。 */
    private fun changeMode(newMode: Boolean) {
        if (!newMode && selected.isEmpty()) {
            Toast.makeText(this, getString(R.string.toast_min_one_app), Toast.LENGTH_SHORT).show()
            return
        }
        mode = newMode
    }

    /** 勾选/取消;仅代理模式取消最后一个时阻止(§8#6)。勾选(排除/代理)时清除该应用的
     *  拦截态(两者互斥,拦截优先)。 */
    private fun toggle(pkg: String, checked: Boolean) {
        if (!checked && !mode && selected.size == 1 && selected.contains(pkg)) {
            Toast.makeText(this, getString(R.string.toast_min_one_app), Toast.LENGTH_SHORT).show()
            return
        }
        selected = if (checked) selected + pkg else selected - pkg
        if (checked) blocked = blocked - pkg
    }

    /** 切换「禁止联网」(§5):白名单模式 UI 不显示入口,这里防御性返回。与 selected 互斥:
     *  拦截一个应用就把它从排除里移掉,反之勾选排除也会清掉拦截。 */
    private fun toggleBlock(pkg: String) {
        if (!mode) return
        blocked = if (blocked.contains(pkg)) blocked - pkg else blocked + pkg
        if (blocked.contains(pkg)) selected = selected - pkg
    }

    override fun onDestroy() {
        // 返回自动保存(sockstun 式):批写模式 + 应用列表 + 拦截列表;不重启,下次连接生效。
        AppPrefs.setGlobalMode(this, mode)
        AppPrefs.setSelectedApps(this, selected)
        AppPrefs.setBlockedApps(this, blocked)
        super.onDestroy()
    }
}

// ── 主题色(对齐首页樱花粉色系;主色喂 radio/checkbox/tab 高亮)─────────────
// 浅/深两套(§7):getter 读 ThemeState.isDark,色板与首页同源。
private val PurpleText get() = if (ThemeState.isDark) Color(0xFFF6B8CF) else Color(0xFFD66E9B)
private val GreyText get() = if (ThemeState.isDark) Color(0xFFC9A8B6) else Color(0xFF7A626D)
private val TextDark get() = if (ThemeState.isDark) Color(0xFFF3E3EA) else Color(0xFF3A2A31)
private val SoftBg get() = if (ThemeState.isDark) Color(0xFF2B1A22) else Color(0xFFFFF5F9)
private val PlaceholderBg get() = if (ThemeState.isDark) Color(0xFF3D2430) else Color(0xFFFCE0EC)
private val CardBg get() = if (ThemeState.isDark) Color(0xFF38262F) else Color.White
private val ProxyGreen = Color(0xFF4CAF50)
private val ExcludeRed = Color(0xFFFF6B6B)
private val BlockRed = Color(0xFFFF3B30)

private val AppSelectionColors get() =
    if (ThemeState.isDark) darkColorScheme(primary = PurpleText)
    else lightColorScheme(primary = PurpleText)

/** 排序优先级(数字越小越靠前):选中∩拦截 > 选中 > 拦截 > 其余。
 *  仅代理模式拦截集恒空,此函数自然退化为「选中优先」。 */
private fun blockSortRank(selected: Set<String>, blocked: Set<String>, pkg: String): Int = when {
    pkg in selected && pkg in blocked -> 0
    pkg in selected -> 1
    pkg in blocked -> 2
    else -> 3
}

@Composable
private fun AppSelectionScreen(
    mode: Boolean,
    selected: Set<String>,
    blocked: Set<String>,
    onModeChange: (Boolean) -> Unit,
    onToggle: (String, Boolean) -> Unit,
    onToggleBlock: (String) -> Unit,
    onBack: () -> Unit
) {
    val context = LocalContext.current
    var allApps by remember { mutableStateOf<List<AppEnumerator.AppInfo>>(emptyList()) }
    var loaded by remember { mutableStateOf(false) }
    var tab by remember { mutableStateOf(0) }      // 0 全部 / 1 用户 / 2 系统
    var query by remember { mutableStateOf("") }

    LaunchedEffect(Unit) {
        val list = withContext(Dispatchers.IO) {
            AppEnumerator.list(context).also { apps ->
                // 预热图标缓存:IO 线程解码,主线程滚动只读缓存不卡顿。
                apps.forEach { AppEnumerator.iconBitmap(context, it.pkg) }
            }
        }
        allApps = list
        loaded = true
    }

    // 排序基准 = 进入页面时的勾选/拦截态(§8#2:勾选后不实时置顶,避免列表跳动打断
    // 连续勾选,sockstun 同款)。优先级(§5 二期):选中∩拦截 > 选中 > 拦截 > 其余,
    // 同 tier 按拼音(§8#1)。仅代理模式拦截集恒空,自然退化为「选中优先」。
    val initialSelected = remember { selected }
    val initialBlocked = remember { blocked }
    val collator = remember { Collator.getInstance(Locale.CHINA) }
    val visible = remember(allApps, tab, query, initialSelected, initialBlocked) {
        val q = query.trim().lowercase()
        allApps
            .filter { a ->
                val tabOk = when (tab) {
                    0 -> true
                    1 -> !a.system
                    else -> a.system
                }
                tabOk && (q.isEmpty() || a.label.lowercase().contains(q) || a.pkg.lowercase().contains(q))
            }
            .sortedWith { a, b ->
                val ra = blockSortRank(initialSelected, initialBlocked, a.pkg)
                val rb = blockSortRank(initialSelected, initialBlocked, b.pkg)
                when {
                    ra != rb -> ra.compareTo(rb)
                    else -> collator.compare(a.label, b.label)
                }
            }
    }

    // 角标语义随模式翻转:仅代理=绿"仅代理",仅绕过=红"已排除"(sockstun 同款)。
    val proxyMode = !mode

    // 「禁止联网」只在 API 29+ 可用(getConnectionOwnerUid 唯一重载的起点);
    // 低于此隐藏全部相关 UI(按钮/白名单提示/统计),不误导用户。
    val blockSupported = Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q

    // 流量模式卡随列表滚动收起:滚离顶部(>48px)隐藏,回到顶部再显示(§5 UX)。
    // 搜索 / tab / 统计条保持固定,过滤随时可用;只有模式卡让出屏幕空间。
    val listState = rememberLazyListState()
    val modeCardVisible by remember {
        derivedStateOf {
            listState.firstVisibleItemIndex == 0 && listState.firstVisibleItemScrollOffset <= 48
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
                Text(stringResource(R.string.appsel_title), fontSize = 20.sp, fontWeight = FontWeight.Bold, color = PurpleText)
            }
            Spacer(Modifier.height(8.dp))

            // ── 流量模式(横向两选一,说明文字压成一行,省竖向空间)──
            // 滚动收起:AnimatedVisibility 包住整卡+下方间距,滚离顶部平滑收掉,
            // 回到顶部再展开(默认动画 = 高度收缩 + 淡出,与列表滚动同向,不突兀)。
            AnimatedVisibility(visible = modeCardVisible) {
                Column {
                    Card(
                        shape = RoundedCornerShape(20.dp),
                        colors = CardDefaults.cardColors(containerColor = CardBg)
                    ) {
                        Column(Modifier.padding(16.dp)) {
                            Text(stringResource(R.string.appsel_mode_card), fontSize = 14.sp, fontWeight = FontWeight.SemiBold, color = PurpleText)
                            Spacer(Modifier.height(8.dp))
                            SingleChoiceSegmentedButtonRow(Modifier.fillMaxWidth()) {
                                SegmentedButton(
                                    selected = proxyMode,
                                    onClick = { onModeChange(false) },
                                    shape = SegmentedButtonDefaults.itemShape(index = 0, count = 2),
                                    label = { Text(stringResource(R.string.appsel_mode_proxy), fontSize = 14.sp) }
                                )
                                SegmentedButton(
                                    selected = !proxyMode,
                                    onClick = { onModeChange(true) },
                                    shape = SegmentedButtonDefaults.itemShape(index = 1, count = 2),
                                    label = { Text(stringResource(R.string.appsel_mode_bypass), fontSize = 14.sp) }
                                )
                            }
                            Spacer(Modifier.height(8.dp))
                            // 当前模式的一句说明(替代原 radio 副标题)。
                            Text(
                                if (proxyMode) stringResource(R.string.appsel_proxy_desc) else stringResource(R.string.appsel_bypass_desc),
                                fontSize = 12.sp,
                                color = GreyText
                            )
                            // §5 第一期:禁止联网仅在仅绕过(黑名单)模式提供;白名单模式隐藏
                            // 拦截入口并说明原因;API<29 整段隐藏。
                            if (proxyMode && blockSupported) {
                                Spacer(Modifier.height(6.dp))
                                Text(
                                    stringResource(R.string.appsel_warn_block),
                                    fontSize = 11.sp,
                                    color = ExcludeRed
                                )
                            }
                        }
                    }
                    Spacer(Modifier.height(12.dp))
                }
            }

            // ── 搜索 ────────────────────────────────────────────
            OutlinedTextField(
                value = query,
                onValueChange = { query = it },
                placeholder = { Text(stringResource(R.string.appsel_search)) },
                leadingIcon = { Icon(Icons.Filled.Search, contentDescription = null) },
                singleLine = true,
                shape = RoundedCornerShape(14.dp),
                modifier = Modifier.fillMaxWidth()
            )
            Spacer(Modifier.height(10.dp))

            // ── 行内 tab:全部 / 用户 / 系统 ─────────────────────
            SingleChoiceSegmentedButtonRow(Modifier.fillMaxWidth()) {
                listOf(
                    R.string.appsel_tab_all,
                    R.string.appsel_tab_user,
                    R.string.appsel_tab_system
                ).forEachIndexed { index, res ->
                    SegmentedButton(
                        selected = tab == index,
                        onClick = { tab = index },
                        shape = SegmentedButtonDefaults.itemShape(index = index, count = 3),
                        label = { Text(stringResource(res)) }
                    )
                }
            }
            Spacer(Modifier.height(10.dp))

            // ── 统计条 ──────────────────────────────────────────
            Text(
                buildString {
                    append(
                        stringResource(
                            R.string.appsel_stats,
                            allApps.size,
                            visible.size,
                            selected.size,
                            if (proxyMode) stringResource(R.string.appsel_mode_proxy)
                            else stringResource(R.string.appsel_mode_bypass)
                        )
                    )
                    if (mode && blockSupported) {
                        append(stringResource(R.string.appsel_stats_blocked, blocked.size))
                    }
                },
                fontSize = 12.sp,
                color = GreyText
            )
            Spacer(Modifier.height(4.dp))

            // ── 应用列表 ────────────────────────────────────────
            when {
                // 全量应用枚举 + 图标解码耗时(首次更慢):转圈 + 文案提示,避免"卡住"错觉。
                !loaded -> Column(
                    Modifier.fillMaxWidth().weight(1f),
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.Center
                ) {
                    CircularProgressIndicator(color = PurpleText)
                    Spacer(Modifier.height(12.dp))
                    Text(stringResource(R.string.appsel_loading), fontSize = 13.sp, color = GreyText)
                }
                visible.isEmpty() -> Box(
                    Modifier.fillMaxWidth().weight(1f),
                    contentAlignment = Alignment.Center
                ) {
                    Text(stringResource(R.string.appsel_empty), fontSize = 13.sp, color = GreyText)
                }
                else -> LazyColumn(state = listState, modifier = Modifier.weight(1f)) {
                    items(visible, key = { it.pkg }) { app ->
                        AppRow(
                            app = app,
                            checked = selected.contains(app.pkg),
                            blocked = blocked.contains(app.pkg),
                            blockable = mode && blockSupported,
                            proxyMode = proxyMode,
                            onToggle = onToggle,
                            onToggleBlock = onToggleBlock
                        )
                    }
                }
            }

            // ── 保存提示:返回自动保存,下次连接生效 ──────────────
            Spacer(Modifier.height(8.dp))
            Text(
                stringResource(R.string.appsel_footer),
                fontSize = 11.sp,
                color = GreyText,
                textAlign = TextAlign.Center,
                modifier = Modifier.fillMaxWidth()
            )
            Spacer(Modifier.height(8.dp))
        }
    }
}

/** 应用行:方形图标 + label/pkg·uid + 状态角标 + 拦截按钮 + 勾选框;整行可点切换。
 *  §5 三态:仅绕过模式下可勾选(已排除)或拦截(已拦截联网),二者互斥;拦截优先级更高。
 *  blockable=false(仅代理/白名单)时隐藏拦截按钮。 */
@Composable
private fun AppRow(
    app: AppEnumerator.AppInfo,
    checked: Boolean,
    blocked: Boolean,
    blockable: Boolean,
    proxyMode: Boolean,
    onToggle: (String, Boolean) -> Unit,
    onToggleBlock: (String) -> Unit
) {
    val context = LocalContext.current
    val icon = remember(app.pkg) { AppEnumerator.iconBitmap(context, app.pkg) }

    Row(
        verticalAlignment = Alignment.CenterVertically,
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(12.dp))
            .clickable { onToggle(app.pkg, !checked) }
            .padding(vertical = 6.dp, horizontal = 4.dp)
    ) {
        if (icon != null) {
            Image(
                bitmap = icon,
                contentDescription = null,
                modifier = Modifier.size(40.dp).clip(RoundedCornerShape(9.dp))
            )
        } else {
            // 图标解析失败:包名首字符占位(与面板 app-icon 一致的处理)。
            Box(
                modifier = Modifier.size(40.dp).clip(RoundedCornerShape(9.dp)).background(PlaceholderBg),
                contentAlignment = Alignment.Center
            ) {
                Text(app.pkg.take(1).uppercase(), color = GreyText, fontSize = 16.sp)
            }
        }
        Spacer(Modifier.width(12.dp))
        Column(Modifier.weight(1f)) {
            Text(
                app.label,
                fontSize = 14.sp,
                color = TextDark,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )
            Text(
                "${app.pkg} · uid ${app.uid}",
                fontSize = 11.sp,
                color = GreyText,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )
        }
        if (checked || blocked) {
            Surface(
                color = when {
                    blocked -> BlockRed
                    proxyMode -> ProxyGreen
                    else -> ExcludeRed
                },
                shape = RoundedCornerShape(999.dp)
            ) {
                Text(
                    when {
                        blocked -> stringResource(R.string.appsel_badge_blocked)
                        proxyMode -> stringResource(R.string.appsel_mode_proxy)
                        else -> stringResource(R.string.appsel_badge_excluded)
                    },
                    color = Color.White,
                    fontSize = 10.sp,
                    fontWeight = FontWeight.Bold,
                    modifier = Modifier.padding(horizontal = 7.dp, vertical = 2.dp)
                )
            }
            Spacer(Modifier.width(4.dp))
        }
        // 禁止联网按钮(仅绕过/黑名单模式显示;白名单隐藏,模式卡内已说明)。点它切换拦截态,
        // 与勾选框互斥(勾选会清拦截,拦截会清勾选)。
        if (blockable) {
            IconButton(onClick = { onToggleBlock(app.pkg) }) {
                Icon(
                    Icons.Filled.Block,
                    contentDescription = stringResource(R.string.cd_block_network),
                    tint = if (blocked) BlockRed else GreyText
                )
            }
        }
        // 整行已可点;Checkbox 自身也响应(命中其区域只触发一次,不重复切换)。
        Checkbox(checked = checked, onCheckedChange = { onToggle(app.pkg, it) })
    }
}
