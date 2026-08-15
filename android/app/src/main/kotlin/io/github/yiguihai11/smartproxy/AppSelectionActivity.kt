package io.github.yiguihai11.smartproxy

import android.os.Bundle
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
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
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
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
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
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
 *    勾选框 + 状态角标(仅代理下勾选=绿"仅代理",仅绕过下勾选=红"已排除")
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

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        mode = AppPrefs.globalMode(this)
        selected = AppPrefs.selectedApps(this)
        enableEdgeToEdge()
        setContent {
            MaterialTheme(colorScheme = AppSelectionColors) {
                AppSelectionScreen(
                    mode = mode,
                    selected = selected,
                    onModeChange = { newMode -> changeMode(newMode) },
                    onToggle = { pkg, checked -> toggle(pkg, checked) },
                    onBack = { finish() }
                )
            }
        }
    }

    /** 切模式;仅代理 + 空名单阻止(§8#6,防"全部直连"裸奔)。
     *  命名 changeMode 而非 setMode:避免与 mode 属性生成的 JVM setter(setMode(Z)V)冲突。 */
    private fun changeMode(newMode: Boolean) {
        if (!newMode && selected.isEmpty()) {
            Toast.makeText(this, "仅代理模式至少勾选 1 个应用", Toast.LENGTH_SHORT).show()
            return
        }
        mode = newMode
    }

    /** 勾选/取消;仅代理模式取消最后一个时阻止(§8#6)。 */
    private fun toggle(pkg: String, checked: Boolean) {
        if (!checked && !mode && selected.size == 1 && selected.contains(pkg)) {
            Toast.makeText(this, "仅代理模式至少勾选 1 个应用", Toast.LENGTH_SHORT).show()
            return
        }
        selected = if (checked) selected + pkg else selected - pkg
    }

    override fun onDestroy() {
        // 返回自动保存(sockstun 式):批写模式 + 应用列表;不重启,下次连接生效。
        AppPrefs.setGlobalMode(this, mode)
        AppPrefs.setSelectedApps(this, selected)
        super.onDestroy()
    }
}

// ── 主题色(对齐首页紫色系;主色喂 radio/checkbox/tab 高亮)─────────────
private val PurpleText = Color(0xFF7850AA)
private val GreyText = Color(0xFF666666)
private val TextDark = Color(0xFF222222)
private val SoftBg = Color(0xFFF3F0F8)
private val PlaceholderBg = Color(0xFFEEEAF6)
private val ProxyGreen = Color(0xFF4CAF50)
private val ExcludeRed = Color(0xFFFF6B6B)

private val AppSelectionColors = lightColorScheme(primary = PurpleText)

@Composable
private fun AppSelectionScreen(
    mode: Boolean,
    selected: Set<String>,
    onModeChange: (Boolean) -> Unit,
    onToggle: (String, Boolean) -> Unit,
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

    // 已选优先,其余按拼音 label 排序(§8#1)。排序基准 = 进入页面时的勾选态(§8#2:
    // 勾选后不实时置顶,避免列表跳动打断连续勾选,sockstun 同款)。
    val initialSelected = remember { selected }
    val collator = remember { Collator.getInstance(Locale.CHINA) }
    val visible = remember(allApps, tab, query, initialSelected) {
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
                val sa = initialSelected.contains(a.pkg)
                val sb = initialSelected.contains(b.pkg)
                when {
                    sa != sb -> if (sa) -1 else 1
                    else -> collator.compare(a.label, b.label)
                }
            }
    }

    // 角标语义随模式翻转:仅代理=绿"仅代理",仅绕过=红"已排除"(sockstun 同款)。
    val proxyMode = !mode
    val modeLabel = if (proxyMode) "仅代理" else "仅绕过"

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
                Text("应用选择", fontSize = 20.sp, fontWeight = FontWeight.Bold, color = PurpleText)
            }
            Spacer(Modifier.height(8.dp))

            // ── 流量模式(横向两选一,说明文字压成一行,省竖向空间)──
            Card(
                shape = RoundedCornerShape(20.dp),
                colors = CardDefaults.cardColors(containerColor = Color.White)
            ) {
                Column(Modifier.padding(16.dp)) {
                    Text("流量模式", fontSize = 14.sp, fontWeight = FontWeight.SemiBold, color = PurpleText)
                    Spacer(Modifier.height(8.dp))
                    SingleChoiceSegmentedButtonRow(Modifier.fillMaxWidth()) {
                        SegmentedButton(
                            selected = proxyMode,
                            onClick = { onModeChange(false) },
                            shape = SegmentedButtonDefaults.itemShape(index = 0, count = 2),
                            label = { Text("仅代理", fontSize = 14.sp) }
                        )
                        SegmentedButton(
                            selected = !proxyMode,
                            onClick = { onModeChange(true) },
                            shape = SegmentedButtonDefaults.itemShape(index = 1, count = 2),
                            label = { Text("仅绕过", fontSize = 14.sp) }
                        )
                    }
                    Spacer(Modifier.height(8.dp))
                    // 当前模式的一句说明(替代原 radio 副标题)。
                    Text(
                        if (proxyMode) "只代理下方勾选的应用,其余直连" else "全局走代理,放行下方勾选的应用",
                        fontSize = 12.sp,
                        color = GreyText
                    )
                }
            }
            Spacer(Modifier.height(12.dp))

            // ── 搜索 ────────────────────────────────────────────
            OutlinedTextField(
                value = query,
                onValueChange = { query = it },
                placeholder = { Text("搜索应用…") },
                leadingIcon = { Icon(Icons.Filled.Search, contentDescription = null) },
                singleLine = true,
                shape = RoundedCornerShape(14.dp),
                modifier = Modifier.fillMaxWidth()
            )
            Spacer(Modifier.height(10.dp))

            // ── 行内 tab:全部 / 用户 / 系统 ─────────────────────
            SingleChoiceSegmentedButtonRow(Modifier.fillMaxWidth()) {
                listOf("全部", "用户", "系统").forEachIndexed { index, label ->
                    SegmentedButton(
                        selected = tab == index,
                        onClick = { tab = index },
                        shape = SegmentedButtonDefaults.itemShape(index = index, count = 3),
                        label = { Text(label) }
                    )
                }
            }
            Spacer(Modifier.height(10.dp))

            // ── 统计条 ──────────────────────────────────────────
            Text(
                "共 ${allApps.size} · 显示 ${visible.size} · 已选 ${selected.size}（$modeLabel）",
                fontSize = 12.sp,
                color = GreyText
            )
            Spacer(Modifier.height(4.dp))

            // ── 应用列表 ────────────────────────────────────────
            when {
                !loaded -> Box(
                    Modifier.fillMaxWidth().weight(1f),
                    contentAlignment = Alignment.Center
                ) {
                    CircularProgressIndicator(color = PurpleText)
                }
                visible.isEmpty() -> Box(
                    Modifier.fillMaxWidth().weight(1f),
                    contentAlignment = Alignment.Center
                ) {
                    Text("没有匹配的应用", fontSize = 13.sp, color = GreyText)
                }
                else -> LazyColumn(Modifier.weight(1f)) {
                    items(visible, key = { it.pkg }) { app ->
                        AppRow(
                            app = app,
                            checked = selected.contains(app.pkg),
                            proxyMode = proxyMode,
                            onToggle = onToggle
                        )
                    }
                }
            }

            // ── 保存提示:返回自动保存,下次连接生效 ──────────────
            Spacer(Modifier.height(8.dp))
            Text(
                "退出即保存 · 改动在下次连接时生效",
                fontSize = 11.sp,
                color = GreyText,
                textAlign = TextAlign.Center,
                modifier = Modifier.fillMaxWidth()
            )
            Spacer(Modifier.height(8.dp))
        }
    }
}

/** 应用行:方形图标 + label/pkg·uid + 状态角标 + 勾选框;整行可点切换。 */
@Composable
private fun AppRow(
    app: AppEnumerator.AppInfo,
    checked: Boolean,
    proxyMode: Boolean,
    onToggle: (String, Boolean) -> Unit
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
        if (checked) {
            Surface(color = if (proxyMode) ProxyGreen else ExcludeRed, shape = RoundedCornerShape(999.dp)) {
                Text(
                    if (proxyMode) "仅代理" else "已排除",
                    color = Color.White,
                    fontSize = 10.sp,
                    fontWeight = FontWeight.Bold,
                    modifier = Modifier.padding(horizontal = 7.dp, vertical = 2.dp)
                )
            }
            Spacer(Modifier.width(4.dp))
        }
        // 整行已可点;Checkbox 自身也响应(命中其区域只触发一次,不重复切换)。
        Checkbox(checked = checked, onCheckedChange = { onToggle(app.pkg, it) })
    }
}
