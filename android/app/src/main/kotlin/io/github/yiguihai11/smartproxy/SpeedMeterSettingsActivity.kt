package io.github.yiguihai11.smartproxy

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Slider
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlin.math.roundToInt

/**
 * 悬浮网速计设置对话框(长按胶囊弹出,见 SpeedMeterOverlay.openSettings):
 *  - 全屏透明对话框 Activity + 自绘 scrim + 居中卡片;胶囊(TYPE_APPLICATION_OVERLAY)
 *    在窗口之上,拖动滑块即可实时预览。
 *  - 4 条滑块:胶囊大小 / 字号 / 图标大小 / 透明度(改即存:一动就写 AppPrefs + applySettingsInPlace)。
 *  - 「⇅ 调换位置」按钮:翻转 ↑/↓ 的左右显示顺序(实时预览,见 SpeedMeterOverlay.arrangeRateOrder)。
 *  - 底部「恢复默认」/「完成」;点卡片外(scrim)关闭。
 *  无保存/取消:偏好即真源,每次改动即时生效,本页只是长按胶囊的便捷入口。
 */
class SpeedMeterSettingsActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            // 主题(§7):与首页同源(同一份 AppPrefs.themeMode + 深色色板)。
            AutoSystemBarStyle(AppPrefs.themeMode(this))
            SmartProxyTheme(mode = AppPrefs.themeMode(this)) {
                MaterialTheme(colorScheme = SpeedMeterSettingsColors) {
                    SpeedMeterSettingsScreen(onClose = { finish() })
                }
            }
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        // 配置期间悬浮胶囊被强制保持显示(设置页前台自我排除、无流量会淡出),关页即恢复。
        SpeedMeterOverlay.onSettingsClosed()
    }
}

@Composable
private fun SpeedMeterSettingsScreen(onClose: () -> Unit) {
    val ctx = LocalContext.current.applicationContext

    // 改即存:偏好即真源,state 只是滑块/开关的瞬时值(初始读偏好,改动同步写偏好)。
    var capsuleSize by remember { mutableStateOf(AppPrefs.speedMeterCapsuleSize(ctx).toFloat()) }
    var fontSize by remember { mutableStateOf(AppPrefs.speedMeterFontSize(ctx).toFloat()) }
    var iconSize by remember { mutableStateOf(AppPrefs.speedMeterIconSize(ctx).toFloat()) }
    var alpha by remember { mutableStateOf(AppPrefs.speedMeterAlpha(ctx).toFloat()) }
    var upLabel by remember { mutableStateOf(AppPrefs.speedMeterUpLabel(ctx)) }
    var downLabel by remember { mutableStateOf(AppPrefs.speedMeterDownLabel(ctx)) }
    var swapOrder by remember { mutableStateOf(AppPrefs.speedMeterSwapOrder(ctx)) }
    var upColor by remember { mutableStateOf(AppPrefs.speedMeterUpColor(ctx)) }
    var downColor by remember { mutableStateOf(AppPrefs.speedMeterDownColor(ctx)) }
    // 颜色输入框文本(随选中色/输入同步;非法时红框不写入)。
    var upColorHex by remember { mutableStateOf(hexOf(AppPrefs.speedMeterUpColor(ctx))) }
    var downColorHex by remember { mutableStateOf(hexOf(AppPrefs.speedMeterDownColor(ctx))) }

    /** 改动即实时应用到悬浮胶囊(主线程);胶囊未显示时内部 no-op,下次构建读新偏好。 */
    fun applyAppearance() = SpeedMeterOverlay.applySettingsInPlace(ctx)

    Box(
        // 自绘 scrim + 点卡片外关闭;卡片自身 no-op clickable 消费,防空白区误触发关闭。
        Modifier
            .fillMaxSize()
            .background(Color.Black.copy(alpha = 0.45f))
            .pointerInput(Unit) { detectTapGestures { onClose() } },
        contentAlignment = Alignment.Center
    ) {
        Card(
            shape = RoundedCornerShape(20.dp),
            colors = CardDefaults.cardColors(containerColor = CardBg),
            elevation = CardDefaults.cardElevation(defaultElevation = 8.dp),
            modifier = Modifier
                .widthIn(min = 300.dp, max = 360.dp)
                // 消费卡片空白区点击:子 Slider 自己消费手势,不受影响。
                .clickable(
                    interactionSource = remember { MutableInteractionSource() },
                    indication = null
                ) {}
        ) {
            Column(
                Modifier
                    .padding(24.dp)
                    .verticalScroll(rememberScrollState())
                    .imePadding()
            ) {
                Text(
                    stringResource(R.string.speed_meter_settings_title),
                    color = TitleColor,
                    fontSize = 20.sp,
                    fontWeight = FontWeight.Bold
                )
                SliderRow(
                    label = stringResource(R.string.speed_meter_capsule_size),
                    valueText = stringResource(R.string.speed_meter_size_fmt, capsuleSize.roundToInt()),
                    value = capsuleSize,
                    valueRange = 2f..20f,
                    steps = 17,
                    onValueChange = {
                        capsuleSize = it
                        AppPrefs.setSpeedMeterCapsuleSize(ctx, it.roundToInt())
                        applyAppearance()
                    }
                )
                SliderRow(
                    label = stringResource(R.string.speed_meter_font_size),
                    valueText = stringResource(R.string.speed_meter_font_fmt, fontSize.roundToInt()),
                    value = fontSize,
                    valueRange = 8f..24f,
                    steps = 15,
                    onValueChange = {
                        fontSize = it
                        AppPrefs.setSpeedMeterFontSize(ctx, it.roundToInt())
                        applyAppearance()
                    }
                )
                SliderRow(
                    label = stringResource(R.string.speed_meter_icon_size),
                    valueText = stringResource(R.string.speed_meter_size_fmt, iconSize.roundToInt()),
                    value = iconSize,
                    valueRange = 8f..32f,
                    steps = 23,
                    onValueChange = {
                        iconSize = it
                        AppPrefs.setSpeedMeterIconSize(ctx, it.roundToInt())
                        applyAppearance()
                    }
                )
                SliderRow(
                    label = stringResource(R.string.speed_meter_alpha),
                    valueText = stringResource(R.string.speed_meter_alpha_fmt, alpha.roundToInt()),
                    value = alpha,
                    valueRange = 0f..100f,
                    steps = 0,
                    onValueChange = {
                        alpha = it
                        AppPrefs.setSpeedMeterAlpha(ctx, it.roundToInt())
                        applyAppearance()
                    }
                )
                Row(
                    Modifier
                        .fillMaxWidth()
                        .padding(top = 20.dp),
                    horizontalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    LabelField(
                        modifier = Modifier.weight(1f),
                        label = stringResource(R.string.speed_meter_up_label),
                        value = upLabel,
                        onValueChange = {
                            upLabel = it
                            AppPrefs.setSpeedMeterUpLabel(ctx, it)
                            applyAppearance()
                        }
                    )
                    LabelField(
                        modifier = Modifier.weight(1f),
                        label = stringResource(R.string.speed_meter_down_label),
                        value = downLabel,
                        onValueChange = {
                            downLabel = it
                            AppPrefs.setSpeedMeterDownLabel(ctx, it)
                            applyAppearance()
                        }
                    )
                }
                ColorRow(
                    label = stringResource(R.string.speed_meter_up_color),
                    selected = upColor,
                    hex = upColorHex,
                    onSelect = {
                        upColor = it
                        upColorHex = hexOf(it)
                        AppPrefs.setSpeedMeterUpColor(ctx, it)
                        applyAppearance()
                    },
                    onHexChange = { text ->
                        upColorHex = text
                        hexToColor(text)?.let { c ->
                            upColor = c
                            AppPrefs.setSpeedMeterUpColor(ctx, c)
                            applyAppearance()
                        }
                    }
                )
                ColorRow(
                    label = stringResource(R.string.speed_meter_down_color),
                    selected = downColor,
                    hex = downColorHex,
                    onSelect = {
                        downColor = it
                        downColorHex = hexOf(it)
                        AppPrefs.setSpeedMeterDownColor(ctx, it)
                        applyAppearance()
                    },
                    onHexChange = { text ->
                        downColorHex = text
                        hexToColor(text)?.let { c ->
                            downColor = c
                            AppPrefs.setSpeedMeterDownColor(ctx, c)
                            applyAppearance()
                        }
                    }
                )
                // 调换 ↑/↓ 显示左右位:点一下翻转并持久化。胶囊在设置页之上实时可见,
                // 一按立刻看到 ↓ 挪到 ↑ 左边(反之亦然),预览即所得。
                Row(
                    Modifier
                        .fillMaxWidth()
                        .padding(top = 16.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        stringResource(R.string.speed_meter_rate_order),
                        color = LabelColor,
                        fontSize = 15.sp,
                        modifier = Modifier.weight(1f)
                    )
                    TextButton(onClick = {
                        val next = !swapOrder
                        swapOrder = next
                        AppPrefs.setSpeedMeterSwapOrder(ctx, next)
                        applyAppearance()
                    }) {
                        Text(stringResource(R.string.speed_meter_swap_order), color = AccentColor)
                    }
                }
                Row(
                    Modifier
                        .fillMaxWidth()
                        .padding(top = 12.dp),
                    horizontalArrangement = Arrangement.End
                ) {
                    TextButton(onClick = {
                        // 恢复默认:写偏好 + 重置 state + 实时应用,三步缺一不可。
                        AppPrefs.setSpeedMeterCapsuleSize(ctx, AppPrefs.SPEED_METER_DEFAULT_CAPSULE_SIZE)
                        AppPrefs.setSpeedMeterFontSize(ctx, AppPrefs.SPEED_METER_DEFAULT_FONT_SIZE)
                        AppPrefs.setSpeedMeterIconSize(ctx, AppPrefs.SPEED_METER_DEFAULT_ICON_SIZE)
                        AppPrefs.setSpeedMeterAlpha(ctx, AppPrefs.SPEED_METER_DEFAULT_ALPHA)
                        AppPrefs.setSpeedMeterUpLabel(ctx, AppPrefs.SPEED_METER_DEFAULT_UP_LABEL)
                        AppPrefs.setSpeedMeterDownLabel(ctx, AppPrefs.SPEED_METER_DEFAULT_DOWN_LABEL)
                        AppPrefs.setSpeedMeterUpColor(ctx, AppPrefs.SPEED_METER_DEFAULT_UP_COLOR)
                        AppPrefs.setSpeedMeterDownColor(ctx, AppPrefs.SPEED_METER_DEFAULT_DOWN_COLOR)
                        AppPrefs.setSpeedMeterSwapOrder(ctx, false) // 出厂:上行在左、下行在右
                        capsuleSize = AppPrefs.SPEED_METER_DEFAULT_CAPSULE_SIZE.toFloat()
                        fontSize = AppPrefs.SPEED_METER_DEFAULT_FONT_SIZE.toFloat()
                        iconSize = AppPrefs.SPEED_METER_DEFAULT_ICON_SIZE.toFloat()
                        alpha = AppPrefs.SPEED_METER_DEFAULT_ALPHA.toFloat()
                        upLabel = AppPrefs.SPEED_METER_DEFAULT_UP_LABEL
                        downLabel = AppPrefs.SPEED_METER_DEFAULT_DOWN_LABEL
                        upColor = AppPrefs.SPEED_METER_DEFAULT_UP_COLOR
                        downColor = AppPrefs.SPEED_METER_DEFAULT_DOWN_COLOR
                        upColorHex = hexOf(AppPrefs.SPEED_METER_DEFAULT_UP_COLOR)
                        downColorHex = hexOf(AppPrefs.SPEED_METER_DEFAULT_DOWN_COLOR)
                        swapOrder = false
                        applyAppearance()
                    }) {
                        Text(stringResource(R.string.speed_meter_restore_defaults), color = LabelColor)
                    }
                    TextButton(onClick = onClose) {
                        Text(stringResource(R.string.speed_meter_done), color = AccentColor)
                    }
                }
            }
        }
    }
}

@Composable
private fun SliderRow(
    label: String,
    valueText: String,
    value: Float,
    valueRange: ClosedFloatingPointRange<Float>,
    steps: Int,
    onValueChange: (Float) -> Unit
) {
    Column(Modifier
        .fillMaxWidth()
        .padding(top = 20.dp)
    ) {
        Row(
            Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(label, color = LabelColor, fontSize = 15.sp, modifier = Modifier.weight(1f))
            Text(valueText, color = ValueColor, fontSize = 13.sp)
        }
        Slider(
            value = value,
            onValueChange = onValueChange,
            valueRange = valueRange,
            steps = steps,
            modifier = Modifier.fillMaxWidth()
        )
    }
}

@Composable
private fun LabelField(
    modifier: Modifier = Modifier,
    label: String,
    value: String,
    onValueChange: (String) -> Unit
) {
    // weight 是 RowScope 扩展,只能在父 Row 内容里调,故由调用点传入 modifier。
    Column(modifier) {
        Text(label, color = LabelColor, fontSize = 14.sp)
        OutlinedTextField(
            value = value,
            onValueChange = { if (it.length <= 4) onValueChange(it) }, // 标签是符号,限 4 字
            singleLine = true,
            shape = RoundedCornerShape(10.dp),
            modifier = Modifier
                .fillMaxWidth()
                .padding(top = 6.dp)
        )
    }
}

@Composable
private fun ColorRow(
    label: String,
    selected: Int,
    hex: String,
    onSelect: (Int) -> Unit,
    onHexChange: (String) -> Unit
) {
    // 非空且不合法 → 红框提示,此时不写入(空 = 保持现色继续编辑)。
    val badHex = hex.isNotEmpty() && hexToColor(hex) == null
    Column(Modifier
        .fillMaxWidth()
        .padding(top = 16.dp)
    ) {
        Row(
            Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(label, color = LabelColor, fontSize = 15.sp, modifier = Modifier.weight(1f))
            OutlinedTextField(
                value = hex,
                onValueChange = onHexChange,
                singleLine = true,
                isError = badHex,
                shape = RoundedCornerShape(10.dp),
                colors = OutlinedTextFieldDefaults.colors(
                    focusedBorderColor = if (badHex) ErrorColor else AccentColor,
                    unfocusedBorderColor = if (badHex) ErrorColor else DividerLine,
                    focusedContainerColor = Color.Transparent,
                    unfocusedContainerColor = Color.Transparent
                ),
                modifier = Modifier.width(132.dp)
            )
        }
        Row(
            Modifier
                .fillMaxWidth()
                .padding(top = 8.dp),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            PRESET_TEXT_COLORS.forEach { c ->
                val sel = c == selected
                Box(
                    Modifier
                        .size(24.dp)
                        .clip(CircleShape)
                        .background(Color(c))
                        .border(2.dp, if (sel) AccentColor else DividerLine, CircleShape)
                        .clickable { onSelect(c) }
                )
            }
        }
    }
}

// 浅/深两套(§7):getter 读 ThemeState.isDark,色板与全 App 惯例一致。
private val AccentColor get() = if (ThemeState.isDark) Color(0xFF7CCB7C) else Color(0xFF2EBD85)
private val CardBg get() = if (ThemeState.isDark) Color(0xFF26262B) else Color(0xFFFAFAFA)
private val TitleColor get() = if (ThemeState.isDark) Color(0xFFF2F2F2) else Color(0xFF1C1C1E)
private val LabelColor get() = if (ThemeState.isDark) Color(0xFFD1D1D6) else Color(0xFF3A3A3C)
private val ValueColor get() = if (ThemeState.isDark) Color(0xFF8E8E93) else Color(0xFF6E6E73)
private val DividerLine get() = if (ThemeState.isDark) Color(0xFF3A3A3E) else Color(0xFFE0E0E0)
private val SpeedMeterSettingsColors get() =
    if (ThemeState.isDark) darkColorScheme(primary = AccentColor)
    else lightColorScheme(primary = AccentColor)

// 可在深色胶囊上清晰读出的预设文字色(白 + 高亮系;前三个含历史默认绿/蓝)。
private val PRESET_TEXT_COLORS = listOf(
    0xFFFFFFFF.toInt(),
    0xFF7CCB7C.toInt(),
    0xFF6FB7FF.toInt(),
    0xFF5FD4C4.toInt(),
    0xFFFFE08A.toInt(),
    0xFFFFB74D.toInt(),
    0xFFFF7A7A.toInt(),
    0xFFFF8AC4.toInt()
)

private val ErrorColor get() = if (ThemeState.isDark) Color(0xFFFF6B6B) else Color(0xFFD32F2F)

private val HEX_RE = Regex("^[0-9a-fA-F]{6}$")

/** "#RRGGBB"(可带可不带 #,大小写都可,6 位不透明) → ARGB Color int;非法返回 null。 */
private fun hexToColor(hex: String): Int? {
    val h = hex.removePrefix("#").trim()
    return if (HEX_RE.matches(h)) 0xFF000000.toInt() or h.toInt(16) else null
}

/** ARGB Color int → "#RRGGBB"(六位大写,不透明)。 */
private fun hexOf(color: Int): String = String.format("#%06X", color and 0xFFFFFF)
