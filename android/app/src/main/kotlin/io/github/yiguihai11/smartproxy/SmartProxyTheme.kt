package io.github.yiguihai11.smartproxy

import android.content.Context
import android.content.res.Configuration
import androidx.activity.ComponentActivity
import androidx.activity.SystemBarStyle
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.platform.LocalContext

/**
 * 主题(§7):三档 auto(跟随系统)/ light / dark,首页右上角切换。
 * 各 Activity 的颜色取值(getter)读 [ThemeState.isDark] 响应式自适应,
 * 避免把所有硬编码 Color 常量改写成传参——getter 读 Snapshot state,
 * 主题切换时引用处自动重组。
 */
object ThemeState {
    /** 当前是否深色。由 [SmartProxyTheme] 按模式(含系统)写入,颜色 getter 读取。 */
    var isDark by mutableStateOf(false)
        internal set
}

/** 切换顺序:自动 → 浅色 → 深色 → 自动。 */
fun cycleThemeMode(current: String): String = when (current) {
    AppPrefs.THEME_AUTO -> AppPrefs.THEME_LIGHT
    AppPrefs.THEME_LIGHT -> AppPrefs.THEME_DARK
    else -> AppPrefs.THEME_AUTO
}

/** 首页右上角切换钮显示的当前模式名。 */
fun themeModeLabel(mode: String): String = when (mode) {
    AppPrefs.THEME_LIGHT -> "浅色"
    AppPrefs.THEME_DARK -> "深色"
    else -> "自动"
}

/** 按模式(含跟随系统)解析是否深色。Activity 调 enableEdgeToEdge 定条栏图标色用;
 *  composable 侧用 [SmartProxyTheme] 里的 isSystemInDarkTheme(),两者同源。 */
fun resolveDarkMode(context: Context, mode: String): Boolean = when (mode) {
    AppPrefs.THEME_DARK -> true
    AppPrefs.THEME_LIGHT -> false
    else -> (context.resources.configuration.uiMode and Configuration.UI_MODE_NIGHT_MASK) ==
        Configuration.UI_MODE_NIGHT_YES
}

/** 系统状态栏/导航栏图标色跟随当前主题(§7)。默认 enableEdgeToEdge 的 auto 只看系统深色
 *  模式;手动深色 + 系统浅色时,深色图标会落在深色背景上不可见,故按解析结果重设。 */
@Composable
fun AutoSystemBarStyle(mode: String) {
    val context = LocalContext.current
    val dark = resolveDarkMode(context, mode)
    LaunchedEffect(dark) {
        if (context is ComponentActivity) {
            val style = if (dark) SystemBarStyle.dark(0x00000000)
            else SystemBarStyle.light(0x00000000, 0x00000000)
            // enableEdgeToEdge 是 ComponentActivity 的扩展函数:context 已智能转成
            // ComponentActivity,但要显式带接收者调用,裸调用找不到 receiver。
            context.enableEdgeToEdge(statusBarStyle = style, navigationBarStyle = style)
        }
    }
}

/** 全局主题包装:按模式选 dark/light colorScheme,并同步 [ThemeState.isDark]。 */
@Composable
fun SmartProxyTheme(mode: String, content: @Composable () -> Unit) {
    val dark = when (mode) {
        AppPrefs.THEME_DARK -> true
        AppPrefs.THEME_LIGHT -> false
        else -> isSystemInDarkTheme()
    }
    ThemeState.isDark = dark
    MaterialTheme(
        colorScheme = if (dark) darkColorScheme() else lightColorScheme(),
        content = content
    )
}
