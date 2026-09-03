package io.github.yiguihai11.smartproxy

import android.util.Log

/**
 * 引擎连接统计采集开关(Mobile.setConnStatsEnabled)的引用计数闸。
 *
 * 采集在引擎侧有开销(每连接记账 + 快照),必须「有消费者才开、全走光就关」。
 * 消费者有两个:联网状态页(NetworkStatusActivity)和悬浮网速计(SpeedMeterOverlay)。
 * 两者可能同时存在(页面在前台 + 悬浮窗也在),直接各开各关会互相拆台 —— 例如页面
 * onPause 延迟关采集时把悬浮窗正在用的统计也清了。用计数把多消费者合并:
 * 计数 0→1 才真正开采集,1→0 才真正关。
 *
 * 同步:方法加 @Synchronized,计数值与 JNI 调用原子化,防快速切前后台时
 * acquire/release 乱序导致有消费者却被关掉统计(竞态)。
 * 调用方须保证 acquire/release 严格配对(建议配一个 held 布尔,见两个调用方)。
 * gomobile 的 error 以 Java 异常抛出,这里 runCatching 兜底。
 */
object ConnStatsGate {
    private const val TAG = "ConnStatsGate"
    private var count = 0

    @Synchronized
    fun acquire() {
        count++
        if (count == 1) {
            runCatching { smartproxy.mobile.Mobile.setConnStatsEnabled(true) }
                .onFailure { Log.e(TAG, "setConnStatsEnabled(true) failed", it) }
        }
    }

    @Synchronized
    fun release() {
        if (count > 0) {
            count--
            if (count == 0) {
                runCatching { smartproxy.mobile.Mobile.setConnStatsEnabled(false) }
                    .onFailure { Log.e(TAG, "setConnStatsEnabled(false) failed", it) }
            }
        }
    }
}
