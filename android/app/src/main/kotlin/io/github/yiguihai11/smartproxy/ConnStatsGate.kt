package io.github.yiguihai11.smartproxy

import android.util.Log
import java.util.concurrent.atomic.AtomicInteger

/**
 * 引擎连接统计采集开关(Mobile.setConnStatsEnabled)的引用计数闸。
 *
 * 采集在引擎侧有开销(每连接记账 + 快照),必须「有消费者才开、全走光就关」。
 * 消费者有两个:联网状态页(NetworkStatusActivity)和悬浮网速计(SpeedMeterOverlay)。
 * 两者可能同时存在(页面在前台 + 悬浮窗也在),直接各开各关会互相拆台 —— 例如页面
 * onPause 延迟关采集时把悬浮窗正在用的统计也清了。用计数把多消费者合并:
 * 计数 0→1 才真正开采集,1→0 才真正关。
 *
 * 调用方须保证 acquire/release 严格配对(建议配一个 held 布尔,见两个调用方)。
 * gomobile 的 error 以 Java 异常抛出,这里 runCatching 兜底,计数仍照常增减
 * (引擎未启动时开采集失败无副作用,连上后消费者会重新触发)。
 */
object ConnStatsGate {
    private const val TAG = "ConnStatsGate"
    private val count = AtomicInteger(0)

    fun acquire() {
        if (count.getAndIncrement() == 0) {
            runCatching { smartproxy.mobile.Mobile.setConnStatsEnabled(true) }
                .onFailure { Log.e(TAG, "setConnStatsEnabled(true) failed", it) }
        }
    }

    fun release() {
        val n = count.decrementAndGet()
        if (n <= 0) {
            // 钳到 0,容错重复 release(不应发生,但不能让计数变负导致后续永远关不掉采集)。
            count.compareAndSet(n, 0)
            runCatching { smartproxy.mobile.Mobile.setConnStatsEnabled(false) }
                .onFailure { Log.e(TAG, "setConnStatsEnabled(false) failed", it) }
        }
    }
}
