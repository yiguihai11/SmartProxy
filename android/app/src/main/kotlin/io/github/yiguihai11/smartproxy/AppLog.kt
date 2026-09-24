package io.github.yiguihai11.smartproxy

import android.util.Log

/**
 * 融合日志桥接门面:同时输出到 Android logcat 和 Go 融合日志管线 (Mobile.logAndroid)。
 * 保证在 Android Kotlin 层的关键生命周期、VPN 事件与崩溃异常能无缝汇入
 * 按天轮转文件日志 (smartproxy_yyyy-MM-dd.log) 与内存环形缓冲 (logbuf.Default)。
 */
object AppLog {

    fun d(tag: String, msg: String): Int {
        Log.d(tag, msg)
        runCatching {
            smartproxy.mobile.Mobile.logAndroid("DEBUG", tag, msg)
        }
        return 0
    }

    fun i(tag: String, msg: String): Int {
        Log.i(tag, msg)
        runCatching {
            smartproxy.mobile.Mobile.logAndroid("INFO", tag, msg)
        }
        return 0
    }

    fun w(tag: String, msg: String): Int {
        Log.w(tag, msg)
        runCatching {
            smartproxy.mobile.Mobile.logAndroid("WARN", tag, msg)
        }
        return 0
    }

    fun w(tag: String, msg: String, tr: Throwable?): Int {
        if (tr != null) {
            Log.w(tag, msg, tr)
        } else {
            Log.w(tag, msg)
        }
        val fullMsg = if (tr != null) "$msg: ${Log.getStackTraceString(tr)}" else msg
        runCatching {
            smartproxy.mobile.Mobile.logAndroid("WARN", tag, fullMsg)
        }
        return 0
    }

    fun e(tag: String, msg: String): Int {
        Log.e(tag, msg)
        runCatching {
            smartproxy.mobile.Mobile.logAndroid("ERROR", tag, msg)
        }
        return 0
    }

    fun e(tag: String, msg: String, tr: Throwable?): Int {
        if (tr != null) {
            Log.e(tag, msg, tr)
        } else {
            Log.e(tag, msg)
        }
        val fullMsg = if (tr != null) "$msg: ${Log.getStackTraceString(tr)}" else msg
        runCatching {
            smartproxy.mobile.Mobile.logAndroid("ERROR", tag, fullMsg)
        }
        return 0
    }

    fun getStackTraceString(tr: Throwable?): String = Log.getStackTraceString(tr)
}
