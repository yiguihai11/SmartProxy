package io.github.yiguihai11.smartproxy

import android.app.AppOpsManager
import android.app.usage.UsageEvents
import android.app.usage.UsageStatsManager
import android.content.Context
import android.content.Intent
import android.graphics.Color
import android.graphics.PixelFormat
import android.graphics.drawable.Drawable
import android.os.Handler
import android.os.HandlerThread
import android.os.Process
import android.os.SystemClock
import android.provider.Settings
import android.util.Log
import android.util.TypedValue
import android.view.Gravity
import android.view.MotionEvent
import android.view.View
import android.view.WindowManager
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
import org.json.JSONObject
import kotlin.math.abs
import kotlin.math.hypot

/**
 * 悬浮网速计(塞班式角落小胶囊):VPN 运行期间在其它 App 上层显示一个半透明胶囊,
 * 内容 = 单个应用的小图标 + 该应用 ↑ 上传 / ↓ 下载 实时速率,可拖动。
 * 显示哪个应用走「谁网速大显示谁」:候选 = 当前前台应用(UsageStatsManager 判定,需
 * 「使用情况访问权限」)与流量最大应用,比各自上下行之和,大的上;拿不到前台(未授权/
 * 无可判定)就退流量最大,两者都无流量时若前台可判定则显示前台(0 速率)。
 *
 * 双击胶囊(未拖动)打开 App 内的「联网状态」页(NetworkStatusActivity),不做自绘模态框;
 * 单击不做任何事。按应用的明细/掐断/pin 全在联网状态页 —— 该页与悬浮窗各自持
 * ConnStatsGate 采集(引擎引用计数,互不打断)。
 *
 * 数据来自引擎连接统计(Mobile.getConnectionStats,仅 VPN 隧道的 TUN 数据路径有
 * 按 UID 记账;仅代理 SOCKS5 模式无此数据,故只在 VPN 模式由服务拉起)。每秒轮询,
 * δ 速率 = 本快照累计字节 − 上一次;和联网状态页共用采集闸 ConnStatsGate(悬浮窗
 * 是第二个消费者,显示期间持有一份采集)。
 *
 * 视图用经典 View + WindowManager(TYPE_APPLICATION_OVERLAY,API 26 = minSdk,无需
 * 兼容分支);轮询在独立 HandlerThread,碰视图/WM 一律 post 回主线程。
 */
object SpeedMeterOverlay {
    private const val TAG = "SpeedMeter"
    private const val POLL_INTERVAL_MS = 1000L
    private const val DOUBLE_TAP_MS = 300L
    /** 前台应用判定缓存刷新周期:queryEvents 不便宜,5s 一次足够(切前台 5s 内跟上)。 */
    private const val FOREGROUND_REFRESH_MS = 5000L

    // 胶囊配色:40% 不透明度深底 + 上传绿 / 下载蓝(白字在深底上对比足够)。
    private const val BG_COLOR = 0x66000000.toInt()
    private val UP_COLOR = Color.parseColor("#FF7CCB7C")
    private val DOWN_COLOR = Color.parseColor("#FF6FB7FF")

    private var appContext: Context? = null
    private var wm: WindowManager? = null
    private var capsule: View? = null
    private var layoutParams: WindowManager.LayoutParams? = null
    private var iconView: ImageView? = null
    private var upView: TextView? = null
    private var downView: TextView? = null

    private var pollThread: HandlerThread? = null
    private var bgHandler: Handler? = null
    private val mainHandler = Handler(android.os.Looper.getMainLooper())

    /** 上一次轮询的各 UID 累计字节(算 δ);uid → (up, down)。仅 bg 线程访问。 */
    private val prevTotals = HashMap<Int, Pair<Long, Long>>()
    /** uid → (应用名, 图标),仅 bg 线程写、主线程读引用。 */
    private val metaCache = HashMap<Int, Pair<String, Drawable?>>()
    /** 当前前台应用 uid;-1 = 拿不到(未授权「使用情况访问权限」/无可判定)。仅 bg 线程访问。 */
    private var foregroundUid = -1
    private var lastForegroundQuery = 0L
    private var gateHeld = false

    /** VPN 连上后由服务调用:开关开 + 有悬浮窗权限才显示;否则静默跳过(下次连或
     *  开关/权限就绪后再由服务/抽屉触发)。重复调用幂等。 */
    fun autoShow(context: Context) {
        val app = context.applicationContext
        if (!AppPrefs.speedMeterEnabled(app)) return
        if (!canDrawOverlays(app)) return
        mainHandler.post { showOnMain(app) }
    }

    /** VPN 断开 / 开关关闭 / 权限撤销时调用:移除胶囊与面板、停轮询、放采集。幂等。 */
    fun hide() {
        mainHandler.post { hideOnMain() }
    }

    fun canDrawOverlays(context: Context): Boolean =
        Settings.canDrawOverlays(context.applicationContext)

    // ── 主线程:视图生命周期 ─────────────────────────────────────────────

    private fun showOnMain(app: Context) {
        if (capsule != null) return // 已显示
        val manager = app.getSystemService(Context.WINDOW_SERVICE) as? WindowManager ?: return
        val view = buildCapsule(app)
        val (sx, sy) = AppPrefs.speedMeterPos(app)
        val defaultPos = sx < 0 || sy < 0
        val params = WindowManager.LayoutParams(
            WindowManager.LayoutParams.WRAP_CONTENT,
            WindowManager.LayoutParams.WRAP_CONTENT,
            WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY,
            // 不抢焦点(不挡输入)、窗口外触摸透传给下层 App;半透明像素格式。
            WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE or
                WindowManager.LayoutParams.FLAG_NOT_TOUCH_MODAL,
            PixelFormat.TRANSLUCENT
        ).apply {
            gravity = Gravity.TOP or Gravity.START
            if (defaultPos) {
                // 默认放到右上角:x 先给屏宽(屏外),测量后按实际宽度贴回右边。
                x = app.resources.displayMetrics.widthPixels
                y = dp(app, 40)
            } else {
                x = sx; y = sy
            }
        }
        try {
            manager.addView(view, params)
        } catch (e: Exception) {
            // 权限在添加瞬间被撤销等极端情况:清理,不崩。
            runCatching { manager.removeView(view) }
            return
        }
        appContext = app
        wm = manager
        capsule = view
        layoutParams = params
        if (defaultPos) {
            // 首次(无保存位置):布局完成后贴到右边并留 8dp 边距。
            view.post {
                val lp = layoutParams ?: return@post
                lp.x = app.resources.displayMetrics.widthPixels - view.width - dp(app, 8)
                runCatching { manager.updateViewLayout(view, lp) }
            }
        }
        attachDrag(app, view, params, manager)
        startPolling(app)
        if (!gateHeld) { ConnStatsGate.acquire(); gateHeld = true }
    }

    private fun hideOnMain() {
        stopPolling()
        val view = capsule
        val manager = wm
        if (view != null && manager != null) {
            runCatching { manager.removeView(view) }
        }
        capsule = null
        wm = null
        layoutParams = null
        iconView = null
        upView = null
        downView = null
        appContext = null
        if (gateHeld) { ConnStatsGate.release(); gateHeld = false }
        prevTotals.clear()
        metaCache.clear()
    }

    private fun buildCapsule(app: Context): View {
        val padH = dp(app, 10)
        val padV = dp(app, 5)
        val container = LinearLayout(app).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(padH, padV, padH, padV)
            background = android.graphics.drawable.GradientDrawable().apply {
                cornerRadius = dp(app, 22).toFloat()
                setColor(BG_COLOR)
            }
        }
        val icon = ImageView(app).apply {
            val s = dp(app, 18)
            layoutParams = LinearLayout.LayoutParams(s, s).apply { marginEnd = dp(app, 6) }
            scaleType = ImageView.ScaleType.FIT_CENTER
            visibility = View.GONE // 无流量时隐藏,有最大流量 App 才显示
        }
        val up = TextView(app).apply {
            setTextColor(UP_COLOR)
            textSize = 12f
            includeFontPadding = false
            text = "↑ --"
        }
        val down = TextView(app).apply {
            setTextColor(DOWN_COLOR)
            textSize = 12f
            includeFontPadding = false
            setPadding(dp(app, 6), 0, 0, 0)
            text = "↓ --"
        }
        container.addView(icon)
        container.addView(up)
        container.addView(down)
        iconView = icon
        upView = up
        downView = down
        return container
    }

    /** 拖动:按下记起点,移动 updateViewLayout,抬起持久化位置。未拖动且双击(轻点两次)→ 打开联网状态页。 */
    private fun attachDrag(
        app: Context,
        view: View,
        params: WindowManager.LayoutParams,
        manager: WindowManager
    ) {
        val slop = android.view.ViewConfiguration.get(app).scaledTouchSlop
        var startRawX = 0f
        var startRawY = 0f
        var startX = 0
        var startY = 0
        var dragging = false
        var lastTapTime = 0L
        var lastTapX = 0f
        var lastTapY = 0f
        view.setOnTouchListener { v, ev ->
            when (ev.actionMasked) {
                MotionEvent.ACTION_DOWN -> {
                    startRawX = ev.rawX; startRawY = ev.rawY
                    startX = params.x; startY = params.y
                    dragging = false
                    true
                }
                MotionEvent.ACTION_MOVE -> {
                    val dx = ev.rawX - startRawX
                    val dy = ev.rawY - startRawY
                    if (!dragging && abs(dx) + abs(dy) > slop) dragging = true
                    if (dragging) {
                        val dm = app.resources.displayMetrics
                        params.x = (startX + dx).toInt()
                            .coerceIn(0, (dm.widthPixels - view.width).coerceAtLeast(0))
                        params.y = (startY + dy).toInt()
                            .coerceIn(0, (dm.heightPixels - view.height).coerceAtLeast(0))
                        runCatching { manager.updateViewLayout(view, params) }
                    }
                    true
                }
                MotionEvent.ACTION_UP, MotionEvent.ACTION_CANCEL -> {
                    if (dragging) {
                        AppPrefs.setSpeedMeterPos(app, params.x, params.y)
                    } else if (ev.actionMasked == MotionEvent.ACTION_UP) {
                        // 双击胶囊打开联网状态页;单击(未拖动)不做任何事。
                        val now = SystemClock.uptimeMillis()
                        val dx = ev.rawX - lastTapX
                        val dy = ev.rawY - lastTapY
                        lastTapX = ev.rawX; lastTapY = ev.rawY
                        if (now - lastTapTime < DOUBLE_TAP_MS && hypot(dx, dy) < dp(app, 40)) {
                            lastTapTime = 0
                            openNetworkStatus(app)
                        } else {
                            lastTapTime = now
                        }
                    }
                    dragging = false
                    true
                }
                else -> false
            }
        }
    }

    /** 双击胶囊 → 打开 App 内的「联网状态」页(引擎采集由该页自行持 gate,与悬浮窗并存)。 */
    private fun openNetworkStatus(app: Context) {
        runCatching {
            app.startActivity(
                Intent(app, NetworkStatusActivity::class.java)
                    .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            )
        }.onFailure { Log.e(TAG, "open NetworkStatusActivity failed", it) }
    }

    // ── 后台轮询 ────────────────────────────────────────────────────────

    private fun startPolling(app: Context) {
        if (pollThread != null) return
        val thread = HandlerThread("SpeedMeterPoll").apply { start() }
        val handler = Handler(thread.looper)
        pollThread = thread
        bgHandler = handler
        val tick = object : Runnable {
            override fun run() {
                pollOnce(app)
                handler.postDelayed(this, POLL_INTERVAL_MS)
            }
        }
        handler.post(tick)
    }

    private fun stopPolling() {
        bgHandler?.removeCallbacksAndMessages(null)
        bgHandler = null
        pollThread?.quit()
        pollThread = null
    }

    /** 在 bg 线程:取快照 → 「谁网速大显示谁」(前台应用 vs 流量最大)→ post 回主线程。 */
    private fun pollOnce(app: Context) {
        data class Tick(val appUid: Int, val appUp: Long, val appDown: Long)
        val tick = runCatching {
            val json = smartproxy.mobile.Mobile.getConnectionStats()
            val root = JSONObject(json)
            val appsArr = root.optJSONArray("apps")
            var maxUid = -1
            var maxSum = -1L
            val nowSeen = HashSet<Int>()
            // uid -> 本秒 (up, down);winner 展示需要各自速率。
            val speeds = HashMap<Int, Pair<Long, Long>>()
            if (appsArr != null) {
                for (i in 0 until appsArr.length()) {
                    val a = appsArr.optJSONObject(i) ?: continue
                    val uid = a.optInt("uid", -1)
                    if (uid < 0) continue
                    val up = a.optLong("up", 0L)
                    val down = a.optLong("down", 0L)
                    nowSeen.add(uid)
                    val prev = prevTotals[uid]
                    val upD = (up - (prev?.first ?: up)).coerceAtLeast(0L)
                    val downD = (down - (prev?.second ?: down)).coerceAtLeast(0L)
                    prevTotals[uid] = Pair(up, down)
                    speeds[uid] = Pair(upD, downD)
                    val sum = upD + downD
                    if (sum > maxSum) { maxSum = sum; maxUid = uid }
                }
            }
            // 清掉已不在快照里的 uid 旧基准,防 map 无限增长。
            prevTotals.keys.removeAll { it !in nowSeen }

            // 「谁网速大显示谁」:比前台应用 vs 流量最大的上下行之和,大的上;平局优先
            // 前台(正在看的应用);前台拿不到(未授权/无 RESUMED)退流量最大;都无则前台(0 速率)。
            val fg = refreshForegroundUid(app)
            var win = maxUid
            var winSum = maxSum
            if (fg >= 0) {
                val fgSum = speeds[fg]?.let { it.first + it.second } ?: 0L
                if (fgSum >= winSum) { win = fg; winSum = fgSum }
            }
            val (wUp, wDown) = speeds[win] ?: Pair(0L, 0L)
            Tick(win, wUp, wDown)
        }.getOrNull() ?: return // 引擎未启动等:本次跳过,视图保持原样

        val icon: Drawable? = if (tick.appUid >= 0) metaFor(app, tick.appUid).second else null
        mainHandler.post {
            if (capsule == null) return@post
            if (tick.appUid >= 0) {
                upView?.text = "↑ ${fmt(tick.appUp)}/s"
                downView?.text = "↓ ${fmt(tick.appDown)}/s"
                val iv = iconView
                if (iv != null) {
                    if (icon != null) {
                        iv.setImageDrawable(icon)
                        iv.visibility = View.VISIBLE
                    } else {
                        iv.visibility = View.GONE
                    }
                }
            } else {
                upView?.text = "↑ --"
                downView?.text = "↓ --"
                iconView?.visibility = View.GONE
            }
        }
    }

    /** 前台应用 uid(UsageStats 精确判定,需「使用情况访问权限」;未授权/无 RESUMED = -1)。
     *  5s 缓存刷新避免每秒 queryEvents;排除本应用自己(悬浮窗场景看自己无意义)。仅 bg 线程调用。 */
    private fun refreshForegroundUid(app: Context): Int {
        val now = SystemClock.uptimeMillis()
        if (now - lastForegroundQuery < FOREGROUND_REFRESH_MS) return foregroundUid
        lastForegroundQuery = now
        foregroundUid = if (hasUsageAccess(app)) {
            runCatching {
                val usm = app.getSystemService(Context.USAGE_STATS_SERVICE) as UsageStatsManager
                val end = System.currentTimeMillis()
                val events = usm.queryEvents(end - 15_000, end) // 近 15s 事件,取最后一次前台
                var fgPkg: String? = null
                var fgTime = 0L
                val e = UsageEvents.Event()
                while (events.hasNextEvent()) {
                    events.getNextEvent(e)
                    if (e.eventType == UsageEvents.Event.ACTIVITY_RESUMED && e.timeStamp > fgTime) {
                        fgTime = e.timeStamp
                        fgPkg = e.packageName
                    }
                }
                if (fgPkg != null) {
                    val uid = app.packageManager.getPackageUid(fgPkg, 0)
                    if (uid != Process.myUid()) uid else -1 // 排除自身
                } else -1
            }.getOrElse { -1 }
        } else -1
        return foregroundUid
    }

    /** 是否有「使用情况访问权限」(PACKAGE_USAGE_STATS 特殊授权,AppOps 判定,无需运行时请求)。 */
    private fun hasUsageAccess(app: Context): Boolean =
        runCatching {
            val appOps = app.getSystemService(Context.APP_OPS_SERVICE) as AppOpsManager
            appOps.checkOpNoThrow(
                AppOpsManager.OPSTR_GET_USAGE_STATS,
                Process.myUid(),
                app.packageName
            ) == AppOpsManager.MODE_ALLOWED
        }.getOrDefault(false)

    /** 首次开启悬浮网速计时引导授予「使用情况访问权限」(前台应用判定用):未授权 Toast 提示 +
     *  跳系统使用情况访问设置页。不阻塞胶囊:拿不到权限就退回显示流量最大应用。 */
    fun ensureUsageAccess(context: Context) {
        val app = context.applicationContext
        if (hasUsageAccess(app)) return
        Toast.makeText(app, app.getString(R.string.speed_meter_usage_access_needed), Toast.LENGTH_LONG).show()
        runCatching {
            app.startActivity(
                Intent(Settings.ACTION_USAGE_ACCESS_SETTINGS)
                    .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            )
        }.onFailure { Log.e(TAG, "open usage access settings failed", it) }
    }

    /** uid → (应用名, 图标),懒解析 + 缓存;失败回退 "UID x"。仅 bg 线程写。 */
    private fun metaFor(app: Context, uid: Int): Pair<String, Drawable?> =
        metaCache.getOrPut(uid) {
            runCatching {
                val pm = app.packageManager
                val pkg = pm.getPackagesForUid(uid)?.firstOrNull()
                if (pkg == null) {
                    "UID $uid" to null
                } else {
                    val ai = pm.getApplicationInfo(pkg, 0)
                    val label = pm.getApplicationLabel(ai).toString()
                    label to pm.getApplicationIcon(pkg)
                }
            }.getOrElse { "UID $uid" to null }
        }

    private fun fmt(bps: Long): String {
        val f = bps.toDouble()
        return when {
            f >= 1_048_576.0 -> String.format("%.1fM", f / 1_048_576.0)
            f >= 1024.0 -> String.format("%.0fK", f / 1024.0)
            else -> "${bps}B"
        }
    }

    private fun dp(app: Context, value: Int): Int =
        TypedValue.applyDimension(
            TypedValue.COMPLEX_UNIT_DIP, value.toFloat(),
            app.resources.displayMetrics
        ).toInt()
}
