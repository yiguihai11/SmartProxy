package io.github.yiguihai11.smartproxy

import android.content.Context
import android.graphics.Color
import android.graphics.PixelFormat
import android.graphics.drawable.Drawable
import android.os.Handler
import android.os.HandlerThread
import android.os.SystemClock
import android.provider.Settings
import android.util.TypedValue
import android.view.Gravity
import android.view.MotionEvent
import android.view.View
import android.view.WindowManager
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import org.json.JSONObject
import kotlin.math.abs
import kotlin.math.hypot

/**
 * 悬浮网速计(塞班式角落小胶囊):VPN 运行期间在其它 App 上层显示一个半透明胶囊,
 * 内容 = 当前网速最大的 App 小图标 + 全局 ↑ 上传 / ↓ 下载 总速率,可拖动。
 *
 * 点击胶囊(未拖动)展开成模态面板 [SpeedMeterPanel] —— 多应用网速列表、双击看访问明细
 * (SNI/host)、掐断、pin 定住、点面板外收回。
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

    // 胶囊配色:半透明深底 + 上传绿 / 下载蓝(白字在深底上对比足够)。
    private const val BG_COLOR = 0xB3000000.toInt()
    private val UP_COLOR = Color.parseColor("#FF7CCB7C")
    private val DOWN_COLOR = Color.parseColor("#FF6FB7FF")

    private var appContext: Context? = null
    private var wm: WindowManager? = null
    private var capsule: View? = null
    private var layoutParams: WindowManager.LayoutParams? = null
    private var iconView: ImageView? = null
    private var upView: TextView? = null
    private var downView: TextView? = null

    /** 展开的模态面板(点击胶囊弹出);null = 未展开。 */
    private var panel: SpeedMeterPanel? = null

    private var pollThread: HandlerThread? = null
    private var bgHandler: Handler? = null
    private val mainHandler = Handler(android.os.Looper.getMainLooper())

    /** 上一次轮询的各 UID 累计字节(算 δ);uid → (up, down)。仅 bg 线程访问。 */
    private val prevTotals = HashMap<Int, Pair<Long, Long>>()
    /** uid → (应用名, 图标),仅 bg 线程写、主线程读引用。 */
    private val metaCache = HashMap<Int, Pair<String, Drawable?>>()
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
        collapsePanel() // 面板关闭时自行复位引擎 pin
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

    /** 拖动:按下记起点,移动 updateViewLayout,抬起持久化位置。未拖动且双击(轻点两次)→ 展开面板。 */
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
                        // 双击胶囊展开面板;单击(未拖动)不做任何事。
                        val now = SystemClock.uptimeMillis()
                        val dx = ev.rawX - lastTapX
                        val dy = ev.rawY - lastTapY
                        lastTapX = ev.rawX; lastTapY = ev.rawY
                        if (now - lastTapTime < DOUBLE_TAP_MS && hypot(dx, dy) < dp(app, 40)) {
                            lastTapTime = 0
                            openPanel(app)
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

    /** 点击胶囊展开模态面板;重复点击幂等。 */
    private fun openPanel(app: Context) {
        if (panel != null) return
        val manager = wm ?: return
        val p = SpeedMeterPanel(app, manager) { collapsePanel() }
        if (p.show()) panel = p
    }

    private fun collapsePanel() {
        panel?.dismiss() // dismiss 内复位引擎 pin
        panel = null
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

    /** 在 bg 线程:取快照 → 总速率 + 最大流量 uid + 完整应用列表(含连接明细)→ post 回主线程。 */
    private fun pollOnce(app: Context) {
        data class Tick(
            val upBps: Long,
            val downBps: Long,
            val topUid: Int,
            val apps: List<SpeedMeterPanel.AppData>
        )
        val tick = runCatching {
            val json = smartproxy.mobile.Mobile.getConnectionStats()
            val root = JSONObject(json)
            val appsArr = root.optJSONArray("apps")
            var totalUp = 0L
            var totalDown = 0L
            var topUid = -1
            var topBytes = -1L
            val nowSeen = HashSet<Int>()
            val appList = ArrayList<SpeedMeterPanel.AppData>()
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
                    totalUp += upD
                    totalDown += downD
                    val sum = upD + downD
                    if (sum > topBytes) { topBytes = sum; topUid = uid }
                    // 连接明细(SNI/host:port + 累计上下行),供展开面板显示/掐断。
                    val connsArr = a.optJSONArray("conns")
                    val conns = ArrayList<SpeedMeterPanel.ConnData>()
                    if (connsArr != null) {
                        for (j in 0 until connsArr.length()) {
                            val c = connsArr.optJSONObject(j) ?: continue
                            conns += SpeedMeterPanel.ConnData(
                                proto = c.optInt("proto", 0),
                                host = c.optString("host", ""),
                                port = c.optInt("port", 0),
                                up = c.optLong("up", 0L),
                                down = c.optLong("down", 0L)
                            )
                        }
                    }
                    val meta = metaFor(app, uid)
                    appList += SpeedMeterPanel.AppData(uid, meta.first, meta.second, upD, downD, conns)
                }
            }
            // 清掉已不在快照里的 uid 旧基准,防 map 无限增长。
            prevTotals.keys.removeAll { it !in nowSeen }
            Tick(totalUp, totalDown, if (topBytes > 0) topUid else -1, appList)
        }.getOrNull() ?: return // 引擎未启动等:本次跳过,视图保持原样

        val icon: Drawable? = if (tick.topUid >= 0) metaFor(app, tick.topUid).second else null
        mainHandler.post {
            if (capsule == null) return@post
            upView?.text = "↑ ${fmt(tick.upBps)}/s"
            downView?.text = "↓ ${fmt(tick.downBps)}/s"
            val iv = iconView
            if (iv != null) {
                if (icon != null) {
                    iv.setImageDrawable(icon)
                    iv.visibility = View.VISIBLE
                } else {
                    iv.visibility = View.GONE
                }
            }
            panel?.render(tick.apps)
        }
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
