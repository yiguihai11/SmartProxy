package io.github.yiguihai11.smartproxy

import android.content.Context
import android.graphics.Color
import android.graphics.PixelFormat
import android.graphics.drawable.Drawable
import android.text.TextUtils
import android.util.Log
import android.util.TypedValue
import android.view.Gravity
import android.view.MotionEvent
import android.view.View
import android.view.ViewGroup
import android.view.WindowManager
import android.widget.FrameLayout
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView

/**
 * 悬浮网速计的展开面板 —— 「双击胶囊」弹出的模态面板,和程序里的「联网状态」页一样:
 * 多应用网速列表(按当前总速率排序) + 点每行右侧下拉箭头展开访问明细(SNI/host:port、
 * 累计上下行)+ 每行「定住」(pin,引擎不淡出该应用)+ 每条连接「掐断」(二次确认后
 * Mobile.blockConnection)。
 *
 * 窗口为全屏遮罩 + 居中深色卡片(经典 View 构建)。点卡片外(遮罩边缘)或 ✕ 收回,收回时
 * 若引擎还 pin 着某应用则复位(-1),不留残留。1s 轮询由 SpeedMeterOverlay 驱动 [render]:
 * 结构不变时原位刷新文本,变化时按排序重建(视图对象复用,展开/定住/确认态天然保留)。
 *
 * 本类只在主线程操作视图;数据快照在轮询线程组装后 post 过来。
 */
class SpeedMeterPanel(
    private val app: Context,
    private val wm: WindowManager,
    private val onDismiss: () -> Unit
) {
    data class ConnData(val proto: Int, val host: String, val port: Int, val up: Long, val down: Long)
    data class AppData(
        val uid: Int,
        val label: String,
        val icon: Drawable?,
        val upBps: Long,
        val downBps: Long,
        val conns: List<ConnData>
    )

    private var root: View? = null
    private var scrollView: ScrollView? = null
    private var listContainer: LinearLayout? = null
    private var lastApps: List<AppData> = emptyList()

    /** 已双击展开明细的 uid;展开即 pin(同联网状态页语义:正在查看的应用不被引擎淡出)。 */
    private val expandedUids = HashSet<Int>()
    /** 当前 pin 到引擎的 uid(-1 = 无)。 */
    private var pinnedUid = -1
    /** 正在等待二次确认「掐断」的 host。 */
    private var armedHost: String? = null
    /** uid -> 行视图(缓存复用,结构不变时原位刷新)。 */
    private val rows = LinkedHashMap<Int, RowHolder>()
    private var lastScrollY = 0

    val isShowing: Boolean get() = root != null

    fun show(): Boolean {
        if (root != null) return true
        val scrim = buildScrim()
        return try {
            wm.addView(scrim, buildParams())
            root = scrim
            render(lastApps)
            true
        } catch (e: Exception) {
            Log.e(TAG, "show failed", e)
            runCatching { wm.removeView(scrim) }
            root = null
            false
        }
    }

    /** 收回面板:移除窗口 + 清理引擎 pin + 复位状态。幂等。 */
    fun dismiss() {
        val v = root ?: run { resetState(); return }
        runCatching { wm.removeView(v) }
        root = null
        resetState()
    }

    private fun resetState() {
        if (pinnedUid != -1) {
            pinnedUid = -1
            runCatching { smartproxy.mobile.Mobile.setConnStatsPin(-1) }
                .onFailure { Log.e(TAG, "setConnStatsPin(-1) failed", it) }
        }
        armedHost = null
        expandedUids.clear()
        rows.clear()
        listContainer?.removeAllViews()
        lastApps = emptyList()
        lastScrollY = 0
    }

    /** 主线程调用:用最新快照刷新列表。结构不变只改文本;变化按排序重建。 */
    fun render(apps: List<AppData>) {
        if (root == null) return
        lastApps = apps
        val container = listContainer ?: return
        val sorted = apps.sortedByDescending { it.upBps + it.downBps }
        val uids = sorted.map { it.uid }

        val sameStructure = rows.keys.toList() == uids
        if (sameStructure) {
            for (data in sorted) updateRow(rows[data.uid] ?: continue, data)
        } else {
            val it = rows.entries.iterator()
            while (it.hasNext()) {
                val (uid, h) = it.next()
                if (uid !in uids) { container.removeView(h.row); it.remove() }
            }
            var idx = 0
            for (data in sorted) {
                val h = rows[data.uid]
                if (h == null) {
                    val nh = buildRow(data)
                    rows[data.uid] = nh
                    container.addView(nh.row, idx)
                } else {
                    if (container.indexOfChild(h.row) != idx) {
                        container.removeView(h.row)
                        container.addView(h.row, idx)
                    }
                    updateRow(h, data)
                }
                idx++
            }
        // 仅在结构变化(重建/重排)后恢复滚动;原位刷新不动 scroll,避免打断用户滚动。
        if (!sameStructure) scrollView?.scrollTo(0, lastScrollY)
    }
}

    // ── 窗口/视图构建 ───────────────────────────────────────────────────

    private fun buildParams(): WindowManager.LayoutParams =
        WindowManager.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.MATCH_PARENT,
            WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY,
            // 不抢焦点;全屏窗口内触摸全归我们,遮罩点按即收回。
            WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE or
                WindowManager.LayoutParams.FLAG_NOT_TOUCH_MODAL,
            PixelFormat.TRANSLUCENT
        ).apply { gravity = Gravity.TOP or Gravity.START }

    private fun buildScrim(): View {
        val scrim = FrameLayout(app).apply {
            setBackgroundColor(SCRIM)
            // 点卡片外(遮罩区域)收回;卡片自身及其子 View 消费触摸,不会冒泡到这里。
            setOnTouchListener { _, ev ->
                if (ev.actionMasked == MotionEvent.ACTION_DOWN) { onDismiss(); true } else false
            }
        }
        val card = LinearLayout(app).apply {
            orientation = LinearLayout.VERTICAL
            background = android.graphics.drawable.GradientDrawable().apply {
                cornerRadius = dp(18).toFloat()
                setColor(CARD_COLOR)
                setStroke(dp(1), 0x33FFFFFF)
            }
            // 居中卡片:占屏宽减边距、高上限 72% 屏,内容滚动。
            layoutParams = FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                (app.resources.displayMetrics.heightPixels * 0.72f).toInt()
            ).apply {
                leftMargin = dp(20); rightMargin = dp(20)
                topMargin = dp(40); bottomMargin = dp(40)
                gravity = Gravity.CENTER
            }
            setPadding(dp(14), dp(14), dp(14), dp(14))
        }
        val header = LinearLayout(app).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
        }
        val titleCol = LinearLayout(app).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
        }
        titleCol.addView(TextView(app).apply {
            text = app.getString(R.string.speed_meter_panel_title)
            textSize = 15f
            setTextColor(Color.WHITE)
            typeface = android.graphics.Typeface.DEFAULT_BOLD
        })
        titleCol.addView(TextView(app).apply {
            text = app.getString(R.string.speed_meter_panel_hint)
            textSize = 10f
            setTextColor(SUB_COLOR)
        })
        val close = TextView(app).apply {
            text = "✕"
            textSize = 15f
            setTextColor(SUB_COLOR)
            gravity = Gravity.CENTER
            setPadding(dp(8), dp(8), dp(8), dp(8))
            setOnClickListener { onDismiss() }
        }
        header.addView(titleCol)
        header.addView(close)

        val scroll = ScrollView(app).apply {
            layoutParams = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f).apply { topMargin = dp(8) }
            isFillViewport = true
            setOnScrollChangeListener { _, _, scrollY, _, _ -> lastScrollY = scrollY }
        }
        val list = LinearLayout(app).apply { orientation = LinearLayout.VERTICAL }
        scroll.addView(list)

        card.addView(header)
        card.addView(scroll)
        scrim.addView(card)
        scrollView = scroll
        listContainer = list
        return scrim
    }

    private class RowHolder(
        val row: LinearLayout,
        val icon: ImageView,
        val label: TextView,
        val sub: TextView,
        val up: TextView,
        val down: TextView,
        val pinBtn: TextView,
        val chevron: TextView,
        val connsContainer: LinearLayout
    )

    private fun buildRow(data: AppData): RowHolder {
        val row = LinearLayout(app).apply { orientation = LinearLayout.VERTICAL }
        val header = LinearLayout(app).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(dp(10), dp(8), dp(8), dp(8))
        }
        val icon = ImageView(app).apply {
            val s = dp(30)
            layoutParams = LinearLayout.LayoutParams(s, s)
            scaleType = ImageView.ScaleType.FIT_CENTER
        }
        val info = LinearLayout(app).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f).apply { marginStart = dp(8) }
        }
        val label = TextView(app).apply {
            textSize = 13f
            setTextColor(TEXT_COLOR)
            maxLines = 1
            ellipsize = TextUtils.TruncateAt.END
        }
        val sub = TextView(app).apply { textSize = 10f; setTextColor(SUB_COLOR) }
        val speedCol = LinearLayout(app).apply { orientation = LinearLayout.VERTICAL; gravity = Gravity.END }
        val up = TextView(app).apply { textSize = 11f; setTextColor(UP_COLOR); gravity = Gravity.END }
        val down = TextView(app).apply { textSize = 11f; setTextColor(DOWN_COLOR); gravity = Gravity.END }
        val pinBtn = TextView(app).apply {
            text = "📌"
            textSize = 13f
            gravity = Gravity.CENTER
            setPadding(dp(7), dp(7), dp(7), dp(7))
            setOnClickListener { togglePin(data.uid) }
        }
        val chevron = TextView(app).apply {
            text = "▾"
            textSize = 13f
            setTextColor(SUB_COLOR)
            // 点右侧下拉箭头展开/收起访问明细(加大触控区)。
            setPadding(dp(10), dp(6), dp(4), dp(6))
            setOnClickListener { toggleExpand(data.uid) }
        }
        info.addView(label); info.addView(sub)
        speedCol.addView(up); speedCol.addView(down)
        header.addView(icon); header.addView(info); header.addView(speedCol)
        header.addView(pinBtn); header.addView(chevron)
        val connsContainer = LinearLayout(app).apply {
            orientation = LinearLayout.VERTICAL
            visibility = View.GONE
        }
        row.addView(header)
        row.addView(connsContainer)
        val h = RowHolder(row, icon, label, sub, up, down, pinBtn, chevron, connsContainer)
        updateRow(h, data)
        return h
    }

    /** 点右侧箭头 → 展开/收起明细(展开即 pin,收起时若是被 pin 的则复位,同联网状态页)。 */
    private fun toggleExpand(uid: Int) {
        if (uid in expandedUids) {
            expandedUids.remove(uid)
            if (pinnedUid == uid) {
                pinnedUid = -1
                runCatching { smartproxy.mobile.Mobile.setConnStatsPin(-1) }
                    .onFailure { Log.e(TAG, "setConnStatsPin(-1) failed", it) }
            }
        } else {
            expandedUids.add(uid)
            if (pinnedUid != uid) {
                pinnedUid = uid
                runCatching { smartproxy.mobile.Mobile.setConnStatsPin(uid) }
                    .onFailure { Log.e(TAG, "setConnStatsPin($uid) failed", it) }
            }
        }
        render(lastApps)
    }

    private fun togglePin(uid: Int) {
        if (pinnedUid == uid) {
            pinnedUid = -1
            runCatching { smartproxy.mobile.Mobile.setConnStatsPin(-1) }
                .onFailure { Log.e(TAG, "setConnStatsPin(-1) failed", it) }
        } else {
            pinnedUid = uid
            runCatching { smartproxy.mobile.Mobile.setConnStatsPin(uid) }
                .onFailure { Log.e(TAG, "setConnStatsPin($uid) failed", it) }
        }
        render(lastApps)
    }

    private fun updateRow(h: RowHolder, data: AppData) {
        h.icon.setImageDrawable(data.icon)
        h.label.text = data.label
        h.sub.text = app.getString(R.string.net_conn_count, data.conns.size)
        h.up.text = "↑ ${fmt(data.upBps)}/s"
        h.down.text = "↓ ${fmt(data.downBps)}/s"
        val expanded = data.uid in expandedUids
        h.chevron.rotation = if (expanded) 180f else 0f
        h.chevron.setTextColor(if (expanded) ACCENT_COLOR else SUB_COLOR)
        val pinned = data.uid == pinnedUid
        h.pinBtn.alpha = if (pinned) 1f else 0.45f
        h.pinBtn.setBackgroundColor(if (pinned) 0x22FFFFFF else Color.TRANSPARENT)
        // 明细区:展开才显示;每次重建(连接数少,1s 一次可忽略),确认态由 armedHost 恢复。
        h.connsContainer.removeAllViews()
        if (expanded) {
            h.connsContainer.visibility = View.VISIBLE
            if (data.conns.isEmpty()) {
                h.connsContainer.addView(TextView(app).apply {
                    text = app.getString(R.string.net_conn_empty)
                    textSize = 11f
                    setTextColor(SUB_COLOR)
                    setPadding(dp(12), dp(2), 0, dp(4))
                })
            } else {
                for (c in data.conns) h.connsContainer.addView(buildConnRow(c))
            }
        } else {
            h.connsContainer.visibility = View.GONE
        }
    }

    /** 连接明细行:TCP/UDP 徽标 + host:port + 累计上下行 + 掐断(二次确认)。 */
    private fun buildConnRow(c: ConnData): View {
        val armed = c.host == armedHost
        val row = LinearLayout(app).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(dp(14), dp(4), dp(8), dp(4))
        }
        val badge = TextView(app).apply {
            text = if (c.proto == 17) "UDP" else "TCP"
            textSize = 8f
            setTextColor(Color.WHITE)
            setPadding(dp(4), dp(1), dp(4), dp(1))
            background = android.graphics.drawable.GradientDrawable().apply {
                cornerRadius = dp(3).toFloat()
                setColor(if (c.proto == 17) UDP_COLOR else TCP_COLOR)
            }
        }
        val info = LinearLayout(app).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f).apply { marginStart = dp(8) }
        }
        val host = TextView(app).apply {
            text = hostPort(c.host, c.port)
            textSize = 12f
            setTextColor(TEXT_COLOR)
            maxLines = 1
            ellipsize = TextUtils.TruncateAt.END
        }
        val bytes = TextView(app).apply {
            text = "↑ ${fmtBytes(c.up)} · ↓ ${fmtBytes(c.down)}"
            textSize = 10f
            setTextColor(SUB_COLOR)
        }
        val block = TextView(app).apply {
            text = app.getString(if (armed) R.string.speed_meter_confirm_block else R.string.speed_meter_block)
            textSize = 11f
            setTextColor(if (armed) 0xFFFF6B6B.toInt() else 0xFFFF8A80.toInt())
            setPadding(dp(8), dp(4), dp(8), dp(4))
            background = android.graphics.drawable.GradientDrawable().apply {
                cornerRadius = dp(6).toFloat()
                setColor(if (armed) 0x33FF6B6B else 0x22FFFFFF)
            }
            setOnClickListener { onBlockClicked(c.host) }
        }
        info.addView(host); info.addView(bytes)
        row.addView(badge); row.addView(info); row.addView(block)
        return row
    }

    /** 掐断:第一次点进入确认态,再点确认执行(加入 ACL 并掐断现有连接)。 */
    private fun onBlockClicked(host: String) {
        if (armedHost == host) {
            armedHost = null
            // blockConnection 会写 ACL 文件 + 掐断现有连接,gomobile 桥接可能阻塞数 ms,放后台线程。
            Thread {
                runCatching { smartproxy.mobile.Mobile.blockConnection(host) }
                    .onFailure { Log.e(TAG, "blockConnection($host) failed", it) }
            }.start()
        } else {
            armedHost = host
        }
        render(lastApps)
    }

    // ── 格式化 / 工具 ───────────────────────────────────────────────────

    private fun fmt(bps: Long): String {
        val f = bps.toDouble()
        return when {
            f >= 1_048_576.0 -> String.format("%.1fM", f / 1_048_576.0)
            f >= 1024.0 -> String.format("%.0fK", f / 1024.0)
            else -> "${bps}B"
        }
    }

    private fun fmtBytes(bytes: Long): String {
        val f = bytes.toDouble()
        return when {
            f >= 1_048_576.0 -> String.format("%.1fM", f / 1_048_576.0)
            f >= 1024.0 -> String.format("%.0fK", f / 1024.0)
            else -> "${bytes}B"
        }
    }

    /** host 可能是 IPv6 字面量,带冒号时补方括号避免 :port 歧义(与联网状态页一致)。 */
    private fun hostPort(host: String, port: Int): String =
        if (host.contains(':')) "[$host]:$port" else "$host:$port"

    private fun dp(value: Int): Int =
        TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_DIP, value.toFloat(), app.resources.displayMetrics).toInt()

    companion object {
        private const val TAG = "SpeedMeterPanel"
        private val SCRIM = 0x66000000
        // 0xF01E1E2E 超 Int 正范围,Kotlin 会推断为 Long;颜色要 Int(带符号补码),显式 .toInt()。
        private val CARD_COLOR = 0xF01E1E2E.toInt()
        private val TEXT_COLOR = Color.WHITE
        private val SUB_COLOR = Color.parseColor("#B3FFFFFF")
        private val UP_COLOR = Color.parseColor("#FF7CCB7C")
        private val DOWN_COLOR = Color.parseColor("#FF6FB7FF")
        private val TCP_COLOR = Color.parseColor("#FFD66E9B")
        private val UDP_COLOR = Color.parseColor("#FF3E7BFA")
        private val ACCENT_COLOR = Color.parseColor("#FFF6B8CF")
    }
}
