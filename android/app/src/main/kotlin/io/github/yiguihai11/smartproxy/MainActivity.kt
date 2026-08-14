package io.github.yiguihai11.smartproxy

import android.app.Activity
import android.net.VpnService
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

/**
 * M1 最小启动器(纯启动器方向,§4.4):
 *  - 首次点击启动 → VpnService.prepare() 弹系统授权
 *  - 授权后 startForegroundService → SmartProxyVpnService
 *  - 按钮/状态由 isRunning 驱动(§4.5)
 * M2 会扩展为完整首页(拦截开关/开机自启/面板入口)。
 */
class MainActivity : ComponentActivity() {

    private val vpnConsent =
        registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
            if (result.resultCode == Activity.RESULT_OK) {
                SmartProxyVpnService.start(this)
            }
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme {
                Surface(Modifier.fillMaxSize()) {
                    HomeLauncher(onToggle = { onToggleClicked() })
                }
            }
        }
    }

    private fun onToggleClicked() {
        val running = SmartProxyVpnService.isRunning.value
        if (running) {
            SmartProxyVpnService.stop(this)
            return
        }
        // 首次或授权失效:弹系统授权框;成功后由回调启动服务。
        val intent = VpnService.prepare(this)
        if (intent != null) {
            vpnConsent.launch(intent)
        } else {
            SmartProxyVpnService.start(this)
        }
    }
}

@Composable
private fun HomeLauncher(onToggle: () -> Unit) {
    val running by SmartProxyVpnService.isRunning.collectAsState()
    Column(
        modifier = Modifier.fillMaxSize().padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        Text(
            text = if (running) "运行中" else "未运行",
            fontSize = 22.sp
        )
        Spacer(Modifier.height(24.dp))
        Button(onClick = onToggle) {
            Text(if (running) "停止 VPN" else "启动 VPN")
        }
    }
}
