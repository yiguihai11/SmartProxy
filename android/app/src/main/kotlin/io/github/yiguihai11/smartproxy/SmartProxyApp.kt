package io.github.yiguihai11.smartproxy

import android.app.Application

/**
 * Application 入口(M5):一上来就把 Go→Android 桥注册好。
 * 必须在任何组件(Activity / VpnService / BootReceiver)之前执行,否则 VpnService
 * 经 StartRouter 取 currentBridge() 时会取到 nil,面板 /api/* 全 503。
 */
class SmartProxyApp : Application() {
    override fun onCreate() {
        super.onCreate()
        AndroidBridgeImpl.register(this)
    }
}
