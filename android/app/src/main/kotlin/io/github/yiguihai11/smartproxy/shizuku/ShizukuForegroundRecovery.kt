package io.github.yiguihai11.smartproxy.shizuku

import android.app.Activity
import android.app.Application
import android.os.Build
import android.os.Bundle

/** Forwards app-foreground events needed to recover a replaced Shizuku Binder. */
internal object ShizukuForegroundRecovery : Application.ActivityLifecycleCallbacks {

    fun register(application: Application) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.UPSIDE_DOWN_CAKE ||
            Application.getProcessName() != application.packageName
        ) return
        application.registerActivityLifecycleCallbacks(this)
    }

    override fun onActivityResumed(activity: Activity) {
        // Android 14+ can defer Shizuku's replacement-Binder notification while the app process is
        // cached. When foregrounded, request replacement Binder to restore protected tethering.
        TetheringCoreSync.onAppForegrounded(activity)
    }

    override fun onActivityCreated(activity: Activity, savedInstanceState: Bundle?) = Unit
    override fun onActivityStarted(activity: Activity) = Unit
    override fun onActivityPaused(activity: Activity) = Unit
    override fun onActivityStopped(activity: Activity) = Unit
    override fun onActivitySaveInstanceState(activity: Activity, outState: Bundle) = Unit
    override fun onActivityDestroyed(activity: Activity) = Unit
}
