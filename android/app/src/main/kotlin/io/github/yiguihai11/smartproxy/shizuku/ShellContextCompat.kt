package io.github.yiguihai11.smartproxy.shizuku

import android.annotation.SuppressLint
import android.content.Context
import android.content.ContextWrapper

/**
 * 创建 Binder 归属为 shell UID 的 Context(适配 v2rayNG PR #5903)。
 *
 * Shizuku UserService 跑在 shell UID(2000),但框架服务按"调用方应用"区分权限:
 * test_network / tethering 这些隐藏服务只认 com.android.shell 归属,普通应用 Context
 * 拿不到。这里用反射从 ContextImpl 里取 ActivityThread,再 createPackageContext 出
 * com.android.shell 的 LoadedApk,最终 createAppContext 造一个 shell 归属的 Context。
 */
@SuppressLint("PrivateApi", "DiscouragedPrivateApi")
internal object ShellContextCompat {

    fun create(context: Context): Context {
        val baseContext = (context as? ContextWrapper)?.baseContext ?: context
        val contextImplClass = Class.forName("android.app.ContextImpl")
        val activityThreadClass = Class.forName("android.app.ActivityThread")
        val loadedApkClass = Class.forName("android.app.LoadedApk")
        val mainThread = contextImplClass.getDeclaredField("mMainThread").run {
            isAccessible = true
            get(baseContext)
        }
        val systemContext = activityThreadClass.getDeclaredMethod("getSystemContext")
            .invoke(mainThread) as Context
        val packageContext = systemContext.createPackageContext(
            SHELL_PACKAGE_NAME,
            Context.CONTEXT_INCLUDE_CODE or Context.CONTEXT_IGNORE_SECURITY,
        )
        val loadedApk = contextImplClass.getDeclaredField("mPackageInfo").run {
            isAccessible = true
            get(packageContext)
        }
        val createAppContext = contextImplClass.declaredMethods.firstOrNull {
            it.name == "createAppContext" && it.parameterTypes.contentEquals(
                arrayOf(activityThreadClass, loadedApkClass, String::class.java),
            )
        } ?: contextImplClass.getDeclaredMethod(
            "createAppContext",
            activityThreadClass,
            loadedApkClass,
        )
        createAppContext.isAccessible = true

        return if (createAppContext.parameterCount == 3) {
            createAppContext.invoke(null, mainThread, loadedApk, SHELL_PACKAGE_NAME) as Context
        } else {
            createAppContext.invoke(null, mainThread, loadedApk) as Context
        }
    }

    private const val SHELL_PACKAGE_NAME = "com.android.shell"
}
