plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

// 版本号形态 <发版版本>-<短commit>(如 1.0-2d27600):CI 注入 VERSION,同时喂这里的
// versionName 和 Go 引擎 /version 控制面板(经 Makefile LDFLAGS),两边同源。本机无 env 回退 1.0.0。
val ciVersion: String = System.getenv("VERSION") ?: "1.0.0"

/**
 * versionCode:CI 注入 VERSION_CODE(100000 + git 提交数,随提交单调递增、绝不降级),
 * 优先用它;本机无 env 时从版本串 semver 段派生(major*100000 + minor*1000 + patch),
 * patch 可缺省(1.0 视同 1.0.0),解析失败回退 1。
 */
fun deriveVersionCode(version: String): Int {
    val m = Regex("""(\d+)\.(\d+)(?:\.(\d+))?""").find(version) ?: return 1
    return m.groupValues[1].toInt() * 100000 +
        m.groupValues[2].toInt() * 1000 +
        (m.groupValues[3].toIntOrNull() ?: 0)
}
val ciVersionCode: Int = System.getenv("VERSION_CODE")?.toIntOrNull() ?: deriveVersionCode(ciVersion)

// Shizuku 免 root 共享跑在一个独立的常驻用户服务进程(shell UID,daemon=true)。Shizuku 仅在
// UserServiceArgs.version() 变化时才杀掉旧守护、用新 APK 重新拉起;版本号相同则复用旧进程。
// APK 升级后旧进程的 classloader 仍指向已被替换删除的旧 APK,其 native 库目录 libgojni.so
// 路径失效,首次启动共享引擎即 dlopen failed / -2。用构建时间戳(每次打包都不同,重装即重启
// 守护),绝不复用悬空的旧进程。刻意不用 versionCode/CI run number——同版本号或重跑时它们不变。
val shizukuServiceVersion: Int = (System.currentTimeMillis() / 1000L).toInt()

android {
    namespace = "io.github.yiguihai11.smartproxy"
    // 编译用最新 API(Android 16 = API 36);targetSdk 暂留 35 —— Android 16 对
    // targetSdk 36 强制 edge-to-edge 等运行时行为,单独评估后再升。
    compileSdk = 36

    defaultConfig {
        applicationId = "io.github.yiguihai11.smartproxy"
        minSdk = 26
        targetSdk = 35
        versionCode = ciVersionCode
        versionName = ciVersion
        // 每次打包都变化的 Shizuku 用户服务版本号(见 shizukuServiceVersion 注释)。
        buildConfigField("int", "ShizukuServiceVersion", shizukuServiceVersion.toString())
    }

    signingConfigs {
        // 固定签名:KEYSTORE_FILE 指向仓库里的 android/ci-release.keystore(PKCS12,openssl
        // 生成,所有构建同一把 key → 新版可直接覆盖安装,不用卸载)。本机无 env 时不配置 →
        // release 为 unsigned,debug 用 debug 签名。私钥入库仅适用于不上架的自分发 app。
        create("release") {
            val ksFile = System.getenv("KEYSTORE_FILE")
            if (ksFile != null) {
                storeFile = file(ksFile)
                storeType = "PKCS12"
                storePassword = System.getenv("KEYSTORE_PASSWORD") ?: "android"
                keyAlias = System.getenv("KEY_ALIAS") ?: "androiddebugkey"
                keyPassword = System.getenv("KEY_PASSWORD") ?: "android"
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
            if (System.getenv("KEYSTORE_FILE") != null) {
                signingConfig = signingConfigs.getByName("release")
            }
        }
    }

    splits {
        abi {
            // 每 ABI 一个 APK,不产 universal:fat 包 64MB 几乎全是 4 个 ABI 的
            // Go 引擎 .so(各 ~16MB),分包后单个 ~16MB,用户按设备选一个装。
            // 对齐 sockstun(hev.sockstun):armeabi-v7a / arm64-v8a / x86 / x86_64。
            isEnable = true
            reset()
            include("armeabi-v7a", "arm64-v8a", "x86", "x86_64")
            isUniversalApk = false
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    buildFeatures {
        compose = true
        aidl = true
        // AGP 8 默认不生成 BuildConfig;Shizuku 用户服务要用 APPLICATION_ID / DEBUG。
        buildConfig = true
    }
    packaging {
        jniLibs {
            // useLegacyPackaging=true → APK 里 .so 压缩存储(install 时解压),体积大幅缩小。
            // 代价是安装略慢、安装后多占一份磁盘;对个人分发的小 app,体积优先。
            useLegacyPackaging = true
        }
    }
}

// KGP 2.x 推荐 DSL:android{} 里的 kotlinOptions 已废弃(2.4 可能移除),jvmTarget 移这里。
kotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
        // M3 TopAppBar/CenterAlignedTopAppBar 是 @ExperimentalMaterial3Api(Kotlin 2.4 下
        // 未 opt-in 直接报错),整模块 opt-in(Compose 官方对 M3 实验 API 的通行做法)。
        optIn.add("androidx.compose.material3.ExperimentalMaterial3Api")
    }
}

dependencies {
    // Go engine AAR (built by `make android` → build/smartproxy.aar, copied to
    // app/libs/ during CI). Not committed; see scripts/README or the workflow.
    implementation(files("libs/smartproxy.aar"))

    // Shizuku API & Provider for non-root privileged tethering (Android 13+)
    implementation("dev.rikka.shizuku:api:13.1.5")
    implementation("dev.rikka.shizuku:provider:13.1.5")

    // 2026-08 最新稳定 BOM(Compose 1.11);Kotlin 2.4 的 compose 编译器要求 runtime 匹配,必须连带升。
    implementation(platform("androidx.compose:compose-bom:2026.05.01"))
    implementation("androidx.activity:activity-compose:1.13.0")
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-core") // 首页 Apps 卡 / 应用选择页导航图标
    implementation("androidx.compose.material:material-icons-extended") // 主题切换太阳/月亮/自动图标(release 有 R8 裁剪,不涨包)
    implementation("androidx.compose.ui:ui-tooling-preview")
    // core-ktx 1.19 / lifecycle 2.11 要求 minCompileSdk=37(API 37 未发布),用不上,停在新版兼容线。
    implementation("androidx.core:core-ktx:1.18.0")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.10.0")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.10.0") // LocalLifecycleOwner 新归宿(compose.ui.platform 版已弃用)

    // 面板入口二维码(M2):直接用 QRCodeWriter 编码,无反射路径,R8 安全。
    implementation("com.google.zxing:core:3.5.4")

    debugImplementation("androidx.compose.ui:ui-tooling")
}
