plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

// 版本从 git tag 派生(M4,对齐 internal/version 的 Makefile 机制):CI 注入 VERSION =
// `git describe --tags --match 'v[0-9]*' --always --dirty | sed 's/^v//'`,如
// "1.0.0" / "1.0.0-105-g7c7ef53";本机无 env 时回退 1.0.0。
val ciVersion: String = System.getenv("VERSION") ?: "1.0.0"

/** versionCode 取 VERSION 的 semver 段(major*100000 + minor*1000 + patch),解析失败回退 1。 */
fun deriveVersionCode(version: String): Int {
    val m = Regex("""(\d+)\.(\d+)\.(\d+)""").find(version) ?: return 1
    val (major, minor, patch) = m.destructured
    return major.toInt() * 100000 + minor.toInt() * 1000 + patch.toInt()
}

android {
    namespace = "io.github.yiguihai11.smartproxy"
    // 编译用最新 API(Android 16 = API 36);targetSdk 暂留 35 —— Android 16 对
    // targetSdk 36 强制 edge-to-edge 等运行时行为,单独评估后再升。
    compileSdk = 36

    defaultConfig {
        applicationId = "io.github.yiguihai11.smartproxy"
        minSdk = 26
        targetSdk = 35
        versionCode = deriveVersionCode(ciVersion)
        versionName = ciVersion
    }

    signingConfigs {
        // CI 注入:KEYSTORE_FILE 存在才可用(临时 debug 签名,每次构建不同)。
        // 本机无 env 时不配置 → release 构建为 unsigned,debug 构建用 debug 签名。
        create("release") {
            val ksFile = System.getenv("KEYSTORE_FILE")
            if (ksFile != null) {
                storeFile = file(ksFile)
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
    }
}

dependencies {
    // Go engine AAR (built by `make android` → build/smartproxy.aar, copied to
    // app/libs/ during CI). Not committed; see scripts/README or the workflow.
    implementation(files("libs/smartproxy.aar"))

    // 2026-08 最新稳定 BOM(Compose 1.11);Kotlin 2.4 的 compose 编译器要求 runtime 匹配,必须连带升。
    implementation(platform("androidx.compose:compose-bom:2026.05.01"))
    implementation("androidx.activity:activity-compose:1.9.2")
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-core") // 首页 Apps 卡 / 应用选择页导航图标
    implementation("androidx.compose.material:material-icons-extended") // 主题切换太阳/月亮/自动图标(release 有 R8 裁剪,不涨包)
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.6")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.8.6") // LocalLifecycleOwner 新归宿(compose.ui.platform 版已弃用)

    // 面板入口二维码(M2):直接用 QRCodeWriter 编码,无反射路径,R8 安全。
    implementation("com.google.zxing:core:3.5.3")

    debugImplementation("androidx.compose.ui:ui-tooling")
}
