plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "io.github.yiguihai11.smartproxy"
    compileSdk = 35

    defaultConfig {
        applicationId = "io.github.yiguihai11.smartproxy"
        minSdk = 26
        targetSdk = 35
        versionCode = 1
        versionName = "1.0.0"
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
    kotlinOptions {
        jvmTarget = "17"
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

dependencies {
    // Go engine AAR (built by `make android` → build/smartproxy.aar, copied to
    // app/libs/ during CI). Not committed; see scripts/README or the workflow.
    implementation(files("libs/smartproxy.aar"))

    implementation(platform("androidx.compose:compose-bom:2024.09.03"))
    implementation("androidx.activity:activity-compose:1.9.2")
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.6")

    // 面板入口二维码(M2):直接用 QRCodeWriter 编码,无反射路径,R8 安全。
    implementation("com.google.zxing:core:3.5.3")

    debugImplementation("androidx.compose.ui:ui-tooling")
}
