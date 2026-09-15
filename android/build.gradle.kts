// Top-level build file. Plugin versions are pinned here (single source of truth).
buildscript {
    repositories {
        google()
        mavenCentral()
    }
    dependencies {
        // R8 覆盖(官方 kotlin-d8-r8-versions 兼容表):Kotlin 2.4 原生适配 R8 9.x 系列。
        // 配套 AGP 9.4.0 采用 R8 9.4.x 最新版本。
        classpath("com.android.tools:r8:9.4.17")
        // AGP 9.4 内置 Kotlin 默认只带 KGP 2.2.10。官方「升级到更高 KGP」路径:
        // buildscript classpath 声明更高版即可把内置 KGP 顶到 2.4.20(R8 9.4 / Compose
        // 编译器 2.4.20 与之配套)。不要再 apply org.jetbrains.kotlin.android——内置
        // Kotlin 已接管,apply 外部插件会直接报 "no longer required since AGP 9.0"。
        classpath("org.jetbrains.kotlin:kotlin-gradle-plugin:2.4.20")
    }
}

plugins {
    // AGP 9.x 最新特性线(9.4.0),与 Gradle 9.6.0 配套。
    id("com.android.application") version "9.4.0" apply false
    // Kotlin Android 插件不再需要(AGP 9 内置 Kotlin 接管),但 Compose 编译器是
    // 独立的 Kotlin 编译器插件:Kotlin 2.0+ 只要 buildFeatures.compose=true 就必须
    // 显式 apply org.jetbrains.kotlin.plugin.compose,AGP 9.4 不会替你自动应用
    // (否则报 "the Compose Compiler Gradle plugin is required when compose is enabled")。
    // 版本必须与 buildscript classpath 上的 KGP 2.4.20 对齐。
    id("org.jetbrains.kotlin.plugin.compose") version "2.4.20" apply false
}
