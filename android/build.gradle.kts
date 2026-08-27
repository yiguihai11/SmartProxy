// Top-level build file. Plugin versions are pinned here (single source of truth).
// R8 覆盖(官方 kotlin-d8-r8-versions 兼容表):Kotlin 2.4 需 R8 9.1.29+,而 AGP 8.13.2 内置
// R8 8.13.19 最高完整支持到 Kotlin 2.3 —— 解析 2.4 metadata 失败,release 混淆阶段刷一堆
// "R8: An error occurred when parsing kotlin metadata" 警告。不动 AGP(9.x = 内置 Kotlin
// 大迁移,单独议),仅把 buildscript classpath 上的 R8 覆盖到 9.1.x 消除警告(官方支持覆盖)。
buildscript {
    repositories {
        google()
        mavenCentral()
    }
    dependencies {
        classpath("com.android.tools:r8:9.1.43")
    }
}

plugins {
    // AGP 8.x 最新线(9.x = 内置 Kotlin 大迁移,单独议)。与 Gradle 8.14.5 配套。
    id("com.android.application") version "8.13.2" apply false
    // Kotlin 2.4.10(2026-07 最新),compose plugin 必须与 Kotlin 同版。
    id("org.jetbrains.kotlin.android") version "2.4.10" apply false
    id("org.jetbrains.kotlin.plugin.compose") version "2.4.10" apply false
}
