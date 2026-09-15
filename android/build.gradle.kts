// Top-level build file. Plugin versions are pinned here (single source of truth).
// R8 覆盖(官方 kotlin-d8-r8-versions 兼容表):Kotlin 2.4 原生适配 R8 9.x 系列。
// 配套 AGP 9.4.0 采用 R8 9.4.x 最新版本。
buildscript {
    repositories {
        google()
        mavenCentral()
    }
    dependencies {
        classpath("com.android.tools:r8:9.4.17")
    }
}

plugins {
    // AGP 9.x 最新特性线(9.4.0),与 Gradle 9.6.0 配套。
    id("com.android.application") version "9.4.0" apply false
    // Kotlin 2.4.20,compose plugin 必须与 Kotlin 同版。
    id("org.jetbrains.kotlin.android") version "2.4.20" apply false
    id("org.jetbrains.kotlin.plugin.compose") version "2.4.20" apply false
}
