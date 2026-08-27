// Top-level build file. Plugin versions are pinned here (single source of truth).
plugins {
    // AGP 8.x 最新线(9.x = 内置 Kotlin 大迁移,单独议)。与 Gradle 8.14.5 配套。
    id("com.android.application") version "8.13.2" apply false
    // Kotlin 2.4.10(2026-07 最新),compose plugin 必须与 Kotlin 同版。
    id("org.jetbrains.kotlin.android") version "2.4.10" apply false
    id("org.jetbrains.kotlin.plugin.compose") version "2.4.10" apply false
}
