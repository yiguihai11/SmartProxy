# Android 构建与 CI 安装

本机内存太小,Gradle + Kotlin 构建容易把机器搞宕机,所以**所有 Android/Gradle 构建都在
GitHub Actions 上跑**(GitHub-hosted runner 2 核 / 7 GB),本机不装 Android SDK、不跑构建。
本机验证 Kotlin/Gradle 语法用 `git diff` + CI 反馈即可。

## 相关文件

| 文件 | 作用 |
|---|---|
| `android/` | 手写的 Android 工程(Compose + Kotlin + Gradle wrapper 8.9),M1 起逐步成型 |
| `android/app/src/main/assets/` | 引擎运行资产:config.json(tun 段含 dns_servers)、chnroute.txt、acl.txt |
| `mobile/` | gomobile bind 的 Go 引擎导出层(bridge.go),产出 `build/smartproxy.aar` |
| `.github/workflows/android-build.yml` | Actions 工作流:装 SDK/NDK → gomobile 出 AAR → Gradle 签名 release → 上传 APK |

## 构建链路

```
Go 引擎(mobile/) --gomobile bind--> build/smartproxy.aar
android/app/libs/smartproxy.aar --Gradle assembleRelease--> app-release.apk
```

一次 CI 构建做:

1. `actions/setup-java` 配 JDK 17 + `actions/setup-go` 配 Go
2. `go install golang.org/x/mobile/cmd/gomobile` + `sdkmanager` 装 platform-35 / build-tools
3. `gomobile init` + `make android` → `build/smartproxy.aar`,拷进 `android/app/libs/`
4. `keytool` 现生成 debug keystore(**临时签名**,`android`/`androiddebugkey`)
5. `./gradlew assembleRelease`(env 注入签名)→ **签名** `app-release.apk`
6. 上传为 workflow artifact `smartproxy-signed-release-apk`

> 签名说明:临时调试用,每次构建的 keystore 是**现生成的**,因此**每次签名不同**——
> 覆盖安装新包前要先卸载旧的。以后要做正式更新包再配持久 keystore + secrets。
> 签名配置在 `android/app/build.gradle.kts` 里按 env(`KEYSTORE_FILE` 等)条件注入。

## CI 触发规则

工作流**按路径触发**(`on: push: paths:`),只在以下文件变更时自动跑:

- `.github/workflows/android-build.yml`
- `scripts/**`、`Makefile`、`go.mod`、`go.sum`
- `mobile/**`(引擎导出层)
- `android/**`

纯 Go 内部改动不触发;想出新包就在 Actions 页手动 `Run workflow`。

## 下载安装包

```bash
gh run download <run-id> --repo yiguihai11/SmartProxy --name smartproxy-signed-release-apk
```

## 本地(可选)联调引擎

如果只想在桌面验证引擎逻辑(不碰 Android),照常 `make build` / `go test ./...` 即可,
与本工程 Android 侧无关。
