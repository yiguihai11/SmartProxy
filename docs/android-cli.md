# Android CLI 安装与 CI 构建

本机内存太小,Gradle + Kotlin 构建容易把机器搞宕机,所以:

- **本机**只装轻量的 `android` CLI 二进制(约 20 MB launcher + 首次运行时约 78 MB),
  不装 Android SDK / 模拟器,也不在本机跑构建。
- **重活在 CI 里干**:GitHub-hosted runner(2 核 / 7 GB 内存)跑 Gradle 构建并产出 APK。

## 相关文件

| 文件 | 作用 |
|---|---|
| `scripts/install-android-cli.sh` | 便携安装脚本:JDK 17(必需)+ Android CLI。Linux/macOS/CI 通用 |
| `.github/workflows/android-build.yml` | Actions 工作流:装 CLI → 脚手架项目 → Gradle 构建 → 上传 APK |

## 本地使用

```bash
bash scripts/install-android-cli.sh   # 装 JDK 17 + android CLI 到 ~/.local/bin
source ~/.bashrc
android --version                     # 验证
```

接上 Claude Code 技能(可选):

```bash
android init --agent=claude-code      # 把官方 Android skills 装进 Claude Code
```

## CI 触发规则

工作流是**按路径触发**的(`on: push: paths:`),只在以下文件变更时才自动跑:

- `.github/workflows/android-build.yml`
- `scripts/install-android-cli.sh`
- `android/**`
- `mobile/android/**`

纯 Go 的提交不会触发。也可以随时在 Actions 页手动 `Run workflow`。

一次构建会做:

1. `actions/setup-java` 配 JDK 17
2. `scripts/install-android-cli.sh` 装 Android CLI
3. `android create` 脚手架一个 Compose 示例工程(模板需要的 SDK 包由 CLI 自动安装)
4. `./gradlew assembleDebug`,APK 上传为 workflow artifact

## Android CLI 常用命令速查

| 命令 | 说明 |
|---|---|
| `android update` | 更新 CLI 自身 |
| `android create --list` | 列出可用的项目模板 |
| `android describe` | 输出项目的构建目标 / APK 路径等 JSON 元数据 |
| `android run --apks=<paths>` | 部署 APK 到已连接的设备/模拟器 |
| `android sdk install platforms/android-36 build-tools/36.0.0` | 按需装 SDK 包 |
| `android docs search <query>` | 查 Android 官方知识库 |

> 两点实测教训:
> - CLI 对**不存在的模板名只打 ERROR 到 stderr 且退出码为 0**,所以不要用
>   `if … else` 做模板回退,直接用 `android create --list` 查到的名字。
> - 模板列表命令是 `android create --list`(位置参数写法 `android create list`
>   会被当成模板名并报 `Missing required option: '--name='`)。

> Android CLI 是 Google 的预览工具(v0.7+),命令形态还在演进,以
> [官方文档](https://developer.android.com/tools/agents/android-cli) 为准。
