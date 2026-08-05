# 热重载

程序运行时可对三类文件做热重载：`config.json`、`acl.txt`、`chnroute.txt`。实现位于 `internal/config/watcher.go`，基于 **github.com/fsnotify/fsnotify（事件驱动）**——监听文件所在目录，文件被写入/创建时立刻触发对应的 reloader，近似实时，**不是 mtime 轮询**。

## §1 Watcher 结构

```
config.NewWatcher()
  │ AddFile("config", cfgPath)
  │ AddFile("acl", aclPath)
  │ AddFile("chnroute", cfg.Routing.ChnrouteFile)
  │ SetConfigReloader(...)
  │ SetACLReloader(...)
  │ SetChnRouteReloader(...)
  ▼ Start()
  fsnotify.NewWatcher()
  │ 对每个文件的父目录 Add(dir)（按目录去重）
  ▼
  循环接收事件：
    event.Name == 已注册文件路径 && (Write || Create)
      └─► trigger(name) → 对应 reloader
```

`cmd/smartproxy/main.go` 中装配了三个 reloader：

| 注册名 | 文件 | reloader 动作 |
| --- | --- | --- |
| `config` | `cfgPath`（启动参数 `-config`） | `configReload`：`config.Load` → `Validate` → 逐项更新引擎 |
| `acl` | `cfg.Routing.ACLFile` | `eng.RuleEng.Reload(aclPath)` |
| `chnroute` | `cfg.Routing.ChnrouteFile` | `chnroute.Load` → `eng.Chnroute.Pull(newTrie)` |

核心实现（`internal/config/watcher.go`）：

- `AddFile(name, path)` 内部做 `filepath.Abs(path)` 并存入 `files` map；`Start()` 启动 `fsnotify.NewWatcher()`，对每个注册文件的**父目录** `watcher.Add(dir)`（按目录去重，避免重复监听）。
- 事件循环单协程（`safego.Go("config.watcher.loop", w.loop)`）：收到事件后先在 `files` 中匹配 `event.Name == path`，命中且 `event.Has(fsnotify.Write) || event.Has(fsnotify.Create)` 才触发对应 reloader。
- `Stop()` 关闭 `stopCh` 并 `wg.Wait()` 等待循环退出。

## §2 关键机制

1. **监听目录而非文件**：直接 `Add(文件)` 对"编辑保存后原子替换"（临时文件 rename 覆盖）不可靠；监听父目录 + `event.Name` 精确匹配，可同时覆盖两种保存方式：
   - 直接覆盖写 → `Write` 事件；
   - 临时文件 rename（编辑器 save）→ 目标路径出现 `Create` 事件。
2. **只响应 `Write` / `Create`**：`Rename`、`Chmod` 等事件不触发，避免抖动。
3. **近似实时**：fsnotify 事件毫秒级送达，无需轮询间隔，改动后立即生效。
4. **多平台**：fsnotify 底层走 Linux `inotify`、macOS/iOS `kqueue`/`FSEvents`、Windows `ReadDirectoryChangesW`，天然跨平台。

## §3 config 重载（configReload）

`cmd/smartproxy/main.go` 的 `configReload`：

```
config.Load(cfgPath) → newCfg.Validate()
  ├─ 失败：仅记日志，保留旧配置（脏配置不进内存）
  └─ 成功：
      cfg = newCfg
      eng.Config.Store(cfg)              // 引擎配置 atomic.Pointer 换新
      setLogLevel(cfg.LogLevel)          // 日志级别即时生效
      eng.UpstreamMgr.Reload(upstreamCfg) // 上游代理重建 + 健康检查重启
      eng.Router.UpdateConfig(smartTimeout, blacklistTTL) // router 配置 atomic.Pointer
      eng.DNSHandler.UpdateConfig(...)   // DNS 配置 atomic.Pointer（storeConfig）
      eng.AdminServer().SetAdminAuth(...)
```

- **DNS 配置**用 `atomic.Pointer[dnsConfig]`：`dns.Handler.storeConfig` 构建新 `dnsConfig` 后 `h.cfg.Store(...)`。
- **router 配置**用 `atomic.Pointer[routerConfig]`：`Router.UpdateConfig` 构建新 `routerConfig` 后 `r.cfg.Store(...)`。
- 同一个 `configReload` 也被注册为 admin 接口的 `SetReloadConfig`，可从 admin 触发。

## §4 ACL / chnroute 重载

```
ACL:      eng.RuleEng.Reload(aclPath)       // 新建 ruleSet 快照 → 原子交换
chnroute: chnroute.Load(chnrouteFile) → 新 Trie → eng.Chnroute.Pull(newTrie)  // 原子换根
```

- **ACL**：`rules.Engine.Reload` 就是 `Load`——`newRuleSet().load(path)` 构建全新不可变快照，成功后 `e.rules.Store(rs)` 原子交换；失败则旧快照继续生效，仅报错。
- **chnroute**：`chnroute.Load` 读出新 `Trie` 后 `eng.Chnroute.Pull(newTrie)`——`Pull` 内部 `t.root.Store(other.root.Load())` 原子换根；旧 Trie 的读取方仍持有旧指针，安全无竞态。
- **两者失败都保留旧数据仅报错**；生效均无锁（读方只做一次 `atomic.Pointer.Load`）。

## §5 开发注意事项

1. **`NewWatcher` 无参数**：事件驱动不需要轮询间隔。早期残留的 `NewWatcher(10*time.Second)` 死参数已移除，签名现为 `NewWatcher()`，别在调用处加回时间参数。
2. **监听目录 + 精确路径匹配**：新增可热重载文件时只需 `AddFile(name, path)` 即可（父目录自动加入监听）。必须保证 `event.Name` 与注册的绝对路径一致——`AddFile` 内部已做 `filepath.Abs`，注册相对路径时会自动规范化；因此调用方也应使用与磁盘一致的绝对/相对写法，避免匹配失败。
3. **`Write`/`Create` 之外的事件不触发**：若某保存方式只产生 `Rename` 而不在目标路径产生 `Write`/`Create`（少见），热重载不会触发。需要时在 `loop` 的触发条件里补对应事件类型。
4. **reloader 内部要 `Validate()`**：config 重载先 `config.Load` 再 `Validate`，校验失败保留旧配置、脏配置不进内存；ACL/chnroute 由 `Load` 解析失败即中止（旧数据保留）。
5. **不要在 reloader 里做阻塞重活**：fsnotify 事件循环是**单协程**，`UpstreamMgr.Reload` 中停/启健康检查循环（`HealthChecker.Stop` 的 `wg.Wait()`）与重建 UDP 池的耗时也在 watcher 协程内同步执行（健康检查自身的 `checkLoop` 是异步 goroutine）。新增慢操作（如大文件解析、网络调用）时考虑放到独立 goroutine，避免阻塞后续事件触发。
