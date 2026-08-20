//go:build race

package engine

// raceEnabled 报告测试是否在 -race 下运行。
//
// Go 的 go test -race 会隐式设置 race 构建标签,所以这两个同名函数
// (本文件 / race_disabled_test.go)在 -race 与普通构建里各取其一。
// TUN 端到端用例依赖 sing-tun 的 gvisor 栈,而 gvisor 栈启动存在上游数据竞态
// (CreateNICWithOptions 先 attach 拉起 dispatch 循环,transport handler 后装),
// -race 下必然报 DATA RACE(见 tun_e2e_test.go 文件头),因此 -race 下跳过 TUN 用例。
func raceEnabled() bool { return true }
