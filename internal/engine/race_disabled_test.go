//go:build !race

package engine

// raceEnabled 报告测试是否在 -race 下运行(本文件为普通构建的实现,见 race_enabled_test.go)。
func raceEnabled() bool { return false }
