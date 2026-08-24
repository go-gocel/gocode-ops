package l0

// engine_drift_p2_test.go — P2 修复回归测试：内容恒变探针的漂移归一化
// （state_uptime 单调累计不算变化、回退才是重启痕迹；state_timers
// 时间列不参与对比）。

import (
	"testing"
)

func TestStateValue_MonotonicUptime(t *testing.T) {
	// 单调累计：新值 > 旧值 → 未变化（不算漂移）。
	before := "12345.67 890.12\n"
	cur := "12405.13 890.12\n"
	if !stateUnchanged("state_uptime", before, cur) {
		t.Fatal("uptime 单调累计不应算变化")
	}
	// 数值回退（重启）：算变化 → 漂移线索。
	reboot := "12.34 1.00\n"
	if stateUnchanged("state_uptime", before, reboot) {
		t.Fatal("uptime 回退（重启）应算变化")
	}
	// 非单调探针原样对比。
	if stateUnchanged("state_sshd", "a", "b") {
		t.Fatal("普通探针内容变化应算变化")
	}
	if !stateUnchanged("state_sshd", "a", "a") {
		t.Fatal("普通探针内容相同应算未变化")
	}
}

func TestStateValue_TimersStripsTimeColumns(t *testing.T) {
	// systemctl list-timers 输出：NEXT/LEFT/LAST/PASSED 时间列每轮必变。
	before := "Mon 2030-01-01 00:00:00 UTC  5h left  Mon 2029-12-31 23:00:00 UTC 1h ago cleanup.service cleanup.timer\n"
	cur := "Tue 2030-01-01 00:05:00 UTC  5h left  Mon 2029-12-31 23:05:00 UTC 1h ago cleanup.service cleanup.timer\n"
	if !stateUnchanged("state_timers", before, cur) {
		t.Fatal("定时器时间列变化不应算漂移（归一化应相同）")
	}
	// 定时器增删仍算变化。
	added := before + "Wed 2030-01-02 00:00:00 UTC 2h left Tue 2030-01-01 22:00:00 UTC 2h ago backup.service backup.timer\n"
	if stateUnchanged("state_timers", before, added) {
		t.Fatal("定时器新增应算变化")
	}
}
