package collect

import (
	"strings"
	"testing"
)

// collect_parse_test.go — 采集命令构建/输出处理/CPU 解析测试（随实现留在 ops 顶层）。

func TestParseCPUStat(t *testing.T) {
	out := `cpu  100 0 50 5000 100 0 0 0 0 0
cpu0 50 0 25 2500 50 0 0 0 0 0`
	got, err := parseCPUStat(out)
	if err != nil {
		t.Fatalf("parseCPUStat: %v", err)
	}
	wantTotal := 100.0 + 0 + 50 + 5000 + 100 // 前 5 项
	if got.total != wantTotal {
		t.Errorf("total = %.0f, want %.0f", got.total, wantTotal)
	}
	if got.idle != 5100 {
		t.Errorf("idle = %.0f, want 5100", got.idle)
	}
}

// TestBuildMetricsCommand_StderrShielded 每个片段包一层 { ...; } 2>/dev/null：
// stderr 噪声（LD_PRELOAD 注入报错、find 权限告警等）不得进入采集值
// （R7 实测 LD_PRELOAD 噪声污染 state_crontab/big_files/tmp_dirs）。
func TestBuildMetricsCommand_StderrShielded(t *testing.T) {
	env := &Env{HasSystemd: true, HasSS: true}
	cmd := BuildMetricsCommand(env, Metrics(env))
	for _, m := range Metrics(env) {
		mark := fragmentMark(m.ID)
		if !strings.Contains(cmd, mark+"; { ") {
			t.Errorf("片段 %s 应被 { } 包裹", m.ID)
		}
	}
	if !strings.Contains(cmd, "} 2>/dev/null") {
		t.Error("片段末尾应统一屏蔽 stderr")
	}
	if !strings.Contains(cmd, "cat /proc/stat; } 2>/dev/null") {
		t.Error("cpu 片段应被包裹")
	}
}

// TestMetricsProbeNoiseFilters 伪线索噪声在采集层过滤（R21 实测）：
// svc_inactive 排除模板单元（getty@.service 的 is-active 恒为空串）；
// log_errors 排除 journalctl 无条目占位行（-- No entries --）。

func TestSplitFragments(t *testing.T) {
	out := strings.Join([]string{
		"__M_mem__",
		"MemTotal: 100 kB",
		"__M_disk__",
		"/dev/sda1 81% /",
		"__M_cpu__",
		"cpu  1 2 3",
	}, "\n")
	frags := splitFragments(out)
	if frags["mem"] != "MemTotal: 100 kB" {
		t.Errorf("mem fragment = %q", frags["mem"])
	}
	if frags["disk"] != "/dev/sda1 81% /" {
		t.Errorf("disk fragment = %q", frags["disk"])
	}
	if frags["cpu"] != "cpu  1 2 3" {
		t.Errorf("cpu fragment = %q", frags["cpu"])
	}
	if len(frags) != 3 {
		t.Errorf("fragments = %d, want 3", len(frags))
	}
}

func TestStripSectionHeader(t *testing.T) {
	out := "## web-01\nuptime output here\n"
	got := StripSectionHeader(out)
	if got != "uptime output here\n" {
		t.Errorf("got %q", got)
	}
	// 无分段头时原样返回
	if StripSectionHeader("plain") != "plain" {
		t.Error("plain 输出不应被修改")
	}
}

func approx(a, b, eps float64) bool {
	d := a - b
	if d < 0 {
		d = -d
	}
	return d <= eps
}
