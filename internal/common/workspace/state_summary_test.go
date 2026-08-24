package workspace

// state_summary_test.go — L0 事实进上下文管道（StateSummary 覆盖）。

import (
	"strings"
	"testing"
)

// TestPublishL0Facts_ContextPipeline 事实进上下文管道：StateSummary
// 包含 L0 安全事实（大脑必须看见）。
func TestPublishL0Facts_ContextPipeline(t *testing.T) {
	ws, err := NewWorkspace(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ws.SetL0Facts(map[string]string{
		"web-01": "## listen_ports\nLISTEN 0.0.0.0:4444 python3\n## uid0_users\nbackdoor:/bin/bash",
	})
	sum := ws.StateSummary()
	for _, want := range []string{"l0_facts", "listen_ports", "0.0.0.0:4444", "backdoor"} {
		if !strings.Contains(sum, want) {
			t.Errorf("StateSummary 缺少 %q: %s", want, sum)
		}
	}
}
