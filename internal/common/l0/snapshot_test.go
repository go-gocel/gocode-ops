package l0

import (
	"context"
	"os"
	"strings"
	"testing"
)

// snapshot_test.go — L0 快检共享工作区测试。

func TestEngine_SnapshotL0_SharedWorkspace(t *testing.T) {
	cfg := DefaultEngineConfig()
	cfg.WorkDir = t.TempDir()
	e, err := newEngine(cfg, nil, &Env{NProc: 8})
	if err != nil {
		t.Fatal(err)
	}
	// 快检上下文：头 + 已知状态（工作区 JSON）。
	text, err := e.SnapshotL0(context.Background())
	if err != nil {
		t.Fatalf("SnapshotL0: %v", err)
	}
	for _, want := range []string{"L0 确定性快检", "已知状态（工作区）"} {
		if !strings.Contains(text, want) {
			t.Errorf("快检上下文缺 %q:\n%s", want, text)
		}
	}
	// 基线已落盘：跨产品共用同一 baseline.json。
	if got := len(e.ws.Baseline()); got != 1 {
		t.Errorf("基线点数 = %d, want 1（快检写入共享工作区）", got)
	}
	// 报告可渲染：RenderReport 是 renderReport 的公开入口。
	if err := e.RenderReport(); err != nil {
		t.Fatalf("RenderReport: %v", err)
	}
	if _, err := os.Stat(e.ReportPath()); err != nil {
		t.Errorf("报告应落盘: %v", err)
	}
}
