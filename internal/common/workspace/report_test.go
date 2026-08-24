package workspace

import (
	"strings"
	"testing"
	"time"
)

// 报告渲染测试：阶段记录不重复刷屏（周期复扫合并显示）。

func TestRenderReport_RescanConsolidated(t *testing.T) {
	// 复扫记录会反复出现（环境变脏→重收敛→再复扫）——报告必须合并
	// 为一行（rescan×N），不能每条重复行。
	dir := t.TempDir()
	ws, err := NewWorkspace(dir)
	if err != nil {
		t.Fatal(err)
	}
	// 真实语义：survey 一次 + 48 次周期复扫。
	if err := ws.AddPhaseLog(PhaseLog{Phase: Phase("survey"), At: time.Now(), OK: true, Covered: []string{"cpu", "mem"}}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 48; i++ {
		if err := ws.AddPhaseLog(PhaseLog{Phase: PhaseRescan, At: time.Now(), OK: true, Covered: []string{"cpu", "mem", "log"}}); err != nil {
			t.Fatal(err)
		}
	}
	report := RenderReport(ws, time.Now())
	// 阶段记录不重复刷屏：survey 一行，48 次复扫合并为一行 rescan×48。
	if c := strings.Count(report, "| survey |"); c != 1 {
		t.Errorf("阶段 survey 出现 %d 行, want 1", c)
	}
	if c := strings.Count(report, "rescan×48"); c != 1 {
		t.Errorf("复扫应合并为 rescan×48 一行: %d 处", c)
	}
	if c := strings.Count(report, "| rescan |"); c != 0 {
		t.Errorf("不应有独立 rescan 重复行: %d 处", c)
	}
}

func TestPhaseLogs_Cap(t *testing.T) {
	dir := t.TempDir()
	ws, err := NewWorkspace(dir)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < maxPhaseLogs+50; i++ {
		if err := ws.AddPhaseLog(PhaseLog{Phase: PhaseRescan, At: time.Now(), OK: true}); err != nil {
			t.Fatal(err)
		}
	}
	if got := len(ws.Phases()); got != maxPhaseLogs {
		t.Errorf("阶段记录 = %d, want %d（上限裁剪）", got, maxPhaseLogs)
	}
}
