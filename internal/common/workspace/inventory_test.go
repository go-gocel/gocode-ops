package workspace

import (
	"strings"
	"testing"
	"time"
)

// TestWorkspace_InventoryRoundtrip S2 上板基线随工作区持久化（JSON
// 落盘往返后仍在，含 partial 重试记录）。
func TestWorkspace_InventoryRoundtrip(t *testing.T) {
	dir := t.TempDir()
	ws, err := NewWorkspace(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := ws.PutInventory("web-01", "suid_files_full", &FactInventory{
		At:      time.Now().UTC(),
		Entries: map[string]string{"/usr/bin/suid1": "suid", "/var/lib/.find": "suid"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := ws.PutInventory("web-01", "big_files", &FactInventory{
		At: time.Now().UTC(), Partial: true,
	}); err != nil {
		t.Fatal(err)
	}
	// 重载工作区（模拟崩溃恢复/跨产品延续）。
	ws2, err := NewWorkspace(dir)
	if err != nil {
		t.Fatal(err)
	}
	inv := ws2.GetInventory("web-01", "suid_files_full")
	if inv == nil || inv.Partial {
		t.Fatalf("上板基线应持久化: %+v", inv)
	}
	if len(inv.Entries) != 2 {
		t.Errorf("基线条目 = %d, want 2", len(inv.Entries))
	}
	if p := ws2.GetInventory("web-01", "big_files"); p == nil || !p.Partial {
		t.Errorf("partial 重试记录应持久化: %+v", p)
	}
}

// TestWorkspace_InventorySnapshotIsolation 快照深拷贝：外部修改不影响
// 工作区（报告渲染并发安全）。
func TestWorkspace_InventorySnapshotIsolation(t *testing.T) {
	dir := t.TempDir()
	ws, err := NewWorkspace(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := ws.PutInventory("web-01", "suid_files_full", &FactInventory{
		At: time.Now().UTC(), Entries: map[string]string{"/a": "suid"},
	}); err != nil {
		t.Fatal(err)
	}
	snap := ws.InventorySnapshot()
	snap["web-01"]["suid_files_full"].Entries["/evil"] = "suid"
	got := ws.GetInventory("web-01", "suid_files_full")
	if _, ok := got.Entries["/evil"]; ok {
		t.Error("快照修改不得污染工作区")
	}
}

// TestRenderReport_InventoryAndCoverageSections 报告审计面：S2 上板状态
// 与 L0 覆盖标注（partial/skipped）如实可见。
func TestRenderReport_InventoryAndCoverageSections(t *testing.T) {
	dir := t.TempDir()
	ws, err := NewWorkspace(dir)
	if err != nil {
		t.Fatal(err)
	}
	ws.SetL0Facts(map[string]string{"web-01": "## suid_files\n/usr/bin/passwd\n"})
	ws.SetL0Coverage(map[string]map[string]string{
		"web-01": {
			"suid_files":      "full",
			"suid_files_full": "skipped",
			"world_writable":  "partial",
			"big_files":       "skipped",
		},
	})
	if err := ws.PutInventory("web-01", "suid_files_full", &FactInventory{
		At: time.Now().UTC(), Entries: map[string]string{"/a": "suid"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := ws.PutInventory("web-01", "big_files", &FactInventory{
		At: time.Now().UTC(), Partial: true,
	}); err != nil {
		t.Fatal(err)
	}
	report := RenderReport(ws, time.Now())
	for _, want := range []string{
		"**S2 上板基线**",
		"suid_files_full: ✅ 上板",
		"big_files: ⚠️ 未上板",
		"**覆盖**",
		"world_writable=不完整",
		"suid_files_full=未扫",
	} {
		if !strings.Contains(report, want) {
			t.Errorf("报告应含 %q:\n%s", want, report)
		}
	}
	// 健康轮不刷屏：full 项不标注。
	if strings.Contains(report, "suid_files=完整") || strings.Contains(report, "world_writable=完整") {
		t.Error("full 覆盖不应标注（健康轮零噪音）")
	}
}
