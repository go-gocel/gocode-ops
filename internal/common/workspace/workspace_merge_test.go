package workspace

// workspace_merge_test.go — merge 语义 P1 修复回归测试：
//   - 稀疏模型输出（最小对象）不得洗掉已有证据链（发现层非空合并）；
//   - confirmed+remediated 被 L0 同 key 重检出时 Redetect 照记
//     （watch 模式复发感知）；
//   - 跨进程合并（mergeDiskInto）只增不减：处置状态/计数/去向不回退。

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-gocel/gocode-ops/internal/common/model"
)

// TestMerge_SparseModelOutputPreservesDiscovery 稀疏模型输出（复扫/终裁
// 最小对象）不得清空已有追查成果——空字段不覆盖已有数据。
func TestMerge_SparseModelOutputPreservesDiscovery(t *testing.T) {
	ws, err := NewWorkspace(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	// 追查沉淀：完整证据链。
	deep := &Finding{Host: "web-01", Signal: "svc_failed", Key: "nginx",
		Status: FindingPending, Desc: "nginx 失败", RootCause: "磁盘满",
		Confidence: 0.8, Evidence: []string{"df -h: / 100%"}}
	deep.ID = findingID(deep)
	if err := ws.AddFindings([]*Finding{deep}); err != nil {
		t.Fatal(err)
	}
	// 模型稀疏输出：只回 host/signal/status（JSON 输出模式常见最小对象）。
	sparse := &Finding{Host: "web-01", Signal: "svc_failed", Key: "nginx", Status: FindingPending}
	sparse.ID = findingID(sparse)
	if err := ws.AddFindings([]*Finding{sparse}); err != nil {
		t.Fatal(err)
	}
	f := ws.Pending()[0]
	if f.Desc != "nginx 失败" || f.RootCause != "磁盘满" || f.Confidence != 0.8 || len(f.Evidence) != 1 {
		t.Fatalf("稀疏输出不得洗掉证据链: %+v", f)
	}
}

// TestMerge_RemediatedRedetectCounts watch 复发感知：confirmed+remediated
// 被 L0 同 key 重检出时 Redetect 照记（状态不降级、发现层不动）——
// 任务模式收敛不受影响（isCleanRound 不读 Redetect）。
func TestMerge_RemediatedRedetectCounts(t *testing.T) {
	ws, err := NewWorkspace(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	done := &Finding{Host: "web-01", Signal: "svc_failed", Key: "nginx",
		Status: FindingConfirmed, Remediated: true}
	done.ID = findingID(done)
	if err := ws.AddFindings([]*Finding{done}); err != nil {
		t.Fatal(err)
	}
	// L0 同 key 重检出（pending + L0 源）。
	l0 := &Finding{Host: "web-01", Signal: "svc_failed", Key: "nginx",
		Status: FindingPending, Source: SourceL0}
	l0.ID = findingID(l0)
	if err := ws.AddFindings([]*Finding{l0}); err != nil {
		t.Fatal(err)
	}
	got := ws.Confirmed()[0]
	if got.Remediated != true || got.Redetect != 1 {
		t.Fatalf("已处置项被重检出应计数且不降级: %+v", got)
	}
	if got.Desc != "" {
		t.Fatal("已处置项发现层不应被 L0 稀疏对象改写")
	}
	// 未处置的 confirmed 不计数（保持终态语义）。
	open := &Finding{Host: "web-01", Signal: "svc_failed", Key: "mysql",
		Status: FindingConfirmed}
	open.ID = findingID(open)
	if err := ws.AddFindings([]*Finding{open}); err != nil {
		t.Fatal(err)
	}
	l0b := &Finding{Host: "web-01", Signal: "svc_failed", Key: "mysql",
		Status: FindingPending, Source: SourceL0}
	l0b.ID = findingID(l0b)
	if err := ws.AddFindings([]*Finding{l0b}); err != nil {
		t.Fatal(err)
	}
	if got := ws.Confirmed()[1]; got.Redetect != 0 {
		t.Fatalf("未处置 confirmed 不应被重检出计数: %+v", got)
	}
}

// TestMergeDiskInto_Monotonic 跨进程合并只增不减：处置状态（remediated）、
// 计数（Tried/RespondTried/Redetect）、去向（Actions/Disposition）任何
// 一方的新进展都不得被对方旧视图回退。
func TestMergeDiskInto_Monotonic(t *testing.T) {
	dir := t.TempDir()
	ws, err := NewWorkspace(dir)
	if err != nil {
		t.Fatal(err)
	}
	// 内存：本进程处置成功（remediated=true、RespondTried=1、工单去向）。
	mem := &Finding{Host: "web-01", Signal: "suid_unowned", Key: "/usr/bin/x",
		Status: FindingConfirmed, Remediated: true, RespondTried: 1}
	mem.ID = findingID(mem)
	mem.Disposition = &model.Disposition{Outcome: model.DispositionVerifiedFixed}
	mem.Actions = []model.Action{{Name: "chmod", Command: "chmod 0755 /usr/bin/x", Auto: true, Verified: true}}
	if err := ws.AddFindings([]*Finding{mem}); err != nil {
		t.Fatal(err)
	}
	// 磁盘：对方进程旧视图（未处置、RespondTried=0）——模拟磁盘上
	// mtime 较新的旧内容（对方最后落盘）。
	disk := &Finding{Host: "web-01", Signal: "suid_unowned", Key: "/usr/bin/x",
		Status: FindingConfirmed, RespondTried: 0}
	disk.ID = findingID(disk)
	disk.Source = SourceL0
	data, err := json.Marshal([]*Finding{disk})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(model.ConfigDir(dir), "findings.json"), data, 0o644); err != nil {
		t.Fatal(err)
	}
	// 模拟：磁盘 mtime 晚于本进程上次落盘 → 触发并入。
	ws.lastFindingsSave = time.Now().Add(-time.Minute)
	ws.mergeDiskFindings()
	got := ws.Confirmed()[0]
	if !got.Remediated {
		t.Fatal("跨进程合并不得回退本进程处置状态")
	}
	if got.RespondTried != 1 {
		t.Fatalf("计数不得被对方旧视图回退: %d", got.RespondTried)
	}
	if got.Disposition == nil || len(got.Actions) == 0 {
		t.Fatal("去向不得被对方旧视图回退")
	}
	// 反向：磁盘是已处置（对方进展），内存是旧视图 → 处置状态并入内存。
	ws2, err := NewWorkspace(dir)
	if err != nil {
		t.Fatal(err)
	}
	// 对方进程处置成功后落盘（mtime 晚于本进程上次落盘）。
	diskDone := &Finding{Host: "web-01", Signal: "suid_unowned", Key: "/usr/bin/x",
		Status: FindingConfirmed, Remediated: true, RespondTried: 2}
	diskDone.ID = findingID(diskDone)
	data2, err := json.Marshal([]*Finding{diskDone})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(model.ConfigDir(dir), "findings.json"), data2, 0o644); err != nil {
		t.Fatal(err)
	}
	ws2.lastFindingsSave = time.Now().Add(-time.Minute)
	ws2.mergeDiskFindings()
	got2 := ws2.Confirmed()[0]
	if !got2.Remediated {
		t.Fatal("对方处置状态应并入内存（只增不减方向）")
	}
	if got2.RespondTried != 2 {
		t.Fatalf("对方计数应并入内存: %d", got2.RespondTried)
	}
}
