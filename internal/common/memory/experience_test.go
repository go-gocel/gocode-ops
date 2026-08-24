package memory

// 记忆/工作台测试：学习沉淀、recall 检索、主机档案、假设引擎。

import (
	"strings"
	"testing"

	"github.com/go-gocel/gocode-ops/internal/common/model"
	"github.com/go-gocel/gocode-ops/internal/common/workbench"
)

// TestMemory_LearnAndRecall 学习沉淀 → 误报统计 → recall 检索。
func TestMemory_LearnAndRecall(t *testing.T) {
	m, err := NewMemory(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	f := &model.Finding{Host: "web-01", Signal: "unattributed_listen", Key: "0.0.0.0:9090",
		Desc: "9090 后门", Status: model.FindingConfirmed, Remediated: true,
		Actions: []model.Action{{Name: "kill", Command: "kill 226", Auto: true, Verified: true}}}
	if !m.Learn(f) {
		t.Fatal("首次沉淀应返回 true")
	}
	// 同信号同对象再沉淀（复发处理）→ 合并计数。
	f2 := &model.Finding{Host: "web-01", Signal: "unattributed_listen", Key: "0.0.0.0:9090",
		Status: model.FindingConfirmed, Remediated: true}
	if !m.Learn(f2) {
		t.Fatal("重复沉淀应合并")
	}
	hits := m.Recall("unattributed_listen", "web-01", 5)
	if len(hits) == 0 {
		t.Fatal("recall 应有命中")
	}
	if !strings.Contains(hits[0], "2 次") || !strings.Contains(hits[0], "kill 226") {
		t.Errorf("recall 摘要不符: %s", hits[0])
	}
	// 误报沉淀 → 置信度下降。
	bad := &model.Finding{Host: "web-01", Signal: "unattributed_listen", Key: "0.0.0.0:9090",
		Status: model.FindingDismissed}
	m.Learn(bad)
	hits2 := m.Recall("unattributed_listen", "web-01", 5)
	if !strings.Contains(hits2[0], "误报 1") || !strings.Contains(hits2[0], "置信 67") {
		t.Errorf("误报统计不符: %s", hits2[0])
	}
	// 无经验信号返回空。
	if hits := m.Recall("nonexistent_signal", "", 5); len(hits) != 0 {
		t.Errorf("未知信号应无命中: %v", hits)
	}
}

// TestMemory_HostDossier 主机档案读写。
func TestMemory_HostDossier(t *testing.T) {
	m, err := NewMemory(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	m.RecordHostEvent("web-01", "recovery", "kill 226; rm /etc/cron.d/keepalive")
	m.RecordHostEvent("web-01", "quirk", "LD_PRELOAD 常见误报")
	brief := m.DossierBrief("web-01")
	if !strings.Contains(brief, "恢复模式") || !strings.Contains(brief, "kill 226") {
		t.Errorf("档案摘要不符: %s", brief)
	}
	if m.DossierBrief("other") != "" {
		t.Error("无档案主机应返回空")
	}
}

// TestWorkbench_HypothesisEngine 假设引擎：新建/证据/激活。
func TestWorkbench_HypothesisEngine(t *testing.T) {
	dir := t.TempDir()
	w, err := workbench.NewWorkbench(dir)
	if err != nil {
		t.Fatal(err)
	}
	id := w.AddHypothesis("LD_PRELOAD 注入", "对比 ld.so.preload mtime 与进程启动时间")
	if id == "" {
		t.Fatal("假设应返回 ID")
	}
	// 同 claim 幂等。
	if id2 := w.AddHypothesis("LD_PRELOAD 注入", ""); id2 != id {
		t.Errorf("同 claim 应复用 ID: %s vs %s", id, id2)
	}
	// 支持证据。
	if !w.UpdateHypothesis(id, "libevil.so 被 5 个进程映射", true, "") {
		t.Fatal("更新假设失败")
	}
	// 证据变化激活（先手动去激活模拟跨轮：直接改状态再调 Activate）。
	// 新建假设 next_check 非空时 Active=true；验证 Brief 包含假设。
	brief := w.Brief(0)
	if !strings.Contains(brief, "LD_PRELOAD") || !strings.Contains(brief, "待验证") {
		t.Errorf("作战图摘要应含假设: %s", brief)
	}
	// 持久化：重新加载（NewWorkbench 接收工作目录）。
	w2, err := workbench.NewWorkbench(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(w2.Brief(0), "LD_PRELOAD") {
		t.Error("工作台持久化失败")
	}
}

// TestWorkbench_PendingChecksAndActions 待验证登记与动作去重。
func TestWorkbench_PendingChecksAndActions(t *testing.T) {
	w, err := workbench.NewWorkbench(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	w.AddPendingCheck("f1", "缺进程启动时间", "svc_units")
	if !w.RecordAction("f1:check-proc") {
		t.Fatal("新动作应记录")
	}
	if w.RecordAction("f1:check-proc") {
		t.Error("重复动作应返回 false")
	}
	checks := w.ResolvePendingChecks()
	if len(checks) != 1 || checks[0].FindingID != "f1" || checks[0].Probe != "svc_units" {
		t.Errorf("待验证不符: %+v", checks)
	}
	if len(w.ResolvePendingChecks()) != 0 {
		t.Error("解析后应清空")
	}
}
