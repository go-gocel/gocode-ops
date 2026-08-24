package workspace

import (
	"strings"
	"testing"
	"time"
)

// ── 工作区发现三态 ────────────────────────────────────────────────────

func TestWorkspace_FindingLifecycle(t *testing.T) {
	ws, err := NewWorkspace(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	// L0 线索 pending
	f := NewFinding("web-01", "svc", "svc_failed", "服务失败")
	if err := ws.AddFindings([]*Finding{f}); err != nil {
		t.Fatal(err)
	}
	if len(ws.Pending()) != 1 || len(ws.Confirmed()) != 0 {
		t.Errorf("初始应为 pending: pending=%d confirmed=%d", len(ws.Pending()), len(ws.Confirmed()))
	}
	// DeepDive 确认（新对象，同 host+signal 升级——模拟模型输出的新 Finding）
	up := &Finding{Host: f.Host, Signal: f.Signal, Status: FindingConfirmed, RootCause: "配置损坏"}
	if err := ws.AddFindings([]*Finding{up}); err != nil {
		t.Fatal(err)
	}
	if len(ws.Confirmed()) != 1 || len(ws.Pending()) != 0 {
		t.Errorf("升级后应为 confirmed: %+v", ws.Findings())
	}
	if ws.Confirmed()[0].RootCause != "配置损坏" {
		t.Errorf("根因应更新: %+v", ws.Confirmed()[0])
	}
	// confirmed 不被降级（新对象 dismissed）
	down := &Finding{Host: f.Host, Signal: f.Signal, Status: FindingDismissed, Desc: "排除"}
	ws.AddFindings([]*Finding{down})
	if len(ws.Confirmed()) != 1 {
		t.Error("confirmed 不应被降级")
	}
}

func TestWorkspace_FindingDedup(t *testing.T) {
	ws, _ := NewWorkspace(t.TempDir())
	ws.AddFindings([]*Finding{NewFinding("web-01", "disk", "disk_high", "a")})
	ws.AddFindings([]*Finding{NewFinding("web-01", "disk", "disk_high", "b")})
	if len(ws.Findings()) != 1 {
		t.Errorf("同 host+signal 应去重: %d", len(ws.Findings()))
	}
}

func TestWorkspace_FindingDedupNormalizedSignal(t *testing.T) {
	// 同一根因的 signal 大小写/空白不稳定（模型输出自由文本）：
	// 归一化后仍应去重，避免同根因分裂成多条重复确认。
	ws, _ := NewWorkspace(t.TempDir())
	ws.AddFindings([]*Finding{NewFinding("web-01", "svc", "Svc_Failed", "a")})
	ws.AddFindings([]*Finding{NewFinding("web-01", "svc", " svc_failed ", "b")})
	ws.AddFindings([]*Finding{NewFinding("WEB-01", "svc", "svc_failed", "c")})
	if len(ws.Findings()) != 1 {
		t.Errorf("signal/host 归一化后应去重: %d", len(ws.Findings()))
	}
}

// ── 报告分区 ──────────────────────────────────────────────────────────

func TestRenderReport_Sections(t *testing.T) {
	ws, _ := NewWorkspace(t.TempDir())
	ws.AddFindings([]*Finding{NewFinding("web-01", "svc", "svc_failed", "服务失败")})
	ws.AddPhaseLog(PhaseLog{Phase: PhaseRescan, OK: true, Covered: []string{"cpu"}})
	report := RenderReport(ws, time.Now())
	for _, want := range []string{"确认故障", "已排查排除", "可疑待查", "检查覆盖与阶段耗时", "svc_failed"} {
		if !strings.Contains(report, want) {
			t.Errorf("报告缺少分区 %q:\n%s", want, report)
		}
	}
}

func TestRenderReport_ConfirmedShowsDetectedAtAndFix(t *testing.T) {
	// 确认故障区必须展示检出时间与修复建议（未处置时）。
	ws, _ := NewWorkspace(t.TempDir())
	f := NewFinding("web-01", "svc", "svc_failed", "服务失败")
	f.Status = FindingConfirmed
	f.RootCause = "配置损坏"
	f.SuggestedFix = []string{"systemctl restart nginx.service（服务失败，重启恢复）"}
	ws.AddFindings([]*Finding{f})
	report := RenderReport(ws, time.Now())
	for _, want := range []string{"检出时间", "根因", "修复建议", "systemctl restart nginx.service", "未处置"} {
		if !strings.Contains(report, want) {
			t.Errorf("报告缺少 %q:\n%s", want, report)
		}
	}
}
