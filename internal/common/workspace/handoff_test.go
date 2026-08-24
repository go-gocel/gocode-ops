package workspace

import (
	"strings"
	"testing"

	"github.com/go-gocel/gocode-ops/internal/common/model"
)

// 接力协同测试：引擎遗留状态 → 交互助手接管输入面。

func TestLoadHandoff_PicksUpLegacy(t *testing.T) {
	dir := t.TempDir()
	ws, err := NewWorkspace(dir)
	if err != nil {
		t.Fatal(err)
	}
	// 引擎遗留：pending 待裁决、confirmed 未处置、工单（manual_workorder）、
	// 已修复（不应进接力清单）。
	pending := NewFinding("web-01", "security", "ssh_root_login", "root 密码直登")
	pending.Key = "permitrootlogin"
	open := NewFinding("web-01", "security", "suid_unowned", "非包来源 SUID")
	open.Key = "/usr/bin/upd2"
	open.Status = FindingConfirmed
	wo := NewFinding("web-01", "network", "firewall_permissive", "INPUT ACCEPT")
	wo.Key = "INPUT"
	wo.Status = FindingConfirmed
	wo.Disposition = model.NewWorkOrderDisposition(model.ChangeNetwork,
		&model.WorkOrder{Summary: "防火墙弱基线", SuggestedCommands: []string{"iptables -A INPUT -s 10.0.0.0/8 -j ACCEPT"}})
	fixed := NewFinding("web-01", "svc", "svc_failed", "nginx")
	fixed.Key = "nginx.service"
	fixed.Status = FindingConfirmed
	fixed.Remediated = true
	if err := ws.AddFindings([]*Finding{pending, open, wo, fixed}); err != nil {
		t.Fatal(err)
	}
	h := LoadHandoff(dir)
	if !h.HasWork() {
		t.Fatal("有遗留项应 HasWork=true")
	}
	if len(h.Open) != 2 || len(h.WorkOrders) != 1 {
		t.Fatalf("Open=%d（want 2）WorkOrders=%d（want 1）", len(h.Open), len(h.WorkOrders))
	}
	s := h.String()
	for _, want := range []string{"ssh_root_login", "suid_unowned", "/usr/bin/upd2", "firewall_permissive", "iptables -A INPUT"} {
		if !strings.Contains(s, want) {
			t.Errorf("摘要缺 %q：\n%s", want, s)
		}
	}
	// 已修复项不得进入接力清单。
	if strings.Contains(s, "svc_failed") {
		t.Errorf("已修复项不应进接力摘要：\n%s", s)
	}
}

func TestLoadHandoff_EmptyAndMissing(t *testing.T) {
	// 无工作区状态（独立使用场景）→ 空 Handoff（不阻塞）。
	if h := LoadHandoff(t.TempDir()); h.HasWork() {
		t.Fatalf("无状态应 HasWork=false，got %+v", h)
	}
	// 全部已处置 → 空。
	dir := t.TempDir()
	ws, err := NewWorkspace(dir)
	if err != nil {
		t.Fatal(err)
	}
	fixed := NewFinding("web-01", "svc", "svc_failed", "nginx")
	fixed.Status = FindingConfirmed
	fixed.Remediated = true
	if err := ws.AddFindings([]*Finding{fixed}); err != nil {
		t.Fatal(err)
	}
	if h := LoadHandoff(dir); h.HasWork() {
		t.Fatalf("全部已处置应 HasWork=false，got %+v", h)
	}
}
