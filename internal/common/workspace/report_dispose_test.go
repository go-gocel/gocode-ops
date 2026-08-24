package workspace

import (
	"strings"
	"testing"
	"time"
)

// 处置机制报告渲染测试（design-v2.md §四）：三态去向渲染 + 不变量横幅。

func wsWithConfirmed(t *testing.T, f *Finding) *Workspace {
	t.Helper()
	dir := t.TempDir()
	ws, err := NewWorkspace(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := ws.AddFindings([]*Finding{f}); err != nil {
		t.Fatal(err)
	}
	return ws
}

func TestRenderReport_VerifiedFixedShowsEvidence(t *testing.T) {
	f := NewFinding("web-01", "security", "ssh_weak_config", "root 口令直登")
	f.Status = FindingConfirmed
	f.Remediated = true
	f.RemediationNote = "已收紧 sshd 配置"
	f.Disposition = NewVerifiedDisposition(ChangeAuth, []VerificationEvidence{
		{VerifyCmd: "ssh -o BatchMode=yes root@web-01 true", CheckUp: "key_ok", Output: "key_ok"},
	})
	report := RenderReport(wsWithConfirmed(t, f), time.Now())
	for _, want := range []string{
		"✅ 已处置（verified_fixed）",
		"验证证据",
		"ssh -o BatchMode=yes root@web-01 true",
		"key_ok",
	} {
		if !strings.Contains(report, want) {
			t.Errorf("报告应含 %q:\n%s", want, report)
		}
	}
}

func TestRenderReport_ManualWorkOrderShowsPackage(t *testing.T) {
	f := NewFinding("web-01", "security", "ssh_weak_config", "root 口令直登")
	f.Status = FindingConfirmed
	f.RemediationNote = "人工工单：模型判定无法自动处置"
	f.Disposition = NewWorkOrderDisposition(ChangeAuth, &WorkOrder{
		Summary:           "模型判定无法自动处置（证据不足或已恢复）",
		Impact:            "root 口令 SSH 登录面开启（置信度 90%）",
		SuggestedCommands: []string{"sed -i 's/^PermitRootLogin.*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config"},
		Steps:             []string{"先确认密钥通道可用，再修改配置"},
		VerificationSteps: []string{"新会话用密钥实际认证"},
		Rollback:          "变更前备份 sshd_config",
	})
	report := RenderReport(wsWithConfirmed(t, f), time.Now())
	for _, want := range []string{
		"📋 人工工单（manual_workorder）",
		"工单摘要",
		"影响面",
		"建议命令",
		"人工步骤",
		"验证步骤",
		"回滚预案",
		"prohibit-password",
	} {
		if !strings.Contains(report, want) {
			t.Errorf("报告应含 %q:\n%s", want, report)
		}
	}
}

func TestRenderReport_AcceptedRiskShowsRationale(t *testing.T) {
	f := NewFinding("web-01", "security", "ssh_weak_config", "root 口令直登")
	f.Status = FindingConfirmed
	f.RemediationNote = "密码登录是唯一运维通道"
	f.Disposition = NewAcceptedRiskDisposition(ChangeAuth, "密码登录是业务约束，已用 MaxAuthTries+来源白名单补偿")
	report := RenderReport(wsWithConfirmed(t, f), time.Now())
	for _, want := range []string{
		"⚠️ 接受风险（accepted_risk）",
		"业务约束",
		"MaxAuthTries",
	} {
		if !strings.Contains(report, want) {
			t.Errorf("报告应含 %q:\n%s", want, report)
		}
	}
}

// TestRenderReport_FinalClosureBanner 终态报告：confirmed 无处置去向 →
// 头部不变量违规横幅（运行被取消/未收敛时结构上不能伪装成完成报告）。
func TestRenderReport_FinalClosureBanner(t *testing.T) {
	f := NewFinding("web-01", "svc", "svc_failed", "network.service 开机失败")
	f.Status = FindingConfirmed // 运行被取消：confirmed 但从未处置
	report := RenderReport(wsWithConfirmed(t, f), time.Now())
	if strings.Contains(report, "报告不变量违规") {
		t.Error("运行中实时渲染：confirmed 无去向是合法在途状态，不应出横幅")
	}
	final := RenderReportFinal(wsWithConfirmed(t, f), time.Now(), "⏹ 运行被取消（context canceled）：剩余待查 0，未处置 1，详见报告分区。")
	if !strings.Contains(final, "报告不变量违规") {
		t.Error("终态报告：confirmed 无处置去向必须出横幅（未完成快照）")
	}
	if !strings.Contains(final, "中途快照") {
		t.Error("横幅应标注中途快照")
	}
	if !strings.Contains(final, "## 六、运行结论") {
		t.Error("终态报告应含运行结论段")
	}
}

// TestRenderReport_StructuralBanner 运行中渲染也对结构违规出横幅
// （已处置∧待查互斥、✓ 无证据等闭环违规不等待终态）。
func TestRenderReport_StructuralBanner(t *testing.T) {
	f := NewFinding("web-01", "svc", "svc_failed", "d")
	f.Status = FindingPending
	f.Remediated = true // 已处置 ∧ 待查 互斥违规
	report := RenderReport(wsWithConfirmed(t, f), time.Now())
	if !strings.Contains(report, "报告不变量违规") {
		t.Error("互斥违规必须在实时渲染出横幅")
	}
}

// TestRenderReport_DispositionPersistedViaWorkspace 处置去向经工作区落盘
// 往返（JSON 序列化）后仍在。
func TestRenderReport_DispositionPersistedViaWorkspace(t *testing.T) {
	f := NewFinding("web-01", "security", "ssh_weak_config", "root 口令直登")
	f.Status = FindingConfirmed
	f.Disposition = NewWorkOrderDisposition(ChangeAuth, &WorkOrder{Summary: "人工处置"})
	ws := wsWithConfirmed(t, f)
	ws2, err := NewWorkspace(ws.Dir())
	if err != nil {
		t.Fatal(err)
	}
	got := ws2.Confirmed()
	if len(got) != 1 || got[0].Disposition == nil {
		t.Fatalf("处置去向应随工作区持久化: %+v", got)
	}
	if got[0].Disposition.Outcome != DispositionManualWorkOrder {
		t.Errorf("去向 = %s, want manual_workorder", got[0].Disposition.Outcome)
	}
}
