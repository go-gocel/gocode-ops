package model

import (
	"strings"
	"testing"
)

// TestDispositionValidate 三态去向契约校验：✓ 绑定证据、工单内容、
// 风险理由、枚举合法性。
func TestDispositionValidate(t *testing.T) {
	cases := []struct {
		name    string
		d       *Disposition
		wantBad bool
	}{
		{"nil 去向非法", nil, true},
		{"非法枚举", &Disposition{Outcome: "maybe"}, true},
		{"verified_fixed 无证据", &Disposition{Outcome: DispositionVerifiedFixed}, true},
		{"verified_fixed 有证据", &Disposition{
			Outcome: DispositionVerifiedFixed,
			Evidence: []VerificationEvidence{
				{VerifyCmd: "ssh -o BatchMode=yes host true", CheckUp: "OK"},
			},
		}, false},
		{"验证证据缺命令", &Disposition{
			Outcome:  DispositionVerifiedFixed,
			Evidence: []VerificationEvidence{{CheckUp: "OK"}},
		}, true},
		{"验证证据缺判据", &Disposition{
			Outcome:  DispositionVerifiedFixed,
			Evidence: []VerificationEvidence{{VerifyCmd: "mc ls"}},
		}, true},
		{"工单缺内容", &Disposition{Outcome: DispositionManualWorkOrder}, true},
		{"工单有摘要", &Disposition{
			Outcome:   DispositionManualWorkOrder,
			WorkOrder: &WorkOrder{Summary: "人工处置"},
		}, false},
		{"工单只有步骤", &Disposition{
			Outcome:   DispositionManualWorkOrder,
			WorkOrder: &WorkOrder{Steps: []string{"步骤 1"}},
		}, false},
		{"接受风险缺理由", &Disposition{Outcome: DispositionAcceptedRisk}, true},
		{"接受风险有理由", &Disposition{Outcome: DispositionAcceptedRisk, RiskRationale: "密码登录是业务约束，已用限速补偿"}, false},
	}
	for _, c := range cases {
		bad := c.d.Validate()
		if got := len(bad) > 0; got != c.wantBad {
			t.Errorf("%s: violations=%v, wantBad=%v", c.name, bad, c.wantBad)
		}
	}
}

// TestDispositionInvariants_Structural 运行中/终态共有的结构违规断言：
// 已处置∧待查互斥、空方案文本残留、✓ 无去向、已处置非 verified_fixed。
func TestDispositionInvariants_Structural(t *testing.T) {
	mk := func(status string, remediated bool, note string, d *Disposition) *Finding {
		f := NewFinding("h1", "svc", "svc_failed", "desc")
		f.Status = status
		f.Remediated = remediated
		f.RemediationNote = note
		f.Disposition = d
		return f
	}
	cases := []struct {
		name string
		f    *Finding
		want bool // 是否应产违规
	}{
		{"待查且已处置互斥", mk(FindingPending, true, "", nil), true},
		{"空方案文本残留", mk(FindingConfirmed, false, "处置方案为空（模型判定证据不足或已恢复）", nil), true},
		{"已处置但无去向", mk(FindingConfirmed, true, "ok", nil), true},
		{"已处置但去向为工单", mk(FindingConfirmed, true, "ok", &Disposition{Outcome: DispositionManualWorkOrder, WorkOrder: &WorkOrder{Summary: "s"}}), true},
		{"已处置且 verified_fixed 带证据", mk(FindingConfirmed, true, "ok", &Disposition{
			Outcome:  DispositionVerifiedFixed,
			Evidence: []VerificationEvidence{{VerifyCmd: "ssh host true", CheckUp: "OK"}},
		}), false},
		{"已修复去向缺证据", mk(FindingConfirmed, false, "ok", &Disposition{Outcome: DispositionVerifiedFixed}), true},
		{"confirmed 无去向运行中", mk(FindingConfirmed, false, "ok", nil), false}, // final=false 不强制闭合
	}
	for _, c := range cases {
		v := DispositionInvariants([]*Finding{c.f}, false)
		got := len(v) > 0
		if got != c.want {
			t.Errorf("%s: violations=%v, want=%v", c.name, v, c.want)
		}
	}
}

// TestDispositionInvariants_FinalClosure 终态报告去向闭合断言：confirmed
// 无去向 → 违规；有去向（三态任一合法）→ 通过。
func TestDispositionInvariants_FinalClosure(t *testing.T) {
	noDisp := NewFinding("h1", "svc", "svc_failed", "desc")
	noDisp.Status = FindingConfirmed

	withWorkOrder := NewFinding("h1", "svc", "svc_failed", "desc")
	withWorkOrder.Status = FindingConfirmed
	withWorkOrder.Disposition = &Disposition{Outcome: DispositionManualWorkOrder, WorkOrder: &WorkOrder{Summary: "人工处置"}}

	if v := DispositionInvariants([]*Finding{noDisp}, true); len(v) == 0 {
		t.Error("终态报告：confirmed 无处置去向必须产违规（去向闭合）")
	}
	if v := DispositionInvariants([]*Finding{withWorkOrder}, true); len(v) > 0 {
		t.Errorf("终态报告：confirmed 有合法去向不应违规: %v", v)
	}
	// 已修复的 confirmed 也闭合。
	remediated := NewFinding("h1", "svc", "svc_failed", "desc")
	remediated.Status = FindingConfirmed
	remediated.Remediated = true
	remediated.Disposition = &Disposition{
		Outcome:  DispositionVerifiedFixed,
		Evidence: []VerificationEvidence{{VerifyCmd: "ssh host true", CheckUp: "OK"}},
	}
	if v := DispositionInvariants([]*Finding{remediated}, true); len(v) > 0 {
		t.Errorf("已修复且有证据不应违规: %v", v)
	}
}

// TestDispositionInvariants_IllegalTextFreed 旧数据迁移：残留"处置方案
// 为空"文本必须被标记（报告横幅兜底，直到数据修复）。
func TestDispositionInvariants_IllegalTextFreed(t *testing.T) {
	f := NewFinding("h1", "sec", "ssh_weak_config", "root 口令直登")
	f.Status = FindingConfirmed
	f.RemediationNote = "处置方案为空（模型判定证据不足或已恢复）"
	v := DispositionInvariants([]*Finding{f}, false)
	found := false
	for _, s := range v {
		if strings.Contains(s, "处置方案为空") {
			found = true
		}
	}
	if !found {
		t.Errorf("非法文本残留必须被断言: %v", v)
	}
}
