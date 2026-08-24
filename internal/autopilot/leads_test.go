package autopilot

import (
	"testing"
)

// 机制 2：通道约束兜底——模型把疑点写进自由文本而非 findings 时，
// 引擎提取实例化为 pending 线索（发现不因通道错位丢失）。

// TestExtractDoubtLeads_NotesHints notes 里的疑点（高信号词 + 具体对象）
// → 实例化 pending。
func TestExtractDoubtLeads_NotesHints(t *testing.T) {
	sum := &PhaseSummary{
		Notes: "4444 端口 python 进程疑似后门监听，需追查根因",
	}
	leads := extractDoubtLeads(sum, []string{"ops-env"})
	if len(leads) == 0 {
		t.Fatal("notes 中的疑点应被提取")
	}
	f := leads[0]
	if f.Host != "ops-env" || f.Status != FindingPending || f.Signal == "" {
		t.Errorf("疑点线索字段异常: %+v", f)
	}
	if f.Source == SourceL0 {
		t.Error("文本提取线索不应标记 L0 来源")
	}
	if !containsDesc(f.Desc, "4444") {
		t.Errorf("线索描述应含疑点对象: %q", f.Desc)
	}
}

// TestExtractDoubtLeads_NegationExcluded 否定语境不提取。
func TestExtractDoubtLeads_NegationExcluded(t *testing.T) {
	cases := []string{
		"全盘检查无异常",
		"未发现可疑进程",
		"日志无后门痕迹，一切正常",
		"无任何风险暴露",
		"端口检查未发现异常监听",
	}
	for _, notes := range cases {
		sum := &PhaseSummary{Notes: notes}
		if leads := extractDoubtLeads(sum, []string{"web-01"}); len(leads) != 0 {
			t.Errorf("否定语境不应提取: %q → %+v", notes, leads)
		}
	}
}

// TestExtractDoubtLeads_DescEvidenceHint desc/evidence 里的疑点（含路径
// 实体）同样提取。
func TestExtractDoubtLeads_DescEvidenceHint(t *testing.T) {
	sum := &PhaseSummary{
		Findings: []*Finding{
			{Host: "web-01", Domain: "svc", Signal: "svc_failed",
				Desc:     "nginx 配置疑似被篡改（/etc/nginx/nginx.conf 与备份不一致）",
				Evidence: []string{"diff 显示 nginx.conf 与备份不一致"}},
		},
	}
	leads := extractDoubtLeads(sum, []string{"web-01"})
	signals := map[string]bool{}
	for _, f := range leads {
		signals[f.Signal] = true
	}
	if !signals["tampered_hint"] {
		t.Errorf("desc/evidence 疑点应被提取: %+v", leads)
	}
}

// TestExtractDoubtLeads_GenericNoObject 泛泛描述（高信号词但无具体对象）
// 不实例化——防噪音线索（run6 实测 7 条 hint 噪音的修复）。
func TestExtractDoubtLeads_GenericNoObject(t *testing.T) {
	cases := []string{
		"整体安全状态存在风险，建议加强巡检",
		"可能有后门，建议关注",
		"该主机疑似被植入过恶意程序（历史遗留）",
	}
	for _, notes := range cases {
		sum := &PhaseSummary{Notes: notes}
		if leads := extractDoubtLeads(sum, []string{"web-01"}); len(leads) != 0 {
			t.Errorf("无具体对象的泛泛描述不应实例化: %q → %+v", notes, leads)
		}
	}
}

// TestExtractDoubtLeads_Dedup 同信号同 host 只产一条。
func TestExtractDoubtLeads_Dedup(t *testing.T) {
	sum := &PhaseSummary{
		Notes: "可疑进程 A；还有可疑进程 B；疑似后门 C",
	}
	leads := extractDoubtLeads(sum, []string{"web-01"})
	if len(leads) > 2 {
		t.Errorf("同信号应去重: %d 条", len(leads))
	}
}

// TestExtractDoubtLeads_NilSummary 空小结不 panic。
func TestExtractDoubtLeads_NilSummary(t *testing.T) {
	if leads := extractDoubtLeads(nil, nil); len(leads) != 0 {
		t.Errorf("nil 小结不应有线索: %+v", leads)
	}
}

func containsDesc(desc, sub string) bool {
	return len(desc) > 0 && indexOf(desc, sub) >= 0
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
