package probe

import (
	"testing"
)

// L0 覆盖语义测试（design-v2.md §二：覆盖度是事实的一部分，partial 只产
// 待下钻线索，不产结论）。

// TestJudgeSecurityFacts_PartialCoverage partial 探针：产"待下钻"线索
// （coverage_partial），归属规则对该探针跳过——不完整枚举不得驱动
// 归属规则（超时截断被当"扫描无结果"是假阴性源）。
func TestJudgeSecurityFacts_PartialCoverage(t *testing.T) {
	hm := HostMetric{Host: "web-01"}
	hm.Raw = map[string]string{
		"suid_files": "/usr/bin/passwd\n/var/lib/.find\n", // 含非标准位置 SUID
	}
	hm.FactCoverage = map[string]string{"suid_files": "partial"}
	got := JudgeSecurityFacts(&hm)
	foundLead := false
	for _, a := range got {
		if a.Key == "coverage_partial" {
			foundLead = true
		}
		if a.Metric == "suid_files" && a.Key == "/var/lib/.find" {
			t.Error("partial 探针不得产归属结论（规则跳过）")
		}
	}
	if !foundLead {
		t.Errorf("partial 探针必须产待下钻线索: %+v", got)
	}
}

// TestJudgeSecurityFacts_FullCoverage full 探针：归属规则正常产线。
func TestJudgeSecurityFacts_FullCoverage(t *testing.T) {
	hm := HostMetric{Host: "web-01"}
	hm.Raw = map[string]string{
		"suid_files": "/usr/bin/passwd\n/var/lib/.find\n",
	}
	hm.FactCoverage = map[string]string{"suid_files": "full"}
	got := JudgeSecurityFacts(&hm)
	for _, a := range got {
		if a.Key == "/var/lib/.find" {
			return // 标准目录外 SUID 产线
		}
	}
	t.Errorf("full 探针应正常产归属结论: %+v", got)
}

// TestJudgeSecurityFacts_DrilldownVariantSameRule 下钻变体（suid_files_full/
// world_writable_full）与例行探针共用归属规则。
func TestJudgeSecurityFacts_DrilldownVariantSameRule(t *testing.T) {
	hm := HostMetric{Host: "web-01"}
	hm.Raw = map[string]string{
		"suid_files_full": "/usr/bin/passwd\n/var/lib/.find\n",
	}
	got := JudgeSecurityFacts(&hm)
	for _, a := range got {
		if a.Key == "/var/lib/.find" {
			return
		}
	}
	t.Errorf("下钻变体结果应产归属结论: %+v", got)
}

// TestJudgeSecurityFacts_CollectFailNoProbeFlood collect 级失败不刷
// per-探针 partial 线索（collect_anomaly 单条覆盖，逐探针刷线是噪音）。
func TestJudgeSecurityFacts_CollectFailNoProbeFlood(t *testing.T) {
	hm := HostMetric{Host: "web-01", Errors: map[string]string{"collect": "超时"}}
	hm.FactCoverage = map[string]string{
		"net_identity":    "partial",
		"ssh_chain":       "partial",
		"empty_passwords": "partial",
	}
	got := JudgeSecurityFacts(&hm)
	for _, a := range got {
		if a.Key == "coverage_partial" {
			t.Errorf("collect 级失败不应刷 per-探针 partial 线索: %+v", got)
		}
	}
}

// TestSignalProbePlan_RecheckExhaustive 复检计划穷尽性：suid_files/
// world_writable 信号复检走全盘下钻变体（例行定点探针覆盖不到非标准
// 位置/数据面——复检用定点探针会假放行）。
