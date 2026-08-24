package collect

// signal_plan_test.go — 信号→探针计划与安全探针有界性验证（组合 probe 导出 + 命令构建）。

import (
	"strings"
	"testing"

	p "github.com/go-gocel/gocode-ops/internal/common/probe"
)

func TestSignalProbePlan_RecheckExhaustive(t *testing.T) {
	env := &Env{HasSystemd: true, HasSS: true, NProc: 4}
	_, fids := p.SignalProbePlan(env, "suid_files")
	joined := strings.Join(fids, ",")
	if !strings.Contains(joined, "suid_files_full") {
		t.Errorf("suid_files 复检计划应含 suid_files_full: %v", fids)
	}
	for _, id := range fids {
		if id == "suid_files" {
			t.Errorf("复检计划不应再用例行定点探针 suid_files: %v", fids)
		}
	}
	_, fids2 := p.SignalProbePlan(env, "world_writable")
	joined2 := strings.Join(fids2, ",")
	if !strings.Contains(joined2, "world_writable_full") {
		t.Errorf("world_writable 复检计划应含 world_writable_full: %v", fids2)
	}
	// 常规信号不受影响。
	_, fids3 := p.SignalProbePlan(env, "unattributed_listen")
	if !strings.Contains(strings.Join(fids3, ","), "listen_ports") {
		t.Errorf("unattributed_listen 复检计划应含 listen_ports: %v", fids3)
	}
}

// TestSecurityFacts_NoUnboundedRoutineProbes 例行探针规格书：例行集
// （S0/S1）不得含全盘枚举形态（S2/S3 下钻）；例行命令构造不包含
// 下钻探针——探针分层是规格书级约束，不是运行时侥幸。
func TestSecurityFacts_NoUnboundedRoutineProbes(t *testing.T) {
	env := &Env{HasSystemd: true, HasSS: true, NProc: 4}
	for _, fp := range p.SecurityFacts(env) {
		if fp.Class > FactTargeted {
			continue
		}
		// 例行探针必须自带成本护栏（timeout + 完成哨兵）或天然 O(1)。
		frag := fp.Fragment(env)
		if strings.Contains(frag, "find ") && !strings.Contains(frag, "timeout ") {
			t.Errorf("例行探针 %s 含 find 但无 timeout 护栏（成本无界）: %s", fp.ID, frag)
		}
		if strings.Contains(frag, "find ") && !strings.Contains(frag, probeIncompleteMark) {
			t.Errorf("例行探针 %s 含 find 但无完成哨兵（不完整结果会被当无结果）: %s", fp.ID, frag)
		}
	}
	// 例行命令构造：facts=nil 排除下钻探针。
	cmd := BuildMetricsCommand(env, p.Metrics(env))
	for _, id := range []string{"big_files", "suid_files_full", "world_writable_full"} {
		if strings.Contains(cmd, fragmentMark(id)) {
			t.Errorf("例行命令不得含下钻探针 %s", id)
		}
	}
	for _, id := range []string{"suid_files", "world_writable", "file_caps", "tmp_dirs"} {
		if !strings.Contains(cmd, fragmentMark(id)) {
			t.Errorf("例行命令应含定点探针 %s", id)
		}
	}
}
