package autopilot

// respond_test.go — 处置协议层测试（执行层测试随机制下沉到
// common/remediate；本文件只保留依赖 autopilot 内部编排的用例）。

import (
	"testing"

	"github.com/go-gocel/gocode-ops/internal/common/model"
	"github.com/go-gocel/gocode-ops/internal/common/remediate"
)

// TestPlanContractRejections_PkillNotRejected pkill 自杀风险动作不再被
// 契约预检拦截：执行层机械改写（括号化/拆段）后安全执行——引擎已确认
// 问题存在，预检拒绝只会把处置卡死在重试循环（评测实测 9090/8088
// 后门 3 轮达限悬置）。
func TestPlanContractRejections_PkillNotRejected(t *testing.T) {
	targets := []*model.Finding{{ID: "f1", Signal: "config_drift", Key: "keepalive"}}
	plans := &ResponsePlans{Plans: []remediate.Plan{{
		FindingID: "f1",
		Actions: []remediate.PlanAction{{
			Name:      "del",
			Command:   "rm -f /tmp/keepalive.sh; pkill -f 'keepalive[.]sh'",
			Rationale: "x", Verify: "test ! -f /tmp/keepalive.sh && echo ok", CheckUp: "ok", Rollback: "true",
		}},
	}}}
	if rej := planContractRejections(targets, plans); len(rej) != 0 {
		t.Fatalf("pkill 方案应通过契约预检（执行层机械改写）: %+v", rej)
	}
}

// TestPlanContractRejections_OutOfBatchTolerated 越批输出容忍：模型常为
// 本批之外的故障也生成方案（同 signal 多 finding 分批、模型视野含全部
// 故障）——匹配不到本批目标的 plan 不得触发整批拒绝重试（实测：
// firewall_permissive 越批 plan 导致 3 轮重试全废）。
func TestPlanContractRejections_OutOfBatchTolerated(t *testing.T) {
	// 本批只有 firewall_permissive[INPUT]；模型额外输出 FORWARD 与
	// 其他批的 plan（越批）——只有本批目标缺方案才应拒绝。
	targets := []*model.Finding{{ID: "web-01/firewall_permissive/1", Signal: "firewall_permissive", Key: "INPUT"}}
	plans := &ResponsePlans{Plans: []remediate.Plan{
		{FindingID: "firewall_permissive:INPUT",
			Actions: []remediate.PlanAction{{Name: "x", Command: "true", Rationale: "x",
				Verify: "true && echo ok", CheckUp: "ok", Rollback: "true"}}},
		{FindingID: "firewall_permissive:FORWARD", // 越批：不在本批
			Actions: []remediate.PlanAction{{Name: "x", Command: "true", Rationale: "x",
				Verify: "true && echo ok", CheckUp: "ok", Rollback: "true"}}},
		{FindingID: "web-01/passwd_policy_weak/2", // 越批：其他信号
			Actions: []remediate.PlanAction{{Name: "x", Command: "true", Rationale: "x",
				Verify: "true && echo ok", CheckUp: "ok", Rollback: "true"}}},
	}}
	if rej := planContractRejections(targets, plans); len(rej) != 0 {
		t.Fatalf("越批 plan 应被容忍（不拒绝重试）: %+v", rej)
	}
}

// TestPlanContractRejections_NoBatchMatchRejected 本批目标完全无方案才
// 拒绝重试（提示模型输出本批方案）。
func TestPlanContractRejections_NoBatchMatchRejected(t *testing.T) {
	targets := []*model.Finding{{ID: "web-01/firewall_permissive/1", Signal: "firewall_permissive", Key: "INPUT"}}
	plans := &ResponsePlans{Plans: []remediate.Plan{
		{FindingID: "web-01/passwd_policy_weak/2", // 与本批无关
			Actions: []remediate.PlanAction{{Name: "x", Command: "true", Rationale: "x",
				Verify: "true && echo ok", CheckUp: "ok", Rollback: "true"}}},
	}}
	if rej := planContractRejections(targets, plans); len(rej) == 0 {
		t.Fatal("本批目标无任何方案应拒绝重试")
	}
}
