package remediate

// remediate_verify_test.go — verify 只读强制回归测试（P0 修复）：
// verify 命令由模型生成、直接执行，此前无任何守卫——破坏性命令
// （rm -rf /x; echo restored 等）作 verify 即绕过硬性禁止。修复后
// verify 必须为只读形态（CheckReadOnly：风险审查 + 不命中高危规则）。

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/go-gocel/gocode-ops/internal/common/guard"
	"github.com/go-gocel/gocode-ops/internal/common/model"
)

func TestExecutor_VerifyReadOnlyEnforced(t *testing.T) {
	gd := guard.NewRiskyCommandGuard(nil, guard.PolicyAuto)
	ex := NewExecutor(Config{VerifyTimeout: time.Second, Guard: gd}, gd, nil, nil, nil)

	// 破坏性 verify：不得执行、不得算恢复证据。
	plan := &Plan{Actions: []PlanAction{{
		Name: "a", Command: "true", Rationale: "r",
		Verify: "rm -rf /x; echo restored", CheckUp: "restored", Rollback: "true",
	}}}
	acts := []model.Action{{Name: "a", Host: ""}}
	if allOK := ex.verifyAll(context.Background(), "", plan, &acts); allOK {
		t.Fatal("破坏性 verify 不得通过验证")
	}
	if !strings.Contains(acts[0].VerifyNote, "只读") {
		t.Errorf("应记录 verify 非只读原因: %q", acts[0].VerifyNote)
	}

	// 硬性禁止命令作 verify：同样拒绝。
	plan2 := &Plan{Actions: []PlanAction{{
		Name: "a", Command: "true", Rationale: "r",
		Verify: "cat /etc/shadow && echo ok", CheckUp: "ok", Rollback: "true",
	}}}
	acts2 := []model.Action{{Name: "a", Host: ""}}
	if allOK := ex.verifyAll(context.Background(), "", plan2, &acts2); allOK {
		t.Fatal("凭证读取 verify 不得通过验证")
	}

	// 只读 verify：正常执行验证路径（不因只读校验被拒）。
	plan3 := &Plan{Actions: []PlanAction{{
		Name: "a", Command: "true", Rationale: "r",
		Verify: "test -f /x && echo absent", CheckUp: "absent", Rollback: "true",
	}}}
	acts3 := []model.Action{{Name: "a", Host: ""}}
	_ = ex.verifyAll(context.Background(), "", plan3, &acts3)
	if strings.Contains(acts3[0].VerifyNote, "只读") {
		t.Errorf("只读 verify 不应因只读校验被拒: %q", acts3[0].VerifyNote)
	}
}

func TestPrecheckSatisfied_VerifyReadOnly(t *testing.T) {
	gd := guard.NewRiskyCommandGuard(nil, guard.PolicyAuto)
	cfg := Config{VerifyTimeout: time.Second, Guard: gd}

	// 幂等预检同样不执行非只读 verify：直接返回不预检（走真实执行，
	// verifyAll 会拒绝并如实记录）。
	plan := &Plan{Actions: []PlanAction{{
		Name: "a", Command: "true", Rationale: "r",
		Verify: "rm -rf /x; echo restored", CheckUp: "restored", Rollback: "true",
	}}}
	if ok, acts := PrecheckSatisfied(context.Background(), cfg, nil, "", plan, "x"); ok || len(acts) != 0 {
		t.Fatalf("非只读 verify 不应预检通过: ok=%v acts=%v", ok, acts)
	}
}
