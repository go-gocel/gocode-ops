package remediate

// remediate_p2_test.go — P2 修复回归测试：回滚错误行检测（谎报已回滚）。

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/go-gocel/gocode-ops/internal/common/guard"
	"github.com/go-gocel/gocode-ops/internal/common/model"
)

// TestExecutor_RollbackErrorLineDetected 回滚命令输出错误行（整体退出码
// 被尾随 echo 掩蔽为 0）→ 不得谎报已回滚（与执行侧 R15 语义同源）。
func TestExecutor_RollbackErrorLineDetected(t *testing.T) {
	gd := guard.NewRiskyCommandGuard(nil, guard.PolicyAuto)
	ex := NewExecutor(Config{ActTimeout: 3 * time.Second, Guard: gd}, gd, nil, nil, nil)

	// 回滚命令实际失败但退出码为 0：错误行是唯一信号。
	plan := &Plan{Actions: []PlanAction{{
		Name: "a", Command: "true", Rationale: "r",
		Verify: "true", CheckUp: "up", Rollback: `echo "sed: cannot rename /x: Device or resource busy"; echo OK`,
	}}}
	acts := []model.Action{{Name: "a", Host: ""}}
	ex.rollback(context.Background(), "", plan, &acts)
	if acts[0].RolledBac {
		t.Fatal("回滚输出错误行不得谎报已回滚")
	}
	if !strings.Contains(acts[0].Error, "错误行") && !strings.Contains(acts[0].Error, "回滚失败") {
		t.Errorf("应记录回滚失败原因: %q", acts[0].Error)
	}

	// 正常回滚：标记已回滚。
	plan2 := &Plan{Actions: []PlanAction{{
		Name: "a", Command: "true", Rationale: "r",
		Verify: "true", CheckUp: "up", Rollback: "echo restored",
	}}}
	acts2 := []model.Action{{Name: "a", Host: ""}}
	ex.rollback(context.Background(), "", plan2, &acts2)
	if !acts2[0].RolledBac {
		t.Fatal("正常回滚应标记已回滚")
	}
}
