package guard

// guard_callback_test.go — 守卫背书回调与裁决白盒测试。

import (
	"context"
	"testing"
)

// TestGuardOnApprovedCallback 守卫背书回调：操作员确认放行触发回调。
func TestGuardOnApprovedCallback(t *testing.T) {
	rule := matchRiskyRule("systemctl restart nginx")
	if rule == nil {
		t.Fatal("restart 应命中高危规则")
	}

	// 1) 逐条确认（y）触发回调。
	g1 := NewRiskyCommandGuard(&fakeOperator{answers: []string{"y"}}, PolicyAsk)
	var approved1 []string
	g1.OnApproved = func(cmd string, hosts []string) { approved1 = append(approved1, cmd) }
	if err := g1.decide(context.Background(), "systemctl restart nginx", rule, nil, "terminal"); err != nil {
		t.Fatalf("decide 确认后应放行: %v", err)
	}
	if len(approved1) != 1 || approved1[0] != "systemctl restart nginx" {
		t.Errorf("批准回调应记录命令: %v", approved1)
	}

	// 2) 拒绝（n）不触发回调且返回错误。
	g2 := NewRiskyCommandGuard(&fakeOperator{answers: []string{"n"}}, PolicyAsk)
	var approved2 []string
	g2.OnApproved = func(cmd string, hosts []string) { approved2 = append(approved2, cmd) }
	if err := g2.decide(context.Background(), "systemctl restart nginx", rule, nil, "terminal"); err == nil {
		t.Fatal("拒绝应返回错误")
	}
	if len(approved2) != 0 {
		t.Errorf("拒绝不应触发回调: %v", approved2)
	}

	// 3) 会话放行（a）触发回调，且后续命令走 session_allow 同样触发。
	g3 := NewRiskyCommandGuard(&fakeOperator{answers: []string{"a"}}, PolicyAsk)
	var approved3 []string
	g3.OnApproved = func(cmd string, hosts []string) { approved3 = append(approved3, cmd) }
	if err := g3.decide(context.Background(), "systemctl restart nginx", rule, nil, "terminal"); err != nil {
		t.Fatalf("会话放行: %v", err)
	}
	if err := g3.decide(context.Background(), "systemctl restart mysql", rule, nil, "terminal"); err != nil {
		t.Fatalf("会话放行后续命令: %v", err)
	}
	if len(approved3) != 2 {
		t.Errorf("会话放行也应触发回调: %v", approved3)
	}
}
