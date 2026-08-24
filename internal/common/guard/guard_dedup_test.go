package guard

import (
	"context"
	"sync"
	"testing"
)

// syncOperator 用于并发去重测试：第一个 Ask 到达时关闭 started 通知测试
// 主 goroutine，随后阻塞在 release 上，直到测试放开——强制同一 key 的
// 并发重叠窗口。
type syncOperator struct {
	mu      sync.Mutex
	calls   int
	started chan struct{}
	release chan struct{}
}

func (s *syncOperator) Ask(prompt string, options []string) (string, error) {
	s.mu.Lock()
	first := s.calls == 0
	s.calls++
	s.mu.Unlock()
	if first {
		close(s.started)
	}
	<-s.release
	return "y", nil
}

// TestDecide_AskDeduplicatedConcurrent 回归 P2：同一 (cmd,hosts) 的高危命令
// 被并发触发时，守卫应仅向操作员弹一次确认，其余 goroutine 复用同一结论
// （旧实现在「检查缓存→解锁→问操作员→加锁写回」窗口中，并发命令会双弹
// 甚至多弹确认）。go test -race 下同时验证结论广播无竞态。
func TestDecide_AskDeduplicatedConcurrent(t *testing.T) {
	const n = 16
	op := &syncOperator{started: make(chan struct{}), release: make(chan struct{})}
	g := NewRiskyCommandGuard(op, PolicyAsk)
	cmd := "systemctl restart nginx"
	rule := matchRiskyRule(cmd)
	if rule == nil {
		t.Fatal("命令应命中常规变更规则")
	}

	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs[i] = g.decide(context.Background(), cmd, rule, nil, "terminal")
		}(i)
	}
	// 等至少一个 goroutine 已进入 Ask（确认并发重叠已发生），再统一放开。
	<-op.started
	close(op.release)
	wg.Wait()

	op.mu.Lock()
	calls := op.calls
	op.mu.Unlock()
	if calls != 1 {
		t.Errorf("并发同 key 仅应询问操作员一次，实际 %d 次（旧实现会每人各问一次）", calls)
	}
	for i, e := range errs {
		if e != nil {
			t.Errorf("goroutine %d 应放行，实际 err=%v", i, e)
		}
	}
}
