package collect

// collect_cpu_test.go — prevCPU 并发安全回归测试：轮内多主机并行采集
// 各自 goroutine 增量读写 prevCPU 的等价形态。修复前无锁并发 map 写
// 触发 Go 运行时 fatal（-race 必现）；修复后持锁安全。

import (
	"fmt"
	"sync"
	"testing"
)

func TestCollector_PrevCPUConcurrent(t *testing.T) {
	c := &Collector{env: &Env{NProc: 8}, prevCPU: map[string]*cpuStat{}}
	const statOut = "cpu  100 0 50 5000 100 0 0 0 0 0"
	const loadOut = "0.05 0.10 0.15 1/234 12345"
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			host := fmt.Sprintf("h%d", i)
			for j := 0; j < 500; j++ {
				c.cpuUsage(host, statOut, loadOut)
			}
		}(i)
	}
	wg.Wait()
	// 并发后状态一致：每台主机都有上一轮采样。
	c.cpuMu.Lock()
	defer c.cpuMu.Unlock()
	for i := 0; i < 8; i++ {
		if _, ok := c.prevCPU[fmt.Sprintf("h%d", i)]; !ok {
			t.Fatalf("主机 h%d 应有采样", i)
		}
	}
}
