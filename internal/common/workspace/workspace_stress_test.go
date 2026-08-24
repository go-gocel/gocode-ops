package workspace

// 压力复现：高密度并发写同一路径，放大 Windows MoveFileEx 的瞬时占用
// 窗口（并发 rename 竞争 + 实时防护扫描）。修复前（5 次/100ms 重试）
// 在 Windows 上会偶发 Access is denied；修复后（指数退避 ~800ms 窗口）
// 应稳定通过。Linux 上 rename 原子替换，此测试恒快通过。

import (
	"fmt"
	"github.com/go-gocel/gocode-ops/internal/common/fsutil"
	"os"
	"strings"
	"sync"
	"testing"
)

func TestWriteFileAtomic_ConcurrentStress(t *testing.T) {
	if testing.Short() {
		t.Skip("short mode")
	}
	dir := t.TempDir()
	path := dir + "/findings.json"
	const writers = 10 // 单字符数据（w=0..9），终态断言不依赖数字位数
	const rounds = 25  // 10×25 = 250 次并发落盘
	var wg sync.WaitGroup
	var mu sync.Mutex
	var failures []string
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			data := []byte(strings.Repeat(fmt.Sprintf("%d", w), 2000))
			for r := 0; r < rounds; r++ {
				if err := fsutil.WriteFileAtomic(path, data, 0o644); err != nil {
					mu.Lock()
					failures = append(failures, fmt.Sprintf("w%d/r%d: %v", w, r, err))
					mu.Unlock()
				}
			}
		}(w)
	}
	wg.Wait()
	if len(failures) > 0 {
		t.Fatalf("并发落盘失败 %d 次，示例：%v", len(failures), failures[:min(5, len(failures))])
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// 终态必须是某个 writer 的完整单版本（2000 字节单字符重复），
	// 不允许交叉/半截。
	if len(got) != 2000 {
		t.Fatalf("终态文件长度异常: %d 字节", len(got))
	}
	for _, b := range got {
		if b != got[0] {
			t.Fatal("终态文件不应是交叉内容")
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, ent := range entries {
		if strings.HasSuffix(ent.Name(), ".tmp") {
			t.Errorf("不应残留 tmp 文件: %s", ent.Name())
		}
	}
}
