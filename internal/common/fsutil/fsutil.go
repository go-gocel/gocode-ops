package fsutil

// fsutil — 通用文件与字符串工具（单一来源，替代 collect/l0/memory/probe/
// workspace 各自的本地副本——原副本注释自认"与 store 包实现独立的本地副本"，
// 重复实现已统一收敛到此包）。

import (
	"fmt"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

var atomicTmpSeq atomic.Int64

// renameLocks 进程内 per-path rename 互斥：Windows 的 MoveFileEx 对同一
// 目标文件没有并发原子保证（多个 REPLACE_EXISTING 同时执行会相互触发
// Access is denied）；同一路径的并发写在本进程内串行化，跨进程竞争由
// rename 重试兜底。锁按路径累积（工作区文件数有限，无泄漏问题）。
var renameLocks sync.Map // path → *sync.Mutex

// WriteFileAtomic atomically writes data to path using a unique temp file, fsync, and rename.
// WriteFileAtomic 原子写文件：唯一 tmp 名（PID+时间戳+原子序号，防双
// 进程同目录互截断）+ 写入后 fsync + rename（读者只会看到旧或新完整
// 文件，不会读到半截——断电/并发下内容完整性由 rename 原子性保证）。
func WriteFileAtomic(path string, data []byte, mode os.FileMode) error {
	// 进程内同目标串行化（Windows rename 无并发原子保证；Linux 上
	// 无害——rename 原子替换本就允许并发，锁只消除竞争窗口）。
	lock, _ := renameLocks.LoadOrStore(path, &sync.Mutex{})
	mu := lock.(*sync.Mutex)
	mu.Lock()
	defer mu.Unlock()

	tmp := fmt.Sprintf("%s.%d.%d.%d.tmp", path, os.Getpid(), time.Now().UnixNano(), atomicTmpSeq.Add(1))
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	// Windows 并发 rename 同一目标可能瞬时失败（Access is denied）：
	// 目标被其他并发 rename 短暂占用，或刚写入的 tmp 被实时防护
	// （Defender/索引器）短暂持有句柄（无 FILE_SHARE_DELETE）——指数
	// 退避重试覆盖毫秒~秒级占用窗口（密集并发实测：10ms 级重试在
	// 防护扫描风暴下不够，占用可持续数百 ms~秒级）。
	// Linux rename 原子替换首试即成功，失败即真实错误，不重试。
	if runtime.GOOS == "windows" {
		for attempt := 0; ; attempt++ {
			if err := os.Rename(tmp, path); err == nil {
				return nil
			}
			if attempt >= 19 {
				os.Remove(tmp)
				return err
			}
			// 10,20,40,80,160,200ms 封顶：总窗口 ~2.8s，覆盖扫描占用
			// 波峰；持续占用（>3s）是真实异常，如实返回错误。
			delay := 10 * (1 << min(attempt, 4))
			if delay > 200 {
				delay = 200
			}
			time.Sleep(time.Duration(delay) * time.Millisecond)
		}
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// TruncateStr truncates s to n runes and appends an ellipsis when s is longer.
// TruncateStr 截断字符串到 n 个 rune（超长加省略号）。
func TruncateStr(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}
