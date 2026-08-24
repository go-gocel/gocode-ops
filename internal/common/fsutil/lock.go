package fsutil

// lock.go — 跨进程文件锁：同一工作目录多进程（全自动引擎 + 交互运维
// 助手并行）写共享状态文件时，"读-改-写"必须互斥，否则后写覆盖先写、
// 状态丢失。
//
// 纯 Go 实现（O_EXCL 锁文件 + 重试 + 陈旧检测），跨平台可用（Windows
// 开发机与 Linux 目标一致）。写临界区应保持很短（marshal+原子写）；
// 崩溃残留的陈旧锁按 mtime 超时清理。归属令牌：锁文件内容记录持锁者
// 身份（pid+时间戳+序号），释放时校验令牌一致才删除——防止"持锁进程
// 被挂起超过 TTL → 锁被他人按陈旧清理接管 → 原持锁者释放时错删他人
// 新锁"的互斥失效链。

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"
)

// LockTTL 陈旧锁判定：持有超过该时长视为崩溃残留（可清理）。
// 60s：正常临界区毫秒级，留足挂起余量（休眠/慢盘）缩小"活锁被误判
// 陈旧"的窗口。
const LockTTL = 60 * time.Second

// LockWait 获取锁的最大等待时长。
const LockWait = 5 * time.Second

// 包内别名（兼容既有引用）。
const (
	stateLockTTL = LockTTL
	stateLockWait = LockWait
)

// lockSeq 本进程锁令牌序号（同 pid 同时刻多次持锁也唯一）。
var lockSeq atomic.Int64

// FileLock 获取跨进程文件锁（阻塞式重试）。返回释放函数；失败返回
// 错误（调用方按无锁降级处理——锁是防丢更新的优化，不是正确性前提）。
func FileLock(lockPath string) (func(), error) {
	token := fmt.Sprintf("pid=%d at=%s seq=%d\n", os.Getpid(), time.Now().UTC().Format(time.RFC3339Nano), lockSeq.Add(1))
	deadline := time.Now().Add(stateLockWait)
	for {
		f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
		if err == nil {
			_, werr := f.WriteString(token)
			f.Close()
			if werr != nil {
				os.Remove(lockPath) // 令牌未写入成功：不留无法归属的空锁
				return nil, fmt.Errorf("fsutil: 锁令牌写入失败: %w", werr)
			}
			return func() { FileUnlock(lockPath, token) }, nil
		}
		if !os.IsExist(err) {
			return nil, fmt.Errorf("fsutil: 创建文件锁失败: %w", err)
		}
		// 锁已存在：陈旧检测（崩溃残留清理）。只清理内容为合法锁记录
		// （pid= 前缀）或空文件（创建后未写入即崩溃）的陈旧锁——其他
		// 内容（误放的普通文件）不动，避免删除无关文件。
		if fi, serr := os.Stat(lockPath); serr == nil && time.Since(fi.ModTime()) > stateLockTTL {
			if data, rerr := os.ReadFile(lockPath); rerr == nil {
				content := strings.TrimSpace(string(data))
				if content == "" || strings.HasPrefix(content, "pid=") {
					os.Remove(lockPath) // 陈旧锁：删除重试（下一次循环）
				}
			}
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("fsutil: 文件锁等待超时（%s 被占用）", lockPath)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// FileUnlock 释放锁：仅当锁文件内容仍为本持锁者令牌时删除——锁已被
// 他人接管（陈旧清理后新建）时不动，防止错删他人锁导致互斥失效。
// 读失败（文件被并发删除等）不删除（留给 TTL 清理兜底）。
func FileUnlock(lockPath, token string) {
	data, err := os.ReadFile(lockPath)
	if err != nil {
		return
	}
	if strings.TrimSpace(string(data)) != strings.TrimSpace(token) {
		return // 非本持锁者的锁（已被接管）：不删除
	}
	os.Remove(lockPath)
}

// WithFileLock 持锁执行 fn（锁获取失败时直接执行——降级不阻塞）。
func WithFileLock(lockPath string, fn func() error) error {
	rel, err := FileLock(lockPath)
	if err != nil {
		return fn() // 无锁降级（竞争窗口极小，原子写兜底防半截）
	}
	defer rel()
	return fn()
}

// LockPathFor 状态文件对应的锁文件路径（同目录 .lock 后缀）。
func LockPathFor(stateFile string) string {
	return filepath.Join(filepath.Dir(stateFile), filepath.Base(stateFile)+".lock")
}
