package collect

import (
	"bytes"
	"sync"
)

// cappedBuffer 读取时截断的输出收集器（内存保护的统一机制）。
//
// 根因：命令输出曾"全量收集后截断"（execLocal 的 CombinedOutput、
// 远程 io.Copy）——任何大输出命令（cat 大文件、无 head 的 find/du、
// 巨型日志）都会把整个输出读进内存后才截断，内存随输出线性增长，
// OOM 由输出大小决定而不是由代码决定。
//
// 修复：截断发生在读取时——超过上限即丢弃后续字节（进程继续运行，
// 输出被截断）。命令输出多大，内存只吃上限。
//
// 线程安全：Stdout/Stderr 由 os/exec 内部并发拷贝，Write 加锁。
type cappedBuffer struct {
	mu        sync.Mutex
	buf       bytes.Buffer
	remaining int // 剩余可收集字节
	truncated bool
}

// newCappedBuffer 创建上限为 limit 字节的收集器。
func newCappedBuffer(limit int) *cappedBuffer {
	return &cappedBuffer{remaining: limit}
}

// Write collects up to the configured byte limit from p and discards the rest without blocking the writer.
// Write 收集 p 的前 remaining 字节，超出部分丢弃（不阻塞上游）。
// 返回 len(p)（模拟全量写入）——io.Copy 等调用方不因截断而报错。
func (c *cappedBuffer) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.remaining <= 0 {
		c.truncated = true
		return len(p), nil
	}
	n := len(p)
	if n > c.remaining {
		n = c.remaining
	}
	c.buf.Write(p[:n])
	c.remaining -= n
	if n < len(p) {
		c.truncated = true
	}
	return len(p), nil
}

// String returns the content collected so far.
// String 返回已收集的内容。
func (c *cappedBuffer) String() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.String()
}

// Truncated reports whether truncation has occurred during collection (used to diagnose large-output commands).
// Truncated 是否发生过截断（诊断大输出命令用）。
func (c *cappedBuffer) Truncated() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.truncated
}
