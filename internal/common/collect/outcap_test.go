package collect

import (
	"strings"
	"testing"
	"time"
)

// cappedBuffer 读取时截断：输出多大，内存只吃上限（OOM 根因修复）。

// TestCappedBuffer_TruncatesOversize 超限输出读取时截断。
func TestCappedBuffer_TruncatesOversize(t *testing.T) {
	cap := newCappedBuffer(8)
	big := strings.Repeat("x", 1024)
	if n, _ := cap.Write([]byte(big)); n != len(big) {
		t.Fatalf("Write 应返回全量长度（不阻塞上游）: %d", n)
	}
	if got := cap.String(); got != strings.Repeat("x", 8) {
		t.Errorf("应只收集上限内内容: %q", got)
	}
	if !cap.Truncated() {
		t.Error("应标记截断")
	}
}

// TestCappedBuffer_UnderLimit 未超限时原样收集。
func TestCappedBuffer_UnderLimit(t *testing.T) {
	cap := newCappedBuffer(64)
	small := "hello world"
	if _, err := cap.Write([]byte(small)); err != nil {
		t.Fatal(err)
	}
	if cap.String() != small {
		t.Errorf("未超限应原样收集: %q", cap.String())
	}
	if cap.Truncated() {
		t.Error("未超限不应标记截断")
	}
}

// TestCappedBuffer_Concurrent 并发写入安全（os/exec 的 stdout/stderr
// 双 goroutine 拷贝场景）。
func TestCappedBuffer_Concurrent(t *testing.T) {
	cap := newCappedBuffer(64 << 10)
	done := make(chan struct{}, 2)
	for i := 0; i < 2; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			for j := 0; j < 4000; j++ {
				cap.Write([]byte("0123456789abcdef"))
			}
		}()
	}
	<-done
	<-done
	if len(cap.String()) != 64<<10 {
		t.Errorf("并发写入后应恰好达到上限: %d", len(cap.String()))
	}
}

// TestExecLocal_CappedOversizeOutput 本地执行大输出命令不炸内存：
// 输出被读取时截断，返回上限内内容。
func TestExecLocal_CappedOversizeOutput(t *testing.T) {
	ctx := t.Context()
	out, err := ExecLocal(ctx, "head -c 2000000 /dev/zero | tr '\\0' 'x'", 10*1e9)
	if err != nil {
		t.Fatalf("execLocal: %v", err)
	}
	if len(out) > maxCollectOut {
		t.Errorf("输出应被截断到上限内: %d > %d", len(out), maxCollectOut)
	}
	if len(out) != maxCollectOut {
		t.Errorf("应恰好收集到上限: %d != %d", len(out), maxCollectOut)
	}
}

// TestExecLocal_TimeoutKillsHangingCommand 挂死的本地探针必须被 timeout
// 强制终止（此前 timeout 参数从未使用，NFS/journalctl 挂死会卡死整轮快检）。
func TestExecLocal_TimeoutKillsHangingCommand(t *testing.T) {
	ctx := t.Context()
	start := time.Now()
	out, err := ExecLocal(ctx, "sleep 30", 300*time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "超时") {
		t.Fatalf("挂死命令应超时报错: out=%q err=%v", out, err)
	}
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Fatalf("超时应在 timeout 附近生效，实际 %v", elapsed)
	}
}
