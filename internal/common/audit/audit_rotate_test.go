package audit

// audit_rotate_test.go — P3 修复回归测试：审计日志大小轮转。

import (
	"os"
	"testing"
)

func TestAuditLog_RotatesAtSize(t *testing.T) {
	dir := t.TempDir()
	al, err := NewAuditLog(dir)
	if err != nil {
		t.Fatal(err)
	}
	path := al.Path()
	// 预写一个超阈值文件（模拟长跑进程的累积日志）。
	big := make([]byte, auditRotateSize+1024)
	if err := os.WriteFile(path, big, 0o600); err != nil {
		t.Fatal(err)
	}
	// 再写一条：触发轮转（当前文件 → .1，新文件承接本条）。
	if err := al.Write(AuditEvent{Kind: "guard", Tool: "terminal", Args: "uptime", Decision: "approved"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path + ".1"); err != nil {
		t.Fatalf("轮转文件应存在: %v", err)
	}
	// 新文件只含本条记录。
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) > 4096 {
		t.Fatalf("轮转后新文件应只含本条记录: %d 字节", len(data))
	}
}
