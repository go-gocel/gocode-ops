package workspace

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-gocel/gocode-ops/internal/common/fsutil"
	"github.com/go-gocel/gocode-ops/internal/common/model"
)

// 跨进程并行安全测试：同一工作目录双形态同时运行时的状态保护。

// TestAcquireStateLock_MutualExclusion 锁互斥：持锁期间第二次获取阻塞
// 直到释放（写临界区串行化）。
func TestAcquireStateLock_MutualExclusion(t *testing.T) {
	dir := t.TempDir()
	rel, err := acquireStateLock(dir)
	if err != nil {
		t.Fatal(err)
	}
	got := make(chan error, 1)
	go func() {
		_, err := acquireStateLock(dir)
		got <- err
	}()
	select {
	case err := <-got:
		t.Fatalf("持锁期间第二次获取不应成功: %v", err)
	case <-time.After(100 * time.Millisecond):
		// 正确阻塞
	}
	rel()
	select {
	case err := <-got:
		if err != nil {
			t.Fatalf("释放后应能获取: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("释放后获取超时")
	}
}

// TestAcquireStateLock_StaleRecovery 陈旧锁清理：崩溃残留（mtime 超龄）
// 自动删除重试。残留锁内容为真实持锁形态（pid= 记录）；非锁记录内容
// （误放的普通文件）不清理（见 TestAcquireStateLock_StaleForeignFile）。
func TestAcquireStateLock_StaleRecovery(t *testing.T) {
	dir := t.TempDir()
	lockPath := filepath.Join(dir, stateLockName)
	// 模拟崩溃残留：mtime 超龄的合法锁记录（pid= 前缀）。
	if err := os.WriteFile(lockPath, []byte("pid=99999 at=2000-01-01T00:00:00Z\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// 伪造陈旧 mtime（超过 fsutil.LockTTL）。
	old := time.Now().Add(-fsutil.LockTTL - time.Minute)
	if err := os.Chtimes(lockPath, old, old); err != nil {
		t.Fatal(err)
	}
	rel, err := acquireStateLock(dir)
	if err != nil {
		t.Fatalf("陈旧锁应被清理后获取: %v", err)
	}
	rel()
}

// TestAcquireStateLock_StaleForeignFile 非锁记录内容的陈旧文件不清理
// （避免误删用户误放的普通文件；锁获取超时如实返回）。
func TestAcquireStateLock_StaleForeignFile(t *testing.T) {
	dir := t.TempDir()
	lockPath := filepath.Join(dir, stateLockName)
	if err := os.WriteFile(lockPath, []byte("user note, not a lock\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-fsutil.LockTTL - time.Minute)
	if err := os.Chtimes(lockPath, old, old); err != nil {
		t.Fatal(err)
	}
	if _, err := acquireStateLock(dir); err == nil {
		t.Fatal("非锁记录内容的陈旧文件不应被清理获取")
	}
	// 文件未被删除。
	if data, err := os.ReadFile(lockPath); err != nil || string(data) != "user note, not a lock\n" {
		t.Fatalf("非锁记录文件不应被删除: %v %q", err, string(data))
	}
}

// TestReleaseStateLock_Ownership 释放归属校验：锁被他人接管（陈旧清理
// 后新建）时，原持锁者释放不得删除他人的新锁——互斥不能被"错删他人
// 锁"破坏。
func TestReleaseStateLock_Ownership(t *testing.T) {
	dir := t.TempDir()
	rel, err := acquireStateLock(dir)
	if err != nil {
		t.Fatal(err)
	}
	lockPath := filepath.Join(dir, stateLockName)
	// 模拟：原锁被另一进程按陈旧清理后接管（内容换成新持锁者令牌）。
	if err := os.WriteFile(lockPath, []byte("pid=88888 at=2030-01-01T00:00:00Z seq=1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	rel() // 原持锁者释放：不得删除他人的新锁
	if data, err := os.ReadFile(lockPath); err != nil || !strings.HasPrefix(string(data), "pid=88888") {
		t.Fatalf("他人锁不应被原持锁者释放删除: %v %q", err, string(data))
	}
	// 新持锁者正常释放自己的锁（fsutil.FileUnlock：归属一致才删除）。
	fsutil.FileUnlock(lockPath, "pid=88888 at=2030-01-01T00:00:00Z seq=1\n")
	if _, err := os.Stat(lockPath); !os.IsNotExist(err) {
		t.Fatalf("归属一致的释放应删除锁: %v", err)
	}
}

// TestAcquireStateLock_EmptyStale 创建后未写入即崩溃的空锁文件（mtime
// 超龄）同样可清理——不留无法归属的永久阻塞。
func TestAcquireStateLock_EmptyStale(t *testing.T) {
	dir := t.TempDir()
	lockPath := filepath.Join(dir, stateLockName)
	if err := os.WriteFile(lockPath, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-fsutil.LockTTL - time.Minute)
	if err := os.Chtimes(lockPath, old, old); err != nil {
		t.Fatal(err)
	}
	rel, err := acquireStateLock(dir)
	if err != nil {
		t.Fatalf("陈旧空锁应被清理后获取: %v", err)
	}
	rel()
}

// TestMergeDiskFindings_KeepsOtherProcessState 并行合并：磁盘上另一
// 进程（引擎）的处置状态（行为层）在本地落盘后保留；本地新发现追加。
func TestMergeDiskFindings_KeepsOtherProcessState(t *testing.T) {
	dir := t.TempDir()
	ws, err := NewWorkspace(dir)
	if err != nil {
		t.Fatal(err)
	}
	// 模拟引擎进程先写：suid_unowned 已 confirmed+处置（行为层），
	// svc_failed 已修复。
	eng := &Finding{Host: "web-01", Signal: "suid_unowned", Key: "/usr/bin/upd2",
		Status: FindingConfirmed, RootCause: "引擎确认的根因"}
	eng.ID = findingID(eng)
	eng.Disposition = &model.Disposition{Outcome: model.DispositionManualWorkOrder}
	eng.Actions = []model.Action{{Name: "a", Command: "chmod 000 /usr/bin/upd2", Auto: true, Verified: true}}
	fixed := &Finding{Host: "web-01", Signal: "svc_failed", Key: "nginx",
		Status: FindingConfirmed, Remediated: true}
	fixed.ID = findingID(fixed)
	if err := ws.AddFindings([]*Finding{eng, fixed}); err != nil {
		t.Fatal(err)
	}
	// 助手进程（新实例）加载同一工作区：只看到引擎写的状态。
	ws2, err := NewWorkspace(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(ws2.FindingList) != 2 {
		t.Fatalf("助手应加载引擎状态（2 条），got %d", len(ws2.FindingList))
	}
	// 助手新增发现（ssh_root_login pending）并落盘：走合并路径。
	dis := &Finding{Host: "web-01", Signal: "ssh_root_login", Key: "permitrootlogin",
		Status: FindingPending, Desc: "助手发现"}
	dis.ID = findingID(dis)
	if err := ws2.AddFindings([]*Finding{dis}); err != nil {
		t.Fatal(err)
	}
	// 引擎再加载（模拟引擎进程后续读）：3 条都在，引擎的处置状态未丢。
	ws3, err := NewWorkspace(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(ws3.FindingList) != 3 {
		t.Fatalf("合并后应 3 条（引擎2+助手1），got %d", len(ws3.FindingList))
	}
	byKey := map[string]*Finding{}
	for _, f := range ws3.FindingList {
		byKey[dedupKeyF(f)] = f
	}
	engGot := byKey[dedupKeyF(eng)]
	if engGot == nil || len(engGot.Actions) == 0 || engGot.RootCause != "引擎确认的根因" {
		t.Errorf("引擎处置状态应在合并后保留: %+v", engGot)
	}
	if !byKey[dedupKeyF(fixed)].Remediated {
		t.Error("引擎修复状态应在合并后保留")
	}
	if byKey[dedupKeyF(dis)] == nil {
		t.Error("助手新增发现应保留")
	}
}
