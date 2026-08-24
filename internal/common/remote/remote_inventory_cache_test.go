package remote

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writeHostsYAML 写一个最简清单（names 为逗号分隔的别名）。
func writeHostsYAML(t *testing.T, p, names string) {
	t.Helper()
	var b strings.Builder
	b.WriteString("hosts:\n")
	for _, n := range strings.Split(names, ",") {
		b.WriteString("  - name: " + n + "\n")
		b.WriteString("    address: 10.0.0.1\n")
		b.WriteString("    user: root\n")
		b.WriteString("    key_file: /tmp/k\n")
	}
	if err := os.WriteFile(p, []byte(b.String()), 0o600); err != nil {
		t.Fatalf("写清单失败: %v", err)
	}
}

// TestLoadInventoryCache 验证 loadInventory 的 mtime 失效缓存：
// 同文件二次调用命中缓存（复用同一指针），改内容并推进 mtime 后自动重载。
func TestLoadInventoryCache(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "hosts.yaml")
	writeHostsYAML(t, p, "h1")

	ex := newSSHExecutor(RemoteConfig{InventoryPath: p})

	inv1, err := ex.loadInventory()
	if err != nil {
		t.Fatalf("首次加载失败: %v", err)
	}
	if len(inv1.Hosts) != 1 {
		t.Fatalf("期望 1 台主机, 实际 %d", len(inv1.Hosts))
	}
	if ex.invCache == nil {
		t.Fatal("期望清单缓存已填充")
	}

	// 同文件二次调用应命中缓存（返回同一指针，避免重读重解析）。
	inv2, err := ex.loadInventory()
	if err != nil {
		t.Fatalf("二次加载失败: %v", err)
	}
	if inv2 != inv1 {
		t.Fatal("同文件二次加载未命中缓存（应复用同一 *Inventory）")
	}

	// 改内容并推进 mtime → 必须重新加载出新内容。
	writeHostsYAML(t, p, "h1,h2")
	if err := os.Chtimes(p, time.Now().Add(time.Hour), time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("chtimes 失败: %v", err)
	}
	inv3, err := ex.loadInventory()
	if err != nil {
		t.Fatalf("重载失败: %v", err)
	}
	if len(inv3.Hosts) != 2 {
		t.Fatalf("期望重载出 2 台主机, 实际 %d", len(inv3.Hosts))
	}
	if inv3 == inv1 {
		t.Fatal("mtime 变更后未重新加载（仍返回旧缓存指针）")
	}
}
