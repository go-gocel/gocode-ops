package remote

// remote_p2_test.go — P2 修复回归测试：resolveHosts 去重、UTF-8 截断。

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func validUTF8(s string) bool { return utf8.ValidString(s) }

func TestResolveHosts_Dedup(t *testing.T) {
	ex := &sshExecutor{}
	inv := &Inventory{Hosts: []Host{
		{Name: "web-01", Address: "10.0.0.1", User: "root"},
		{Name: "db-01", Address: "10.0.0.2", User: "root"},
		{Name: "app-01", Address: "10.0.0.3", User: "root"},
	}}
	// ["all"] 中已含的主机再显式列出：不得重复执行。
	hosts, err := ex.resolveHosts(inv, []string{"all", "web-01", "web-01", "db-01"})
	if err != nil {
		t.Fatal(err)
	}
	if len(hosts) != 3 {
		t.Fatalf("应去重为 3 台: %d", len(hosts))
	}
	seen := map[string]bool{}
	for _, h := range hosts {
		if seen[h.Name] {
			t.Fatalf("重复主机 %s", h.Name)
		}
		seen[h.Name] = true
	}
}

func TestTruncateHeadTail_UTF8Safe(t *testing.T) {
	// 中文内容截断边界：不得切裂多字节字符。
	s := strings.Repeat("运维日志内容", 100) // 600 字节
	got := truncateHeadTail(s, 100)
	if !strings.Contains(got, "…（输出过长") {
		t.Fatalf("应含省略提示: %q", got[:40])
	}
	if !validUTF8(got) {
		t.Fatal("截断结果含非法 UTF-8")
	}
	// 短输出不截断。
	if truncateHeadTail("abc", 100) != "abc" {
		t.Fatal("短输出不应截断")
	}
}
