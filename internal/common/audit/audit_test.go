package audit

import (
	"os"
	"runtime"
	"testing"
)

func TestIsToolError(t *testing.T) {
	cases := []struct {
		name    string
		content string
		want    bool
	}{
		{"守卫拦截", `{"error":"tool call blocked: ops 安全守卫: 高危命令"}`, true},
		{"执行失败", `{"error":"exit status 1"}`, true},
		{"带前导空白", "  {\"error\":\"x\"}  ", true},
		{"正常输出", "Filesystem 1K-blocks Used", false},
		{"正常 JSON 结果", `{"ok":true,"rows":3}`, false},
		{"空内容", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := IsToolError(c.content); got != c.want {
				t.Errorf("IsToolError(%q) = %v, want %v", c.content, got, c.want)
			}
		})
	}
}

// TestAuditFileMode600 审计含命令原文与参数，仅属主可读。
func TestAuditFileMode600(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows 不校验 POSIX 权限位")
	}
	dir := t.TempDir()
	a, err := NewAuditLog(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Write(AuditEvent{Kind: "tool", Tool: "terminal", Args: "uptime"}); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(a.Path())
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("审计文件应 0600，实际 %v", st.Mode().Perm())
	}
}

// TestSanitizeArgs 审计参数脱敏：URL 内嵌凭证、密码/令牌参数、认证头。
func TestSanitizeArgs(t *testing.T) {
	cases := []struct{ in, want string }{
		{"curl -u user:pass http://user:pass@example.com/x", "curl -u *** http://***@example.com/x"},
		{"mysql -uroot -psecret -e 'x'", "mysql -uroot -p *** -e 'x'"},
		{"psql --password=xxx db", "psql --password *** db"},
		{"curl -H 'Authorization: Bearer abc' https://x", "curl -H 'Authorization ***"},
		{"uptime", "uptime"},
	}
	for _, c := range cases {
		if got := SanitizeArgs(c.in); got != c.want {
			t.Errorf("SanitizeArgs(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
