package audit

// audit_p2_test.go — P2 修复回归测试：脱敏补漏（API Key 头/env 凭证）。

import (
	"strings"
	"testing"
)

func TestSanitizeArgs_ApiKeyHeaderAndEnvSecrets(t *testing.T) {
	cases := []struct {
		in   string
		want string // 期望不包含的明文
	}{
		{`curl -H 'x-api-key: sk-abcdef123456' https://api.example.com`, "sk-abcdef123456"},
		{`curl -H 'X-Auth-Token: tok_987654' https://api.example.com/v1`, "tok_987654"},
		{`PGPASSWORD=supersecret psql -h db -c 'select 1'`, "supersecret"},
		{`MYSQL_PWD=hunter2 mysql -uroot -e 'show databases'`, "hunter2"},
		{`GITHUB_TOKEN=ghp_1234567890 gh release list`, "ghp_1234567890"},
		{`DATABASE_URL=postgres://user:pass@host:5432/db psql -c '\dt'`, "pass"},
	}
	for _, c := range cases {
		got := SanitizeArgs(c.in)
		if strings.Contains(got, c.want) {
			t.Errorf("脱敏漏掩 %q: %q → %q", c.want, c.in, got)
		}
	}
	// 变量名保留（排查可读），值掩掉。
	got := SanitizeArgs("PGPASSWORD=secret psql -c 'x'")
	if !strings.Contains(got, "PGPASSWORD") {
		t.Errorf("变量名应保留: %q", got)
	}
	if strings.Contains(got, "secret") {
		t.Errorf("env 凭证值应掩掉: %q", got)
	}
}
