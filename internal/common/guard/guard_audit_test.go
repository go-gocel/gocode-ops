package guard

// guard_audit_test.go — 守卫 × 审计联动测试（audit 包不反向依赖 guard，
// 联动测试留在守卫侧）。

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/go-gocel/gocode-ops/internal/common/audit"
)

// TestGuardRecord_ToolAndHosts 守卫审计记录真实工具名与目标主机。
func TestGuardRecord_ToolAndHosts(t *testing.T) {
	dir := t.TempDir()
	al, err := audit.NewAuditLog(dir)
	if err != nil {
		t.Fatal(err)
	}
	g := NewRiskyCommandGuard(nil, PolicyAuto)
	g.Audit = al
	if err := g.decide(t.Context(), "systemctl restart nginx", matchRiskyRule("systemctl restart nginx"), []string{"web-01", "db-01"}, "remote_batch"); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(al.Path())
	if err != nil {
		t.Fatal(err)
	}
	var ev audit.AuditEvent
	if err := json.Unmarshal([]byte(strings.TrimSpace(string(data))), &ev); err != nil {
		t.Fatal(err)
	}
	if ev.Tool != "remote_batch" {
		t.Errorf("Tool = %q, want remote_batch", ev.Tool)
	}
	if len(ev.Hosts) != 2 || ev.Hosts[0] != "web-01" {
		t.Errorf("Hosts = %v, want [web-01 db-01]", ev.Hosts)
	}
	if ev.Decision != "auto_allowed" {
		t.Errorf("Decision = %q, want auto_allowed", ev.Decision)
	}
}
