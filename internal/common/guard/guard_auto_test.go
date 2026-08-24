package guard

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-gocel/gocode-ops/internal/common/audit"
	"github.com/go-gocel/gocode-ops/internal/common/model"
)

// TestDecide_PolicyAuto 验证 auto 策略（命令风险审查 + 策略）：
// 常规变更命令自动放行（全自动自判合规）、命令风险审查拒绝（宕机类
// hard / 自身影响面）、放行与拒绝都留痕审计。
func TestDecide_PolicyAuto(t *testing.T) {
	g := NewRiskyCommandGuard(nil, PolicyAuto)

	// 常规变更面：未登记白名单也放行（auto 即自动审查风险、自行判断合规）。
	cmd := "systemctl restart nginx"
	if err := g.decide(context.Background(), cmd, matchRiskyRule(cmd), nil, "terminal"); err != nil {
		t.Fatalf("auto 下常规变更命令应放行: %v", err)
	}
	// 只读命令：天然放行。
	if err := g.decide(context.Background(), "df -h", nil, nil, "terminal"); err != nil {
		t.Fatalf("只读命令应放行: %v", err)
	}
	// 宕机类（目标危害面）：永远拒绝（硬性禁止）。
	if err := g.decide(context.Background(), "rm -rf /", matchRiskyRule("rm -rf /"), nil, "terminal"); err == nil {
		t.Fatal("宕机类命令必须拒绝")
	}
	if err := g.decide(context.Background(), "reboot", matchRiskyRule("reboot"), nil, "terminal"); err == nil {
		t.Fatal("重启/关机类命令必须拒绝")
	}
	// 自身影响面：断自身 SSH 通道的命令拒绝（无需白名单，策略不可调节）。
	impact := "sed -i 's/^PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config && systemctl reload sshd"
	if err := g.decide(context.Background(), impact, matchRiskyRule(impact), []string{"web-01"}, "terminal"); err == nil {
		t.Fatal("自断通道命令必须拒绝")
	}
	// 凭证面：读 shadow 拒绝（硬性禁止）。
	if err := g.decide(context.Background(), "cat /etc/shadow", matchRiskyRule("cat /etc/shadow"), nil, "terminal"); err == nil {
		t.Fatal("读取凭证必须拒绝")
	}
}

// TestDecide_PolicyAutoImpactNeedsFacts 自身影响面的对称例外依赖连接事实：
// 密钥登录时仅禁密码认证 → 通道保留 → 放行；无连接事实（保守）→ 拒绝。
func TestDecide_PolicyAutoImpactNeedsFacts(t *testing.T) {
	cmd := "sed -i 's/^PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config"
	// 保守模式（无 ConnFacts 注入）：拒绝。
	g := NewRiskyCommandGuard(nil, PolicyAuto)
	if err := g.decide(context.Background(), cmd, matchRiskyRule(cmd), []string{"web-01"}, "terminal"); err == nil {
		t.Fatal("无连接事实时自断通道命令必须拒绝（保守）")
	}
	// 注入连接事实：密钥认证 → 仅禁密码 → 放行。
	g2 := NewRiskyCommandGuard(nil, PolicyAuto)
	g2.ConnFacts = func(aliases []string) map[string]model.ConnFact {
		return map[string]model.ConnFact{"web-01": {Host: "web-01", User: "root", Auth: "key", Port: "22"}}
	}
	if err := g2.decide(context.Background(), cmd, matchRiskyRule(cmd), []string{"web-01"}, "terminal"); err != nil {
		t.Fatalf("密钥认证时仅禁密码应放行: %v", err)
	}
	// 密码认证 + 禁密码 → 拒绝。
	g3 := NewRiskyCommandGuard(nil, PolicyAuto)
	g3.ConnFacts = func(aliases []string) map[string]model.ConnFact {
		return map[string]model.ConnFact{"web-01": {Host: "web-01", User: "root", Auth: "password", Port: "22"}}
	}
	if err := g3.decide(context.Background(), cmd, matchRiskyRule(cmd), []string{"web-01"}, "terminal"); err == nil {
		t.Fatal("密码认证时禁密码必须拒绝")
	}
}

// TestDecide_PolicyAutoKeyLoginNoRoot 密钥登录 + PermitRootLogin no（root）
// → 仍拒绝：no 完全禁止 root 登录，密钥也失效。
func TestDecide_PolicyAutoKeyLoginNoRoot(t *testing.T) {
	cmd := "sed -i 's/^PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config && systemctl reload sshd"
	g := NewRiskyCommandGuard(nil, PolicyAuto)
	g.ConnFacts = func(aliases []string) map[string]model.ConnFact {
		return map[string]model.ConnFact{"web-01": {Host: "web-01", User: "root", Auth: "key", Port: "22"}}
	}
	if err := g.decide(context.Background(), cmd, matchRiskyRule(cmd), []string{"web-01"}, "terminal"); err == nil {
		t.Fatal("PermitRootLogin no 即使密钥认证也必须拒绝")
	}
}

// readAuditFile 读取审计文件内容（测试辅助）。
func readAuditFile(dir string) (string, error) {
	data, err := os.ReadFile(filepath.Join(model.ConfigDir(dir), audit.AuditFileName))
	return string(data), err
}

// TestDecide_PolicyAutoAudit 验证 auto 决策写入审计（决策理由留痕）。
func TestDecide_PolicyAutoAudit(t *testing.T) {
	dir := t.TempDir()
	al, err := audit.NewAuditLog(dir)
	if err != nil {
		t.Fatal(err)
	}
	g := NewRiskyCommandGuard(nil, PolicyAuto)
	g.Audit = al

	// 常规变更 → auto_allowed 留痕。
	cmd := "systemctl restart nginx"
	if err := g.decide(context.Background(), cmd, matchRiskyRule(cmd), nil, "terminal"); err != nil {
		t.Fatalf("auto 放行失败: %v", err)
	}
	data, err := readAuditFile(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(data, "auto_allowed") || !strings.Contains(data, cmd) {
		t.Errorf("审计应记录 auto_allowed 决策: %s", data)
	}

	// 命令风险审查拒绝也留痕（hard_blocked）。
	if err := g.decide(context.Background(), "reboot", matchRiskyRule("reboot"), nil, "terminal"); err == nil {
		t.Fatal("reboot 应被命令风险审查拒绝")
	}
	data, _ = readAuditFile(dir)
	if !strings.Contains(data, "hard_blocked") || !strings.Contains(data, "reboot") {
		t.Errorf("审计应记录 hard_blocked 决策: %s", data)
	}
}
