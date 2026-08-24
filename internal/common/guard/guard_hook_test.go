package guard

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/go-gocel/gocel-core/core/kernel"
)

// guard_hook_test.go — 守卫工具钩子白盒测试（remote_* 工具的拦截/放行）。

func TestGuard_RemoteBatchHook(t *testing.T) {
	g := NewRiskyCommandGuard(&fakeOperator{answers: []string{"n"}}, PolicyAsk)
	args, _ := json.Marshal(map[string]any{
		"hosts":   []string{"web-01"},
		"command": "systemctl restart nginx",
	})
	info := &kernel.ToolCallInfo{Name: "remote_batch", Args: string(args)}
	if _, _, err := g.onToolCall(context.Background(), info); err == nil {
		t.Error("remote_batch 高危命令应被钩子拦截")
	}
	// 只读远端命令放行
	args, _ = json.Marshal(map[string]any{
		"hosts":   []string{"web-01"},
		"command": "uptime",
	})
	info = &kernel.ToolCallInfo{Name: "remote_batch", Args: string(args)}
	if _, _, err := g.onToolCall(context.Background(), info); err != nil {
		t.Errorf("远端只读命令不应被拦截: %v", err)
	}
}

func TestGuard_RemoteTransferHook(t *testing.T) {
	g := NewRiskyCommandGuard(nil, PolicyDeny)
	for _, tc := range []struct {
		tool string
		args string
	}{
		{"remote_upload", `{"hosts":["web-01"],"local_path":"k","remote_path":"~/.ssh/authorized_keys"}`},
		{"remote_download", `{"hosts":["web-01"],"remote_path":"/root/.ssh/id_rsa"}`},
	} {
		info := &kernel.ToolCallInfo{Name: tc.tool, Args: tc.args}
		if _, _, err := g.onToolCall(context.Background(), info); err == nil {
			t.Errorf("%s 触碰凭证路径应被钩子拦截: %s", tc.tool, tc.args)
		}
	}
	// 普通路径放行
	info := &kernel.ToolCallInfo{Name: "remote_upload", Args: `{"hosts":["web-01"],"local_path":"app.tar","remote_path":"/opt/app.tar"}`}
	if _, _, err := g.onToolCall(context.Background(), info); err != nil {
		t.Errorf("普通上传不应被拦截: %v", err)
	}
}

func TestGuard_BlocksCredentialExposure(t *testing.T) {
	// 模型自建 ssh 连接 / 读取凭证 / 明文密码：全部硬性禁止
	blocked := []string{
		"ssh root@10.0.0.11 uptime",
		"scp x.tar web-01:/tmp/",
		"sshpass -p secret ssh root@x uptime",
		"cat /etc/shadow",
		"cat ~/.ssh/id_rsa",
		"tail -n 5 /root/.ssh/id_ed25519",
		"grep -r key /root/.gocode/",
		"cat /etc/nginx/ssl/server.key",
		"mysql -uroot -psecret",
		"redis-cli -asecret get x",
		"curl http://user:pass@example.com/",
		"scp ~/.ssh/id_rsa /tmp/backup",
		"cat /var/lib/mysql/.my.cnf",
	}
	for _, c := range blocked {
		rule := matchRiskyRule(c)
		if rule == nil || !rule.hard {
			t.Errorf("凭证命令应被硬性禁止：%q（命中 %v）", c, rule)
		}
	}

	// 合法命令不受影响
	safe := []string{
		"ssh-keygen -t ed25519 -f /tmp/testkey", // 生成新密钥到工作目录，不触碰现有凭证
		"psql -p5432 -c 'select 1'",             // -p 后接端口不算明文密码
		"cat /etc/nginx/nginx.conf",
		"grep -r error /var/log",
		"ls /root",
		"uptime",
	}
	for _, c := range safe {
		if rule := matchRiskyRule(c); rule != nil {
			t.Errorf("安全命令 %q 不应命中规则，实际 %s", c, rule.name)
		}
	}
}

func TestGuard_BlocksCredentialReadTool(t *testing.T) {
	g := NewRiskyCommandGuard(nil, PolicyDeny)
	for _, tc := range []struct {
		tool string
		args string
	}{
		{"read", `{"path":"/root/.ssh/id_rsa"}`},
		{"read", `{"path":"~/.gocode/hosts.yaml"}`},
		{"grep", `{"pattern":"password","path":"/etc/shadow"}`},
		{"read", `{"path":"/home/ops/.my.cnf"}`},
	} {
		info := &kernel.ToolCallInfo{Name: tc.tool, Args: tc.args}
		if _, _, err := g.onToolCall(context.Background(), info); err == nil {
			t.Errorf("%s(%s) 应被凭证守卫拦截", tc.tool, tc.args)
		}
	}
	// 普通路径不受影响
	info := &kernel.ToolCallInfo{Name: "read", Args: `{"path":"/etc/nginx/nginx.conf"}`}
	if _, _, err := g.onToolCall(context.Background(), info); err != nil {
		t.Errorf("普通读取不应被拦截: %v", err)
	}
}

func TestGuard_RemoteTerminalHook(t *testing.T) {
	g := NewRiskyCommandGuard(&fakeOperator{answers: []string{"n"}}, PolicyAsk)
	args, _ := json.Marshal(map[string]any{
		"host":    "web-01",
		"command": "systemctl restart nginx",
	})
	info := &kernel.ToolCallInfo{Name: "remote_terminal", Args: string(args)}
	if _, _, err := g.onToolCall(context.Background(), info); err == nil {
		t.Error("remote_terminal 高危命令应被钩子拦截")
	}
	// 只读远端命令放行
	args, _ = json.Marshal(map[string]any{
		"host":    "web-01",
		"command": "uptime",
	})
	info = &kernel.ToolCallInfo{Name: "remote_terminal", Args: string(args)}
	if _, _, err := g.onToolCall(context.Background(), info); err != nil {
		t.Errorf("远端只读命令不应被拦截: %v", err)
	}
}
