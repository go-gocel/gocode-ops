package remediate

import "testing"

// 业务面校验纯函数测试：等保收窄不得锁死业务流量。

func TestParseBusinessPorts(t *testing.T) {
	raw := "80|httpd\n443|httpd\n3306|mysqld\nbad-line\n|noname\n  6379|redis-server  \n"
	m := ParseBusinessPorts(raw)
	if len(m) != 4 {
		t.Fatalf("应解析 4 条，got %d: %v", len(m), m)
	}
	if m["80"] != "httpd" || m["3306"] != "mysqld" || m["6379"] != "redis-server" {
		t.Errorf("解析错误: %v", m)
	}
	if _, ok := m["bad-line"]; ok {
		t.Error("畸形行不应解析")
	}
}

func TestBusinessDiff_TargetPortGoneIsExpected(t *testing.T) {
	before := map[string]string{"4444": "python", "80": "httpd", "3306": "mysqld"}
	after := map[string]string{"80": "httpd", "3306": "mysqld"}
	// 处置命令 kill 后门进程（4444）：消失属预期。
	cmds := []string{"pkill -f 'SimpleHTTPServer 4444'", "rm -f /tmp/backdoor"}
	if lost := BusinessDiff(before, after, cmds); len(lost) != 0 {
		t.Fatalf("处置目标端口消失应属预期，got %v", lost)
	}
}

func TestBusinessDiff_NonTargetLostIsAccident(t *testing.T) {
	before := map[string]string{"80": "httpd", "443": "httpd", "3306": "mysqld"}
	after := map[string]string{} // 业务端口全消失（等保收窄锁死业务）
	// 处置命令只针对 sshd/防火墙默认策略——80/443/3306 均非目标。
	cmds := []string{"iptables -A INPUT -s 192.168.1.9 -p tcp --dport 22 -j ACCEPT", "iptables -A INPUT -j DROP"}
	lost := BusinessDiff(before, after, cmds)
	if len(lost) != 3 {
		t.Fatalf("非目标业务端口消失应判事故（3 个），got %v", lost)
	}
}

func TestBusinessDiff_NoChangeOK(t *testing.T) {
	before := map[string]string{"80": "httpd"}
	after := map[string]string{"80": "httpd"}
	if lost := BusinessDiff(before, after, nil); len(lost) != 0 {
		t.Fatalf("无变化不应有事故，got %v", lost)
	}
}

func TestBusinessDiff_NewPortNotChecked(t *testing.T) {
	// 处置新增监听（如引擎自建服务）不影响校验：只查"消失"。
	before := map[string]string{"80": "httpd"}
	after := map[string]string{"80": "httpd", "9090": "agent"}
	if lost := BusinessDiff(before, after, nil); len(lost) != 0 {
		t.Fatalf("新增端口不应触发，got %v", lost)
	}
}

func TestBusinessDiff_PortTokenNoFalseMatch(t *testing.T) {
	// 命令含 "8080" 不应误判为针对 "80"（\b 边界）；含 "80" token 才算。
	before := map[string]string{"80": "httpd"}
	after := map[string]string{}
	if lost := BusinessDiff(before, after, []string{"kill -9 8080"}); len(lost) != 1 {
		t.Fatalf("8080 不应匹配端口 80（事故应保留），got %v", lost)
	}
	if lost := BusinessDiff(before, after, []string{"fuser -k 80/tcp"}); len(lost) != 0 {
		t.Fatalf("80 token 应判为处置目标，got %v", lost)
	}
}

func TestBusinessDiff_ProcNameMatch(t *testing.T) {
	// 进程名子串匹配（kill httpd 进程 → 80/443 消失属预期）。
	before := map[string]string{"80": "httpd", "443": "httpd", "3306": "mysqld"}
	after := map[string]string{"3306": "mysqld"}
	if lost := BusinessDiff(before, after, []string{"pkill httpd"}); len(lost) != 0 {
		t.Fatalf("kill 进程名匹配应判处置目标，got %v", lost)
	}
}
