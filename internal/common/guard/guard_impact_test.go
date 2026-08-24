package guard

import (
	"context"
	"testing"

	"github.com/go-gocel/gocode-ops/internal/common/model"
)

// 自身影响面（命令风险审查子集）规则测试：断自身通道/毁工具链的命令
// 拒绝并给建议；保留通道的收紧与常规运维命令放行。

// passwordFacts / keyFacts 两种典型连接事实。
func passwordFacts() map[string]model.ConnFact {
	return map[string]model.ConnFact{"web-01": {Host: "web-01", User: "root", Auth: "password", Port: "22"}}
}
func keyFacts() map[string]model.ConnFact {
	return map[string]model.ConnFact{"web-01": {Host: "web-01", User: "root", Auth: "key", Port: "22"}}
}

// TestImpact_ChannelAuthRepair 认证面修复分级（迭代 5）：sed 把禁用
// 改写为启用（恢复被投毒配置）→ 净效果启用，放行；禁用形态在后（后写
// 覆盖先写）→ 拒绝。
func TestImpact_ChannelAuthRepair(t *testing.T) {
	allowed := []struct {
		cmd   string
		facts map[string]model.ConnFact
		why   string
	}{
		{"sed -i 's/^PermitRootLogin no/PermitRootLogin yes/' /etc/ssh/sshd_config && systemctl reload sshd", passwordFacts(), "恢复 root 登录（投毒修复）"},
		{"sed -i 's/^PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config", passwordFacts(), "恢复密码认证（投毒修复）"},
		{"sed -i 's/^PubkeyAuthentication no/PubkeyAuthentication yes/' /etc/ssh/sshd_config && systemctl reload sshd", keyFacts(), "恢复密钥认证（投毒修复）"},
		{"sed -i -e 's/^PermitRootLogin no/PermitRootLogin yes/' -e 's/^PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config", passwordFacts(), "多指令同方向修复"},
	}
	for _, c := range allowed {
		if v := reviewCommandRisk(c.cmd, c.facts); v != nil {
			t.Errorf("[%s] 修复面不应命中: %q → %s/%s", c.why, c.cmd, v.Face, v.Category)
		}
	}
	blocked := []struct {
		cmd   string
		facts map[string]model.ConnFact
		why   string
	}{
		{"sed -i 's/^PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config && echo 'PasswordAuthentication no' >> /etc/ssh/sshd_config.d/harden.conf", passwordFacts(), "后写禁用覆盖先写启用"},
		{"echo 'PasswordAuthentication yes' > /tmp/x; sed -i 's/^PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config", passwordFacts(), "净效果禁用（替换侧为 no）"},
	}
	for _, c := range blocked {
		if v := reviewCommandRisk(c.cmd, c.facts); v == nil {
			t.Errorf("[%s] 应命中认证面: %q", c.why, c.cmd)
		} else if v.Category != impactChannelAuth {
			t.Errorf("[%s] %q → %s，期望 channel-auth", c.why, c.cmd, v.Category)
		}
	}
}

// TestImpact_ChannelAuthBlocked 认证面：禁用当前登录方式 → 拒绝。
func TestImpact_ChannelAuthBlocked(t *testing.T) {
	cases := []struct {
		cmd   string
		facts map[string]model.ConnFact
		why   string
	}{
		{"sed -i 's/^PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config && systemctl reload sshd", passwordFacts(), "密码登录 + 禁 root"},
		{"sed -i 's/^PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config && systemctl reload sshd", keyFacts(), "密钥登录 + PermitRootLogin no 仍完全禁 root"},
		{"sed -i 's/^#*PasswordAuthentication .*/PasswordAuthentication no/' /etc/ssh/sshd_config", passwordFacts(), "密码登录 + 禁密码认证"},
		{"sed -i 's/^#*PubkeyAuthentication .*/PubkeyAuthentication no/' /etc/ssh/sshd_config", keyFacts(), "密钥登录 + 禁密钥认证"},
		{"echo 'PasswordAuthentication no' >> /etc/ssh/sshd_config.d/harden.conf", passwordFacts(), "追加禁用密码"},
		{"tee /etc/ssh/sshd_config.d/harden.conf <<< 'PermitRootLogin no'", passwordFacts(), "tee 写禁用 root"},
		{"sed -i 's/^PermitRootLogin yes/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config", passwordFacts(), "密码登录 + 只留密钥通道"},
	}
	for _, c := range cases {
		if v := reviewCommandRisk(c.cmd, c.facts); v == nil {
			t.Errorf("[%s] 应命中自身影响面: %q", c.why, c.cmd)
		} else if v.Face != riskFaceSelfImpact || v.Category != impactChannelAuth {
			t.Errorf("[%s] 应为 channel-auth: %q → %s/%s", c.why, c.cmd, v.Face, v.Category)
		}
	}
}

// TestImpact_ChannelPort 通道面：修改 sshd 监听端口（净效果非当前
// 管理端口）→ 拒绝；改回/保持当前端口（修复面）→ 放行。
func TestImpact_ChannelPort(t *testing.T) {
	blocked := []struct {
		cmd   string
		facts map[string]model.ConnFact
		why   string
	}{
		{"sed -i 's/^Port 22/Port 2222/' /etc/ssh/sshd_config && systemctl reload sshd", passwordFacts(), "改监听端口"},
		{"sed -i 's/^#Port 22/Port 2222/' /etc/ssh/sshd_config", passwordFacts(), "取消注释并改端口"},
		{"echo 'Port 2222' >> /etc/ssh/sshd_config.d/port.conf", passwordFacts(), "追加改端口"},
		{"sed -i 's/^Port 2222/Port 22/' /etc/ssh/sshd_config", port2222Facts(), "从 2222 改回 22（引擎连 2222 会被切断）"},
	}
	for _, c := range blocked {
		if v := reviewCommandRisk(c.cmd, c.facts); v == nil {
			t.Errorf("[%s] 应命中端口面: %q", c.why, c.cmd)
		} else if v.Category != impactChannelPort {
			t.Errorf("[%s] %q → %s，期望 channel-port", c.why, c.cmd, v.Category)
		}
	}
	allowed := []struct {
		cmd   string
		facts map[string]model.ConnFact
		why   string
	}{
		{"sed -i 's/^Port 2222/Port 22/' /etc/ssh/sshd_config", passwordFacts(), "改回当前管理端口（修复面）"},
		{"sed -i 's/^Port 22/Port 22/' /etc/ssh/sshd_config", passwordFacts(), "保持当前端口（无净变化）"},
		{"sed -i 's/^Port 22/Port 2222/' /etc/nginx/nginx.conf", passwordFacts(), "改 nginx 端口（非 sshd 配置）"},
		{"grep -E '^Port' /etc/ssh/sshd_config", passwordFacts(), "只读查询"},
		{"echo '#Port 22' >> /etc/ssh/sshd_config.d/port.conf", passwordFacts(), "追加注释行（无净效果）"},
	}
	for _, c := range allowed {
		if v := reviewCommandRisk(c.cmd, c.facts); v != nil {
			t.Errorf("[%s] 不应命中: %q → %s/%s", c.why, c.cmd, v.Face, v.Category)
		}
	}
}

func port2222Facts() map[string]model.ConnFact {
	return map[string]model.ConnFact{"web-01": {Host: "web-01", User: "root", Auth: "password", Port: "2222"}}
}

// TestImpact_ChannelAuthAllow 认证面对称例外：禁用的恰好不是当前认证
// 方式 → 放行；未写 sshd 配置（只读查询）→ 放行。
func TestImpact_ChannelAuthAllow(t *testing.T) {
	cases := []struct {
		cmd   string
		facts map[string]model.ConnFact
		why   string
	}{
		{"sed -i 's/^PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config", keyFacts(), "密钥登录 + 仅禁密码"},
		{"sed -i 's/^PubkeyAuthentication yes/PubkeyAuthentication no/' /etc/ssh/sshd_config", passwordFacts(), "密码登录 + 仅禁密钥"},
		{"grep -E '^(PermitRootLogin|PasswordAuthentication)' /etc/ssh/sshd_config", passwordFacts(), "只读查询"},
		{"sed -i 's/^PermitRootLogin yes/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config", keyFacts(), "密钥登录 + prohibit-password 保留密钥"},
		{"systemctl reload sshd", passwordFacts(), "仅 reload 不改认证"},
	}
	for _, c := range cases {
		if v := reviewCommandRisk(c.cmd, c.facts); v != nil {
			t.Errorf("[%s] 不应命中: %q → %s", c.why, c.cmd, v.Category)
		}
	}
}

// TestImpact_ChannelServiceBlocked 服务面：停用/杀 sshd → 拒绝。
func TestImpact_ChannelServiceBlocked(t *testing.T) {
	cases := []string{
		"systemctl stop sshd",
		"systemctl stop sshd.service",
		"systemctl disable sshd",
		"systemctl mask sshd",
		"service ssh stop",
		"service sshd kill",
		"pkill sshd",
		"killall sshd",
	}
	for _, c := range cases {
		if v := reviewCommandRisk(c, passwordFacts()); v == nil {
			t.Errorf("应命中服务面: %q", c)
		} else if v.Category != impactChannelService {
			t.Errorf("%q → %s，期望 channel-service", c, v.Category)
		}
	}
}

// TestImpact_ChannelServiceAllow 服务面放行：常规服务管理不受影响。
func TestImpact_ChannelServiceAllow(t *testing.T) {
	cases := []string{
		"systemctl stop nginx",
		"systemctl restart sshd",
		"systemctl reload sshd",
		"systemctl enable nginx",
	}
	for _, c := range cases {
		if v := reviewCommandRisk(c, passwordFacts()); v != nil {
			t.Errorf("不应命中服务面: %q → %s", c, v.Category)
		}
	}
}

// TestImpact_ChannelFirewallBlocked 防火墙面：阻断管理端口 → 拒绝。
func TestImpact_ChannelFirewallBlocked(t *testing.T) {
	cases := []struct {
		cmd   string
		facts map[string]model.ConnFact
	}{
		{"iptables -A INPUT -p tcp --dport 22 -j DROP", passwordFacts()},
		{"iptables -I INPUT -p tcp --dport 22 -j REJECT", passwordFacts()},
		{"ufw deny 22", passwordFacts()},
		{"ufw deny ssh", passwordFacts()},
		{"firewall-cmd --permanent --remove-service=ssh", passwordFacts()},
		{"iptables -P INPUT DROP", passwordFacts()},
		{"nft add rule inet filter input tcp dport 22 drop", passwordFacts()},
	}
	for _, c := range cases {
		if v := reviewCommandRisk(c.cmd, c.facts); v == nil {
			t.Errorf("应命中防火墙面: %q", c.cmd)
		} else if v.Category != impactChannelFirewall {
			t.Errorf("%q → %s，期望 channel-firewall", c.cmd, v.Category)
		}
	}
}

// TestImpact_ChannelFirewallRepair 防火墙面修复分级（迭代 5）：删除
// 阻断规则（iptables -D / nft delete rule / ufw delete deny）→ 放行。
func TestImpact_ChannelFirewallRepair(t *testing.T) {
	cases := []string{
		"iptables -D INPUT -p tcp --dport 22 -j DROP",
		"iptables -t filter -D INPUT -p tcp --dport 22 -j REJECT",
		"nft delete rule inet filter input tcp dport 22 drop",
		"ufw delete deny 22",
	}
	for _, c := range cases {
		if v := reviewCommandRisk(c, passwordFacts()); v != nil {
			t.Errorf("删除阻断规则应放行: %q → %s/%s", c, v.Face, v.Category)
		}
	}
}

// TestImpact_ChannelFirewallAllow 防火墙面放行：放行规则与只读查询。
func TestImpact_ChannelFirewallAllow(t *testing.T) {
	cases := []string{
		"iptables -L -n",
		"iptables -A INPUT -p tcp --dport 22 -j ACCEPT",
		"ufw allow 22",
		"firewall-cmd --list-all",
		"ufw status",
	}
	for _, c := range cases {
		if v := reviewCommandRisk(c, passwordFacts()); v != nil {
			t.Errorf("不应命中防火墙面: %q → %s", c, v.Category)
		}
	}
}

// TestImpact_ChannelFirewallNarrowAll 全入站收窄（无来源限定）→ 拒绝：
// "只放行引擎 IP + 全入站 DROP"的收窄会锁死其他合法来源与业务端口，
// 自通道校验只能验引擎自身来源（历史实测事故场景）。
func TestImpact_ChannelFirewallNarrowAll(t *testing.T) {
	cases := []string{
		"iptables -A INPUT -j DROP",
		"iptables -I INPUT -j REJECT",
		"iptables -A INPUT -p tcp -j DROP",
		"iptables -A INPUT -s 0.0.0.0/0 -j DROP", // 伪来源限定 = 全入站
		"iptables -A INPUT -s 0.0.0.0 -j DROP",
		"iptables -A INPUT -s any -j DROP",
		"ufw default deny incoming",
		"nft add rule inet filter input drop",
		"firewall-cmd --permanent --set-default-zone=drop", // firewalld 默认拒绝
		"firewall-cmd --permanent --set-default-zone=deny",
	}
	for _, c := range cases {
		if v := reviewCommandRisk(c, passwordFacts()); v == nil {
			t.Errorf("全入站收窄应命中 channel-firewall: %q", c)
		} else if v.Category != impactChannelFirewall {
			t.Errorf("%q → %s，期望 channel-firewall", c, v.Category)
		}
	}
}

// TestImpact_ChannelFirewallBlockSource 带来源限定的 DROP（封禁攻击源）
// → 放行（修复面）；但封禁引擎管理端口的来源仍拒绝。
func TestImpact_ChannelFirewallBlockSource(t *testing.T) {
	allow := []string{
		"iptables -A INPUT -s 1.2.3.4 -j DROP",
		"iptables -A INPUT -s 1.2.3.4 -p tcp --dport 80 -j REJECT",
		"nft add rule ip filter INPUT ip saddr 1.2.3.4 drop",
	}
	for _, c := range allow {
		if v := reviewCommandRisk(c, passwordFacts()); v != nil {
			t.Errorf("封禁攻击源应放行: %q → %s/%s", c, v.Face, v.Category)
		}
	}
	// 来源封禁命中管理端口：仍是断通道（引擎来源被禁）。
	for _, c := range []string{
		"iptables -A INPUT -s 1.2.3.4 -p tcp --dport 22 -j DROP",
	} {
		if v := reviewCommandRisk(c, passwordFacts()); v == nil {
			t.Errorf("封禁引擎管理端口来源应命中: %q", c)
		}
	}
}

// TestImpact_ChannelNetworkBlocked 网络面：断开接口/连接 → 拒绝。
func TestImpact_ChannelNetworkBlocked(t *testing.T) {
	cases := []string{
		"ip link set eth0 down",
		"ifdown eth0",
		"nmcli device disconnect eth0",
		"nmcli connection down Wired",
		"ip addr flush dev eth0",
		"ip route del default",
	}
	for _, c := range cases {
		if v := reviewCommandRisk(c, passwordFacts()); v == nil {
			t.Errorf("应命中网络面: %q", c)
		} else if v.Category != impactChannelNetwork {
			t.Errorf("%q → %s，期望 channel-network", c, v.Category)
		}
	}
}

// TestImpact_ChannelNetworkAllow 网络面放行：启用/查询类。
func TestImpact_ChannelNetworkAllow(t *testing.T) {
	cases := []string{
		"ip link set eth0 up",
		"ip addr show",
		"ip route add 10.0.0.0/8 via 172.17.0.1",
		"ip addr add 10.0.0.2/24 dev eth0",
	}
	for _, c := range cases {
		if v := reviewCommandRisk(c, passwordFacts()); v != nil {
			t.Errorf("不应命中网络面: %q → %s", c, v.Category)
		}
	}
}

// TestImpact_ChannelUserBlocked 用户面：处理当前登录用户 → 拒绝；
// 非当前用户（如后门账号）不受影响。
func TestImpact_ChannelUserBlocked(t *testing.T) {
	blocked := []string{
		"userdel root",
		"passwd -l root",
		"usermod -L root",
		"usermod -s /sbin/nologin root",
		"chage -E 0 root",
	}
	for _, c := range blocked {
		if v := reviewCommandRisk(c, passwordFacts()); v == nil {
			t.Errorf("应命中用户面: %q", c)
		} else if v.Category != impactChannelUser {
			t.Errorf("%q → %s，期望 channel-user", c, v.Category)
		}
	}
	// 非当前用户放行：处置后门账号正是常见场景。
	allowed := []string{
		"userdel backdoor",
		"passwd -l backdoor",
		"usermod -s /sbin/nologin backdoor",
		"chage -E 0 backdoor",
	}
	for _, c := range allowed {
		if v := reviewCommandRisk(c, passwordFacts()); v != nil {
			t.Errorf("非当前用户不应命中用户面: %q → %s", c, v.Category)
		}
	}
}

// TestImpact_ToolchainRepairTier 工具链面修复分级（迭代 5）：删除非核心
// 库文件（如 /usr/lib 下被植入的恶意 .so）→ 放行（落入常规变更面）；
// 可执行文件/工具链目录/核心库 → 拒绝。
func TestImpact_ToolchainRepairTier(t *testing.T) {
	allowed := []string{
		"rm -f /usr/lib/libevilhook.so",
		"rm -f /usr/lib64/libminer.so",
		"mv /usr/lib/libhijack.so /quarantine/",
		"unlink /usr/lib/libpersist.so",
		// /usr/local 本地安装区：植入脚本常驻区，清理属修复面。
		"rm -f /usr/local/sbin/fetch-keys",
		"rm -f /usr/local/bin/fake-ps",
		"rm -rf /usr/local/bin",
		"mv /usr/local/lib/libinject.so /quarantine/",
	}
	for _, c := range allowed {
		if v := reviewCommandRisk(c, nil); v != nil {
			t.Errorf("非核心库删除应放行: %q → %s/%s", c, v.Face, v.Category)
		}
	}
	blocked := []string{
		"rm -rf /usr/lib",
		"rm -rf /usr/bin",
		"rm -f /usr/lib64/libc.so.6",
		"rm -f /usr/lib/libpam.so.0",
		"rm -f /lib64/ld-linux-x86-64.so.2",
		"rm -f /usr/lib/systemd/libsystemd-shared-255.so",
		"rm -f /usr/bin/systemctl",
		"rm -f /usr/sbin/sshd",
		"rm -f /usr/libexec/openssh/sftp-server",
	}
	for _, c := range blocked {
		if v := reviewCommandRisk(c, nil); v == nil {
			t.Errorf("核心工具链删除应命中: %q", c)
		} else if v.Category != impactToolchain {
			t.Errorf("%q → %s，期望 toolchain", c, v.Category)
		}
	}
}

// TestImpact_ToolchainBlocked 工具链面：删系统可执行文件/卸载核心包。
func TestImpact_ToolchainBlocked(t *testing.T) {
	blocked := []string{
		"rm -f /usr/bin/grep",
		"rm /bin/ls",
		"mv /usr/bin/curl /tmp/",
		"yum remove -y curl",
		"dnf erase systemd",
		"apt-get purge -y openssh-server",
		"rm -rf /usr/lib64/libc.so.6",
	}
	for _, c := range blocked {
		if v := reviewCommandRisk(c, nil); v == nil {
			t.Errorf("应命中工具链面: %q", c)
		} else if v.Category != impactToolchain {
			t.Errorf("%q → %s，期望 toolchain", c, v.Category)
		}
	}
	// 清理非工具链文件放行。
	allowed := []string{
		"rm -f /tmp/x.sh",
		"rm -f /var/log/app.log",
		"rm -rf /tmp/build",
		"yum remove -y httpd",
	}
	for _, c := range allowed {
		if v := reviewCommandRisk(c, nil); v != nil {
			t.Errorf("不应命中工具链面: %q → %s", c, v.Category)
		}
	}
}

// TestImpact_GuardDecideConservative 守卫级：远程目标但无连接事实注入 →
// 保守模式（按 root+密码+22 判定），自断通道命令拒绝。
func TestImpact_GuardDecideConservative(t *testing.T) {
	g := NewRiskyCommandGuard(nil, PolicyAuto)
	cases := []string{
		"sed -i 's/^PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config && systemctl reload sshd",
		"systemctl stop sshd",
		"iptables -A INPUT -p tcp --dport 22 -j DROP",
		"userdel root",
	}
	for _, c := range cases {
		if err := g.decide(context.Background(), c, matchRiskyRule(c), []string{"web-01"}, "terminal"); err == nil {
			t.Errorf("保守模式应拒绝: %q", c)
		}
	}
	// 处置常规故障不受保守模式影响。
	okCases := []string{
		"kill 130",
		"chmod 644 /etc/passwd",
		"truncate -s 0 /var/log/app.log",
		"systemctl restart nginx",
		"userdel backdoor",
	}
	for _, c := range okCases {
		if err := g.decide(context.Background(), c, matchRiskyRule(c), []string{"web-01"}, "terminal"); err != nil {
			t.Errorf("常规处置不应被拒: %q → %v", c, err)
		}
	}
}

// TestImpact_GuardDecideWithFacts 守卫级：注入连接事实后按事实判定
// （密钥登录 + 仅禁密码 → 放行；密码登录 → 拒绝）。
func TestImpact_GuardDecideWithFacts(t *testing.T) {
	cmd := "sed -i 's/^PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config"
	g := NewRiskyCommandGuard(nil, PolicyAuto)
	g.ConnFacts = func(aliases []string) map[string]model.ConnFact { return keyFacts() }
	if err := g.decide(context.Background(), cmd, matchRiskyRule(cmd), []string{"web-01"}, "terminal"); err != nil {
		t.Errorf("密钥登录时仅禁密码应放行: %v", err)
	}
	g2 := NewRiskyCommandGuard(nil, PolicyAuto)
	g2.ConnFacts = func(aliases []string) map[string]model.ConnFact { return passwordFacts() }
	if err := g2.decide(context.Background(), cmd, matchRiskyRule(cmd), []string{"web-01"}, "terminal"); err == nil {
		t.Error("密码登录时禁密码必须拒绝")
	}
}
