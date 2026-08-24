package probe

// 状态模型测试：期望状态加载/冷启动/偏差计算（端口/服务/用户/SUID/
// 策略/横向对比）。

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/go-gocel/gocode-ops/internal/common/model"
)

// TestComputeDeviations_ExpectAndBans 期望清单与禁项清单的偏差。
func TestComputeDeviations_ExpectAndBans(t *testing.T) {
	d := &DesiredState{
		RoleTemplates: map[string]RoleTemplate{
			"web": {Services: []string{"nginx"}, Ports: []int{80, 443}, NoPorts: []int{4444}},
		},
		Hosts: map[string]HostDesire{
			"web-01": {Role: "web", Expect: ExpectSpec{
				Users: []string{"deploy"}, NoUsers: []string{"backdoor"},
				NoSUID: []string{"/var/lib"},
			}},
		},
	}
	snap := &Snapshot{Hosts: []HostMetric{
		{Host: "web-01", Raw: map[string]string{
			"listen_ports": "LISTEN 0 128 0.0.0.0:80 0.0.0.0:* users:((\"nginx\",pid=1,fd=3))\nLISTEN 0 128 0.0.0.0:443 0.0.0.0:* users:((\"nginx\",pid=1,fd=4))\nLISTEN 0 128 0.0.0.0:4444 0.0.0.0:* users:((\"python3\",pid=2,fd=3))",
			"svc_units":    "nginx.service\nsshd.service",
			"uid0_users":   "root:/bin/bash\nbackdoor:/bin/sh",
			"suid_files":   "/usr/bin/su\n/var/lib/.find",
		}},
	}}
	devs := ComputeDeviations(d, snap)
	got := map[string]bool{}
	for _, dv := range devs {
		got[dv.Kind+":"+dv.Expect] = true
	}
	// 期望服务缺失（nginx 在，sshd 不在期望→无 missing_service）。
	if got["missing_service:服务 nginx 运行中"] {
		t.Errorf("nginx 在运行不应报缺失")
	}
	if !got["unexpected_port:端口 4444 禁止监听"] {
		t.Errorf("禁项端口 4444 应报偏差，got %v", got)
	}
	if !got["unexpected_user:账户 backdoor 禁止存在"] {
		t.Errorf("禁项账户 backdoor 应报偏差")
	}
	if !got["unexpected_suid:路径 /var/lib 下禁止 SUID"] {
		t.Errorf("/var/lib 下 SUID 应报偏差")
	}
	// 期望用户 deploy 缺失。
	if !got["missing_user:账户 deploy 存在"] {
		t.Errorf("期望用户 deploy 缺失应报偏差")
	}
	// 期望端口 80/443 均在监听 → 无 missing_port。
	for k := range got {
		if k == "missing_port:端口 80 监听中" || k == "missing_port:端口 443 监听中" {
			t.Errorf("监听中的期望端口不应报缺失: %s", k)
		}
	}
}

// TestComputeDeviations_PolicyAndPeers 策略偏差与横向对比。
func TestComputeDeviations_PolicyAndPeers(t *testing.T) {
	d := &DesiredState{
		Policies:   PolicyDesire{NoLdPreload: true, NoRootSSH: true},
		PeerGroups: [][]string{{"web-01", "web-02", "web-03"}},
		Hosts: map[string]HostDesire{
			"web-01": {Expect: ExpectSpec{Ports: []int{80}}},
			"web-02": {},
			"web-03": {},
		},
	}
	snap := &Snapshot{Hosts: []HostMetric{
		{Host: "web-01", Raw: map[string]string{
			"ld_preload":   "/tmp/evil/libevil.so",
			"ssh_chain":    "PermitRootLogin yes\nPasswordAuthentication yes",
			"listen_ports": "LISTEN 0 128 0.0.0.0:80 0.0.0.0:*\nLISTEN 0 128 0.0.0.0:9999 0.0.0.0:*",
		}},
		{Host: "web-02", Raw: map[string]string{"listen_ports": "LISTEN 0 128 0.0.0.0:80 0.0.0.0:*"}},
		{Host: "web-03", Raw: map[string]string{"listen_ports": "LISTEN 0 128 0.0.0.0:80 0.0.0.0:*"}},
	}}
	devs := ComputeDeviations(d, snap)
	got := map[string]bool{}
	for _, dv := range devs {
		got[dv.Kind] = true
	}
	if !got["policy_ld_preload"] {
		t.Errorf("LD_PRELOAD 策略偏差应检出")
	}
	if !got["policy_root_ssh"] {
		t.Errorf("root SSH 策略偏差应检出")
	}
	// 9999 是 web-01 独有（组内 3 台只有它监听）→ 横向偏差。
	if !got["unexpected_vs_peers"] {
		t.Errorf("组内独有端口应报横向偏差")
	}
}

// TestDesiredRoundTripAndAutoBaseline 冷启动自动基线 + 保存加载。
func TestDesiredRoundTripAndAutoBaseline(t *testing.T) {
	dir := t.TempDir()
	snap := &Snapshot{Hosts: []HostMetric{
		{Host: "web-01", Raw: map[string]string{
			"listen_ports": "LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\nLISTEN 0 128 0.0.0.0:8080 0.0.0.0:*",
			"svc_units":    "nginx.service\nsshd.service",
			"uid0_users":   "root:/bin/bash",
		}},
	}}
	d := AutoDesiredFromSnapshot(snap)
	if err := SaveDesired(dir, d); err != nil {
		t.Fatalf("保存失败: %v", err)
	}
	loaded, err := LoadDesired(dir)
	if err != nil || loaded == nil {
		t.Fatalf("加载失败: %v", err)
	}
	exp := loaded.Hosts["web-01"].Expect
	if len(exp.Ports) != 2 || exp.Ports[0] != 22 || exp.Ports[1] != 8080 {
		t.Errorf("自动基线端口不符: %v", exp.Ports)
	}
	if len(exp.Services) != 2 {
		t.Errorf("自动基线服务不符: %v", exp.Services)
	}
	// 文件不存在时 LoadDesired 返回 nil,nil。
	if got, err := LoadDesired(t.TempDir()); err != nil || got != nil {
		t.Errorf("无文件应返回 nil,nil: %v, %v", got, err)
	}
}

// TestInitDesired 模板初始化幂等。
func TestInitDesired(t *testing.T) {
	dir := t.TempDir()
	created, err := InitDesired(dir)
	if err != nil || !created {
		t.Fatalf("首次初始化应创建: %v %v", created, err)
	}
	if _, err := os.Stat(filepath.Join(model.ConfigDir(dir), "desired.json")); err != nil {
		t.Fatalf("模板文件应存在: %v", err)
	}
	created2, err := InitDesired(dir)
	if err != nil || created2 {
		t.Fatalf("二次初始化不应覆盖: %v %v", created2, err)
	}
}

// TestParseListenPorts 端口解析（ss 行格式）。
func TestParseListenPorts(t *testing.T) {
	raw := "LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:((\"sshd\",pid=1,fd=3))\n" +
		"LISTEN 0 128 [::]:443 [::]:* users:((\"nginx\",pid=2,fd=6))\n" +
		"LISTEN 0 128 127.0.0.1:3306 0.0.0.0:*\n" +
		"garbage line\n"
	ports := parseListenPorts(raw)
	if len(ports) != 3 || ports[0] != 22 || ports[1] != 443 || ports[2] != 3306 {
		t.Errorf("端口解析不符: %v", ports)
	}
}
