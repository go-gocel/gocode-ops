package probe

import (
	"strings"
	"testing"
)

func TestParseMemInfo(t *testing.T) {
	out := "MemTotal:       16253928 kB\nMemFree:          123456 kB\nMemAvailable:    8000000 kB\n"
	got, err := parseMemInfo(out)
	if err != nil {
		t.Fatalf("parseMemInfo: %v", err)
	}
	want := 8000000.0 / 16253928.0 * 100
	if !approx(got["avail_pct"], want, 0.01) {
		t.Errorf("avail_pct = %.2f, want %.2f", got["avail_pct"], want)
	}
}

func TestParseMemInfo_NoTotal(t *testing.T) {
	if _, err := parseMemInfo("garbage\n"); err == nil {
		t.Error("缺少 MemTotal 应报错")
	}
}

func TestParseDF(t *testing.T) {
	out := `Filesystem     1024-blocks      Used Available Capacity Mounted on
/dev/sda1       104755200  83886080  20869120      81% /
tmpfs            1625392        256   1625136       1% /dev/shm`
	got, err := parseDF("capacity")(out)
	if err != nil {
		t.Fatalf("parseDF: %v", err)
	}
	if !approx(got["/"], 81, 0.01) {
		t.Errorf(`"/" = %.1f, want 81`, got["/"])
	}
	if !approx(got["/dev/shm"], 1, 0.01) {
		t.Errorf(`"/dev/shm" = %.1f, want 1`, got["/dev/shm"])
	}
	if _, ok := got["Filesystem"]; ok {
		t.Error("表头不应被解析为数据")
	}
}

func TestParseZombie(t *testing.T) {
	out := "PID  TTY  TIME CMD\n  Z\n  Z\n  S\n  R\n"
	got, err := parseZombie(out)
	if err != nil {
		t.Fatalf("parseZombie: %v", err)
	}
	if got["count"] != 2 {
		t.Errorf("count = %.0f, want 2", got["count"])
	}
}

func TestParseProcTop(t *testing.T) {
	out := "1234 nginx 97.5\n5678 miner 152.0\n"
	got, err := parseProcTop(out)
	if err != nil {
		t.Fatalf("parseProcTop: %v", err)
	}
	if !approx(got["1234(nginx)"], 97.5, 0.01) || !approx(got["5678(miner)"], 152.0, 0.01) {
		t.Errorf("got = %v", got)
	}
	if _, err := parseProcTop("garbage\n"); err == nil {
		t.Error("无有效进程行应报错（无数据不产线）")
	}
}

func TestParseKernelEvents(t *testing.T) {
	out := "[123.4] Out of memory: Killed process 42 (httpd)\n[124.0] BUG: soft lockup\nnormal line\n"
	got, err := parseKernelEvents(out)
	if err != nil {
		t.Fatalf("parseKernelEvents: %v", err)
	}
	if got["count"] != 2 {
		t.Errorf("count = %.0f, want 2", got["count"])
	}
	if got, _ := parseKernelEvents(""); got["count"] != 0 {
		t.Errorf("空输出 count = %.0f, want 0（受限采集如实降级）", got["count"])
	}
}

func TestParseNetDevErrors(t *testing.T) {
	out := `Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo:       0       0    0    0    0     0          0         0        0       0    0    0    0     0       0          0
  eth0: 1000000    8000    3    0    0     0          0         0  5000000    6000    2    0    0     0       0          0
  eth1:       1       1    0    0    0     0          0         0        1       1    0    0    0     0       0          0`
	got, err := parseNetDevErrors(out)
	if err != nil {
		t.Fatalf("parseNetDevErrors: %v", err)
	}
	if !approx(got["eth0"], 5, 0.01) {
		t.Errorf("eth0 = %v, want 5（rx 3 + tx 2）", got)
	}
	if _, ok := got["eth1"]; ok {
		t.Errorf("无错误的网卡不应产数据: %v", got)
	}
	if _, ok := got["lo"]; ok {
		t.Errorf("lo 不应参与判定: %v", got)
	}
}

func TestParseSwap(t *testing.T) {
	out := "SwapTotal:       2000000 kB\nSwapFree:         500000 kB\n"
	got, err := parseSwap(out)
	if err != nil {
		t.Fatalf("parseSwap: %v", err)
	}
	if !approx(got["swap_pct"], 75, 0.01) {
		t.Errorf("swap_pct = %.1f, want 75", got["swap_pct"])
	}
	if got, _ := parseSwap("SwapTotal:       0 kB\n"); len(got) != 0 {
		t.Errorf("无 swap 主机应无数据: %v", got)
	}
}

func TestParseProcDeleted(t *testing.T) {
	out := "lrwxrwxrwx 1 root root 0 Jan  1 00:00 /proc/1/exe -> /usr/bin/bash\n" +
		"lrwxrwxrwx 1 root root 0 Jan  1 00:00 /proc/2/exe -> /tmp/.evil (deleted)\n" +
		"lrwxrwxrwx 1 root root 0 Jan  1 00:00 /proc/3/exe -> /usr/sbin/sshd (deleted)\n"
	got, err := parseProcDeleted(out)
	if err != nil {
		t.Fatalf("parseProcDeleted: %v", err)
	}
	if got["count"] != 2 {
		t.Errorf("count = %.0f, want 2", got["count"])
	}
}

func TestParseDState(t *testing.T) {
	out := "S 100 systemd\nD 200 nfsd\nD 201 nfsd\nR 300 bash\nZ 400 defunct\n"
	got, err := parseDState(out)
	if err != nil {
		t.Fatalf("parseDState: %v", err)
	}
	if len(got) != 2 || got["200(nfsd)"] != 1 || got["201(nfsd)"] != 1 {
		t.Errorf("got = %v, want 对象级 200(nfsd)/201(nfsd)", got)
	}
	// 0 个 D 状态是健康态：空 map，不产线不报错（与 proc_top 空输出
	// 报错不同——D 状态缺失是正常，进程缺失才是异常）。
	empty, err := parseDState("S 100 systemd\nR 300 bash\n")
	if err != nil || len(empty) != 0 {
		t.Errorf("无 D 状态应返回空 map 且无错误: %v, %v", empty, err)
	}
}

func TestParseFileNR(t *testing.T) {
	// file-nr 格式：已分配 未使用 上限。
	got, err := parseFileNR("12800 0 1048576\n")
	if err != nil {
		t.Fatalf("parseFileNR: %v", err)
	}
	if !approx(got["fd_pct"], 12800.0/1048576*100, 0.001) {
		t.Errorf("fd_pct = %.3f, want %.3f", got["fd_pct"], 12800.0/1048576*100)
	}
	// 未使用槽位不占资源：使用率须扣除（12800 分配 - 2800 空闲）。
	got2, err := parseFileNR("12800 2800 1048576\n")
	if err != nil {
		t.Fatalf("parseFileNR: %v", err)
	}
	if !approx(got2["fd_pct"], 10000.0/1048576*100, 0.001) {
		t.Errorf("fd_pct = %.3f, want %.3f（扣除空闲槽位）", got2["fd_pct"], 10000.0/1048576*100)
	}
	if _, err := parseFileNR("garbage\n"); err == nil {
		t.Error("非法输出应报错")
	}
}

func TestSignalProbePlan(t *testing.T) {
	env := &Env{HasSystemd: true, HasSS: true}
	cases := []struct {
		signal string
		mids   []string
		fids   []string
	}{
		{"config_drift", nil, nil}, // 基线机制负责，无判定层源
		{"svc_failed", []string{"svc_failed"}, nil},
		{"swap_high", []string{"swap"}, nil},
		{"sudo_chain_anomaly", nil, []string{"sudo_chain"}}, // 归属规则兜底命名
		{"oversized_file", nil, []string{"big_files"}},
		// listen_ports 归属依赖 svc_units：定向复检必须一并采集，
		// 否则无归属依据时 JudgeSecurityFacts 保守不产线 → 假放行。
		{"unattributed_listen", nil, []string{"listen_ports", "svc_units"}},
		// UDP 监听面同依赖（listen_udp 归属规则复用 svc_units 依据）。
		{"unattributed_listen_udp", nil, []string{"listen_udp", "svc_units"}},
		// 扩展面指标：D 状态/fd 使用率走数值指标通道。
		{"dstate_procs", []string{"proc_dstate"}, nil},
		{"fd_high", []string{"file_desc"}, nil},
		// 新归属规则信号：用户计划任务/全局环境/链接器配置/rc.local。
		{"user_crons_anomaly", nil, []string{"user_crons"}},
		{"env_global_anomaly", nil, []string{"env_global"}},
		{"ld_so_conf_anomaly", nil, []string{"ld_so_conf"}},
		{"rc_local_anomaly", nil, []string{"rc_local"}},
		{"cpu_high", nil, nil}, // CPU 恒附加采集，不属清单探针
		{"bogus_signal", nil, nil},
	}
	for _, c := range cases {
		mids, fids := SignalProbePlan(env, c.signal)
		if !equalStr(mids, c.mids) || !equalStr(fids, c.fids) {
			t.Errorf("SignalProbePlan(%q) = (%v, %v), want (%v, %v)", c.signal, mids, fids, c.mids, c.fids)
		}
	}
}

// TestShellInitHooksProbeCoverage R24 回归：登录链探针必须覆盖
// .profile 家族与多种持久化形态（/dev/tcp 反连、base64 解码执行）——
// 第四处持久化藏身 /root/.profile（python b64decode）曾静默漏检
// （旧模式只匹配 curl|wget 管道，其余形态失明）。
func TestShellInitHooksProbeCoverage(t *testing.T) {
	env := &Env{HasSystemd: true}
	frag := ""
	for _, m := range SecurityFacts(env) {
		if m.ID == "shell_init_hooks" {
			frag = m.Fragment(env)
			break
		}
	}
	if frag == "" {
		t.Fatal("shell_init_hooks 探针缺失")
	}
	for _, want := range []string{"/root/.profile", "/root/.bash_profile", "/root/.bash_login", "b64decode", "/dev/tcp/", "base64"} {
		if !strings.Contains(frag, want) {
			t.Errorf("shell_init_hooks 探针缺 %q（覆盖不全则对应持久化形态静默漏检）: %s", want, frag)
		}
	}
	// state_shellinit 内容探针同样要覆盖 .profile 家族（deepdive 读取内容）。
	stateFrag := ""
	for _, m := range StateProbes(env) {
		if m.ID == "state_shellinit" {
			stateFrag = m.Fragment(env)
			break
		}
	}
	if stateFrag == "" {
		t.Fatal("state_shellinit 探针缺失")
	}
	for _, want := range []string{"/root/.profile", "/root/.bash_profile", "/root/.bash_login"} {
		if !strings.Contains(stateFrag, want) {
			t.Errorf("state_shellinit 探针缺 %q", want)
		}
	}
}

// TestExpertProbeCoverage 专家知识面探针（第二轮扩展）的关键命令面：
// rootkit（内核模块）、嗅探（混杂模式）、持久化（udev/at/自定义单元/
// init.d）、防护（SELinux）、防篡改（immutable）、入侵痕迹（登录）。
// 命令面缺失 = 对应攻击形态静默失明。
func TestExpertProbeCoverage(t *testing.T) {
	env := &Env{HasSystemd: true}
	frag := map[string]string{}
	for _, m := range securityFacts(env) {
		frag[m.ID] = m.Fragment(env)
	}
	sp := map[string]string{}
	for _, m := range StateProbes(env) {
		sp[m.ID] = m.Fragment(env)
	}
	for id, want := range map[string]string{
		"kernel_modules":  "/proc/modules",
		"promisc_ifaces":  "ip -br link",
		"udev_rules":      "/etc/udev/rules.d",
		"at_jobs":         "atq",
		"systemd_custom":  "/etc/systemd/system",
		"selinux_status":  "getenforce",
		"immutable_files": "lsattr",
		"login_trail":     "last -n 20",
	} {
		if !strings.Contains(frag[id], want) {
			t.Errorf("%s 探针缺 %q（对应攻击形态静默失明）: %s", id, want, frag[id])
		}
	}
	for id, want := range map[string]string{
		"state_kmods":          "/proc/modules",
		"state_at":             "atq",
		"state_systemd_custom": "/etc/systemd/system",
		"state_initd":          "/etc/init.d",
	} {
		if !strings.Contains(sp[id], want) {
			t.Errorf("%s 探针缺 %q: %s", id, want, sp[id])
		}
	}
}

func equalStr(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestParseCountLines(t *testing.T) {
	out := "nginx.service loaded failed failed nginx\nmysql.service loaded failed failed mysql\n"
	got, err := parseCountLines(out)
	if err != nil {
		t.Fatalf("parseCountLines: %v", err)
	}
	if got["count"] != 2 {
		t.Errorf("count = %.0f, want 2", got["count"])
	}
}

func TestParseSSHRootLogin(t *testing.T) {
	cases := []struct {
		name string
		out  string
		want float64
	}{
		{"默认禁用（注释行）", "#PermitRootLogin prohibit-password\n", 0},
		{"允许 root 直登", "#Port 22\nPermitRootLogin yes\n", 1},
		{"prohibit-password 不允许直登", "PermitRootLogin prohibit-password\n", 0},
		{"密钥直登（without-password）不算弱配置", "PermitRootLogin without-password\nPasswordAuthentication yes\n", 0},
		{"root 直登但密码认证已禁用（仅密钥）", "PermitRootLogin yes\nPasswordAuthentication no\n", 0},
		{"root 密码直登", "PermitRootLogin yes\nPasswordAuthentication yes\n", 1},
		{"空文件", "", 0},
	}
	for _, c := range cases {
		got, err := parseSSHRootLogin(c.out)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if got["count"] != c.want {
			t.Errorf("%s: count = %.0f, want %.0f", c.name, got["count"], c.want)
		}
	}
}

func TestMetricsProbeNoiseFilters(t *testing.T) {
	env := &Env{HasSystemd: true}
	frag := map[string]string{}
	for _, m := range Metrics(env) {
		frag[m.ID] = m.Fragment(env)
	}
	if !strings.Contains(frag["svc_inactive"], "*@.service) continue") {
		t.Error("svc_inactive 应跳过模板单元")
	}
	if !strings.Contains(frag["log_errors"], "No entries") {
		t.Error("log_errors 应过滤无条目占位行")
	}
	// 安全事实探针（不在 Metrics 清单内）。
	for _, m := range securityFacts(env) {
		frag[m.ID] = m.Fragment(env)
	}
	if !strings.Contains(frag["auth_chain"], "/etc/pam.d/*") {
		t.Error("auth_chain 应覆盖全部 PAM 文件（R21 实测 pam.d/passwd 漏检）")
	}
	if !strings.Contains(frag["arp_neighbors"], "ip neigh") {
		t.Error("应采集 ARP 邻居表（邻接面事实）")
	}
	// 多文件 grep 必须 -h（不带文件名前缀）：否则归属规则对带前缀的
	// 行永远失明（R21 实测 ssh_chain 基线规则从未真实产线）。
	if !strings.Contains(frag["ssh_chain"], "grep -hvE") {
		t.Error("ssh_chain 应使用 grep -h（多文件不带前缀）")
	}
	if !strings.Contains(frag["sudo_chain"], "grep -hvE") {
		t.Error("sudo_chain 应使用 grep -h（多文件不带前缀）")
	}
}

func approx(a, b, eps float64) bool {
	d := a - b
	if d < 0 {
		d = -d
	}
	return d <= eps
}
