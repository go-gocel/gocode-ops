package probe

import (
	"fmt"
	"github.com/go-gocel/gocode-ops/internal/common/fsutil"
	"regexp"
	"strconv"
	"strings"
)

// judge_security.go — 安全隐患判定：开放端口/SSH 弱配置/弱口令策略/可疑进程/后门痕迹/异常挂载。

var listenLineRe = regexp.MustCompile(`^\S+\s+\S+\s+\S+\s+([0-9a-fA-F.:\[\]]+):(\d+)\s+\S+\s+users?:?\(?\(?"?([^",)]+)`)

// listenEntry 一条监听记录。
type listenEntry struct {
	addrPort string // 本地地址:端口
	proc     string // 进程名
}

// parseListenLines 解析监听端口原始输出。
func parseListenLines(raw string) []listenEntry {
	var out []listenEntry
	for _, line := range strings.Split(raw, "\n") {
		m := listenLineRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		out = append(out, listenEntry{addrPort: m[1] + ":" + m[2], proc: strings.Trim(m[3], `"'`)})
	}
	return out
}

// parseUnitNames 解析运行中服务单元清单（sshd.service → sshd）。
func parseUnitNames(raw string) []string {
	var out []string
	for _, line := range strings.Split(raw, "\n") {
		name := strings.TrimSpace(line)
		if name == "" {
			continue
		}
		out = append(out, strings.TrimSuffix(name, ".service"))
	}
	return out
}

// attributable 进程能否归属到已知服务单元：进程名以某单元名前缀开头
// （sshd→sshd.service、redis-server→redis.service）。
func attributable(proc string, units []string) bool {
	if proc == "" {
		return false
	}
	for _, u := range units {
		if strings.HasPrefix(proc, u) {
			return true
		}
	}
	return false
}

// JudgeSecurityFacts performs data-driven security-fact attribution and
// threshold judgment, skipping when the corresponding data segment is
// absent.
// JudgeSecurityFacts 安全事实归属/阈值判定（数据驱动：无对应数据段即跳过）：
//   - 监听端口无法归属到运行中服务单元 → 疑点（任何端口被同一机制覆盖）；
//   - uid=0 非 root 用户 → 疑点（特权后门账号特征）；
//   - 大文件（采集侧已按 >500M 通用水位过滤）→ 疑点。
//
// 判定只产 pending 线索，DeepDive 验证后裁决（误报由验证回路排除）。
//
// 覆盖语义（design-v2.md §二）：覆盖度是事实的一部分——探针覆盖
// partial（超时/哨兵/采集层失败）时**只产"待下钻"线索，不产结论**：
// 不完整枚举不得驱动归属规则（超时截断被当"扫描无结果"是假阴性源）。
func JudgeSecurityFacts(hm *HostMetric) []Anomaly {
	var out []Anomaly
	// 覆盖不完整探针：统一产"待下钻"线索（显式 collect_probe 复采），
	// 各归属规则对 partial 探针跳过（见 rawCov）。
	// collect 级失败（Errors["collect"]）不刷 per-探针 partial 线索——
	// 整轮失败由 judgeHost 的 collect_anomaly 单条覆盖，逐探针刷线是噪音。
	if _, wholeFail := hm.Errors["collect"]; !wholeFail {
		for id, cov := range hm.FactCoverage {
			if cov == "partial" {
				out = append(out, Anomaly{Host: hm.Host, Metric: id, Key: "coverage_partial", Severity: SevWarn,
					Desc: fmt.Sprintf("探针 %s 本轮覆盖不完整（partial）——枚举结果不可作为结论，需定向下钻复采（collect_probe %s）", id, id)})
			}
		}
	}
	// 监听端口归属：svc_units 数据缺失（无 systemd/采集失败）时跳过——
	// 无归属依据时保守不产线（数据仍进上下文供模型判定）。
	if raw := hm.rawCov("listen_ports"); raw != "" && hm.rawCov("svc_units") != "" {
		units := parseUnitNames(hm.rawCov("svc_units"))
		for _, l := range parseListenLines(raw) {
			if !attributable(l.proc, units) {
				out = append(out, Anomaly{
					Host: hm.Host, Metric: "listen_ports", Key: l.addrPort,
					Severity: SevWarn,
					Desc:     fmt.Sprintf("监听端口 %s 无法归属到已知服务单元（进程 %s），疑似后门/异常服务", l.addrPort, l.proc),
				})
			}
		}
	}
	// UDP 监听面归属（与 TCP 同机制）：ss -ulnp 行格式（UNCONN ...）
	// 与 listenLineRe 兼容（前三个非空白字段 + 地址:端口 + users）。
	// 独立信号（unattributed_listen_udp）——同地址:端口在 TCP/UDP 两
	// 面都异常时不得互吞（去重键为 addr:port，共用信号会合并）。
	if raw := hm.rawCov("listen_udp"); raw != "" && hm.rawCov("svc_units") != "" {
		units := parseUnitNames(hm.rawCov("svc_units"))
		for _, l := range parseListenLines(raw) {
			if !attributable(l.proc, units) {
				out = append(out, Anomaly{
					Host: hm.Host, Metric: "listen_udp", Key: l.addrPort,
					Severity: SevWarn,
					Desc:     fmt.Sprintf("UDP 监听端口 %s 无法归属到已知服务单元（进程 %s），疑似后门/异常服务", l.addrPort, l.proc),
				})
			}
		}
	}
	if raw := hm.rawCov("uid0_users"); raw != "" {
		for _, line := range strings.Split(raw, "\n") {
			name := strings.TrimSpace(line)
			if i := strings.IndexByte(name, ':'); i > 0 {
				name = name[:i]
			}
			if name != "" && name != "root" {
				out = append(out, Anomaly{
					Host: hm.Host, Metric: "uid0_users", Key: name, Severity: SevCrit,
					Desc: fmt.Sprintf("存在 uid=0 非 root 用户 %q（特权后门账号特征）", name),
				})
			}
		}
	}
	if raw := hm.rawCov("big_files"); raw != "" {
		for _, line := range strings.Split(raw, "\n") {
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			p := strings.Join(fields[1:], " ")
			out = append(out, Anomaly{
				Host: hm.Host, Metric: "big_files", Key: p, Severity: SevWarn,
				Desc: fmt.Sprintf("异常大文件 %s（%s 字节，>500M 阈值）", p, fields[0]),
			})
		}
	}
	// 挂载掩盖：标准系统目录被挂载点覆盖（日志/配置目录上的异常挂载）。
	// bind 挂载（源是另一挂载点路径）必须标注两侧关系——对掩盖目标的写
	// 操作即写源挂载点（R22 实测：处置 /var/log 载荷实际误删 /tmp 内容
	// 致 LD_PRELOAD 链路断裂），模型需要此信息才能安全处置。
	// 容器环境豁免（P0 修复）：根文件系统为 overlay 的容器里，标准目录
	// 下的 tmpfs 挂载是运行时（docker --tmpfs/运行时临时卷）常态——chaos-r1
	// 实测 /var/log/orderapp 的运行时 tmpfs 被当"掩盖"线索，驱动模型去
	// umount 日志挂载点（激进误处置）。bind 挂载（源为路径）不豁免——
	// 攻击者/异常 bind 掩盖在任何形态下都是线索。
	if raw := hm.rawCov("mounts"); raw != "" {
		isContainer := containerRootfs(raw)
		for _, m := range parseMountLines(raw) {
			if !maskedMount(m.target) {
				continue
			}
			if isContainer && m.fstype == "tmpfs" && m.src == "tmpfs" {
				continue // 容器运行时 tmpfs（日志/运行时目录的标准形态）
			}
			desc := fmt.Sprintf("标准系统目录 %s 被挂载点覆盖（%s，%s）——日志/配置可能被掩盖", m.target, m.src, m.fstype)
			if isBindSource(m.src) {
				desc += fmt.Sprintf("；bind 自 %s——对 %s 的写操作即写 %s，处置需同时处理两侧", m.src, m.target, m.src)
			}
			out = append(out, Anomaly{
				Host: hm.Host, Metric: "mounts", Key: m.target, Severity: SevWarn,
				Desc: desc,
			})
		}
	}
	// SUID 文件（常规 L0 采集，与 file_caps 同类提权载体）：标准二进制目录
	// 外的 SUID 是异常载体（标准目录内 passwd/su 等为发行版默认，不产线免
	// 噪音——全量列表已进模型上下文由 DeepDive 裁决）。归属规则统一覆盖
	// 任何路径的 SUID（R22 实测 /var/lib/.find 隐藏 SUID 漏检）。
	// 例行探针（suid_files）只扫标准目录；下钻全量（suid_files_full，
	// 显式 collect_probe/复检）对全盘产线——两源共用同一规则。
	if raw := hm.rawAnyCov("suid_files", "suid_files_full"); raw != "" {
		for _, line := range strings.Split(raw, "\n") {
			line = strings.TrimSpace(line)
			if line == "" || suidStandardDir(line) {
				continue
			}
			out = append(out, Anomaly{Host: hm.Host, Metric: "suid_files", Key: line, Severity: SevWarn,
				Desc: fmt.Sprintf("标准二进制目录外的 SUID 文件 %s（非常规提权载体，需裁决是否预期）", line)})
		}
	}
	// SUID 包归属校验（suid_owners）：标准目录内非包来源的 SUID 是
	// 后门特征（伪装名/植入二进制）。发行版无关（rpm/dpkg/apk 链），
	// 归属工具全无时探针无数据（跳过不误报）。"列表交给模型裁决"
	// 依赖注意力不可靠（实测 /usr/bin/upd 伪装名漏检），归属校验是
	// 确定性机制。
	out = append(out, judgeSuidOwners(hm)...)
	// 关键内核参数：安全基线键族（CIS 类标准项）偏离硬基线即产线。
	if raw := hm.rawCov("sysctl_keys"); raw != "" {
		for _, line := range strings.Split(raw, "\n") {
			fields := strings.Fields(line)
			if len(fields) < 3 {
				continue
			}
			key, val := strings.TrimSpace(fields[0]), strings.TrimSpace(fields[2])
			switch {
			case key == "net.ipv4.ip_forward" && val == "1":
				out = append(out, Anomaly{Host: hm.Host, Metric: "sysctl_keys", Key: key, Severity: SevWarn,
					Desc: "net.ipv4.ip_forward 已开启（非网关主机的转发需裁决是否预期）"})
			case key == "kernel.core_pattern" && strings.HasPrefix(val, "|"):
				out = append(out, Anomaly{Host: hm.Host, Metric: "sysctl_keys", Key: key, Severity: SevWarn,
					Desc: fmt.Sprintf("kernel.core_pattern 为管道执行模式（%s）——崩溃转储被外部程序接管", val)})
			case key == "kernel.dmesg_restrict" && val == "0":
				out = append(out, Anomaly{Host: hm.Host, Metric: "sysctl_keys", Key: key, Severity: SevWarn,
					Desc: "kernel.dmesg_restrict=0：内核日志对低权用户可读（地址/模块信息泄露面）"})
			case key == "kernel.randomize_va_space" && val == "0":
				out = append(out, Anomaly{Host: hm.Host, Metric: "sysctl_keys", Key: key, Severity: SevWarn,
					Desc: "kernel.randomize_va_space=0：ASLR 已关闭（内存地址随机化失效）"})
			case key == "kernel.kptr_restrict" && val == "0":
				out = append(out, Anomaly{Host: hm.Host, Metric: "sysctl_keys", Key: key, Severity: SevWarn,
					Desc: "kernel.kptr_restrict=0：内核指针地址泄露给低权用户（提权辅助面）"})
			case (key == "fs.protected_regular" || key == "fs.protected_hardlinks" || key == "fs.protected_symlinks") && val == "0":
				out = append(out, Anomaly{Host: hm.Host, Metric: "sysctl_keys", Key: key, Severity: SevWarn,
					Desc: fmt.Sprintf("%s=0：硬链接/符号链接保护关闭（链接攻击面）", key)})
			case key == "net.ipv4.conf.all.accept_source_route" && val == "1":
				out = append(out, Anomaly{Host: hm.Host, Metric: "sysctl_keys", Key: key, Severity: SevWarn,
					Desc: "accept_source_route=1：源路由接受已开启（路径欺骗面）"})
			case key == "net.ipv4.conf.all.rp_filter" && val == "0":
				out = append(out, Anomaly{Host: hm.Host, Metric: "sysctl_keys", Key: key, Severity: SevWarn,
					Desc: "rp_filter=0：反向路径过滤关闭（IP 欺骗面）"})
			case key == "vm.dirty_ratio":
				// 写缓存水位（通用水位——监控常见告警语义：≥90 写缓存
				// 占满触发写阻塞/数据一致性风险，默认 20）。
				if n, err := strconv.ParseFloat(val, 64); err == nil && n >= 90 {
					out = append(out, Anomaly{Host: hm.Host, Metric: "sysctl_keys", Key: key, Severity: SevWarn,
						Desc: fmt.Sprintf("vm.dirty_ratio=%s（写缓存水位 ≥90%%——写阻塞/数据一致性风险，默认 20）", val)})
				}
			}
		}
	}
	// 临时目录文件洪泛：单目录文件数超采集侧水位（inode 消耗/隐藏落地特征）。
	if raw := hm.rawCov("tmp_dirs"); raw != "" {
		for _, line := range strings.Split(raw, "\n") {
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			out = append(out, Anomaly{Host: hm.Host, Metric: "tmp_dirs", Key: fields[0], Severity: SevWarn,
				Desc: fmt.Sprintf("临时目录 %s 堆积 %s 个文件（超 2000 水位）", fields[0], fields[1])})
		}
	}
	// shell 启动文件含下载即执行注入：登录链持久化特征。
	if raw := hm.rawCov("shell_init_hooks"); raw != "" {
		for _, line := range strings.Split(raw, "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			out = append(out, Anomaly{Host: hm.Host, Metric: "shell_init_hooks", Key: line, Severity: SevWarn,
				Desc: fmt.Sprintf("shell 启动文件 %s 含下载即执行注入（登录链持久化特征）", line)})
		}
	}
	// SysV 启动链（/etc/rc.local）：开机执行注入的另一持久化面——
	// 下载执行/反连/解码执行形态与登录链同一归属（systemd 时代
	// rc-local.service 仍执行该文件）。
	if raw := hm.rawCov("rc_local"); raw != "" {
		for _, line := range strings.Split(raw, "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			if !persistExecRe.MatchString(line) {
				continue
			}
			out = append(out, Anomaly{Host: hm.Host, Metric: "rc_local", Key: line, Severity: SevWarn,
				Desc: fmt.Sprintf("rc.local 含持久化执行注入（%s）——开机启动链特征", fsutil.TruncateStr(line, 120))})
		}
	}
	// 全局环境变量面（/etc/environment）：LD_* 注入对全用户登录会话
	// 生效（登录链注入的第三种形态——不碰 shell 启动文件）；PATH
	// 指向可写目录是命令劫持面。
	if raw := hm.rawCov("env_global"); raw != "" {
		for _, line := range strings.Split(raw, "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			switch {
			case envInjectRe.MatchString(line):
				out = append(out, Anomaly{Host: hm.Host, Metric: "env_global", Key: line, Severity: SevCrit,
					Desc: fmt.Sprintf("全局环境变量含 LD_* 注入（%s）——全会话库劫持面", fsutil.TruncateStr(line, 120))})
			case envPathSuspiciousRe.MatchString(line):
				out = append(out, Anomaly{Host: hm.Host, Metric: "env_global", Key: line, Severity: SevWarn,
					Desc: fmt.Sprintf("全局 PATH 指向可写目录（%s）——命令劫持面", fsutil.TruncateStr(line, 120))})
			}
		}
	}
	// 动态链接器配置链（/etc/ld.so.conf 族）：非标准目录进库搜索链
	// 即任意库劫持（LD_PRELOAD 的持久化兄弟形态）。白名单 = 发行版
	// 标准库目录（/usr/lib*、/lib*、/usr/local/lib*）；include 指令
	// 与空行/注释跳过。
	if raw := hm.rawCov("ld_so_conf"); raw != "" {
		for _, line := range strings.Split(raw, "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "include") {
				continue
			}
			if standardLibDir(line) {
				continue
			}
			out = append(out, Anomaly{Host: hm.Host, Metric: "ld_so_conf", Key: line, Severity: SevWarn,
				Desc: fmt.Sprintf("动态链接器搜索路径 %s 在标准库目录之外——库劫持/异常注入面", line)})
		}
	}
	// 文件能力位：与 SUID 同类的提权载体（迭代 7 权限面完整性）。
	// 全部载体进线索，由 DeepDive 裁决是否预期（发行版默认能力位如
	// ping cap_net_raw 属正常裁决范围）。
	if raw := hm.rawCov("file_caps"); raw != "" {
		for _, line := range strings.Split(raw, "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			out = append(out, Anomaly{Host: hm.Host, Metric: "file_caps", Key: line, Severity: SevWarn,
				Desc: fmt.Sprintf("文件能力位载体 %s（普通用户提权载体，与 SUID 同类，需裁决是否预期）", line)})
		}
	}
	// 世界可写对象：非粘滞位的 0777 文件/目录（任意用户可写面——
	// 日志目录放宽、配置目录可写等异常的归属型事实）。
	// 例行探针（world_writable）只查配置/日志面；下钻全量
	// （world_writable_full，含 /opt 数据面）共用同一规则。
	if raw := hm.rawAnyCov("world_writable", "world_writable_full"); raw != "" {
		for _, line := range strings.Split(raw, "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			out = append(out, Anomaly{Host: hm.Host, Metric: "world_writable", Key: line, Severity: SevWarn,
				Desc: fmt.Sprintf("世界可写对象 %s（0777 无粘滞位——任意用户可写面）", line)})
		}
	}
	// 认证链万能模块：pam_permit 出现在任何 PAM 认证文件都是无条件
	// 放行（CIS 类基线明确禁止），无合法用途。
	if raw := hm.rawCov("auth_chain"); raw != "" {
		for _, line := range strings.Split(raw, "\n") {
			line = strings.TrimSpace(line)
			if !strings.Contains(line, "pam_permit.so") {
				continue
			}
			out = append(out, Anomaly{Host: hm.Host, Metric: "auth_chain", Key: line, Severity: SevCrit,
				Desc: fmt.Sprintf("PAM 认证链含无条件放行模块（%s）——万能认证，认证链已断裂", line)})
		}
	}
	// SSH 配置链弱化指令（CIS 2.2 系列安全基线）：有效行偏离硬基线
	// 即产线，由 DeepDive 裁决是否预期（如业务要求的宽松项）。
	if raw := hm.rawCov("ssh_chain"); raw != "" {
		for _, line := range strings.Split(raw, "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			if v, ok := sshWeakViolation(line); ok {
				out = append(out, Anomaly{Host: hm.Host, Metric: "ssh_chain", Key: line, Severity: SevWarn,
					Desc: fmt.Sprintf("SSH 配置弱化基线违规：%s（需裁决是否预期）", v)})
			}
		}
	}
	// 日志基础设施容量水位：journald 容量 ≤2M 是事件快速丢弃特征——
	// 默认按磁盘 10% 分配，1M 属病态值（故障失明）。
	if raw := hm.rawCov("journald_cfg"); raw != "" {
		for _, line := range strings.Split(raw, "\n") {
			k, v, ok := strings.Cut(line, "=")
			if !ok {
				continue
			}
			k, v = strings.TrimSpace(k), strings.TrimSpace(v)
			if k != "RuntimeMaxUse" && k != "SystemMaxUse" {
				continue
			}
			if mb, ok := parseSizeMB(v); ok && mb <= 2 {
				out = append(out, Anomaly{Host: hm.Host, Metric: "journald_cfg", Key: line, Severity: SevWarn,
					Desc: fmt.Sprintf("journald %s=%s（容量水位 ≤2M——事件快速丢弃，故障失明）", k, v)})
			}
		}
	}
	// 计划任务链下载执行：任何计划任务条目管道到 shell 即持久化执行
	// 特征（crontab/cron.d/anacrontab/cron.* 族统一归属）。
	if raw := hm.rawCov("cron_chain"); raw != "" {
		for _, line := range strings.Split(raw, "\n") {
			line = strings.TrimSpace(line)
			if !cronExecRe.MatchString(line) {
				continue
			}
			out = append(out, Anomaly{Host: hm.Host, Metric: "cron_chain", Key: line, Severity: SevWarn,
				Desc: fmt.Sprintf("计划任务链条目含管道执行注入（%s）——定时持久化特征", fsutil.TruncateStr(line, 120))})
		}
	}
	// 用户计划任务面（/var/spool/cron）：与系统面同一下载执行模式——
	// 用户 crontab 是定时持久化的另一藏身处（系统面被盯上后攻击者的
	// 落点）。独立 Metric（去重键独立于 cron_chain）。
	if raw := hm.rawCov("user_crons"); raw != "" {
		for _, line := range strings.Split(raw, "\n") {
			line = strings.TrimSpace(line)
			if !cronExecRe.MatchString(line) {
				continue
			}
			out = append(out, Anomaly{Host: hm.Host, Metric: "user_crons", Key: line, Severity: SevWarn,
				Desc: fmt.Sprintf("用户计划任务条目含管道执行注入（%s）——定时持久化特征", fsutil.TruncateStr(line, 120))})
		}
	}
	// sudo 授权链万能免密/危险 Defaults：提权链断裂的归属型事实。
	if raw := hm.rawCov("sudo_chain"); raw != "" {
		for _, line := range strings.Split(raw, "\n") {
			line = strings.TrimSpace(line)
			if sudoWeakViolation(line) {
				out = append(out, Anomaly{Host: hm.Host, Metric: "sudo_chain", Key: line, Severity: SevWarn,
					Desc: fmt.Sprintf("sudo 授权链弱化基线违规（%s）——提权链断裂特征", fsutil.TruncateStr(line, 120))})
			}
		}
	}
	// 网络邻接面（ARP）：静态（PERMANENT）邻居条目是邻接面投毒载体——
	// 正常学习条目有生命周期，静态条目只有人为/攻击者写入（R21 实测
	// 静态 ARP 投毒无确定性可见面）。
	if raw := hm.rawCov("arp_neighbors"); raw != "" {
		for _, line := range strings.Split(raw, "\n") {
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			hasPerm := false
			for _, f := range fields {
				if strings.EqualFold(f, "PERMANENT") {
					hasPerm = true
					break
				}
			}
			if !hasPerm {
				continue
			}
			out = append(out, Anomaly{Host: hm.Host, Metric: "arp_neighbors", Key: fields[0], Severity: SevWarn,
				Desc: fmt.Sprintf("静态 ARP 邻居条目 %s（PERMANENT——邻接面投毒载体，正常学习条目有生命周期）", fields[0])})
		}
	}
	// 空密码账户（CIS 基线：空密码字段即无认证登录面）。
	if raw := hm.rawCov("empty_passwords"); raw != "" {
		for _, line := range strings.Split(raw, "\n") {
			name := strings.TrimSpace(line)
			if name == "" {
				continue
			}
			out = append(out, Anomaly{Host: hm.Host, Metric: "empty_passwords", Key: name, Severity: SevCrit,
				Desc: fmt.Sprintf("账户 %q 密码字段为空（CIS 基线：不得存在空密码账户）", name)})
		}
	}
	// 网络身份链：/etc/hosts 公网 IP 映射（域名解析劫持特征——容器/
	// 主机自有的私网条目不产线）。
	if raw := hm.rawCov("net_identity"); raw != "" {
		for _, line := range strings.Split(raw, "\n") {
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			ip := fields[0]
			if !isPublicIPv4(ip) {
				continue
			}
			out = append(out, Anomaly{Host: hm.Host, Metric: "net_identity", Key: line, Severity: SevWarn,
				Desc: fmt.Sprintf("/etc/hosts 含公网 IP 映射（%s → %s）——域名解析劫持特征", ip, fields[1])})
		}
	}
	// 混杂模式网卡：PROMISC 标志 = 抓包监听（嗅探/流量窃听特征）。
	// 监控/虚拟化主机由 DeepDive 裁决是否预期。
	if raw := hm.rawCov("promisc_ifaces"); raw != "" {
		for _, line := range strings.Split(raw, "\n") {
			line = strings.TrimSpace(line)
			if !strings.Contains(line, "PROMISC") {
				continue
			}
			name := "?"
			if fields := strings.Fields(line); len(fields) > 0 {
				name = fields[0]
			}
			out = append(out, Anomaly{Host: hm.Host, Metric: "promisc_ifaces", Key: name, Severity: SevWarn,
				Desc: fmt.Sprintf("网卡 %s 处于混杂模式（PROMISC）——抓包监听/嗅探特征，需裁决是否预期", name)})
		}
	}
	// udev 规则链注入：RUN/PROGRAM 指向可写目录（设备事件持久化
	// 面——rootkit 在设备事件时执行载荷/提权）。
	if raw := hm.rawCov("udev_rules"); raw != "" {
		for _, line := range strings.Split(raw, "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			if !udevInjectRe.MatchString(line) {
				continue
			}
			out = append(out, Anomaly{Host: hm.Host, Metric: "udev_rules", Key: line, Severity: SevWarn,
				Desc: fmt.Sprintf("udev 规则执行体指向可写目录（%s）——设备事件持久化注入特征", fsutil.TruncateStr(line, 120))})
		}
	}
	// SELinux 状态：Permissive/Disabled 是防护面关闭（攻击面扩大）。
	// 未启用 SELinux 的发行版（无输出）不产线；启用后放宽由 DeepDive
	// 裁决是否预期。
	if raw := strings.TrimSpace(hm.rawCov("selinux_status")); raw != "" {
		switch raw {
		case "Permissive", "0":
			out = append(out, Anomaly{Host: hm.Host, Metric: "selinux_status", Key: raw, Severity: SevWarn,
				Desc: "SELinux 处于 Permissive（宽容）模式——强制访问控制未生效，需裁决是否预期"})
		case "Disabled":
			out = append(out, Anomaly{Host: hm.Host, Metric: "selinux_status", Key: raw, Severity: SevWarn,
				Desc: "SELinux 已禁用（Disabled）——强制访问控制关闭，需裁决是否预期"})
		}
	}
	// 关键配置文件 immutable 位（chattr +i）：加固防篡改与恶意防删
	// （篡改者锁死文件防恢复）两面——产线由 DeepDive 裁决。
	if raw := hm.rawCov("immutable_files"); raw != "" {
		for _, line := range strings.Split(raw, "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) < 2 || !strings.Contains(fields[0], "i") {
				continue
			}
			out = append(out, Anomaly{Host: hm.Host, Metric: "immutable_files", Key: fields[1], Severity: SevWarn,
				Desc: fmt.Sprintf("关键配置文件 %s 带 immutable 位（%s）——防篡改加固或恶意防删，需裁决", fields[1], fields[0])})
		}
	}
	return out
}

// judgeSuidOwners SUID 包归属校验（suid_owners 探针）：标准目录 SUID
// 与包数据库比对（rpm/dpkg/apk 链，发行版无关）。行格式 <路径>|<归属>；
// 归属为空/UNOWNED/查询失败 → 非包来源提权载体（后门特征）。归属工具
// 全无时探针无数据（raw 为空）→ 跳过不误报（数据驱动）。
func judgeSuidOwners(hm *HostMetric) []Anomaly {
	raw := hm.rawCov("suid_owners")
	if raw == "" {
		return nil
	}
	var out []Anomaly
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "|", 2)
		if len(parts) != 2 {
			continue
		}
		path, owner := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
		// 未归属判定：空/UNOWNED 哨兵，或包管理器错误文本（rpm -qf 对
		// 非包文件把 "not owned by any package" 写到 stdout，探针端用
		// 退出码兜底，此处再按文本识别双保险——不同发行版措辞不同）。
		if owner == "" || owner == "UNOWNED" || strings.Contains(owner, "not owned") ||
			strings.Contains(owner, "不属于") || strings.Contains(owner, "no path found") {
			out = append(out, Anomaly{Host: hm.Host, Metric: "suid_owners", Key: path, Severity: SevWarn,
				Desc: fmt.Sprintf("SUID 文件 %s 无任何已安装软件包归属（非包来源提权载体——后门/植入特征）", path)})
		}
	}
	return out
}

// parseSizeMB 解析容量后缀（K/M/G，大小写不敏感）为 MB 数。
// 无后缀按字节处理；非法输入返回 false。
