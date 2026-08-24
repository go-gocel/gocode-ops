package probe

// judge_hardening.go — 等保加固归属判定：数据驱动，无对应数据段即
// 跳过（容器/精简环境不误报）。只产 pending 线索，由 DeepDive 裁决
// 是否预期（云环境/业务特例可被排除）。

import (
	"fmt"
	"strconv"
	"strings"
)

// JudgeHardeningFacts is the entry point for attribution/threshold
// judgment of routine compliance (等保) hardening items.
// JudgeHardeningFacts 等保常规项的归属/阈值判定入口。
func JudgeHardeningFacts(hm *HostMetric) []Anomaly {
	var out []Anomaly
	out = append(out, judgeLoginDefs(hm)...)
	out = append(out, judgePwquality(hm)...)
	out = append(out, judgeFaillock(hm)...)
	out = append(out, judgeTimeSync(hm)...)
	out = append(out, judgeUmask(hm)...)
	out = append(out, judgeAuditd(hm)...)
	out = append(out, judgeSyslog(hm)...)
	out = append(out, judgeFirewallPolicy(hm)...)
	out = append(out, judgeSessionTimeout(hm)...)
	return out
}

// judgeLoginDefs 密码老化：PASS_MAX_DAYS>90 / PASS_MIN_LEN<8 /
// PASS_WARN_AGE<7 为等保弱基线。
func judgeLoginDefs(hm *HostMetric) []Anomaly {
	raw := hm.rawCov("login_defs")
	if raw == "" {
		return nil
	}
	var out []Anomaly
	for _, line := range strings.Split(raw, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		n, err := strconv.Atoi(fields[1])
		if err != nil {
			continue
		}
		switch fields[0] {
		case "PASS_MAX_DAYS":
			if n > 90 {
				out = append(out, Anomaly{Host: hm.Host, Metric: "login_defs", Key: "PASS_MAX_DAYS", Severity: SevWarn,
					Desc: fmt.Sprintf("密码最长有效期 PASS_MAX_DAYS=%d（等保基线 ≤90 天）", n)})
			}
		case "PASS_MIN_LEN":
			if n < 8 {
				out = append(out, Anomaly{Host: hm.Host, Metric: "login_defs", Key: "PASS_MIN_LEN", Severity: SevWarn,
					Desc: fmt.Sprintf("密码最小长度 PASS_MIN_LEN=%d（等保基线 ≥8）", n)})
			}
		case "PASS_WARN_AGE":
			if n < 7 {
				out = append(out, Anomaly{Host: hm.Host, Metric: "login_defs", Key: "PASS_WARN_AGE", Severity: SevWarn,
					Desc: fmt.Sprintf("密码过期预警 PASS_WARN_AGE=%d（等保基线 ≥7 天）", n)})
			}
		}
	}
	return out
}

// judgePwquality 密码复杂度与口令重复限制：minlen < 8 为等保弱基线；
// remember（口令重复使用限制）缺失或 <5 为等保弱基线（等保要求近期
// 口令不得重复）。
func judgePwquality(hm *HostMetric) []Anomaly {
	raw := hm.rawCov("pwquality")
	if raw == "" {
		return nil
	}
	var out []Anomaly
	rememberSeen := false
	for _, line := range strings.Split(raw, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		switch fields[0] {
		case "minlen":
			n, err := strconv.Atoi(fields[2])
			if err != nil || n >= 8 {
				continue
			}
			out = append(out, Anomaly{Host: hm.Host, Metric: "pwquality", Key: "minlen", Severity: SevWarn,
				Desc: fmt.Sprintf("密码复杂度 minlen=%d（等保基线 ≥8）", n)})
		case "remember":
			rememberSeen = true
			n, err := strconv.Atoi(fields[2])
			if err != nil || n >= 5 {
				continue
			}
			out = append(out, Anomaly{Host: hm.Host, Metric: "pwquality", Key: "remember", Severity: SevWarn,
				Desc: fmt.Sprintf("口令重复使用限制 remember=%d（等保基线 ≥5 次内不得重复）", n)})
		}
	}
	// 有 pwquality 配置但未设置 remember：等保要求近期口令不得重复。
	if !rememberSeen {
		out = append(out, Anomaly{Host: hm.Host, Metric: "pwquality", Key: "remember", Severity: SevWarn,
			Desc: "未配置口令重复使用限制（remember 缺失）——等保基线要求近期口令不得重复"})
	}
	return out
}

// judgeFaillock 登录失败锁定：deny 存在且 >5（或 =0 关闭）为等保弱
// 基线（要求连续失败锁定，deny ≤5）。
// 系统使用 PAM 密码认证（auth_chain 含 pam_unix/pam_pwquality）但
// 完全未配置 faillock → 同样产线（等保要求失败锁定，未配置即不合规）。
// 无 PAM 数据（容器/无密码认证面）→ 跳过（数据驱动）。
func judgeFaillock(hm *HostMetric) []Anomaly {
	raw := hm.rawCov("faillock_cfg")
	if raw == "" {
		chain := hm.rawCov("auth_chain")
		if chain == "" || (!strings.Contains(chain, "pam_unix") && !strings.Contains(chain, "pam_pwquality")) {
			return nil
		}
		return []Anomaly{{Host: hm.Host, Metric: "faillock_cfg", Key: "deny", Severity: SevWarn,
			Desc: "未配置登录失败锁定（faillock deny 缺失）——等保基线要求连续失败锁定（≤5 次）"}}
	}
	var out []Anomaly
	for _, line := range strings.Split(raw, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 || fields[0] != "deny" {
			continue
		}
		n, err := strconv.Atoi(fields[2])
		if err != nil || (n > 0 && n <= 5) {
			continue
		}
		weak := fmt.Sprintf("deny=%d（等保基线 ≤5 次失败锁定）", n)
		if n == 0 {
			weak = "deny=0（失败锁定已关闭）"
		}
		out = append(out, Anomaly{Host: hm.Host, Metric: "faillock_cfg", Key: "deny", Severity: SevWarn,
			Desc: "登录失败锁定弱基线：" + weak})
	}
	return out
}

// judgeTimeSync 时间同步：timedatectl 声明未同步且 chronyc 无成功
// 跟踪证据 → 线索（无任何数据段则跳过）。
func judgeTimeSync(hm *HostMetric) []Anomaly {
	raw := hm.rawCov("time_sync")
	if raw == "" {
		return nil
	}
	if strings.Contains(raw, "Reference ID") {
		return nil // chronyc tracking 成功：同步中
	}
	if strings.Contains(raw, "NTPSynchronized=no") {
		return []Anomaly{{Host: hm.Host, Metric: "time_sync", Key: "NTPSynchronized", Severity: SevWarn,
			Desc: "系统时间未与 NTP 同步（timedatectl NTPSynchronized=no）——等保基线要求时间同步"}}
	}
	return nil
}

// judgeUmask 登录 umask：002/000 属放宽（等保基线 022 或更严）。
// 数值比较：八进制值 < 022 即弱于基线（002<022、007<022；077>022
// 属更严不产线）。
func judgeUmask(hm *HostMetric) []Anomaly {
	raw := hm.rawCov("umask_cfg")
	if raw == "" {
		return nil
	}
	var out []Anomaly
	for _, line := range strings.Split(raw, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		// 兼容 "umask 022"（profile 系）与 "UMASK 022"（login.defs）。
		val := fields[len(fields)-1]
		if len(val) != 3 {
			continue
		}
		n, err := strconv.ParseInt(val, 8, 64)
		if err != nil {
			continue
		}
		if n >= 0o22 {
			continue
		}
		out = append(out, Anomaly{Host: hm.Host, Metric: "umask_cfg", Key: val, Severity: SevWarn,
			Desc: fmt.Sprintf("登录 umask=%s（等保基线 ≥022，当前放宽）", val)})
	}
	return out
}

// judgeAuditd 审计服务：systemctl is-active 非 active，或 auditctl
// enabled=0 → 线索（无任何输出则跳过：未安装审计组件）。
func judgeAuditd(hm *HostMetric) []Anomaly {
	raw := strings.TrimSpace(hm.rawCov("auditd_cfg"))
	if raw == "" {
		return nil
	}
	var out []Anomaly
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case line == "active":
			// 服务运行中：继续看 auditctl（enabled 可能是 0）
		case line == "inactive" || line == "failed" || line == "unknown":
			out = append(out, Anomaly{Host: hm.Host, Metric: "auditd_cfg", Key: "auditd", Severity: SevWarn,
				Desc: fmt.Sprintf("审计服务 auditd 未运行（systemctl is-active=%s）——等保基线要求审计开启", line)})
		case strings.HasPrefix(line, "enabled"):
			fields := strings.Fields(line)
			if len(fields) >= 2 && fields[1] == "0" {
				out = append(out, Anomaly{Host: hm.Host, Metric: "auditd_cfg", Key: "enabled", Severity: SevWarn,
					Desc: "内核审计已关闭（auditctl enabled=0）——等保基线要求审计开启"})
			}
		}
	}
	return out
}

// judgeSyslog 日志服务：rsyslog 与 syslog-ng 都非 active → 线索
// （无任何输出则跳过：未安装日志服务，由 DeepDive 按环境裁决）。
func judgeSyslog(hm *HostMetric) []Anomaly {
	raw := strings.TrimSpace(hm.rawCov("syslog_cfg"))
	if raw == "" {
		return nil
	}
	lines := strings.Fields(raw) // 两个 is-active 输出可能各占一行或同行
	hasActive := false
	for _, l := range lines {
		if l == "active" {
			hasActive = true
			break
		}
	}
	if hasActive {
		return nil
	}
	return []Anomaly{{Host: hm.Host, Metric: "syslog_cfg", Key: "syslog", Severity: SevWarn,
		Desc: "日志服务 rsyslog/syslog-ng 均未运行——等保基线要求日志采集面开启"}}
}

// judgeFirewallPolicy 防火墙默认策略：INPUT/FORWARD 默认 ACCEPT →
// 线索（等保基线默认拒绝；云安全组场景由 DeepDive 裁决）。
func judgeFirewallPolicy(hm *HostMetric) []Anomaly {
	raw := hm.rawCov("firewall_policy")
	if raw == "" {
		return nil
	}
	var out []Anomaly
	for _, line := range strings.Split(raw, "\n") {
		// iptables -S 行形如 "-P INPUT ACCEPT"。OUTPUT 默认 ACCEPT 是
		// 常规基线，不产线（等保要求的是入向/转发默认拒绝）。
		fields := strings.Fields(line)
		if len(fields) < 3 || fields[0] != "-P" || fields[1] == "OUTPUT" || fields[2] != "ACCEPT" {
			continue
		}
		out = append(out, Anomaly{Host: hm.Host, Metric: "firewall_policy", Key: fields[1], Severity: SevWarn,
			Desc: fmt.Sprintf("防火墙 %s 链默认策略 ACCEPT（等保基线默认拒绝；云环境安全组场景需裁决是否预期）", fields[1])})
	}
	return out
}

// judgeSessionTimeout 会话空闲超时（TMOUT）：等保身份鉴别要求登录
// 会话空闲超时自动退出。profile 系（/etc/profile、profile.d、bashrc、
// csh.cshrc）均无 TMOUT 配置 → 会话永不超时（弱基线）。TMOUT=0 同
// 样视为关闭超时。哨兵：NO_PROFILE（无 profile 文件的环境，非 shell
// 会话面）或空输出（探针失败）→ 跳过不误报（数据驱动）。
func judgeSessionTimeout(hm *HostMetric) []Anomaly {
	raw := hm.rawCov("session_timeout")
	if raw == "" || strings.Contains(raw, "NO_PROFILE") || !strings.Contains(raw, "PROFILE_PRESENT") {
		return nil
	}
	// 解析全部 TMOUT 值：存在 >0 的 TMOUT 即视为已配置超时。
	configured := false
	for _, line := range strings.Split(raw, "\n") {
		i := strings.IndexByte(line, '=')
		if i < 0 {
			continue
		}
		n, err := strconv.Atoi(strings.TrimSpace(line[i+1:]))
		if err != nil || n <= 0 {
			continue
		}
		configured = true
		break
	}
	if configured {
		return nil
	}
	return []Anomaly{{Host: hm.Host, Metric: "session_timeout", Key: "TMOUT", Severity: SevWarn,
		Desc: "未配置会话空闲超时（TMOUT 缺失或为 0）——等保基线要求登录会话空闲超时自动退出"}}
}
