package probe

// metrics_hardening.go — 等保常规加固检查探针（事实级）：密码策略
// （老化/复杂度/失败锁定）、时间同步、umask、审计与日志服务、防火墙
// 默认策略。判定在 judge_hardening.go（归属规则模式：数据驱动，无
// 数据即跳过——容器/精简环境不误报）。

// hardeningFacts 返回等保加固事实探针（例行采集，原始数据进上下文 +
// 归属规则产线索）。
func hardeningFacts() []Metric {
	return []Metric{
		// 密码老化策略（/etc/login.defs）：PASS_MAX_DAYS/PASS_MIN_LEN/
		// PASS_WARN_AGE 是等保密码策略核心项（RHEL 系在此，Debian 系
		// 同文件）。
		{ID: "login_defs", Name: "密码策略（login.defs）",
			Fragment: func(*Env) string {
				return "grep -hE '^(PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_MIN_LEN|PASS_WARN_AGE)' /etc/login.defs 2>/dev/null"
			}},
		// 密码复杂度（pwquality.conf）：minlen 是复杂度下限（等保要求
		// 长度与字符集组合；此处只判长度基线，组合策略由 DeepDive
		// 读原始配置裁决）。remember 是口令重复使用限制（等保要求
		// 近期口令不得重复，重复次数基线 ≥5）。
		{ID: "pwquality", Name: "密码复杂度（pwquality）",
			Fragment: func(*Env) string {
				return "grep -hE '^\\s*(minlen|dcredit|ucredit|lcredit|ocredit|difok|retry|remember)' /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf 2>/dev/null"
			}},
		// 登录失败锁定（faillock）：等保要求连续失败锁定（deny ≤5）。
		{ID: "faillock_cfg", Name: "登录失败锁定（faillock）",
			Fragment: func(*Env) string {
				return "grep -hE '^\\s*(deny|unlock_time|fail_interval)' /etc/security/faillock.conf /etc/security/pam_faillock.conf 2>/dev/null"
			}},
		// 时间同步状态：timedatectl NTPSynchronized 或 chronyc tracking
		// （chrony 成功输出含 "Reference ID" 行；ntpd 场景走 timedatectl）。
		{ID: "time_sync", Name: "时间同步状态",
			Fragment: func(*Env) string {
				return "timedatectl show -p NTPSynchronized -p TimeUSec 2>/dev/null; chronyc tracking 2>/dev/null | head -n 3"
			}},
		// umask：登录会话新建文件权限掩码（等保基线 022；002/000 属
		// 放宽）。profile.d/*.sh 与 bash.bashrc 的登录链 umask 同看。
		{ID: "umask_cfg", Name: "umask 配置",
			Fragment: func(*Env) string {
				return "grep -hE '^\\s*umask\\s+[0-7]{3}' /etc/profile /etc/profile.d/*.sh /etc/bash.bashrc /etc/csh.cshrc 2>/dev/null; grep -hE '^UMASK\\s+[0-7]{3}' /etc/login.defs 2>/dev/null"
			}},
		// 审计服务（auditd）：等保要求审计功能开启。systemctl is-active
		// 输出 active/inactive/failed；auditctl -s 输出 "enabled 1/2"
		// （0=关闭）。
		{ID: "auditd_cfg", Name: "审计服务（auditd）",
			Fragment: func(*Env) string {
				return "systemctl is-active auditd 2>/dev/null; auditctl -s 2>/dev/null | head -n 3"
			}},
		// 日志服务（rsyslog/syslog-ng）：等保要求集中日志采集面开启。
		{ID: "syslog_cfg", Name: "日志服务（rsyslog/syslog-ng）",
			Fragment: func(*Env) string {
				return "systemctl is-active rsyslog 2>/dev/null; systemctl is-active syslog-ng 2>/dev/null"
			}},
		// 防火墙默认策略：iptables -P INPUT/FORWARD ACCEPT 是等保弱
		// 基线（云环境安全组场景由 DeepDive 裁决是否预期）。
		{ID: "firewall_policy", Name: "防火墙默认策略",
			Fragment: func(*Env) string {
				return "iptables -S 2>/dev/null | grep -E '^-P (INPUT|FORWARD) '"
			}},
		// 会话空闲超时（TMOUT）：等保身份鉴别要求登录会话空闲超时
		// 自动退出（基线 TMOUT=600 类）。profile 系无 TMOUT 配置 =
		// 会话永不超时（弱基线）。PROFILE_PRESENT/NO_PROFILE 哨兵
		// 区分"已检查但无配置"与"无 profile 环境"（容器非 shell
		// 会话面跳过，数据驱动）。
		{ID: "session_timeout", Name: "会话空闲超时（TMOUT）",
			Fragment: func(*Env) string {
				return "[ -f /etc/profile ] && echo PROFILE_PRESENT || echo NO_PROFILE; grep -hE '^[[:space:]]*(export[[:space:]]+|readonly[[:space:]]+)*TMOUT[[:space:]]*=[[:space:]]*[0-9]+' /etc/profile /etc/profile.d/*.sh /etc/bashrc /etc/csh.cshrc 2>/dev/null"
			}},
	}
}
