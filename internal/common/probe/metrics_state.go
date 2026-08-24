package probe

// metrics_state.go — 状态探针：期望状态逐项采集（配置漂移检测的观测侧）。

func StateProbeFragment(env *Env, id string) string {
	for _, sp := range StateProbes(env) {
		if sp.ID == id {
			return sp.Fragment(env)
		}
	}
	return ""
}

// StateProbes 状态快照探针（配置漂移检测）：对关键配置/状态做内容
// 级快照，跨轮对比“变化即痕”——无日志痕迹的故障（配置被改、监听
// 变化、计划任务被改）由此确定性检出。首轮为基线快照，后续轮对比；
// 变化产 config_drift 线索由 DeepDive 裁决是否预期。内容级（非摘要）
// 是重基线轮行级归属的前提（见 engine.stateDrift）。env 为 nil 时按
// 无 systemd/ss 处理（仅归属判定用）。
func StateProbes(env *Env) []Metric {
	probes := []Metric{
		{ID: "state_sshd", Name: "sshd 配置内容",
			Fragment: func(*Env) string { return "cat /etc/ssh/sshd_config 2>/dev/null" }},
		{ID: "state_crontab", Name: "计划任务内容",
			Fragment: func(*Env) string { return "cat /etc/crontab /etc/cron.d/* 2>/dev/null" }},
		// 静态状态异常（挂载掩盖、内核参数投毒、凭证条目变化、登录
		// 提示/登录链篡改、sudoers 扩展）可能不越任何数值阈值——
		// 把这些关键状态纳入漂移快照，跨轮变化即痕。
		// 快照为内容级（非 sha256 摘要）：重基线轮需要行级 diff 才能
		// 区分“引擎自身处置引起的变化”与“攻击者交错注入的变化”
		// （R14 实测：摘要级豁免把攻击者追加行一并吞进新基线）。
		{ID: "state_mounts", Name: "挂载表内容",
			Fragment: func(*Env) string { return "mount 2>/dev/null | awk '{print $1, $3, $5}' | sort" }},
		{ID: "state_sysctl", Name: "关键内核参数",
			Fragment: func(*Env) string { return "sysctl net.ipv4.ip_forward kernel.core_pattern 2>/dev/null" }},
		{ID: "state_authkeys", Name: "authorized_keys 条目数",
			Fragment: func(*Env) string { return "wc -l /root/.ssh/authorized_keys 2>/dev/null || echo 0" }},
		{ID: "state_motd", Name: "登录提示内容",
			Fragment: func(*Env) string { return "cat /etc/motd 2>/dev/null" }},
		{ID: "state_shellinit", Name: "shell 启动文件内容",
			Fragment: func(*Env) string {
				return "for f in /etc/profile /etc/bashrc /root/.bashrc /root/.bash_profile /root/.bash_login /root/.profile /etc/profile.d/*; do echo \"== $f\"; cat \"$f\" 2>/dev/null; done"
			}},
		{ID: "state_sudoersd", Name: "sudoers.d 清单",
			Fragment: func(*Env) string { return "ls -1 /etc/sudoers.d/ 2>/dev/null" }},
		// 静态状态异常的扩展漂移面：重启、IP/路由/DNS 变化、用户面
		// 新增、全局环境/链接器配置篡改、防火墙规则变化、用户计划
		// 任务新增、authorized_keys 文件新增——都不越数值阈值，
		// 跨轮内容对比"变化即痕"（与既有 state_* 同一机制）。
		{ID: "state_uptime", Name: "系统运行时长（重启检测）",
			Fragment: func(*Env) string { return "cat /proc/uptime 2>/dev/null" }},
		{ID: "state_interfaces", Name: "网卡地址清单",
			Fragment: func(*Env) string { return "ip -br addr 2>/dev/null | sort" }},
		{ID: "state_routes", Name: "路由表",
			Fragment: func(*Env) string { return "ip route 2>/dev/null | sort" }},
		{ID: "state_resolv", Name: "DNS 配置内容",
			Fragment: func(*Env) string { return "cat /etc/resolv.conf 2>/dev/null" }},
		{ID: "state_passwd", Name: "用户面（passwd）",
			Fragment: func(*Env) string {
				return "awk -F: '{print $1\":\"$3\":\"$6\":\"$7}' /etc/passwd 2>/dev/null | sort"
			}},
		{ID: "state_env", Name: "全局环境变量内容",
			Fragment: func(*Env) string { return "cat /etc/environment 2>/dev/null" }},
		{ID: "state_ldconf", Name: "动态链接器配置内容",
			Fragment: func(*Env) string { return "cat /etc/ld.so.conf /etc/ld.so.conf.d/*.conf 2>/dev/null" }},
		// 防火墙规则面：规则被清空/替换是攻击者的清理与投毒动作
		// （iptables -S + nft ruleset 双栈覆盖；无防火墙主机输出为空，
		// 空键基线语义与既有探针一致）。
		{ID: "state_firewall", Name: "防火墙规则",
			Fragment: func(*Env) string {
				return "iptables -S 2>/dev/null; nft list ruleset 2>/dev/null"
			}},
		{ID: "state_usercrons", Name: "用户计划任务内容",
			Fragment: func(*Env) string {
				return "cat /var/spool/cron/* /var/spool/cron/crontabs/* 2>/dev/null"
			}},
		// authorized_keys 文件清单：新增授权文件 = 后门密钥落地面
		// （state_authkeys 只覆盖 root 的行数，新增文件的漂移由本探针
		// 检出——find 定点 maxdepth 有界）。
		{ID: "state_authfiles", Name: "authorized_keys 文件清单",
			Fragment: func(*Env) string {
				return "find /root /home -maxdepth 3 -name authorized_keys -type f 2>/dev/null | sort"
			}},
		// 内核模块清单变化：新模块加载即痕（rootkit 加载面；事实探针
		// kernel_modules 同源，漂移负责变化检测）。
		{ID: "state_kmods", Name: "内核模块清单",
			Fragment: func(*Env) string {
				return "cat /proc/modules 2>/dev/null | awk '{print $1}' | sort"
			}},
		// at 任务变化：一次性计划任务新增即痕（事实探针 at_jobs 同源）。
		{ID: "state_at", Name: "at 任务队列",
			Fragment: func(*Env) string {
				return "atq 2>/dev/null; ls /var/spool/at/ /var/spool/atd/ 2>/dev/null"
			}},
		// 自定义 systemd 单元文件变化：新增 .service/.d 覆盖即痕
		// （事实探针 systemd_custom 同源）。
		{ID: "state_systemd_custom", Name: "自定义 systemd 单元清单",
			Fragment: func(*Env) string {
				return "find /etc/systemd/system -maxdepth 2 -type f 2>/dev/null | sort"
			}},
		// SysV init 脚本清单：init.d 新增脚本即痕（老式服务持久化面）。
		{ID: "state_initd", Name: "init.d 脚本清单",
			Fragment: func(*Env) string { return "ls -1 /etc/init.d/ 2>/dev/null" }},
		// LVM 逻辑卷尺寸快照：LV 扩容/缩容/新增即痕（磁盘扩容场景的
		// 变更检测面；无 LVM 的主机输出空，空键基线语义与既有探针一致）。
		{ID: "state_lvm", Name: "LVM 逻辑卷尺寸",
			Fragment: func(*Env) string {
				return "command -v lvs >/dev/null 2>&1 && lvs --noheadings -o lv_name,vg_name,lv_size --units b --nosuffix 2>/dev/null || true"
			}},
	}
	if env != nil && env.HasSystemd {
		probes = append(probes, Metric{ID: "state_units", Name: "服务单元清单",
			Fragment: func(*Env) string { return "systemctl list-unit-files --no-legend 2>/dev/null" }})
		// systemd 定时器面：计划任务的第三面（系统 cron + 用户 cron +
		// systemd timer）。进程派生类（systemd 状态面）——重基线轮
		// 静默豁免（见 engine.ephemeralStateProbes）。
		probes = append(probes, Metric{ID: "state_timers", Name: "systemd 定时器清单",
			Fragment: func(*Env) string {
				return "systemctl list-timers --all --no-pager --no-legend 2>/dev/null"
			}})
	}
	if env != nil && env.HasSS {
		probes = append(probes, Metric{ID: "state_ports", Name: "监听端口清单",
			Fragment: func(*Env) string { return "ss -tln 2>/dev/null" }})
	}
	return probes
}

// parseCountLines 数非空行数（如 systemctl --failed 的失败单元数）。
