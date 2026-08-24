package l0

// engine_keynote.go — 关键提示与安全事实 ID：注入本轮上下文的知识要点。

import (
	"fmt"
	"strings"
)

func KeyNote(key string) string {
	if key == "" {
		return ""
	}
	return "[" + key + "]"
}

// publishL0Facts 把最近一轮 L0 安全事实（监听端口/用户/大文件/连接）
// 写入工作区，随 StateSummary 进模型上下文。TTL 缓存复用的事实标注
// 采集龄期——大脑需要知道数据新鲜度才能正确裁决。
// 覆盖语义（design-v2.md §二）：覆盖度是事实的一部分，同步发布——
// 报告审计面据此展示 partial/skipped，模型上下文据此不把不完整枚举
// 当全量。
func (e *Engine) publishL0Facts(snap *Snapshot) {
	facts := map[string]string{}
	coverage := map[string]map[string]string{}
	for i := range snap.Hosts {
		hm := &snap.Hosts[i]
		var parts []string
		for _, id := range securityFactIDs() {
			if raw := hm.Raw[id]; raw != "" {
				header := "## " + id
				if age, ok := hm.FactAge[id]; ok {
					header += fmt.Sprintf("（TTL 缓存，%s 前采集）", age)
				}
				parts = append(parts, header+"\n"+raw)
			}
		}
		if len(parts) > 0 {
			facts[hm.Host] = strings.Join(parts, "\n")
		}
		if len(hm.FactCoverage) > 0 {
			coverage[hm.Host] = hm.FactCoverage
		}
	}
	e.ws.SetL0Facts(facts)
	e.ws.SetL0Coverage(coverage)
}

// securityFactIDs 安全事实探针 ID 顺序（采集与上下文管道共用单一来源）。
func securityFactIDs() []string {
	return []string{"listen_ports", "listen_udp", "uid0_users", "big_files", "estab_conns", "svc_units",
		"mounts", "sysctl_keys", "tmp_dirs", "shell_init_hooks", "file_caps",
		"world_writable", "auth_chain", "ssh_chain", "cron_chain", "sudo_chain",
		"net_identity", "empty_passwords", "arp_neighbors", "journald_cfg",
		"ld_preload", "resolv_conf", "user_crons", "rc_local", "env_global",
		"ld_so_conf", "kernel_modules", "promisc_ifaces", "udev_rules", "at_jobs",
		"systemd_custom", "selinux_status", "immutable_files", "login_trail",
		// Kubernetes 面（k8s 对象级事实进模型上下文：模型不可跳过，
		// 判定权仍在 DeepDive）。
		"k8s_pods", "k8s_deploys", "k8s_nodes", "k8s_quota", "k8s_secrets",
		"k8s_deploy_env", "k8s_events",
		// LVM 拓扑（扩容决策数据面）。
		"lvm_state",
		// 等保常规加固面（密码策略/时间同步/umask/审计日志/防火墙默认
		// 策略——模型裁决是否预期）。
		"login_defs", "pwquality", "faillock_cfg", "time_sync", "umask_cfg",
		"auditd_cfg", "syslog_cfg", "firewall_policy"}
}

// ephemeralStateProbes 进程派生类状态探针：引擎自身处置（杀进程/启停
// 服务/扩容逻辑卷）必然改变其内容且无法行级归属——重基线轮整体跳过
// 对比；其余文件内容类探针在重基线轮仍做行级 diff + 自身动作归属。
// state_lvm 同属：引擎 lvextend/lvreduce 后 LV 尺寸必然变化（行内容
// 为数值，无法与命令原文匹配归属），与 state_units 同类处理。
var ephemeralStateProbes = map[string]bool{"state_units": true, "state_ports": true, "state_timers": true, "state_lvm": true}

// stateDrift 配置漂移检测：本轮状态快照与上一轮内容级对比，变化产
// config_drift 线索（warn 级，由 DeepDive 裁决变化是否预期——发版/授权
// 变更 vs 恶意篡改）。首轮无基线只存快照；多条目变化合并为一条。
//
// rebaseline 为 true（自身处置后）：进程派生类探针跳过；内容类探针的
// 变化行全部能被 selfCmds 解释时豁免（静默重基线），解释不了的变化
// （攻击者与自身处置交错同一目标）照常产线索并附自身动作清单供裁决。
