package probe

import (
	"sort"
	"strings"
)

// judge_signals.go — 信号词表与探针计划：指标→稳定信号名映射、信号→探针展开（去重键单一来源）。

var signalByMetric = map[string]string{
	"cpu":          "cpu_high",
	"mem":          "mem_low",
	"disk":         "disk_high",
	"inode":        "inode_high",
	"zombie":       "zombie_procs",
	"svc_failed":   "svc_failed",
	"svc_inactive": "svc_inactive",
	"log_errors":   "log_errors",
	// 配置漂移信号（stateDrift 直接产线；进词表供模型阶段复用同根因去重）。
	"config_drift": "config_drift",
	"container":    "container_down",
	"suid_files":   "suid_files",
	"suid_owners":  "suid_unowned",
	// 安全弱配置信号（Security 兜底探针；模型阶段的 security findings
	// 也应复用这些信号名，同根因不分裂）。
	"world_writable": "world_writable",
	"ssh_root_login": "ssh_root_login",
	// 安全事实归属信号（机制 1 枚举探针）：任何端口/账号/大文件被同一
	// 归属规则覆盖（非针对具体形态的检测）。
	"listen_ports": "unattributed_listen",
	// UDP 监听面独立信号：与 TCP 同归属机制，但同地址:端口在 TCP/UDP
	// 两面都异常时不得互吞（去重键为 addr:port，共用信号会合并）。
	"listen_udp": "unattributed_listen_udp",
	"uid0_users": "abnormal_uid0",
	"big_files":  "oversized_file",
	// 进程/内核/网络/交换面（迭代扩展）：单进程 CPU、内核事件痕迹、
	// 网卡错误、swap 依赖、已删除二进制进程——同根因去重词表统一。
	"proc_top":      "proc_top_cpu",
	"kernel_events": "kernel_events",
	"net_if_errors": "net_if_errors",
	"swap":          "swap_high",
	"proc_deleted":  "proc_deleted_bin",
	// 系统时钟：跨主机时间偏差（引擎侧判定层对比，skew 超限产线）。
	"clock": "clock_skew",
	// 扩展面（轻/快/广）：D 状态进程（IO/NFS 挂死）、fd 使用率
	// （fd 耗尽故障）——同根因去重词表统一。
	"proc_dstate": "dstate_procs",
	"file_desc":   "fd_high",
	// Kubernetes 面（metrics_k8s.go）：异常 Pod / 未就绪 Deployment /
	// NotReady 节点（数值指标，对象级键）；敏感配置对象与明文 env 名
	// （归属规则，名称级键）。
	"k8s_pod_abnormal":   "k8s_pod_abnormal",
	"k8s_imgpull":        "k8s_img_pull",
	"k8s_deploy_unready": "k8s_deploy_unready",
	"k8s_node_notready":  "k8s_node_notready",
	"k8s_secrets":        "k8s_sensitive_obj",
	"k8s_deploy_env":     "k8s_deploy_env_sensitive",
	"k8s_svcs":           "k8s_svc_no_backend",
	"k8s_endpoints":      "k8s_svc_no_backend",
	// 服务面形态归类数据段（R2 快检进化）：复检须一并重采，否则处置后
	// 判定层仍按旧数据归类。
	"k8s_svc_selectors": "k8s_svc_no_backend",
	"k8s_pod_labels":    "k8s_svc_no_backend",
	// 存储面（R3 快检进化）：PVC 未绑定 + SC 存在性归类，复检一并重采。
	"k8s_pvcs": "k8s_pvc_abnormal",
	"k8s_scs":  "k8s_pvc_abnormal",
	// 调度面（R4 快检进化）：节点不可调度/污点，复检一并重采。
	"k8s_node_unsched": "k8s_node_unschedulable",
	"k8s_node_taints":  "k8s_node_tainted",
	// LVM 面（metrics_lvm.go）：逻辑卷使用率。
	"lvm_lv_full": "lvm_lv_full",
	// 等保加固面（metrics_hardening.go）：密码策略（login.defs/
	// pwquality/faillock 三探针同信号，复检全源重采）、时间同步、
	// umask、审计/日志服务、防火墙默认策略。
	"login_defs":      "passwd_policy_weak",
	"pwquality":       "passwd_policy_weak",
	"faillock_cfg":    "passwd_policy_weak",
	"time_sync":       "time_sync_off",
	"umask_cfg":       "umask_weak",
	"auditd_cfg":      "auditd_off",
	"syslog_cfg":      "syslog_off",
	"firewall_policy": "firewall_permissive",
	"session_timeout": "no_session_timeout",
	// 目标零可见性（采集完整性）：指标/状态/事实全空且无采集错误——
	// 管理通道异常（口令过期/账户锁定/无 shell）的判定层信号。
	"collect_visibility": "target_no_data",
}

// SignalNames returns the stable signal table, referenced by protocol
// prompts so the model names signals per the table.
// SignalNames 返回稳定信号词表（供协议提示词引用，模型按词表命名）。
func SignalNames() []string {
	out := make([]string, 0, len(signalByMetric))
	for _, s := range signalByMetric {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// SignalProbePlan returns the targeted collection plan needed to recheck
// a signal after remediation (deterministic rechecking): metricIDs are
// the numeric probe IDs and factIDs the security-fact probe IDs; an
// empty result means the signal has no judgment-layer source.
// SignalProbePlan 返回复检 signal 所需的定向采集计划（处置后确定性
// 复检用）：metricIDs=数值指标探针 ID，factIDs=安全事实探针 ID。
// 返回空=该 signal 无判定层源（如 config_drift 由基线机制负责）——
// 调用方无需采集即可放行（与全量复检语义一致：判定层不会重新命中）。
//
// 映射来源单一：signalByMetric 词表 + 归属规则信号的 "<probeID>_anomaly"
// 兜底命名（Signal() 的 fallback）。依赖处理：listen_ports 的归属判定
// 依赖 svc_units（运行中服务单元），必须一并采集——否则无归属依据时
// JudgeSecurityFacts 保守不产线，复检会漏掉仍存在的线索（假放行）。
func SignalProbePlan(env *Env, signal string) (metricIDs, factIDs []string) {
	norm := normKey(signal)
	if norm == "config_drift" {
		return nil, nil
	}
	set := map[string]bool{}
	for id, sig := range signalByMetric {
		if normKey(sig) == norm {
			set[id] = true
		}
	}
	if strings.HasSuffix(norm, "_anomaly") {
		set[strings.TrimSuffix(norm, "_anomaly")] = true
	}
	if set["listen_ports"] || set["listen_udp"] {
		set["svc_units"] = true // 归属判定依据（缺失时保守不产线）
	}
	// 复检必须穷尽（处置后"线索仍存在"要在全量面上确认）：例行定点
	// 探针（suid_files/world_writable）覆盖不到非标准位置/数据面——
	// 复检改走全盘下钻变体，避免"非标准位置的 SUID 未被例行探针看到"
	// 被误判为已处置（假放行）。
	if set["suid_files"] {
		delete(set, "suid_files")
		set["suid_files_full"] = true
	}
	// 非包来源 SUID（suid_unowned）复检走全盘下钻：处置后确认全盘
	// 再无未归属 SUID（例行定点只覆盖标准目录）。
	if set["suid_owners"] {
		delete(set, "suid_owners")
		set["suid_files_full"] = true
	}
	if set["world_writable"] {
		delete(set, "world_writable")
		set["world_writable_full"] = true
	}
	facts := map[string]bool{}
	for _, f := range securityFacts(env) {
		facts[f.ID] = true
	}
	metrics := map[string]bool{}
	for _, m := range Metrics(env) {
		metrics[m.ID] = true
	}
	for _, m := range SecurityMetrics(env) {
		metrics[m.ID] = true
	}
	for id := range set {
		switch {
		case id == "cpu":
			// CPU 由采集器恒附加采集（/proc/stat），不属清单探针。
		case facts[id]:
			factIDs = append(factIDs, id)
		case metrics[id]:
			metricIDs = append(metricIDs, id)
		}
	}
	sort.Strings(metricIDs)
	sort.Strings(factIDs)
	return metricIDs, factIDs
}

// KnownSignals returns all known stable signal names, the exported face
// of the dedup-key table's single source: L0 probe signals plus common
// model-phase signals.
// KnownSignals 返回全部已知稳定信号名（去重键词表单一来源的导出面）：
// L0 探针信号 + 模型阶段常见信号。respond 处置目标匹配用它区分
// "模型乱写 finding_id"（候选不在词表，可单目标兜底）与"写错信号"
// （候选在词表但指向别的故障——跨信号错配风险，宁可不执行）。
func KnownSignals() []string {
	seen := map[string]bool{}
	for _, sig := range signalByMetric {
		seen[sig] = true
	}
	// 模型阶段信号（DeepDive/respond 自报，不在 L0 词表）。
	for _, sig := range []string{
		"backdoor_hint", "tampered_hint", "ssh_root_login", "state_drift",
		"exposed_listen", "svc_failed", "config_drift", "suid_files",
		"unexpected_suid", "suid_unowned",
	} {
		seen[sig] = true
	}
	out := make([]string, 0, len(seen))
	for sig := range seen {
		out = append(out, sig)
	}
	sort.Strings(out)
	return out
}

// Signal 返回 anomaly 的触发信号名（incident 聚合键，如 disk_high）。
