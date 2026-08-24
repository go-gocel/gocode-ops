package probe

import (
	"fmt"
	"math"
	"sort"
)

// Anomaly 一条异常判定结果。
type Anomaly struct {
	Host     string   `json:"host"`
	Metric   string   `json:"metric"` // 指标 ID（cpu/mem/disk/…）
	Key      string   `json:"key"`    // 指标内键（挂载点等）；空=整体
	Value    float64  `json:"value"`
	Warn     float64  `json:"warn"`
	Crit     float64  `json:"crit"`
	Severity Severity `json:"severity"`
	Desc     string   `json:"desc"`
}

// ObjectKey 判定 Anomaly.Key 是否为可区分对象键（挂载点/单元名/配置行等）：
// 聚合型指标（svc_failed 的 "count"、mem 的 "avail_pct"）的键不参与去重
// 与复检——"count" 不是对象，同 signal 应合并（模型与 L0 共用一条线索）；
// 事实型/逐对象型指标（sudo 违规行、挂载点、容器名）的键参与去重与复检。
func ObjectKey(k string) string {
	switch k {
	case "count", "avail_pct", "swap_pct":
		return ""
	}
	return k
}

// ToFinding 把异常转成 pending 线索：L0 确定性层只产线索不产结论，
// 确认权在验证回路（DeepDive 阶段模型验证后裁决）。
// 对象键一并带入：去重与处置后复检必须按对象粒度（同 signal 不同对象
// 不互吞——R20 实测 sudoers 本体行与 sudoers.d 文件同 signal 无键合并
// 成一条，处置只修了一个对象）。
func (a Anomaly) ToFinding() *Finding {
	f := NewFinding(a.Host, a.Metric, a.Signal(), a.Desc)
	f.Key = ObjectKey(a.Key)
	f.Evidence = []string{a.Desc}
	f.Source = SourceL0 // L0 确定性探针产出（merge 复发重置/行为层判定的证据链来源）
	return f
}

// signalByMetric 指标 → 稳定信号名的权威映射（去重键单一来源）：
// 模型阶段 findings 与 L0 线索共用同一词表，同根因不会因命名漂移
// 而分裂成多条重复确认。
func (a Anomaly) Signal() string {
	if s, ok := signalByMetric[a.Metric]; ok {
		return s
	}
	return a.Metric + "_anomaly"
}

// sevFor 按阈值判定严重度（failDown 时语义反转：越低越差）。
func sevFor(v, warn, crit float64, failDown bool) (Severity, bool) {
	if failDown {
		if v <= crit {
			return SevCrit, true
		}
		if v <= warn {
			return SevWarn, true
		}
		return "", false
	}
	if v >= crit {
		return SevCrit, true
	}
	if v >= warn {
		return SevWarn, true
	}
	return "", false
}

// Judge 对快照做异常判定：先逐台按阈值，再做跨主机横向对比。
// 返回的异常按严重度降序排列。
func Judge(snap *Snapshot, th Thresholds) []Anomaly {
	var out []Anomaly
	for i := range snap.Hosts {
		out = append(out, judgeHost(&snap.Hosts[i], th)...)
	}
	out = append(out, judgeCrossHost(snap, th)...)
	sortAnomalies(out)
	return out
}

// judgeHost 单台主机的阈值判定。
func judgeHost(hm *HostMetric, th Thresholds) []Anomaly {
	var out []Anomaly
	// 整机采集失败（sh 不可用/SSH 连不上）才是失联异常；
	// metric 级错误（如某命令在精简环境中缺失）只记入报告，不误报失联。
	if msg, ok := hm.Errors["collect"]; ok {
		out = append(out, Anomaly{
			Host: hm.Host, Metric: "collect", Severity: SevWarn,
			Desc: fmt.Sprintf("采集失败: %s", msg),
		})
	}
	if hm.CPU != nil && hm.CPU.Pct >= 0 {
		if sev, ok := sevFor(hm.CPU.Pct, th.CPUWarn, th.CPUCrit, false); ok {
			out = append(out, Anomaly{
				Host: hm.Host, Metric: "cpu", Value: hm.CPU.Pct,
				Warn: th.CPUWarn, Crit: th.CPUCrit, Severity: sev,
				Desc: fmt.Sprintf("CPU 使用率 %.1f%%（核数 %d）", hm.CPU.Pct, hm.CPU.NProc),
			})
		}
	}
	out = append(out, judgeMap(hm, "mem", "avail_pct", th.MemWarn, th.MemCrit, true)...)
	out = append(out, judgeTopKeys(hm, "disk", th.DiskWarn, th.DiskCrit, 2)...)
	out = append(out, judgeTopKeys(hm, "inode", th.InodeWarn, th.InodeCrit, 2)...)
	out = append(out, judgeMap(hm, "zombie", "count", float64(th.ZombieWarn), float64(th.ZombieCrit), false)...)
	if hm.Metrics["svc_failed"] != nil {
		out = append(out, judgeMap(hm, "svc_failed", "count", float64(th.SvcFailWarn), float64(th.SvcFailCrit), false)...)
	}
	if hm.Metrics["svc_inactive"] != nil {
		out = append(out, judgeMap(hm, "svc_inactive", "count", float64(th.SvcInactiveWarn), float64(th.SvcInactiveCrit), false)...)
	}
	if hm.Metrics["log_errors"] != nil {
		out = append(out, judgeMap(hm, "log_errors", "count", float64(th.LogErrorsWarn), float64(th.LogErrorsCrit), false)...)
	}
	if hm.Metrics["container"] != nil {
		out = append(out, judgeTopKeys(hm, "container", 1, 3, 3)...)
	}
	// 进程/内核/网络/交换面（迭代扩展）：对象级或聚合级阈值判定，
	// 与既有指标同一判定语义（数据驱动，无对应数据段即跳过）。
	if hm.Metrics["proc_top"] != nil {
		out = append(out, judgeTopKeys(hm, "proc_top", th.ProcTopWarn, th.ProcTopCrit, 1)...)
	}
	if hm.Metrics["kernel_events"] != nil {
		out = append(out, judgeMap(hm, "kernel_events", "count", float64(th.KernelEventsWarn), float64(th.KernelEventsCrit), false)...)
	}
	if hm.Metrics["net_if_errors"] != nil {
		out = append(out, judgeTopKeys(hm, "net_if_errors", float64(th.NetErrWarn), float64(th.NetErrCrit), 2)...)
	}
	if hm.Metrics["swap"] != nil {
		out = append(out, judgeMap(hm, "swap", "swap_pct", th.SwapWarn, th.SwapCrit, false)...)
	}
	if hm.Metrics["proc_deleted"] != nil {
		out = append(out, judgeMap(hm, "proc_deleted", "count", float64(th.ProcDeletedWarn), float64(th.ProcDeletedCrit), false)...)
	}
	if hm.Metrics["proc_dstate"] != nil {
		out = append(out, judgeTopKeys(hm, "proc_dstate", float64(th.DStateWarn), float64(th.DStateCrit), 3)...)
	}
	if hm.Metrics["file_desc"] != nil {
		out = append(out, judgeMap(hm, "file_desc", "fd_pct", th.FDWarn, th.FDCrit, false)...)
	}
	// Security 兜底探针（仅 Security 阶段失败时采集，常规 L0 无此数据）。
	if hm.Metrics["suid_files"] != nil {
		out = append(out, judgeMap(hm, "suid_files", "count", float64(th.SuidWarn), float64(th.SuidCrit), false)...)
	}
	if hm.Metrics["world_writable"] != nil {
		out = append(out, judgeMap(hm, "world_writable", "count", float64(th.WorldWritableWarn), float64(th.WorldWritableCrit), false)...)
	}
	if hm.Metrics["ssh_root_login"] != nil {
		out = append(out, judgeMap(hm, "ssh_root_login", "count", float64(th.SSHRootLoginWarn), float64(th.SSHRootLoginCrit), false)...)
	}
	// Kubernetes 面（k8s 数值指标，对象级键：异常 pod/未就绪
	// deployment/NotReady 节点——kubectl 可用主机才有数据段）。
	if hm.Metrics["k8s_pod_abnormal"] != nil {
		out = append(out, judgeTopKeys(hm, "k8s_pod_abnormal", 1, 3, 3)...)
	}
	if hm.Metrics["k8s_deploy_unready"] != nil {
		out = append(out, judgeTopKeys(hm, "k8s_deploy_unready", 1, 3, 3)...)
	}
	if hm.Metrics["k8s_node_notready"] != nil {
		out = append(out, judgeTopKeys(hm, "k8s_node_notready", 1, 3, 3)...)
	}
	// LVM 面：逻辑卷使用率（扩容场景；与 disk 同水位语义）。
	if hm.Metrics["lvm_lv_full"] != nil {
		out = append(out, judgeTopKeys(hm, "lvm_lv_full", 85, 95, 3)...)
	}
	// 安全事实归属判定（机制 1）：数据驱动，无对应数据段即跳过。
	out = append(out, JudgeSecurityFacts(hm)...)
	// k8s 敏感配置归属判定（名称级）。
	out = append(out, JudgeK8sFacts(hm)...)
	// 等保常规加固归属判定。
	out = append(out, JudgeHardeningFacts(hm)...)
	// 目标零可见性检查（采集完整性）：一轮采集后指标/状态/事实**全部**
	// 为空且无 collect 级错误——"无数据"与"健康"必须区分（覆盖语义
	// 哲学：静默缺失不得被当全绿）。触发形态：SSH 会话被 PAM 拒绝
	// （口令过期/账户锁定——命令 exit 1 但 banner 输出非空，execOne
	// 容错吞掉退出码后表现为"正常但零数据"）、远端无可用 shell、协议
	// 不兼容等。产线索驱动 DeepDive 下钻通道根因，同时阻止假收敛
	// （零可见性目标不满足"环境干净"）。
	if msg, ok := hm.Errors["collect"]; ok {
		// 整轮采集失败：既有 collect_anomaly 覆盖，不重复产线。
		_ = msg
	} else if len(hm.Metrics) == 0 && len(hm.State) == 0 && len(hm.Raw) == 0 {
		out = append(out, Anomaly{
			Host: hm.Host, Metric: "collect_visibility", Severity: SevWarn,
			Desc: "目标主机本轮采集零可见性（指标/状态/安全事实全部无数据且无采集错误）——管理通道异常或命令全部被拒（口令过期/账户锁定/无可用 shell 等），需下钻确认通道；在确认前不得视为环境健康",
		})
	}
	return out
}

// ── 安全事实归属判定（机制 1 线索层）────────────────────────────────

// listenLineRe 解析 ss -tlnp 行：本地地址:端口 + 首个进程名。
// 格式：LISTEN 0 511 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=200,fd=3))
func judgeMap(hm *HostMetric, metric, key string, warn, crit float64, failDown bool) []Anomaly {
	vals := hm.Metrics[metric]
	if vals == nil {
		return nil
	}
	v, ok := vals[key]
	if !ok {
		return nil
	}
	sev, hit := sevFor(v, warn, crit, failDown)
	if !hit {
		return nil
	}
	desc := fmt.Sprintf("%s=%.1f（阈值 %s%.1f）", metricName(metric), v, cmpWord(failDown), crit)
	return []Anomaly{{
		Host: hm.Host, Metric: metric, Key: key, Value: v,
		Warn: warn, Crit: crit, Severity: sev,
		Desc: desc,
	}}
}

// judgeTopKeys 多键指标（磁盘挂载点）的阈值判定：每台主机最多保留
// topN 个最严重键，避免挂载点刷屏。
func judgeTopKeys(hm *HostMetric, metric string, warn, crit float64, topN int) []Anomaly {
	vals := hm.Metrics[metric]
	if vals == nil {
		return nil
	}
	type kv struct {
		key string
		v   float64
		sev Severity
	}
	var hits []kv
	for k, v := range vals {
		sev, ok := sevFor(v, warn, crit, false)
		if !ok {
			continue
		}
		hits = append(hits, kv{k, v, sev})
	}
	sort.Slice(hits, func(i, j int) bool {
		if hits[i].sev != hits[j].sev {
			return hits[i].sev == SevCrit
		}
		return hits[i].v > hits[j].v
	})
	if len(hits) > topN {
		hits = hits[:topN]
	}
	var out []Anomaly
	for _, h := range hits {
		out = append(out, Anomaly{
			Host: hm.Host, Metric: metric, Key: h.key, Value: h.v,
			Warn: warn, Crit: crit, Severity: h.sev,
			Desc: fmt.Sprintf("%s %s 使用率 %.1f%%", metricName(metric), h.key, h.v),
		})
	}
	return out
}

// judgeCrossHost 跨主机横向离群检测：同指标多台主机时，明显偏离集群
// 中心的主机标记为横向异常（批量部署、部分主机异常的场景下即使绝对
// 阈值未到也能检出）。仅对比整体型指标（cpu、磁盘根分区）。
//
// 方法：MAD（median absolute deviation）稳健离群检测——Hampel (1974)
// 规则，R mad()/scipy median_abs_deviation 同款：
//
//	mad = 1.4826 × median(|vi − med|)      // 1.4826 为正态一致性常数
//	fence = med + 2.5 × mad                 // 2.5× 为 moderate 界
//
// 统计离群且达到最小关注幅度（warn×0.5）才报：低于告警水位一半的
// 离群即使显著也无实际危害，过线后由 DeepDive 验证回路兜底确认。
// 样本 <3 台时无法定义可靠集群中心（分位数/MAD 的最小可用样本），不检测。
func judgeCrossHost(snap *Snapshot, th Thresholds) []Anomaly {
	var out []Anomaly
	hosts := snap.Hosts
	if len(hosts) < 3 {
		return nil
	}
	medianOf := func(sorted []float64) float64 {
		n := len(sorted)
		if n%2 == 1 {
			return sorted[n/2]
		}
		return (sorted[n/2-1] + sorted[n/2]) / 2
	}
	// mad 返回样本的稳健离散度（Hampel 常数 1.4826）；MAD=0 时
	// fence=med，退化由最小关注幅度护栏兜底，无需特殊分支。
	madOf := func(vals []float64) (median, mad float64) {
		median = medianOf(vals)
		devs := make([]float64, len(vals))
		for i, v := range vals {
			devs[i] = math.Abs(v - median)
		}
		sort.Float64s(devs)
		return median, 1.4826 * medianOf(devs)
	}
	check := func(metric string, pick func(*HostMetric) (float64, bool), warn float64) {
		var vals []float64
		for i := range hosts {
			if v, ok := pick(&hosts[i]); ok {
				vals = append(vals, v)
			}
		}
		if len(vals) < 3 {
			return
		}
		sort.Float64s(vals)
		med, mad := madOf(vals)
		fence := med + 2.5*mad
		for i := range hosts {
			v, ok := pick(&hosts[i])
			if !ok {
				continue
			}
			// 统计离群 + 最小关注幅度双条件：防低水位噪声刷线索。
			if v > fence && v >= warn*0.5 {
				out = append(out, Anomaly{
					Host: hosts[i].Host, Metric: metric, Value: v,
					Warn: warn, Severity: SevWarn,
					Desc: fmt.Sprintf("%s=%.1f 横向偏离集群中位数 %.1f（×%.1f，MAD 离群）",
						metricName(metric), v, med, v/med),
				})
			}
		}
	}
	check("cpu", func(h *HostMetric) (float64, bool) {
		if h.CPU == nil || h.CPU.Pct < 0 {
			return 0, false
		}
		return h.CPU.Pct, true
	}, th.CPUWarn)
	check("disk", func(h *HostMetric) (float64, bool) {
		if h.Metrics["disk"] == nil {
			return 0, false
		}
		v, ok := h.Metrics["disk"]["/"]
		return v, ok
	}, th.DiskWarn)
	return out
}

func sortAnomalies(list []Anomaly) {
	sort.SliceStable(list, func(i, j int) bool {
		if list[i].Severity != list[j].Severity {
			return list[i].Severity == SevCrit
		}
		if list[i].Host != list[j].Host {
			return list[i].Host < list[j].Host
		}
		return list[i].Value > list[j].Value
	})
}

func metricName(id string) string {
	for _, m := range []Metric{ // 仅取名称
		{ID: "cpu", Name: "CPU"},
		{ID: "mem", Name: "内存"},
		{ID: "disk", Name: "磁盘"},
		{ID: "inode", Name: "inode"},
		{ID: "zombie", Name: "僵尸进程"},
		{ID: "svc_failed", Name: "失败服务"},
		{ID: "container", Name: "停止容器"},
		{ID: "proc_top", Name: "单进程CPU"},
		{ID: "kernel_events", Name: "内核事件"},
		{ID: "net_if_errors", Name: "网卡错误"},
		{ID: "swap", Name: "交换分区"},
		{ID: "proc_deleted", Name: "已删二进制进程"},
		{ID: "ssh_root_login", Name: "SSH root 密码直登"},
		{ID: "k8s_pod_abnormal", Name: "异常Pod"},
		{ID: "k8s_deploy_unready", Name: "未就绪Deployment"},
		{ID: "k8s_node_notready", Name: "NotReady节点"},
		{ID: "lvm_lv_full", Name: "逻辑卷"},
	} {
		if m.ID == id {
			return m.Name
		}
	}
	return id
}

// cmpWord 描述阈值方向：FailDown 指标是“≤”触发，其余是“≥”触发。
func cmpWord(failDown bool) string {
	if failDown {
		return "≤"
	}
	return "≥"
}
