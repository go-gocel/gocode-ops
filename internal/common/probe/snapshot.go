package probe

// snapshot.go — 快照模型：一轮快检的结构化结果（探针域的产出物）。

import (
	"github.com/go-gocel/gocode-ops/internal/common/fsutil"
	"time"
)

// Snapshot is the structured result of one round of fast inspection.
// Snapshot 一轮快检的结构化结果。
type Snapshot struct {
	At    time.Time    `json:"at"`
	Hosts []HostMetric `json:"hosts"`
}

// HostMetric is the inspection result of a single host.
// HostMetric 单台主机的快检结果。
type HostMetric struct {
	Host    string                        `json:"host"`
	CPU     *CPUInfo                      `json:"cpu,omitempty"`    // nil=本轮无数据
	Metrics map[string]map[string]float64 `json:"metrics"`          // metricID → 键 → 值
	Raw     map[string]string             `json:"raw,omitempty"`    // metricID → 截断原始输出（证据）
	Errors  map[string]string             `json:"errors,omitempty"` // metricID 或 "collect" → 错误
	State   map[string]string             `json:"state,omitempty"`  // 状态快照 probeID → 摘要（漂移检测）
	// FactAge 重探针缓存命中时的数据龄期（probeID → 如 "3m2s"）；空=实采。
	// 供模型上下文标注新鲜度（TTL 复用的事实不是刚采集的）。
	FactAge map[string]string `json:"fact_age,omitempty"`
	// FactCoverage 事实探针覆盖语义（design-v2.md §二：覆盖度是事实的
	// 一部分，沿管道传递）：
	//   full    = 完整采集（例行/缓存命中）
	//   partial = 不完整（探针超时/采集中断/哨兵触发）——枚举结果不可
	//             作为结论，下游只产"待下钻"线索，绝不进缓存/基线
	//   skipped = 本轮未扫描（下钻探针未被例行包含，属设计决策）
	FactCoverage map[string]string `json:"fact_coverage,omitempty"`
}

// CPUInfo is the CPU usage over the most recent sampling interval
// (derived from /proc/stat deltas).
// CPUInfo 最近采样间隔的 CPU 使用率（/proc/stat 增量）。
type CPUInfo struct {
	Pct   float64 `json:"pct"`   // 使用率 %
	Load1 float64 `json:"load1"` // loadavg 1 分钟（证据字段）
	NProc int     `json:"nproc"` // 可见核数
}

// SetError records an error message for the given probe or collector key,
// lazily initializing the Errors map.
// SetError 记录指定探针或采集键的错误信息（惰性初始化 Errors 映射）。
func (hm *HostMetric) SetError(id, msg string) {
	if hm.Errors == nil {
		hm.Errors = map[string]string{}
	}
	hm.Errors[id] = msg
}

// SetRaw records the raw probe output for the given ID, truncated to
// 2048 bytes, lazily initializing the Raw map.
// SetRaw 记录指定探针 ID 的原始输出（截断到 2048 字节，惰性初始化 Raw 映射）。
func (hm *HostMetric) SetRaw(id, frag string) {
	if hm.Raw == nil {
		hm.Raw = map[string]string{}
	}
	hm.Raw[id] = fsutil.TruncateStr(frag, 2048)
}

// rawCov 覆盖感知的探针原始数据读取：探针覆盖为 partial（不完整枚举）
// 时返回空——不完整结果不得驱动归属规则（超时截断被当"扫描无结果"
// 是假阴性源；design-v2.md §二：partial 只产待下钻线索，不产结论）。
func (hm *HostMetric) rawCov(id string) string {
	if hm.FactCoverage[id] == "partial" {
		return ""
	}
	return hm.Raw[id]
}

// rawAnyCov 多探针源读取（例行定点 + 下钻全量变体共用同一归属规则）：
// 任一源有完整数据即返回（下钻结果对全量面产线）；全部 partial 时
// 返回空——不产线，覆盖线索由 JudgeSecurityFacts 的 partial 分支给出。
func (hm *HostMetric) rawAnyCov(ids ...string) string {
	for _, id := range ids {
		if r := hm.rawCov(id); r != "" {
			return r
		}
	}
	return ""
}

// run 在 host（""=本机，否则远程别名）执行命令。收集路径优先用大上限
// 执行器（ExecCollect，L0 全量探针输出 > 8K 展示上限），未实现则回退
// Exec（测试 fake）。
