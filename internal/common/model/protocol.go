package model

import (
	"time"
)

// Phase 协议阶段（类型与共享阶段常量；模型阶段常量见 autopilot 包）。
// 阶段是"流程骨架"不是"故障知识"：每个阶段内查什么、怎么查完全由
// 模型基于现场与方法论决定；引擎只管推进、超时与安全。
type Phase string

// PhaseRescan 复扫（报告层合并 rescan×N 依赖此常量；引擎复用）。
const PhaseRescan Phase = "rescan"

// Finding 发现（统一结构，三态由验证回路裁决）。
type Finding struct {
	ID         string    `json:"id"`
	Host       string    `json:"host"`
	Domain     string    `json:"domain"`             // cpu/mem/disk/svc/security/…
	Signal     string    `json:"signal"`             // 稳定信号名（去重键）
	Key        string    `json:"key,omitempty"`      // 线索子键（如漂移源 state_sshd），参与去重——同 signal 不同源不互吞
	Desc       string    `json:"desc"`               // 现象描述
	Evidence   []string  `json:"evidence,omitempty"` // 证据（命令 + 输出要点）
	Status     string    `json:"status"`             // pending/confirmed/dismissed
	RootCause  string    `json:"root_cause,omitempty"`
	Confidence float64   `json:"confidence,omitempty"`
	At         time.Time `json:"at"`
	Source     string    `json:"source,omitempty"` // 证据链来源：l0/deepdive（引擎）或空=模型上报
	// ConfirmedAt/RemediatedAt 处置时间线（检出→确认→处置耗时，评测复盘
	// 的核心指标——此前只有 at，处置节奏只能从 actions.at 反推）。
	ConfirmedAt     time.Time `json:"confirmed_at,omitempty"`
	RemediatedAt    time.Time `json:"remediated_at,omitempty"`
	Tried           int       `json:"tried,omitempty"`         // 参与 DeepDive 追查次数
	Remediated      bool      `json:"remediated,omitempty"`    // 已处置（confirmed 只处置一次）
	RespondTried    int       `json:"respond_tried,omitempty"` // 处置尝试次数（达上限停止自动重试）
	Reruled         bool      `json:"reruled,omitempty"`       // 已参与重裁决（悬置项只重裁决一次）
	Redetect        int       `json:"redetect,omitempty"`      // L0 连续重检出计数（重追查回路的触发依据）
	Rechased        int       `json:"rechased,omitempty"`      // 重追查次数（达上限停止自动重查）
	FinalRuled      bool      `json:"final_ruled,omitempty"`   // 已参与收敛前终裁（每条线索一次）
	Learned         bool      `json:"learned,omitempty"`       // 已沉淀进记忆（经验库/档案，学习闭环防重复）
	Actions         []Action  `json:"actions,omitempty"`       // 处置动作记录
	RemediationNote string    `json:"remediation_note,omitempty"`
	// Disposition 处置去向（三态契约：verified_fixed/manual_workorder/
	// accepted_risk——处置机制保证 confirmed 必有去向，nil=运行中在途）。
	// 引擎行为层字段：模型上报不得覆盖（merge 见 engineOwned）。
	Disposition *Disposition `json:"disposition,omitempty"`
	// SuggestedFix 修复建议（处置方案的 command+rationale 摘要）。方案
	// 解析成功即记录，处置未执行/失败时仍进报告——修复建议不依赖
	// 处置是否成功。
	SuggestedFix []string `json:"suggested_fix,omitempty"`
}

// 证据链来源（引擎行为层标记，merge 分层与复发重置的依据）。
const (
	SourceL0       = "l0"       // L0 确定性快检/探针产出
	SourceDeepDive = "deepdive" // DeepDive 模型追查确认链
)

// 验证回路三态。
const (
	FindingPending   = "pending"   // 线索/候选：未验证，不视为故障
	FindingConfirmed = "confirmed" // 已验证：可处置、进报告故障区
	FindingDismissed = "dismissed" // 已排除：进报告"已排查"区（防误报）
)

// EnvInfo 环境画像（Explore 产出，供后续阶段与报告使用）。
// 字段类型即契约：布尔字段必须输出 true/false——模型把布尔写成字符串
// 会让整个阶段解析失败（解析层有 LenientBool 兜底，但契约先声明）。
type EnvInfo struct {
	OS         string            `json:"os"`
	Kernel     string            `json:"kernel"`
	Hostname   string            `json:"hostname"`
	ServiceMgr string            `json:"service_mgr"` // systemd/sysvinit/none
	Container  LenientBool       `json:"container"`
	DockerCmd  string            `json:"docker_cmd,omitempty"`
	Network    string            `json:"network,omitempty"`
	Services   []string          `json:"services,omitempty"`  // 关键服务
	LogPaths   []string          `json:"log_paths,omitempty"` // 日志位置
	Toolchain  map[string]string `json:"toolchain,omitempty"` // 工具可用性
	Notes      string            `json:"notes,omitempty"`
}

// NewFinding 创建 pending 线索。ID 由工作区入库时确定性补全
// （workspace.AddFindings：host/signal/去重键的 fnv32 哈希）——
// 本处不预设 ID：历史实现用 UnixNano()%100000 在此预设，低时钟
// 分辨率环境（Hyper-V/容器）同一 tick 内批量创建的 finding 全部
// 同 ID，导致 respond 处置目标定位错配（byID 覆盖丢失）。
func NewFinding(host, domain, signal, desc string) *Finding {
	return &Finding{
		Host: host, Domain: domain, Signal: signal, Desc: desc,
		Status: FindingPending, At: time.Now().UTC(),
	}
}
