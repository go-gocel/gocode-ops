package model

import "time"

// Severity is the severity of an anomaly.
// Severity 异常严重度。
type Severity string

// SevWarn is the warning severity.
// SevCrit is the critical severity.
// 严重度常量：SevWarn=警告（warn），SevCrit=严重（critical）。
const (
	SevWarn Severity = "warn"
	SevCrit Severity = "critical"
)

// Action is the execution record of one remediation action, written
// after the respond phase runs its three-step set.
// Action 一次处置动作的执行记录（respond 阶段三件套执行后写入）。
type Action struct {
	Name      string `json:"name"`
	Host      string `json:"host"`
	Command   string `json:"command"`
	Auto      bool   `json:"auto"` // 经守卫白名单登记自动放行；false=被拒绝或仅建议
	Result    string `json:"result,omitempty"`
	Error     string `json:"error,omitempty"`
	Verified  bool   `json:"verified"`              // 处置后验证通过
	RolledBac bool   `json:"rolled_back,omitempty"` // 验证失败已回滚
	Advised   bool   `json:"advised,omitempty"`     // 自影响风险：未执行，仅给人工建议
	// Prechecked 幂等预检通过：执行前 verify 已满足判据（前次处置已
	// 生效），跳过副作用命令直接视为已验证。只出现在重试轮
	// （RespondTried≥2），首轮不预检。
	Prechecked bool `json:"prechecked,omitempty"`
	// AdvisedReason 建议原因（自影响审查结论 + 安全替代建议）。
	AdvisedReason string `json:"advised_reason,omitempty"`
	// VerifyNote 验证失败详情（期望行 vs 实际输出）——反馈闭环用：
	// 模型下轮据此修正 verify/check_up，而不是重复同样的失败。
	VerifyNote string `json:"verify_note,omitempty"`
	// VerifyOut 验证通过时的实际输出摘要（功能验证证据：✓ 的绑定依据，
	// 处置机制 verified_fixed 的 evidence 来源）。
	VerifyOut string    `json:"verify_out,omitempty"`
	At        time.Time `json:"at"`
	DurationS float64   `json:"duration_s,omitempty"`
}
