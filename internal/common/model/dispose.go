package model

import (
	"fmt"
	"strings"
	"time"
)

// 处置机制（docs/design-v2.md §三）——第一要义机制。
//
// 机制保证（马鞍侧约束，模型在结构内决策）：
//  1. 去向闭合：confirmed finding 必有处置去向（verified_fixed /
//     manual_workorder / accepted_risk）——"处置方案为空"是非法状态，
//     没有自动方案就产出人工工单；
//  2. ✓ 绑定证据：verified_fixed 必须携带功能验证证据（业务协议验证
//     命令 + 恢复判据 + 实际输出），不允许空 ✓；
//  3. 变更分级：动作带变更级（配置/服务/网络/认证），强制手段
//     （杀进程/重启）为最后手段；
//  4. 处置失败升级：自动处置失败/达限 → 人工工单（含影响面/步骤/
//     验证/回滚），不静默、不降级。

// DispositionOutcome is the disposition outcome (three-state contract).
// DispositionOutcome 处置去向（三态契约）。
type DispositionOutcome string

const (
	// DispositionVerifiedFixed marks the finding as fixed with functional verification evidence (business-protocol verification).
	// DispositionVerifiedFixed 已修复：附功能验证证据（业务协议验证）。
	DispositionVerifiedFixed DispositionOutcome = "verified_fixed"
	// DispositionManualWorkOrder marks the finding as handed to a manual work order (evidence package, suggested commands, steps, verification, and impact).
	// DispositionManualWorkOrder 人工工单：附证据包+建议命令+步骤+验证+影响面。
	DispositionManualWorkOrder DispositionOutcome = "manual_workorder"
	// DispositionAcceptedRisk marks the finding as an accepted risk with rationale and compensating measures.
	// DispositionAcceptedRisk 接受风险：附理由与补偿措施。
	DispositionAcceptedRisk DispositionOutcome = "accepted_risk"
)

// Valid reports whether the outcome is one of the three valid states.
// Valid 三态枚举校验。
func (o DispositionOutcome) Valid() bool {
	switch o {
	case DispositionVerifiedFixed, DispositionManualWorkOrder, DispositionAcceptedRisk:
		return true
	}
	return false
}

// ChangeClass is the change class: the basis for the least-destructive ordering of disposition actions.
// ChangeClass 变更分级：处置动作的最小破坏序依据（配置 → 热生效 →
// 优雅重启 → 强制手段为最后手段）。
type ChangeClass string

const (
	// ChangeConfig is the change class for config-only corrections (config/owner only, runtime untouched).
	// ChangeConfig 配置修正类变更：只改配置/属主，不碰运行态。
	ChangeConfig  ChangeClass = "config"  // 配置修正：只改配置/属主，不碰运行态
	// ChangeService is the change class for service-level changes (graceful restart/start).
	// ChangeService 服务级变更：优雅重启/拉起。
	ChangeService ChangeClass = "service" // 服务级：优雅重启/拉起
	// ChangeNetwork is the change class for network changes (firewall/routing; the channel must be verified afterwards).
	// ChangeNetwork 网络面变更：防火墙/路由（改后必须验证通道）。
	ChangeNetwork ChangeClass = "network" // 网络面：防火墙/路由（改后必须验证通道）
	// ChangeAuth is the change class for authentication changes (ssh/pam/passwords; must be verified with a new session).
	// ChangeAuth 认证面变更：ssh/pam/口令（改后必须新会话验证）。
	ChangeAuth    ChangeClass = "auth"    // 认证面：ssh/pam/口令（改后必须新会话验证）
)

// VerificationEvidence is the functional verification evidence that the checkmark binds to.
// VerificationEvidence 功能验证证据：✓ 的绑定依据。验证必须是业务协议
// 验证（ssh 新会话实际认证/minio mc 读写/防火墙新会话可达+业务端口探测），
// pgrep + 端口检查不算验证证据。
type VerificationEvidence struct {
	VerifyCmd string    `json:"verify_cmd"`       // 验证命令（业务协议）
	CheckUp   string    `json:"check_up"`         // 恢复判据（验证输出中表示恢复的行/短语）
	Output    string    `json:"output,omitempty"` // 实际输出摘要（证据）
	At        time.Time `json:"at"`
}

// WorkOrder is the complete disposition package handed to humans when automatic disposition is impossible.
// WorkOrder 人工工单产物：无法自动处置时交付给人工的完整处置包。
type WorkOrder struct {
	Summary           string   `json:"summary"`                      // 问题摘要（根因+置信度）
	Impact            string   `json:"impact,omitempty"`             // 影响面（业务影响/风险）
	SuggestedCommands []string `json:"suggested_commands,omitempty"` // 建议命令（有则给）
	Steps             []string `json:"steps,omitempty"`              // 人工执行步骤
	VerificationSteps []string `json:"verification_steps,omitempty"` // 验证步骤（业务协议）
	Rollback          string   `json:"rollback,omitempty"`           // 回滚预案
}

// Disposition is the data form of the disposition outcome (three-state contract).
// Disposition 处置去向（三态契约的数据形态）。Finding.Disposition 为 nil
// 表示尚未处置（运行中），终态报告断言非 nil。
type Disposition struct {
	Outcome       DispositionOutcome     `json:"outcome"`
	Class         ChangeClass            `json:"class,omitempty"`
	Evidence      []VerificationEvidence `json:"evidence,omitempty"`       // verified_fixed 必需
	WorkOrder     *WorkOrder             `json:"work_order,omitempty"`     // manual_workorder 必需
	RiskRationale string                 `json:"risk_rationale,omitempty"` // accepted_risk 必需
	At            time.Time              `json:"at"`
}

// NewVerifiedDisposition builds a "verified fixed" disposition with functional verification evidence.
// NewVerifiedDisposition 构造"已修复"去向（附功能验证证据）。
func NewVerifiedDisposition(class ChangeClass, evidence []VerificationEvidence) *Disposition {
	return &Disposition{Outcome: DispositionVerifiedFixed, Class: class, Evidence: evidence, At: time.Now().UTC()}
}

// NewWorkOrderDisposition builds a "manual work order" disposition.
// NewWorkOrderDisposition 构造"人工工单"去向。
func NewWorkOrderDisposition(class ChangeClass, wo *WorkOrder) *Disposition {
	return &Disposition{Outcome: DispositionManualWorkOrder, Class: class, WorkOrder: wo, At: time.Now().UTC()}
}

// NewAcceptedRiskDisposition builds an "accepted risk" disposition.
// NewAcceptedRiskDisposition 构造"接受风险"去向。
func NewAcceptedRiskDisposition(class ChangeClass, rationale string) *Disposition {
	return &Disposition{Outcome: DispositionAcceptedRisk, Class: class, RiskRationale: rationale, At: time.Now().UTC()}
}

// Validate checks the disposition outcome contract and returns the list of violations (empty means valid).
// Validate 校验处置去向契约。返回违规列表（空=通过）。
func (d *Disposition) Validate() []string {
	if d == nil {
		return []string{"缺少处置去向（三态契约: verified_fixed/manual_workorder/accepted_risk）"}
	}
	var v []string
	if !d.Outcome.Valid() {
		v = append(v, fmt.Sprintf("非法处置去向 %q（三态契约: verified_fixed/manual_workorder/accepted_risk）", d.Outcome))
		return v
	}
	switch d.Outcome {
	case DispositionVerifiedFixed:
		if len(d.Evidence) == 0 {
			v = append(v, "verified_fixed 缺少功能验证证据（✓ 必须绑定业务协议验证，不允许空 ✓）")
		}
		for i, ev := range d.Evidence {
			if strings.TrimSpace(ev.VerifyCmd) == "" {
				v = append(v, fmt.Sprintf("验证证据 #%d 缺验证命令（业务协议验证）", i+1))
			}
			if strings.TrimSpace(ev.CheckUp) == "" {
				v = append(v, fmt.Sprintf("验证证据 #%d 缺恢复判据 check_up", i+1))
			}
		}
	case DispositionManualWorkOrder:
		if d.WorkOrder == nil || (strings.TrimSpace(d.WorkOrder.Summary) == "" && len(d.WorkOrder.Steps) == 0) {
			v = append(v, "manual_workorder 缺工单内容（问题摘要或人工步骤）")
		}
	case DispositionAcceptedRisk:
		if strings.TrimSpace(d.RiskRationale) == "" {
			v = append(v, "accepted_risk 缺理由（接受风险必须说明理由与补偿）")
		}
	}
	return v
}

// DispositionInvariants asserts the disposition mechanism invariants during report construction.
// DispositionInvariants 处置机制不变量（报告构建期断言）。
//
// final=false（运行中/实时渲染）：只断言闭环结构违规——已发生的状态
// 不得自相矛盾（✓ 无证据、工单残缺、已处置∧待查互斥、"处置方案为空"
// 非法文本残留）；未处置去向不强制（运行中允许在途）。
//
// final=true（终态报告）：追加去向闭合断言——每条 confirmed finding
// 必须有处置去向（已修复/人工工单/接受风险）。
func DispositionInvariants(findings []*Finding, final bool) []string {
	var v []string
	for _, f := range findings {
		id := f.ID
		if id == "" {
			id = f.Host + "/" + f.Signal
		}
		// 已处置 ∧ 待查 互斥（同一 finding 不允许既是待查又是已处置）。
		if f.Status == FindingPending && f.Remediated {
			v = append(v, fmt.Sprintf("finding %s：已处置(remediated)与待查(pending)互斥", id))
		}
		// "处置方案为空"是非法状态残留（空方案必须升级为工单）。
		if strings.Contains(f.RemediationNote, "处置方案为空") {
			v = append(v, fmt.Sprintf("finding %s：残留非法状态文本『处置方案为空』（空方案必须升级为人工工单）", id))
		}
		if f.Disposition == nil {
			if final && f.Status == FindingConfirmed && !f.Remediated {
				v = append(v, fmt.Sprintf("finding %s：confirmed 无处置去向（三态契约: verified_fixed/manual_workorder/accepted_risk）", id))
			}
			if f.Remediated {
				v = append(v, fmt.Sprintf("finding %s：已标记处置但无处置去向（✓ 必须绑定三态去向与验证证据）", id))
			}
			continue
		}
		for _, iv := range f.Disposition.Validate() {
			v = append(v, fmt.Sprintf("finding %s：%s", id, iv))
		}
		// 已处置必须 verified_fixed（接受风险/工单项不得谎报已处置）。
		if f.Remediated && f.Disposition.Outcome != DispositionVerifiedFixed {
			v = append(v, fmt.Sprintf("finding %s：已标记处置但去向为 %s（已处置只允许 verified_fixed）", id, f.Disposition.Outcome))
		}
	}
	return v
}
