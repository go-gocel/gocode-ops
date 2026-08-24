// Package remediate — 处置执行器（公用内核）：三件套契约执行/验证/回滚/
// 幂等预检/自通道校验/确定性复检/人工工单构造。
//
// 这是两种形态共用的处置能力：autopilot（全自动运维引擎）的 respond 阶段
// 驱动本包执行处置；assistant（交互式运维助手）未来可接入同一处置通道
// （操作员批准后自动执行三件套修复）。安全由守卫机械强制（硬性禁止/
// 自影响审查/白名单仅处置通道可登记），与模型自觉无关。
package remediate

import (
	"strings"
	"time"

	"github.com/go-gocel/gocode-ops/internal/common/guard"
)

// Config 处置执行配置。
type Config struct {
	// ActTimeout 单条处置动作命令的执行超时（修复/清理类命令常规上限）。
	ActTimeout time.Duration
	// VerifyTimeout 处置后验证命令的执行超时（验证必须快，慢验证会拖慢收敛循环）。
	VerifyTimeout time.Duration
	// Local 仅本机模式：host 为空或等于 LocalHost 时按本地执行（通道面跳过）。
	Local bool
	// LocalHost 本机显示名（与 Local 配合判定本地执行）。
	LocalHost string
	// Guard 守卫（PolicyAuto 实例）：verify 只读校验（CheckReadOnly）与
	// 动作/回滚预检共用；nil 时 verify 只读校验跳过（测试注入路径）。
	Guard *guard.RiskyCommandGuard
}

// MaxTries 处置尝试上限：达限仍未处置的 confirmed 升级人工工单（不静默、
// 不降级）。autopilot 引用本常量（原 maxRespondTries）。
const MaxTries = 3

// Plan 模型为单个已确认故障生成的处置方案。
//
// 契约（三件套）：每个动作必须同时提供 理由(rationale) + 验证(verify) +
// 回滚(rollback)，缺一即拒绝执行——SOP 由模型按现场动态生成，安全由
// 引擎机械校验。硬性禁止命令（格式化/删根/凭证等）即使三件套齐全也拒绝。
type Plan struct {
	FindingID string       `json:"finding_id"`
	Actions   []PlanAction `json:"actions"`
}

// PlanAction 单个处置动作。
type PlanAction struct {
	Name      string `json:"name"`
	Command   string `json:"command"`
	Rationale string `json:"rationale"` // 处置理由
	Verify    string `json:"verify"`    // 处置后验证命令
	CheckUp   string `json:"check_up"`  // 恢复判据（验证输出中完整相等的行）
	Rollback  string `json:"rollback"`  // 验证失败回滚命令
}

// Validate 校验三件套契约。返回未通过的动作名列表。
func (p *Plan) Validate() []string {
	var bad []string
	if p == nil || len(p.Actions) == 0 {
		return []string{"<empty>"}
	}
	for _, a := range p.Actions {
		if strings.TrimSpace(a.Command) == "" ||
			strings.TrimSpace(a.Rationale) == "" ||
			strings.TrimSpace(a.Verify) == "" ||
			strings.TrimSpace(a.CheckUp) == "" ||
			strings.TrimSpace(a.Rollback) == "" {
			bad = append(bad, a.Name)
		}
	}
	return bad
}

// Suggestions 提取修复建议（命令 + 理由摘要），供报告"修复建议"区展示。
// 缺 command 的动作跳过；缺 rationale 时只列命令。
func (p *Plan) Suggestions() []string {
	if p == nil {
		return nil
	}
	out := make([]string, 0, len(p.Actions))
	for _, a := range p.Actions {
		cmd := strings.TrimSpace(a.Command)
		if cmd == "" {
			continue
		}
		if r := strings.TrimSpace(a.Rationale); r != "" {
			out = append(out, cmd+"（"+r+"）")
		} else {
			out = append(out, cmd)
		}
	}
	return out
}
