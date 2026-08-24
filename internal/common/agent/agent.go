// Package agent 是 gocode-ops 公用内核的装配层：统一装配（AgentConfig/NewAgent）
// 三态、基线、报告、守卫、审计、远程执行与 agent 统一装配。
//
// 两种形态都构建在本包之上：
//   - 交互式运维助手（internal/assistant）：L0 快检按需触发（l0_snapshot 工具）、
//     人在环（Operator + Policy）；
//   - 全自动运维引擎（internal/engine）：组合本包 + 模型阶段协议骨架与收敛循环。
//
// 公共能力：
//   - L0 确定性层（快检/线索/基线/漂移/安全事实）；
//   - 工作区（findings 三态/基线/阶段记录）与实时报告；
//   - 守卫（RiskyCommandGuard，ask/allow/deny/auto 策略）、审计、
//     远程执行（SSH 执行器 + remote_* 工具族）；
//   - agent 统一装配（AgentConfig/NewAgent）、会话（Session）、
//     共享提示词构建块（SharedOpsRules/MethodologyRules）；
//   - 领域工具（AllTools/AskOperatorTool/L0SnapshotTool）。
package agent

import (
	"github.com/go-gocel/gocel-core/core/kernel"
	"github.com/go-gocel/gocel/agents"
	"github.com/go-gocel/gocel/harness"
	"github.com/go-gocel/gocel/module/workspace"

	tl "github.com/go-gocel/gocode-ops/internal/common/tools"
)

// AgentConfig is the unified assembly configuration for the ops domain.
// AgentConfig 是 ops 领域的统一装配配置：交互式运维助手与全自动运维引擎的
// 阶段 agent 共用同一个装配入口（NewAgent），差异仅通过配置表达（工具集、
// 提示词、模块、步数）。安全基础设施（workspace 文件边界 + 高危命令
// 守卫）固定挂载，机械强制不依赖配置。
type AgentConfig struct {
	Model        kernel.Model
	Name         string
	Description  string
	SystemPrompt string
	MaxSteps     int
	WorkDir      string
	Host         string
	Operator     Operator
	Policy       Policy
	Remote       RemoteExecutor
	// Audit 可选：守卫的审计联动（NewAuditLog 返回）；nil 不联动。
	Audit *AuditLog
	// Guard 注入已有守卫（如引擎共享的 PolicyAuto 守卫）；
	// nil 时按 Operator/Policy/Remote 内部创建。
	Guard *RiskyCommandGuard
	// ToolBuilder 自定义工具集（如引擎的最小集：terminal + remote_terminal）；
	// nil 时使用默认全套（AllTools）。
	ToolBuilder func(guard *RiskyCommandGuard) []kernel.Tool
	// Modules 附加模块（如 AGENTS.md 注入）；安全基础设施由 NewAgent 固定挂载。
	Modules []kernel.Module
	// JSONOutput 强制模型以 JSON 对象输出（response_format=json_object，
	// 服务端约束输出语法）。阶段协议引擎使用；TUI 对话模式不设。
	JSONOutput bool
	// L0 非 nil 时追加 l0_snapshot 工具：模型按需触发确定性快检（共享
	// 底座），不再每轮无条件前置。交互式运维助手注入；引擎阶段 agent
	// 不设（引擎主循环自己跑 L0Round）。
	L0 L0Snapshooter
}

// NewAgent assembles a ReAct policy agent from the given config.
// NewAgent 是 ops 领域的统一装配入口：按配置装配一个 React 策略 Agent
// （harness 装配器），固定挂载 workspace 文件边界守卫与高危命令守卫。
// 交互式运维助手与全自动运维引擎的阶段 agent 都从这里装配。
func NewAgent(cfg AgentConfig) (*agents.App, error) {
	// 安全基础设施：文件工具边界 + 高危命令守卫（命令级安全），机械强制。
	ws := workspace.New(cfg.WorkDir)
	// 运维场景的命令级安全由 RiskyCommandGuard 负责（sudo、rm -rf、mkfs、
	// 服务启停等），workspace 守卫只保留文件工具的工作目录限制，避免双重
	// 拦截导致操作员确认流程失效。
	ws.BlockPrefix = nil

	risky := cfg.Guard
	if risky == nil {
		risky = NewRiskyCommandGuard(cfg.Operator, cfg.Policy)
		if cfg.Remote != nil {
			risky.ResolveHosts = cfg.Remote.Resolve
			// 自影响审查需要连接事实（交互式运维助手与全自动运维引擎一套机制）；
			// remote 未实现时按保守模式（通道面一律视为风险）。
			if rf, ok := cfg.Remote.(interface {
				ConnFacts([]string) map[string]ConnFact
			}); ok {
				risky.ConnFacts = rf.ConnFacts
			}
		}
		if cfg.Audit != nil {
			risky.Audit = cfg.Audit
		}
	}

	toolBuilder := cfg.ToolBuilder
	if toolBuilder == nil {
		toolBuilder = func(g *RiskyCommandGuard) []kernel.Tool {
			return tl.AllTools(cfg.Operator, cfg.Remote, g)
		}
	}
	tools := toolBuilder(risky)
	if cfg.L0 != nil {
		tools = append(tools, tl.L0SnapshotTool(cfg.L0))
	}

	modules := append([]kernel.Module{ws, risky}, cfg.Modules...)

	opts := []harness.Option{
		harness.WithReactPolicy(),
		harness.WithName(cfg.Name),
		harness.WithDescription(cfg.Description),
		harness.WithSystemPrompt(cfg.SystemPrompt),
		harness.WithMaxSteps(cfg.MaxSteps),
		harness.WithTools(tools),
		harness.WithModules(modules),
	}
	if cfg.JSONOutput {
		opts = append(opts, harness.WithJSONOutput())
	}
	return harness.NewAgent(cfg.Model, opts...)
}
